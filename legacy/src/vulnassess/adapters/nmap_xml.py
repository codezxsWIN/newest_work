"""Import local Nmap XML; never invoke a scanner, network lookup or model."""

from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5
from xml.etree.ElementTree import Element, TreeBuilder
from xml.parsers import expat

from pydantic import ValidationError

from vulnassess.adapters._input import (
	EVIDENCE_CHARS,
	MAX_XML_DEPTH,
	MAX_XML_ELEMENTS,
	evidence_ids,
	evidence_urls,
	read_capture,
)
from vulnassess.errors import AdapterError
from vulnassess.schema import Finding, Host, Provenance, Service


def _tag_end(content: bytes, start: int) -> int:
	quote = 0
	for position in range(start, len(content)):
		value = content[position]
		if quote:
			if value == quote:
				quote = 0
		elif value in (34, 39):
			quote = value
		elif value == 62:
			return position + 1
	raise ValueError("Unterminated XML tag")


def _xml_records(content: bytes, path: Path) -> tuple[Element, dict[Element, str]]:
	content.decode("utf-8-sig")
	builder = TreeBuilder()
	parser = expat.ParserCreate(encoding="UTF-8")
	stack: list[tuple[Element, int, int]] = []
	excerpts: dict[Element, str] = {}
	element_count = 0

	def start(name: str, attributes: dict[str, str]) -> None:
		nonlocal element_count
		element_count += 1
		if len(stack) >= MAX_XML_DEPTH or element_count > MAX_XML_ELEMENTS:
			raise AdapterError(f"XML structure limit exceeded in {path}")
		node = builder.start(name, attributes)
		offset = parser.CurrentByteIndex
		stack.append((node, offset, _tag_end(content, offset)))

	def end(name: str) -> None:
		node, offset, opening_end = stack.pop()
		builder.end(name)
		if name not in {"port", "script"}:
			return
		stop = (
			opening_end
			if content[opening_end - 2 : opening_end] == b"/>"
			else _tag_end(content, parser.CurrentByteIndex)
		)
		excerpts[node] = content[offset:stop].decode("utf-8")[:EVIDENCE_CHARS]

	def doctype(name: str, system: str | None, public: str | None, subset: int) -> None:
		if name != "nmaprun" or system is not None or public is not None or subset:
			raise AdapterError(f"External or internal XML DTD is forbidden in {path}")

	parser.StartElementHandler = start
	parser.EndElementHandler = end
	parser.CharacterDataHandler = builder.data
	parser.StartDoctypeDeclHandler = doctype
	parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
	parser.Parse(content, True)
	return builder.close(), excerpts


def _required(node: Element, key: str, path: Path) -> str:
	value = node.get(key)
	if value is None or not value.strip():
		raise AdapterError(f"Missing {node.tag}.{key} in {path}")
	return value


def _timestamp(value: str, path: Path, key: str) -> datetime:
	try:
		return datetime.fromtimestamp(int(value), UTC)
	except (ValueError, OverflowError, OSError) as error:
		raise AdapterError(f"Invalid {key} timestamp in {path}") from error


def _text(node: Element) -> str:
	parts = list(node.itertext())
	parts.extend(child.get("output", "") for child in node.iter())
	return "\n".join(parts)


def _service(node: Element, path: Path) -> Service:
	port = int(_required(node, "portid", path))
	if not 1 <= port <= 65535:
		raise AdapterError(f"Invalid port.portid in {path}")
	service = node.find("service")
	attributes = service.attrib if service is not None else {}
	cpe = service.findtext("cpe") if service is not None else None
	banner = next(
		(script.get("output") for script in node.findall("script") if script.get("id") == "banner"),
		None,
	)
	return Service.model_validate(
		{
			"port": port,
			"protocol": _required(node, "protocol", path),
			"name": attributes.get("name"),
			"product": attributes.get("product"),
			"version": attributes.get("version"),
			"cpe": cpe,
			"banner": banner,
			"tls": attributes.get("tunnel") == "ssl",
		}
	)


def _finding(
	node: Element,
	host_ip: str,
	service: Service | None,
	path: Path,
	run_id: str,
	record_index: int,
	first_seen: datetime,
	last_seen: datetime,
	excerpt: str,
) -> Finding:
	port = service.port if service else None
	protocol = service.protocol if service else None
	native_id = _required(node, "id", path) if node.tag == "script" else "open-port"
	native_id = f"{node.tag}:{native_id}"
	observed_text = _text(node)
	fingerprint = Finding.fingerprint(host_ip, port, protocol, "nmap", native_id, None)
	return Finding(
		id=str(uuid5(NAMESPACE_URL, fingerprint)),
		host_ip=host_ip,
		port=port,
		protocol=protocol,
		url=None,
		tool="nmap",
		tool_native_id=native_id,
		title=(
			f"Nmap script: {node.get('id')}"
			if node.tag == "script"
			else f"Observed open {protocol} port {port}"
		),
		description=node.get("output", "") if node.tag == "script" else "Open-port observation",
		evidence=excerpt,
		cve_ids=evidence_ids(observed_text, "CVE") if node.tag == "script" else [],
		cwe_ids=evidence_ids(observed_text, "CWE") if node.tag == "script" else [],
		reference_urls=evidence_urls(observed_text) if node.tag == "script" else [],
		native_severity=None,
		native_confidence=None,
		first_seen=first_seen,
		last_seen=last_seen,
		provenance=Provenance(
			tool="nmap", raw_path=str(path), record_index=record_index, run_id=run_id
		),
	)


def parse_nmap_xml(path: Path, run_id: str) -> tuple[list[Host], list[Finding]]:
	"""Parse a completed capture; caller validates authorisation before persistence."""
	content = read_capture(path)
	if not run_id.strip():
		raise AdapterError(f"Missing run_id for Nmap capture {path}")
	try:
		root, excerpts = _xml_records(content, path)
		if root.tag != "nmaprun" or root.get("scanner") != "nmap":
			raise AdapterError(f"Expected nmaprun with scanner=nmap in {path}")
		start = _timestamp(_required(root, "start", path), path, "nmaprun.start")
		finished = root.find("runstats/finished")
		if finished is None or finished.get("exit") != "success":
			raise AdapterError(f"Missing successful runstats.finished in {path}")
		finish = _timestamp(_required(finished, "time", path), path, "runstats.finished.time")
		if finish < start:
			raise AdapterError(f"runstats.finished.time precedes nmaprun.start in {path}")
		hosts: list[Host] = []
		findings: list[Finding] = []
		for host_node in root.findall("host"):
			address = next(
				(
					node.get("addr")
					for node in host_node.findall("address")
					if node.get("addrtype") in {"ipv4", "ipv6"}
				),
				None,
			)
			if address is None:
				raise AdapterError(f"Missing host.address for record {len(hosts)} in {path}")
			host_ip = str(ip_address(address))
			host_start = _timestamp(
				host_node.get("starttime", str(int(start.timestamp()))), path, "host.starttime"
			)
			host_end = _timestamp(
				host_node.get("endtime", str(int(finish.timestamp()))), path, "host.endtime"
			)
			if host_end < host_start:
				raise AdapterError(f"host.endtime precedes host.starttime in {path}")
			services: list[Service] = []
			records: list[tuple[Element, Service | None]] = []
			for port_node in host_node.findall("ports/port"):
				state = port_node.find("state")
				if state is None:
					raise AdapterError(f"Missing port.state in {path}")
				if _required(state, "state", path) != "open":
					continue
				service = _service(port_node, path)
				services.append(service)
				records.append((port_node, service))
				records.extend((script, service) for script in port_node.findall("script"))
			records.extend((script, None) for script in host_node.findall("hostscript/script"))
			for node, service in records:
				findings.append(
					_finding(
						node,
						host_ip,
						service,
						path,
						run_id,
						len(findings),
						host_start,
						host_end,
						excerpts[node],
					)
				)
			hostname = host_node.find("hostnames/hostname")
			os_matches = host_node.findall("os/osmatch")
			os_match = max(os_matches, key=lambda node: int(node.get("accuracy", "0")), default=None)
			hosts.append(
				Host(
					ip=host_ip,
					hostname=hostname.get("name") if hostname is not None else None,
					os_guess=os_match.get("name") if os_match is not None else None,
					services=services,
				)
			)
		return hosts, findings
	except (expat.ExpatError, ValidationError, ValueError, OverflowError, RecursionError) as error:
		raise AdapterError(
			f"Malformed Nmap XML or invalid record in {path}: {type(error).__name__}"
		) from error
