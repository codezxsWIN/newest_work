"""Import traditional ZAP JSON reports without running ZAP or resolving hosts."""

import json
from collections.abc import Iterator
from datetime import datetime
from email.utils import parsedate_to_datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Literal
from uuid import NAMESPACE_URL, uuid5

from pydantic import AliasChoices, AnyHttpUrl, BaseModel, Field, StrictInt, StrictStr, TypeAdapter

from vulnassess.adapters._input import EVIDENCE_CHARS, evidence_ids, evidence_urls, read_capture
from vulnassess.errors import AdapterError
from vulnassess.schema import Finding, Provenance


class _Instance(BaseModel):
	uri: str
	method: str
	param: str | None = None
	evidence: str | None = None


class _Alert(BaseModel):
	pluginid: StrictStr | StrictInt
	alert_ref: str | None = Field(default=None, alias="alertRef")
	title: str = Field(validation_alias=AliasChoices("alert", "name"))
	riskcode: StrictStr | StrictInt
	confidence: StrictStr | StrictInt
	desc: str
	instances: list[_Instance]
	cweid: StrictStr | StrictInt | None = None
	reference: str | None = None
	otherinfo: str | None = None


class _Site(BaseModel):
	host: str = Field(alias="@host")
	port: StrictStr | StrictInt = Field(alias="@port")
	ssl: Literal["true", "false"] = Field(alias="@ssl")
	alerts: list[_Alert]


class _Report(BaseModel):
	version: str = Field(alias="@version")
	generated: str = Field(alias="@generated")
	sites: list[_Site] = Field(alias="site", min_length=1)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
	result: dict[str, Any] = {}
	for key, value in pairs:
		if key in result:
			raise ValueError(f"Duplicate JSON key: {key}")
		result[key] = value
	return result


def _reject_constant(value: str) -> None:
	raise ValueError(f"Non-finite JSON value: {value}")


def _next_token(text: str, position: int) -> int:
	while position < len(text) and text[position] in " \t\r\n":
		position += 1
	return position


def _member_offsets(text: str, start: int) -> dict[str, int]:
	"""Locate object members using the stdlib decoder after full JSON validation."""
	decoder = json.JSONDecoder()
	position = _next_token(text, start + 1)
	offsets: dict[str, int] = {}
	while text[position] != "}":
		key, position = decoder.raw_decode(text, position)
		position = _next_token(text, position)
		position = _next_token(text, position + 1)
		offsets[key] = position
		_, position = decoder.raw_decode(text, position)
		position = _next_token(text, position)
		if text[position] == ",":
			position = _next_token(text, position + 1)
	return offsets


def _array_spans(text: str, start: int) -> Iterator[tuple[int, int]]:
	decoder = json.JSONDecoder()
	position = _next_token(text, start + 1)
	while text[position] != "]":
		_, end = decoder.raw_decode(text, position)
		yield position, end
		position = _next_token(text, end)
		if text[position] == ",":
			position = _next_token(text, position + 1)


def _generated_at(value: str) -> datetime:
	try:
		return datetime.fromisoformat(value)
	except ValueError:
		return parsedate_to_datetime(value)


def _finding(
	alert: _Alert,
	instance: _Instance | None,
	host_ip: str,
	port: int,
	ssl: str,
	generated: datetime,
	excerpt: str,
	path: Path,
	run_id: str,
	record_index: int,
) -> Finding:
	native_id = alert.alert_ref or str(alert.pluginid)
	if not native_id.strip() or not alert.title.strip():
		raise AdapterError(f"Missing alerts.pluginid/alert in ZAP capture {path}")
	url: str | None = None
	if instance is not None:
		parsed_url = TypeAdapter(AnyHttpUrl).validate_python(instance.uri)
		if parsed_url.username is not None or parsed_url.password is not None:
			raise AdapterError(f"Credential-bearing instance.uri in ZAP capture {path}")
		parsed_host = parsed_url.host
		if parsed_host is None or str(ip_address(parsed_host.strip("[]"))) != host_ip:
			raise AdapterError(f"Instance URI host does not match site.@host in ZAP capture {path}")
		if parsed_url.port != port or (parsed_url.scheme == "https") != (ssl == "true"):
			raise AdapterError(f"Instance URI does not match site.@port/@ssl in ZAP capture {path}")
		if not instance.method.strip():
			raise AdapterError(f"Missing instances.method in ZAP capture {path}")
		url = instance.uri
		native_id = json.dumps(
			[native_id, instance.method, instance.param], separators=(",", ":"), ensure_ascii=False
		)
	severity_by_code = {"0": "Informational", "1": "Low", "2": "Medium", "3": "High"}
	riskcode = str(alert.riskcode)
	confidence = str(alert.confidence)
	if riskcode not in severity_by_code or confidence not in {"0", "1", "2", "3", "4"}:
		raise AdapterError(f"Invalid alerts.riskcode/confidence in ZAP capture {path}")
	cwe_ids: list[str] = []
	if alert.cweid is not None:
		cwe_number = int(alert.cweid)
		if cwe_number < 0:
			raise AdapterError(f"Invalid alerts.cweid in ZAP capture {path}")
		if cwe_number:
			cwe_ids = [f"CWE-{cwe_number}"]
	observed = "\n".join(
		value for value in (alert.title, alert.desc, alert.reference, alert.otherinfo) if value
	)
	fingerprint = Finding.fingerprint(host_ip, port, "tcp", "zap", native_id, url)
	return Finding(
		id=str(uuid5(NAMESPACE_URL, fingerprint)),
		host_ip=host_ip,
		port=port,
		protocol="tcp",
		url=url,
		tool="zap",
		tool_native_id=native_id,
		title=alert.title,
		description=alert.desc,
		evidence=excerpt,
		cve_ids=evidence_ids(observed, "CVE"),
		cwe_ids=sorted(set(cwe_ids) | set(evidence_ids(observed, "CWE"))),
		reference_urls=evidence_urls(alert.reference or ""),
		native_severity=severity_by_code[riskcode],
		native_confidence=confidence,
		first_seen=generated,
		last_seen=generated,
		provenance=Provenance(
			tool="zap", raw_path=str(path), record_index=record_index, run_id=run_id
		),
	)


def parse_zap_json(path: Path, run_id: str) -> list[Finding]:
	"""Parse a report with explicit IP sites; caller checks scope before persistence."""
	content = read_capture(path)
	if not run_id.strip():
		raise AdapterError(f"Missing run_id for ZAP capture {path}")
	try:
		text = content.decode("utf-8-sig")
		payload = json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
		report = _Report.model_validate(payload)
		if not report.version.strip():
			raise AdapterError(f"Missing @version in ZAP capture {path}")
		generated = _generated_at(report.generated)
		root_offsets = _member_offsets(text, _next_token(text, 0))
		findings: list[Finding] = []
		for site, (site_start, _) in zip(
			report.sites, _array_spans(text, root_offsets["site"]), strict=True
		):
			host_ip = str(ip_address(site.host))
			port = int(site.port)
			if not 1 <= port <= 65535:
				raise AdapterError(f"Invalid site.@port in ZAP capture {path}")
			site_offsets = _member_offsets(text, site_start)
			for alert, (alert_start, alert_end) in zip(
				site.alerts, _array_spans(text, site_offsets["alerts"]), strict=True
			):
				if not alert.instances:
					findings.append(
						_finding(
							alert,
							None,
							host_ip,
							port,
							site.ssl,
							generated,
							text[alert_start:alert_end][:EVIDENCE_CHARS],
							path,
							run_id,
							len(findings),
						)
					)
					continue
				alert_offsets = _member_offsets(text, alert_start)
				for instance, (start, end) in zip(
					alert.instances, _array_spans(text, alert_offsets["instances"]), strict=True
				):
					findings.append(
						_finding(
							alert,
							instance,
							host_ip,
							port,
							site.ssl,
							generated,
							text[start:end][:EVIDENCE_CHARS],
							path,
							run_id,
							len(findings),
						)
					)
		return findings
	except (ValueError, TypeError, OverflowError, RecursionError) as error:
		raise AdapterError(
			f"Malformed ZAP JSON or invalid record in {path}: {type(error).__name__}"
		) from error
