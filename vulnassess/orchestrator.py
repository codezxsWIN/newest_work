"""Nmap-first scanner orchestration with explicit coverage outcomes.

Tests inject an executor. The agent never invokes a scanner through this module.
"""

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vulnassess.errors import AdapterError, ConfigError, ScopeError
from vulnassess.readers import parse_nikto_json, parse_nmap_xml, parse_zap_json
from vulnassess.schema import Host, Service

WEB_PORTS = {80, 443, 3000, 8000, 8080, 8443}
WEB_SERVICE = re.compile(r"(?:^|/)(?:https?|ssl/http)(?:$|[-_])", re.IGNORECASE)
TOOLS = ("nmap", "nikto", "zap")


@dataclass(frozen=True)
class Endpoint:
    scheme: str
    host: str
    port: int
    url: str
    evidence: str

    def to_json(self) -> dict[str, Any]:
        return {
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "url": self.url,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class ScannerCommand:
    tool: str
    argv: tuple[str, ...]
    output: Path
    endpoint: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "argv": list(self.argv),
            "output": str(self.output),
            "endpoint": self.endpoint,
        }


@dataclass(frozen=True)
class Execution:
    exit_code: int
    started_at: str
    ended_at: str
    detail: str = ""


@dataclass(frozen=True)
class ToolOutcome:
    tool: str
    status: str
    argv: tuple[str, ...] = ()
    endpoint: str | None = None
    started_at: str | None = None
    ended_at: str | None = None
    exit_code: int | None = None
    raw_path: str | None = None
    finding_count: int = 0
    failure: str | None = None
    skip_reason: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "status": self.status,
            "argv": list(self.argv),
            "endpoint": self.endpoint,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "exit_code": self.exit_code,
            "raw_path": self.raw_path,
            "finding_count": self.finding_count,
            "failure": self.failure,
            "skip_reason": self.skip_reason,
        }


@dataclass(frozen=True)
class OrchestrationPlan:
    target_ip: str
    discovery: ScannerCommand
    web_tools: tuple[str, ...]
    output_dir: Path
    canary_evidence: dict[str, Any]

    def to_json(self) -> dict[str, Any]:
        return {
            "target_ip": self.target_ip,
            "discovery": self.discovery.to_json(),
            "web_tools": list(self.web_tools),
            "output_dir": str(self.output_dir),
            "canary_evidence": dict(self.canary_evidence),
        }


Executor = Callable[[ScannerCommand], Execution]


def _authorize(settings, target_ip: str) -> None:
    if settings.scope.is_canary(target_ip):
        raise ScopeError(
            f"{target_ip} is the canary in {settings.config_dir / 'scope.yaml'}; "
            "no scanner command was built"
        )
    if not settings.scope.contains(target_ip) or settings.scope.name(target_ip) is None:
        raise ScopeError(
            f"{target_ip} is not an explicitly listed lab target in "
            f"{settings.config_dir / 'scope.yaml'}; no scanner command was built"
        )


def check_canary_log(path: str | Path | None) -> dict[str, Any]:
    if path is None:
        return {
            "status": "MISSING",
            "path": None,
            "reason": "no canary access log was supplied",
        }
    log = Path(path)
    if not log.is_file():
        return {
            "status": "MISSING",
            "path": str(log),
            "reason": f"MISSING: canary access log {log}",
        }
    try:
        content = log.read_text(encoding="utf-8")
    except OSError as error:
        raise ConfigError(f"cannot read canary access log {log}: {error}") from error
    if content.strip():
        raise ScopeError(
            f"canary access log {log} is non-empty; stop the scan and investigate"
        )
    return {
        "status": "VERIFIED",
        "path": str(log),
        "reason": "canary access log was empty",
    }


def plan(
    settings,
    target_ip: str,
    output_dir: str | Path,
    tools: Sequence[str] = TOOLS,
    canary_log: str | Path | None = None,
) -> OrchestrationPlan:
    """Authorize and build only the Nmap discovery command."""
    _authorize(settings, target_ip)
    requested = tuple(dict.fromkeys(tools))
    unknown = sorted(set(requested) - set(TOOLS))
    if unknown:
        raise ConfigError(f"unknown scanner {unknown[0]!r}; expected one of {TOOLS}")
    web_tools = tuple(tool for tool in requested if tool in ("nikto", "zap"))
    root = Path(output_dir)
    output = root / f"{target_ip}-nmap.xml"
    discovery = ScannerCommand(
        tool="nmap",
        argv=("nmap", "-sV", "-O", "--script", "vulners", "-oX", str(output), target_ip),
        output=output,
    )
    return OrchestrationPlan(
        target_ip=target_ip,
        discovery=discovery,
        web_tools=web_tools,
        output_dir=root,
        canary_evidence=check_canary_log(canary_log),
    )


def _is_web(service: Service) -> bool:
    return service.port in WEB_PORTS or bool(WEB_SERVICE.search(service.name or ""))


def derive_endpoints(host: Host) -> list[Endpoint]:
    endpoints: dict[tuple[str, int], Endpoint] = {}
    display_host = f"[{host.ip}]" if ":" in host.ip else host.ip
    for service in host.services:
        if not _is_web(service):
            continue
        scheme = (
            "https"
            if service.tls
            or service.port in {443, 8443}
            or "https" in (service.name or "").lower()
            or "ssl/http" in (service.name or "").lower()
            else "http"
        )
        default_port = 443 if scheme == "https" else 80
        suffix = "" if service.port == default_port else f":{service.port}"
        evidence = service.banner or f"{service.port}/{service.protocol} {service.name or ''}".strip()
        endpoints[(scheme, service.port)] = Endpoint(
            scheme=scheme,
            host=host.ip,
            port=service.port,
            url=f"{scheme}://{display_host}{suffix}",
            evidence=evidence,
        )
    return [endpoints[key] for key in sorted(endpoints)]


def web_plan(plan: OrchestrationPlan, host: Host) -> tuple[list[ScannerCommand], list[ToolOutcome]]:
    if host.ip != plan.target_ip:
        raise AdapterError(
            f"Nmap discovery returned host {host.ip}, expected target {plan.target_ip}"
        )
    endpoints = derive_endpoints(host)
    commands: list[ScannerCommand] = []
    skips: list[ToolOutcome] = []
    if not endpoints:
        for tool in plan.web_tools:
            skips.append(
                ToolOutcome(
                    tool=tool,
                    status="skipped",
                    skip_reason="no HTTP service was observed by successful Nmap discovery",
                )
            )
        return commands, skips

    for endpoint in endpoints:
        suffix = f"{endpoint.port}-{endpoint.scheme}"
        for tool in plan.web_tools:
            output = plan.output_dir / f"{plan.target_ip}-{suffix}-{tool}.json"
            argv = (
                (
                    "nikto",
                    "-h",
                    endpoint.url,
                    "-Format",
                    "json",
                    "-output",
                    str(output),
                )
                if tool == "nikto"
                else (
                    "zap-baseline.py",
                    "-t",
                    endpoint.url,
                    "-J",
                    str(output),
                )
            )
            commands.append(
                ScannerCommand(
                    tool=tool,
                    argv=argv,
                    output=output,
                    endpoint=endpoint.url,
                )
            )
    return commands, skips


def _finding_count(command: ScannerCommand, run_id: str, target_ip: str) -> int:
    if command.tool == "nmap":
        _, findings = parse_nmap_xml(command.output, run_id)
        return len([finding for finding in findings if finding.host_ip == target_ip])
    if command.tool == "zap":
        return len(parse_zap_json(command.output, run_id, host_ip=target_ip))
    if command.tool == "nikto":
        return len(parse_nikto_json(command.output, run_id, host_ip=target_ip))
    raise ConfigError(f"unknown scanner {command.tool!r}")


def _execute(command: ScannerCommand, executor: Executor, run_id: str, target_ip: str) -> ToolOutcome:
    try:
        execution = executor(command)
    except Exception as error:
        return ToolOutcome(
            tool=command.tool,
            status="failed",
            argv=command.argv,
            endpoint=command.endpoint,
            raw_path=str(command.output),
            failure=f"executor raised {type(error).__name__}: {error}",
        )
    if execution.exit_code != 0:
        return ToolOutcome(
            tool=command.tool,
            status="failed",
            argv=command.argv,
            endpoint=command.endpoint,
            started_at=execution.started_at,
            ended_at=execution.ended_at,
            exit_code=execution.exit_code,
            raw_path=str(command.output),
            failure=execution.detail or f"scanner exited {execution.exit_code}",
        )
    if not command.output.is_file():
        return ToolOutcome(
            tool=command.tool,
            status="failed",
            argv=command.argv,
            endpoint=command.endpoint,
            started_at=execution.started_at,
            ended_at=execution.ended_at,
            exit_code=execution.exit_code,
            raw_path=str(command.output),
            failure="scanner reported success but wrote no output",
        )
    try:
        count = _finding_count(command, run_id, target_ip)
    except AdapterError as error:
        return ToolOutcome(
            tool=command.tool,
            status="failed",
            argv=command.argv,
            endpoint=command.endpoint,
            started_at=execution.started_at,
            ended_at=execution.ended_at,
            exit_code=execution.exit_code,
            raw_path=str(command.output),
            failure=str(error),
        )
    return ToolOutcome(
        tool=command.tool,
        status="success",
        argv=command.argv,
        endpoint=command.endpoint,
        started_at=execution.started_at,
        ended_at=execution.ended_at,
        exit_code=execution.exit_code,
        raw_path=str(command.output),
        finding_count=count,
    )


def orchestrate(plan: OrchestrationPlan, run_id: str, executor: Executor) -> dict[str, Any]:
    """Execute Nmap first, derive endpoints, then continue independent web tools."""
    plan.output_dir.mkdir(parents=True, exist_ok=True)
    outcomes = [_execute(plan.discovery, executor, run_id, plan.target_ip)]
    discovery = outcomes[0]
    if discovery.status != "success":
        outcomes.extend(
            ToolOutcome(
                tool=tool,
                status="skipped",
                skip_reason="Nmap discovery failed; no endpoint can be justified",
            )
            for tool in plan.web_tools
        )
        return _summary(plan, [], outcomes)

    hosts, _ = parse_nmap_xml(plan.discovery.output, run_id)
    host = next((item for item in hosts if item.ip == plan.target_ip), None)
    if host is None:
        outcomes.extend(
            ToolOutcome(
                tool=tool,
                status="skipped",
                skip_reason=f"successful Nmap output did not contain target {plan.target_ip}",
            )
            for tool in plan.web_tools
        )
        return _summary(plan, [], outcomes)

    endpoints = derive_endpoints(host)
    commands, skips = web_plan(plan, host)
    outcomes.extend(skips)
    for command in commands:
        outcomes.append(_execute(command, executor, run_id, plan.target_ip))
    return _summary(plan, endpoints, outcomes)


def _summary(
    plan: OrchestrationPlan,
    endpoints: Sequence[Endpoint],
    outcomes: Sequence[ToolOutcome],
) -> dict[str, Any]:
    return {
        "target_ip": plan.target_ip,
        "canary_evidence": dict(plan.canary_evidence),
        "endpoints": [endpoint.to_json() for endpoint in endpoints],
        "outcomes": [outcome.to_json() for outcome in outcomes],
        "complete": all(outcome.status in ("success", "skipped") for outcome in outcomes)
        and not any(outcome.status == "failed" for outcome in outcomes),
        "successful_tools": sum(outcome.status == "success" for outcome in outcomes),
        "failed_tools": sum(outcome.status == "failed" for outcome in outcomes),
        "skipped_tools": sum(outcome.status == "skipped" for outcome in outcomes),
        "automated_decisions": {
            "tool_choice": "Nmap discovery is mandatory before requested web tools",
            "endpoint_construction": "only observed web services become endpoints",
            "scheme_selection": "TLS or ports 443/8443 select HTTPS; otherwise HTTP",
        },
    }
