"""Command-line entry points for the staged VulnAssess pipeline."""

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from pydantic.json_schema import models_json_schema

from vulnassess.adapters._input import read_capture
from vulnassess.errors import ConfigError, ScopeError, VulnAssessError
from vulnassess.registry import get_reader
from vulnassess.schema import (
    ContextProfile,
    Enrichment,
    Feature,
    Finding,
    Host,
    Provenance,
    Rationale,
    ScoreBreakdown,
    Service,
)
from vulnassess.settings import Settings
from vulnassess.store import Run, Store

app = typer.Typer(
    name="vulnassess",
    help="Local-first vulnerability prioritisation for authorised lab targets only.",
    no_args_is_help=True,
)

schema_app = typer.Typer(help="Export the canonical data contracts.", no_args_is_help=True)
app.add_typer(schema_app, name="schema")


@schema_app.command("export")
def export_schema(
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit compact, deterministic JSON.")
    ] = False,
    run_id: Annotated[
        str | None, typer.Option("--run-id", help="Attach a caller-supplied run identifier.")
    ] = None,
) -> None:
    """Write JSON Schema definitions without requiring scan, feed or model inputs."""
    if run_id is not None and not run_id.strip():
        error = ConfigError("Invalid schema export --run-id: must not be blank")
        typer.echo(str(error), err=True)
        raise typer.Exit(code=error.exit_code)
    _, document = models_json_schema(
        [
            (Provenance, "validation"),
            (Service, "validation"),
            (Host, "validation"),
            (Finding, "validation"),
            (Feature, "validation"),
            (ContextProfile, "validation"),
            (Enrichment, "validation"),
            (ScoreBreakdown, "validation"),
            (Rationale, "validation"),
        ],
        title="VulnAssess canonical contracts",
    )
    document["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    if run_id is not None:
        document["x-vulnassess-run-id"] = run_id
    typer.echo(
        json.dumps(
            document,
            sort_keys=True,
            indent=None if json_output else 2,
            separators=(",", ":") if json_output else None,
            allow_nan=False,
        )
    )


RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
STORE_FILENAME = "vulnassess.db"
RAW_SUFFIXES = {"nmap": ".xml", "zap": ".json"}


def _raw_dir(data_dir: Path, run_id: str) -> Path:
    return data_dir / "raw" / run_id


def _run_for(store: Store, run_id: str, config_hash: str) -> Run:
    """Reuse an existing run, or record a new one. A changed configuration is an error."""
    try:
        run = store.get_run(run_id)
    except ConfigError as error:
        if "MISSING: runs.run_id" not in str(error):
            raise
        run = Run(
            run_id=run_id,
            started_at=datetime.now(UTC),
            config_hash=config_hash,
            feeds={},
        )
        store.add_run(run)
        return run
    if run.config_hash != config_hash:
        raise ConfigError(
            f"Run {run_id!r} was stored under config_hash {run.config_hash}; "
            f"the current configuration hashes to {config_hash}. Use a new --run-id."
        )
    return run


def _import_run(
    *,
    run_id: str,
    target_ip: str,
    nmap: Path,
    zap: Path | None,
    config_dir: Path,
    data_dir: Path,
) -> dict[str, Any]:
    """Authorise, copy, parse and store. No capture path is touched before the scope check."""
    if not RUN_ID_PATTERN.match(run_id):
        raise ConfigError(
            f"Invalid --run-id {run_id!r}: use 1-64 characters from A-Z a-z 0-9 . _ - "
            "starting with a letter or digit"
        )
    settings = Settings.load(config_dir)
    if not settings.scope.permits(target_ip):
        raise ScopeError(
            f"Target {target_ip!r} is not authorised by {config_dir / 'scope.yaml'} "
            "(allowed_cidrs, allowed_hosts); no capture file was opened"
        )

    raw_dir = _raw_dir(data_dir, run_id)
    try:
        raw_dir.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise ConfigError(f"Cannot create raw capture directory {raw_dir}") from error

    hosts: dict[str, Host] = {}
    findings: list[Finding] = []
    findings_by_tool: dict[str, int] = {}
    sources: list[tuple[str, Path]] = [("nmap", nmap)]
    if zap is not None:
        sources.append(("zap", zap))

    for tool, source in sources:
        content = read_capture(source)
        copy = raw_dir / f"{tool}{RAW_SUFFIXES[tool]}"
        try:
            copy.write_bytes(content)
        except OSError as error:
            raise ConfigError(f"Cannot write raw capture copy {copy}") from error
        result = get_reader(tool)(copy, run_id)
        for host in result.hosts:
            hosts[host.ip] = host
        findings.extend(result.findings)
        findings_by_tool[tool] = len(result.findings)

    for address in sorted({*hosts, *(finding.host_ip for finding in findings)}):
        if not settings.scope.permits(address):
            raise ScopeError(
                f"Capture records address {address!r}, which "
                f"{config_dir / 'scope.yaml'} does not authorise"
            )

    config_hash = settings.config_hash()
    store = Store(data_dir / STORE_FILENAME, create=True)
    try:
        _run_for(store, run_id, config_hash)
        for host in hosts.values():
            store.upsert_host(run_id, host)
        for finding in findings:
            store.upsert_finding(finding)
        stored_hosts = len(store.list_hosts(run_id))
        stored_findings = len(store.list_findings(run_id))
    finally:
        store.close()

    return {
        "run_id": run_id,
        "target_ip": target_ip,
        "hosts": stored_hosts,
        "findings": stored_findings,
        "findings_by_tool": findings_by_tool,
        "raw_dir": raw_dir.as_posix(),
        "store": (data_dir / STORE_FILENAME).as_posix(),
        "config_hash": config_hash,
    }


@app.command("import")
def import_capture(
    run_id: Annotated[str, typer.Option("--run-id", help="Identifier for this assessment run.")],
    target_ip: Annotated[
        str, typer.Option("--target-ip", help="Authorised lab address the captures describe.")
    ],
    nmap: Annotated[Path, typer.Option("--nmap", help="Nmap XML capture to import.")],
    zap: Annotated[
        Path | None, typer.Option("--zap", help="Optional ZAP JSON report to import.")
    ] = None,
    config_dir: Annotated[
        Path, typer.Option("--config-dir", help="Directory holding scope.yaml and friends.")
    ] = Path("config"),
    data_dir: Annotated[
        Path, typer.Option("--data-dir", help="Directory for raw copies and the store.")
    ] = Path("data"),
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the same summary as compact JSON.")
    ] = False,
) -> None:
    """Import existing scanner captures for one authorised target."""
    try:
        summary = _import_run(
            run_id=run_id,
            target_ip=target_ip,
            nmap=nmap,
            zap=zap,
            config_dir=config_dir,
            data_dir=data_dir,
        )
    except VulnAssessError as error:
        typer.echo(str(error), err=True)
        raise typer.Exit(code=error.exit_code) from None
    if json_output:
        typer.echo(json.dumps(summary, sort_keys=True, separators=(",", ":"), allow_nan=False))
        return
    by_tool = " ".join(
        f"{tool}={count}" for tool, count in sorted(summary["findings_by_tool"].items())
    )
    typer.echo(
        f"run={summary['run_id']} target={summary['target_ip']} "
        f"hosts={summary['hosts']} findings={summary['findings']} [{by_tool}] "
        f"raw={summary['raw_dir']}"
    )


def _not_implemented() -> NoReturn:
    typer.echo("not implemented")
    raise typer.Exit(code=2)


@app.command()
def scan() -> None:
    """Collect evidence from authorised lab targets."""
    _not_implemented()


@app.command()
def enrich() -> None:
    """Enrich findings with locally cached intelligence."""
    _not_implemented()


@app.command()
def context() -> None:
    """Infer bounded deployment context from evidence."""
    _not_implemented()


@app.command()
def rank() -> None:
    """Rank findings with the documented scoring formula."""
    _not_implemented()


@app.command()
def explain() -> None:
    """Write plain-English rationales without changing scores."""
    _not_implemented()


@app.command()
def report() -> None:
    """Render an offline report."""
    _not_implemented()


@app.command()
def eval() -> None:
    """Compare rankings with expert judgments."""
    _not_implemented()


@app.command()
def intel() -> None:
    """Manage the local intelligence cache."""
    _not_implemented()


if __name__ == "__main__":
    app()
