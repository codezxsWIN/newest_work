"""The pipeline stages. Each reads what earlier stages left in the store and writes its own."""

import shutil
from pathlib import Path
from typing import Any, Sequence

from vulnassess import context, evaluate, report, scoring
from vulnassess.errors import ConfigError, ScopeError
from vulnassess.readers import parse_nikto_json, parse_nmap_xml, parse_zap_json
from vulnassess.schema import Host, ScoreBreakdown
from vulnassess.settings import Settings
from vulnassess.store import Store

LABEL_WIDTH = 26
COLUMN_WIDTH = 18


def _raw_dir(store: Store, run_id: str) -> Path:
    return Path(store.path).parent / "raw" / run_id


def do_import(
    settings: Settings,
    store: Store,
    run_id: str,
    target_ip: str,
    nmap_path: str | Path | None,
    zap_path: str | Path | None = None,
    nikto_path: str | Path | None = None,
) -> dict[str, Any]:
    """Authorise first. No scan file is opened until the target is inside the fence."""
    scope = settings.scope
    if scope.is_canary(target_ip):
        raise ScopeError(
            f"{target_ip} is the canary in {settings.config_dir / 'scope.yaml'}; "
            "it must never be scanned or imported; nothing was read"
        )
    if not scope.contains(target_ip):
        raise ScopeError(
            f"{target_ip} is not in {settings.config_dir / 'scope.yaml'} "
            f"(allowed: {scope.allowed()}); nothing was read"
        )

    store.start_run(run_id, settings.config_hash())
    raw_dir = _raw_dir(store, run_id)
    raw_dir.mkdir(parents=True, exist_ok=True)

    hosts: list[Host] = []
    counts: dict[str, int] = {}

    if nmap_path:
        copy = raw_dir / Path(nmap_path).name
        if Path(nmap_path).resolve() != copy.resolve():
            shutil.copy2(nmap_path, copy)
        parsed_hosts, findings = parse_nmap_xml(copy, run_id)
        hosts = [host for host in parsed_hosts if host.ip == target_ip]
        findings = [finding for finding in findings if finding.host_ip == target_ip]
        counts["nmap"] = store.upsert_findings(run_id, findings)

    if zap_path:
        copy = raw_dir / Path(zap_path).name
        if Path(zap_path).resolve() != copy.resolve():
            shutil.copy2(zap_path, copy)
        findings = parse_zap_json(copy, run_id, host_ip=target_ip)
        counts["zap"] = store.upsert_findings(run_id, findings)

    if nikto_path:
        copy = raw_dir / Path(nikto_path).name
        if Path(nikto_path).resolve() != copy.resolve():
            shutil.copy2(nikto_path, copy)
        findings = parse_nikto_json(copy, run_id, host_ip=target_ip)
        counts["nikto"] = store.upsert_findings(run_id, findings)

    if not hosts:
        hosts = [Host(ip=target_ip)]
    for host in hosts:
        store.upsert_host(run_id, host)

    summary = {
        "run_id": run_id,
        "target_ip": target_ip,
        "hosts": len(hosts),
        "findings": counts,
    }
    existing = (store.run_info(run_id) or {}).get("summary") or {}
    imports = list(existing.get("imports", []))
    imports.append(summary)
    store.set_run_summary(run_id, {**existing, "imports": imports})
    return summary


def do_context(settings: Settings, store: Store, run_id: str) -> list:
    profiles = []
    for host in store.hosts(run_id):
        profile = context.build_profile(
            host,
            store.findings(run_id, host.ip),
            settings.scope,
            settings.roles,
            settings.controls,
        )
        store.upsert_profile(run_id, profile)
        profiles.append(profile)
    return profiles


def do_rank(settings: Settings, store: Store, run_id: str) -> list[ScoreBreakdown]:
    profiles = {profile.host_ip: profile for profile in store.profiles(run_id)}
    if not profiles:
        raise ConfigError(
            f"no context profiles for run {run_id!r}; run 'vulnassess context --run-id {run_id}' first"
        )
    services = {host.ip: host.services for host in store.hosts(run_id)}
    scores: list[ScoreBreakdown] = []
    for finding in store.findings(run_id):
        profile = profiles.get(finding.host_ip)
        if profile is None:
            continue
        breakdown = scoring.score(
            finding,
            scoring.best_enrichment(store.enrichments(finding.id)),
            profile,
            services.get(finding.host_ip, ()),
            settings.weights,
        )
        store.upsert_score(run_id, breakdown)
        scores.append(breakdown)
    return sorted(scores, key=lambda item: (-item.risk, item.finding_id))


def do_report(
    settings: Settings,
    store: Store,
    run_id: str,
    out_path: str | Path,
    audit_data: dict[str, Any] | None = None,
) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    html = report.render(
        run=store.run_info(run_id) or {"run_id": run_id},
        scores=store.scores(run_id),
        findings=store.findings(run_id),
        profiles=store.profiles(run_id),
        feeds=store.feeds_meta(),
        weights=settings.weights,
        config_hash=settings.config_hash(),
        rationales=store.rationales(run_id),
        audit=audit_data,
    )
    out_path.write_text(html, encoding="utf-8")
    return out_path


def baseline_orders(store: Store, run_id: str) -> dict[str, list[str]]:
    """Our ranking beside the two severity-only baselines it must beat."""
    scores = store.scores(run_id)
    ours = sorted(scores, key=lambda item: (-item.risk, item.finding_id))

    def base_of(item: ScoreBreakdown) -> float:
        return item.base_score if item.base_score is not None else item.risk / 10.0

    cvss_only = sorted(scores, key=lambda item: (-base_of(item), item.finding_id))
    cvss_epss = sorted(
        scores,
        key=lambda item: (
            -(base_of(item) * (0.5 + 0.5 * (item.epss_percentile or 0.0))),
            item.finding_id,
        ),
    )
    return {
        "ours": [item.finding_id for item in ours],
        "cvss_only": [item.finding_id for item in cvss_only],
        "cvss_epss": [item.finding_id for item in cvss_epss],
    }


def do_eval(store: Store, run_id: str, truth_path: str | Path) -> dict[str, Any]:
    truth = evaluate.load_truth(truth_path)
    known = {finding.id for finding in store.findings(run_id)}
    for expert in truth["experts"]:
        for item in evaluate._flatten(expert["ranking"]):
            if item not in known:
                raise ConfigError(
                    f"{truth_path}: expert {expert['name']!r} ranks {item!r}, "
                    f"which is not a finding in run {run_id!r}"
                )
    return evaluate.evaluate(baseline_orders(store, run_id), truth)


def _column(values: Sequence[str], label: str) -> str:
    return label.ljust(LABEL_WIDTH) + "".join(str(value).rjust(COLUMN_WIDTH) for value in values)


def two_machine_table(store: Store, run_id: str, cve: str | None = None) -> str:
    """The headline comparison: one CVE, two machines, two answers."""
    scores = store.scores(run_id)
    profiles = {profile.host_ip: profile for profile in store.profiles(run_id)}

    by_cve: dict[str, dict[str, ScoreBreakdown]] = {}
    for item in scores:
        if not item.cve_id:
            continue
        best = by_cve.setdefault(item.cve_id, {})
        if item.host_ip not in best or item.risk > best[item.host_ip].risk:
            best[item.host_ip] = item

    candidates = {key: value for key, value in by_cve.items() if len(value) >= 2}
    if cve:
        candidates = {key: value for key, value in by_cve.items() if key == cve}
    if not candidates:
        return (
            "No CVE appears on two or more hosts in this run; "
            "the two-machine comparison needs one."
        )

    chosen = max(
        sorted(candidates),
        key=lambda key: max(item.risk for item in candidates[key].values()),
    )
    entries = sorted(candidates[chosen].values(), key=lambda item: (-item.risk, item.host_ip))
    hosts = [item.host_ip for item in entries]

    def waf_of(host: str) -> str:
        profile = profiles.get(host)
        control = profile.controls.get("waf") if profile else None
        return str(control.value) if control and control.value else "no"

    def role_of(host: str) -> str:
        profile = profiles.get(host)
        return str(profile.role.value) if profile else "unknown"

    def exposure_of(host: str) -> str:
        profile = profiles.get(host)
        return str(profile.exposure.value) if profile else "unknown"

    lines = [
        f"Same CVE, same CVSS base - different risk:  {chosen}",
        "",
        _column(hosts, ""),
        _column([item.base_score for item in entries], "CVSS base"),
        _column([role_of(host) for host in hosts], "Role"),
        _column([exposure_of(host) for host in hosts], "Exposure"),
        _column([waf_of(host) for host in hosts], "WAF"),
        _column(
            [
                "-" if item.epss_percentile is None else int(round(item.epss_percentile * 100))
                for item in entries
            ],
            "EPSS percentile",
        ),
        _column(["yes" if item.kev else "no" for item in entries], "KEV"),
        _column([item.env_score for item in entries], "CVSS environmental"),
        _column([item.risk for item in entries], "RISK"),
        _column([item.band for item in entries], "BAND"),
        "",
    ]
    lines.extend(f"  {item.host_ip}: {item.reason}" for item in entries)
    return "\n".join(lines)
