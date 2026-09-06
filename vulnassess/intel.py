"""Offline vulnerability intelligence: load human-supplied snapshots, match CVEs to findings.

Nothing here reaches the network. A missing snapshot is reported, never fetched.
"""

import csv
import gzip
import io
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable

from packaging.version import InvalidVersion, Version

from vulnassess.errors import IntelUnavailable
from vulnassess.schema import Enrichment, Finding, Service

HINTS = {
    "nvd": "NVD API 2.0 JSON pages, e.g. services.nvd.nist.gov/rest/json/cves/2.0",
    "epss": "the EPSS daily CSV from epss.cyentia.com (epss_scores-YYYY-MM-DD.csv.gz)",
    "kev": "the CISA Known Exploited Vulnerabilities catalog JSON",
}
NUMERIC_PREFIX = re.compile(r"^[0-9.]+")
MAX_MATCH_TRACES = 200


@dataclass(frozen=True)
class MatchTrace:
    finding_id: str
    decision: str
    method: str
    cve_id: str | None
    confidence: float | None
    reason: str

    def to_json(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "decision": self.decision,
            "method": self.method,
            "cve_id": self.cve_id,
            "confidence": self.confidence,
            "reason": self.reason,
        }


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _missing(feed_dir: Path) -> list[str]:
    missing: list[str] = []
    nvd_dir = feed_dir / "nvd"
    if not nvd_dir.is_dir() or not sorted(nvd_dir.glob("*.json")):
        missing.append(f"{nvd_dir}/*.json  ({HINTS['nvd']})")
    if not (feed_dir / "epss.csv").is_file() and not (feed_dir / "epss.csv.gz").is_file():
        missing.append(f"{feed_dir / 'epss.csv'}[.gz]  ({HINTS['epss']})")
    if not (feed_dir / "kev.json").is_file():
        missing.append(f"{feed_dir / 'kev.json'}  ({HINTS['kev']})")
    return missing


def _compact_cve(entry: dict[str, Any]) -> dict[str, Any]:
    cve = entry.get("cve", entry)
    metrics = cve.get("metrics", {}) or {}

    def metric(key: str) -> tuple[str | None, float | None]:
        items = metrics.get(key) or []
        if not items:
            return None, None
        data = items[0].get("cvssData", {})
        return data.get("vectorString"), data.get("baseScore")

    cvss31_vector, cvss31_base = metric("cvssMetricV31")
    cvss40_vector, cvss40_base = metric("cvssMetricV40")
    description = next(
        (
            item.get("value", "")
            for item in cve.get("descriptions", [])
            if item.get("lang") == "en"
        ),
        "",
    )
    patch_references = [
        reference.get("url", "")
        for reference in cve.get("references", [])
        if {"Patch", "Vendor Advisory"} & set(reference.get("tags", []))
    ]
    cpe_matches = []
    for configuration in cve.get("configurations", []) or []:
        for node in configuration.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                if not match.get("vulnerable"):
                    continue
                cpe_matches.append(
                    {
                        "criteria": match.get("criteria", ""),
                        "versionStartIncluding": match.get("versionStartIncluding"),
                        "versionStartExcluding": match.get("versionStartExcluding"),
                        "versionEndIncluding": match.get("versionEndIncluding"),
                        "versionEndExcluding": match.get("versionEndExcluding"),
                    }
                )
    return {
        "id": cve.get("id", ""),
        "description": description,
        "cvss31_vector": cvss31_vector,
        "cvss31_base": cvss31_base,
        "cvss40_vector": cvss40_vector,
        "cvss40_base": cvss40_base,
        "patch_references": patch_references,
        "cpe_matches": cpe_matches,
        "published": cve.get("published"),
    }


def _read_epss(path: Path) -> tuple[list[tuple[str, float, float, str]], str | None]:
    raw = gzip.decompress(path.read_bytes()) if path.suffix == ".gz" else path.read_bytes()
    text = raw.decode("utf-8")
    score_date: str | None = None
    lines = text.splitlines()
    if lines and lines[0].startswith("#"):
        for token in lines[0].lstrip("#").split(","):
            key, _, value = token.partition(":")
            if key.strip() == "score_date":
                score_date = value.strip()[:10]
        lines = lines[1:]
    rows: list[tuple[str, float, float, str]] = []
    for record in csv.DictReader(io.StringIO("\n".join(lines))):
        cve = (record.get("cve") or "").strip()
        if not cve:
            continue
        rows.append(
            (cve, float(record.get("epss") or 0.0), float(record.get("percentile") or 0.0),
             score_date or "")
        )
    return rows, score_date


def load_feeds(feed_dir: str | Path, store) -> dict[str, int]:
    """Load the three snapshots a human placed in feed_dir. Never downloads anything."""
    feed_dir = Path(feed_dir)
    missing = _missing(feed_dir)
    if missing:
        raise IntelUnavailable(
            "MISSING feed snapshot(s); a human must place them locally:\n  - "
            + "\n  - ".join(missing)
        )

    nvd_files = sorted((feed_dir / "nvd").glob("*.json"))
    records: list[dict[str, Any]] = []
    per_file = []
    newest = None
    for path in nvd_files:
        per_file.append(_digest(path))
        modified = datetime.fromtimestamp(path.stat().st_mtime, UTC).date().isoformat()
        newest = modified if newest is None else max(newest, modified)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise IntelUnavailable(f"{path} is not valid NVD JSON ({error})") from error
        for entry in payload.get("vulnerabilities", []):
            record = _compact_cve(entry)
            if record["id"]:
                records.append(record)
    nvd_rows = store.put_cves(records)
    store.put_feed_meta(
        "nvd",
        str(feed_dir / "nvd"),
        sha256("".join(per_file).encode("utf-8")).hexdigest(),
        newest,
        nvd_rows,
    )

    epss_path = feed_dir / "epss.csv"
    if not epss_path.is_file():
        epss_path = feed_dir / "epss.csv.gz"
    epss_rows, score_date = _read_epss(epss_path)
    store.put_epss(epss_rows)
    store.put_feed_meta("epss", str(epss_path), _digest(epss_path), score_date, len(epss_rows))

    kev_path = feed_dir / "kev.json"
    try:
        kev_payload = json.loads(kev_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise IntelUnavailable(f"{kev_path} is not valid KEV JSON ({error})") from error
    kev_records = [item for item in kev_payload.get("vulnerabilities", []) if item.get("cveID")]
    store.put_kev(kev_records)
    store.put_feed_meta(
        "kev",
        str(kev_path),
        _digest(kev_path),
        str(kev_payload.get("dateReleased", ""))[:10] or None,
        len(kev_records),
    )
    return {"nvd": nvd_rows, "epss": len(epss_rows), "kev": len(kev_records)}


def _to_cpe23(cpe: str | None) -> tuple[str, str, str, str] | None:
    """Normalise cpe:/a:v:p:ver and cpe:2.3:a:v:p:ver:... to (part, vendor, product, version)."""
    if not cpe:
        return None
    text = cpe.strip()
    if text.startswith("cpe:2.3:"):
        parts = text.split(":")
        if len(parts) < 6:
            return None
        return parts[2], parts[3], parts[4], parts[5]
    if text.startswith("cpe:/"):
        parts = text[len("cpe:/") :].split(":")
        while len(parts) < 4:
            parts.append("*")
        return parts[0], parts[1], parts[2], parts[3] or "*"
    return None


def _same_product(left: str | None, right: str | None) -> bool:
    first, second = _to_cpe23(left), _to_cpe23(right)
    return bool(first and second and first[:3] == second[:3])


def _parse_version(text: str) -> Version | None:
    try:
        return Version(text)
    except InvalidVersion:
        prefix = NUMERIC_PREFIX.match(text or "")
        if not prefix:
            return None
        try:
            return Version(prefix.group(0).rstrip("."))
        except InvalidVersion:
            return None


def _in_range(version: str | None, cpe_match: dict[str, Any]) -> tuple[bool, float, str | None]:
    criteria = _to_cpe23(cpe_match.get("criteria"))
    pinned = criteria[3] if criteria else "*"
    end_bound = cpe_match.get("versionEndExcluding") or cpe_match.get("versionEndIncluding")

    if pinned not in ("*", "-", ""):
        return ((version or "") == pinned, 1.0, None)

    parsed = _parse_version(version or "")
    if parsed is None:
        return (bool(end_bound), 0.5, end_bound)

    bounds = (
        ("versionStartIncluding", lambda a, b: a >= b),
        ("versionStartExcluding", lambda a, b: a > b),
        ("versionEndIncluding", lambda a, b: a <= b),
        ("versionEndExcluding", lambda a, b: a < b),
    )
    for key, holds in bounds:
        limit = cpe_match.get(key)
        if not limit:
            continue
        other = _parse_version(str(limit))
        if other is None or not holds(parsed, other):
            return (False, 0.9, None)
    return (True, 0.9, end_bound)


def _threat(store, cve_id: str) -> tuple[float | None, float | None, bool, str | None]:
    epss_row = store.epss(cve_id)
    kev_row = store.kev(cve_id)
    return (
        None if epss_row is None else epss_row["epss"],
        None if epss_row is None else epss_row["percentile"],
        kev_row is not None,
        None if kev_row is None else kev_row.get("dateAdded"),
    )


def _enrichment(
    finding: Finding,
    cve_id: str,
    record: dict[str, Any] | None,
    method: str,
    confidence: float,
    version_end: str | None,
    store,
    feed_dates: dict[str, str],
) -> Enrichment:
    epss, percentile, kev, kev_date = _threat(store, cve_id)
    record = record or {}
    return Enrichment(
        finding_id=finding.id,
        cve_id=cve_id,
        match_method=method,
        match_confidence=confidence,
        cvss31_vector=record.get("cvss31_vector"),
        cvss31_base=record.get("cvss31_base"),
        cvss40_vector=record.get("cvss40_vector"),
        cvss40_base=record.get("cvss40_base"),
        epss=epss,
        epss_percentile=percentile,
        kev=kev,
        kev_date_added=kev_date,
        patch_references=tuple(record.get("patch_references", [])),
        description=record.get("description", ""),
        version_end=version_end,
        feed_dates=dict(feed_dates),
    )


def match_finding(
    finding: Finding,
    host_services: Iterable[Service],
    store,
    feed_dates: dict[str, str],
) -> list[Enrichment]:
    enrichments, _ = match_finding_with_trace(
        finding, host_services, store, feed_dates
    )
    return enrichments


def match_finding_with_trace(
    finding: Finding,
    host_services: Iterable[Service],
    store,
    feed_dates: dict[str, str],
) -> tuple[list[Enrichment], list[MatchTrace]]:
    service = next(
        (item for item in host_services if finding.port and item.port == finding.port), None
    )
    enrichments: list[Enrichment] = []
    claimed: set[str] = set()
    traces: list[MatchTrace] = []

    def trace(
        decision: str,
        method: str,
        reason: str,
        cve_id: str | None = None,
        confidence: float | None = None,
    ) -> None:
        if len(traces) < MAX_MATCH_TRACES:
            traces.append(
                MatchTrace(
                    finding_id=finding.id,
                    decision=decision,
                    method=method,
                    cve_id=cve_id,
                    confidence=confidence,
                    reason=reason,
                )
            )

    for cve_id in finding.cve_ids:
        record = store.cve(cve_id)
        version_end = None
        if record and service and service.cpe:
            for cpe_match in record.get("cpe_matches", []):
                if not _same_product(service.cpe, cpe_match.get("criteria")):
                    continue
                matched, _, end = _in_range(service.version, cpe_match)
                if matched and end:
                    version_end = end
                    break
        enrichments.append(
            _enrichment(finding, cve_id, record, "explicit", 1.0, version_end, store, feed_dates)
        )
        trace(
            "accepted",
            "explicit",
            (
                "scanner record explicitly named the CVE"
                if record is not None
                else "scanner record explicitly named the CVE, but the NVD snapshot has no row"
            ),
            cve_id,
            1.0,
        )
        claimed.add(cve_id)

    if service is None:
        trace(
            "not_attempted",
            "cpe_range",
            f"no observed service matches finding port {finding.port!r}",
        )
    elif not service.cpe:
        trace(
            "not_attempted",
            "cpe_range",
            "the observed service has no CPE",
        )
    else:
        product_candidates = 0
        for record in store.all_cves():
            if record["id"] in claimed:
                continue
            for cpe_match in record.get("cpe_matches", []):
                if not _same_product(service.cpe, cpe_match.get("criteria")):
                    continue
                product_candidates += 1
                matched, confidence, end = _in_range(service.version, cpe_match)
                if not matched:
                    trace(
                        "rejected",
                        "cpe_range",
                        (
                            f"service version {service.version!r} is outside the vulnerable "
                            "version range"
                        ),
                        record["id"],
                        confidence,
                    )
                    continue
                enrichments.append(
                    _enrichment(
                        finding, record["id"], record, "cpe_range", confidence, end, store,
                        feed_dates,
                    )
                )
                claimed.add(record["id"])
                trace(
                    "accepted",
                    "cpe_range",
                    (
                        f"service CPE product matches and version {service.version!r} is in range"
                    ),
                    record["id"],
                    confidence,
                )
                break
        if product_candidates == 0:
            trace(
                "not_matched",
                "cpe_range",
                f"no NVD CPE candidate matches service product {service.cpe!r}",
            )

    if not enrichments:
        trace(
            "fallback",
            "native_severity",
            "no CVE enrichment was accepted; ranking must use documented native evidence",
        )

    return enrichments, traces


def enrich_run(run_id: str, store) -> dict[str, Any]:
    meta = store.feeds_meta()
    if not meta:
        raise IntelUnavailable(
            "MISSING feed snapshots in the store; run 'vulnassess intel load --from-dir <dir>' first"
        )
    feed_dates = {feed: (info.get("file_date") or "") for feed, info in meta.items()}
    services = {host.ip: host.services for host in store.hosts(run_id)}
    findings = store.findings(run_id)
    matched = 0
    total = 0
    trace_counts: dict[str, int] = {}
    unmatched: list[dict[str, Any]] = []
    for finding in findings:
        enrichments, traces = match_finding_with_trace(
            finding, services.get(finding.host_ip, ()), store, feed_dates
        )
        for item in traces:
            key = f"{item.decision}:{item.method}"
            trace_counts[key] = trace_counts.get(key, 0) + 1
        if enrichments:
            matched += 1
        else:
            unmatched.append(
                {
                    "finding_id": finding.id,
                    "reasons": [item.reason for item in traces],
                }
            )
        for enrichment in enrichments:
            store.upsert_enrichment(enrichment)
            total += 1
    return {
        "findings": len(findings),
        "matched": matched,
        "enrichments": total,
        "trace_counts": dict(sorted(trace_counts.items())),
        "unmatched": unmatched,
    }


def trace_run(run_id: str, store) -> dict[str, Any]:
    """Recompute matching decisions for audit output without writing enrichment rows."""
    meta = store.feeds_meta()
    if not meta:
        raise IntelUnavailable(
            "MISSING feed snapshots in the store; run 'vulnassess intel load --from-dir <dir>' first"
        )
    feed_dates = {feed: (info.get("file_date") or "") for feed, info in meta.items()}
    services = {host.ip: host.services for host in store.hosts(run_id)}
    findings = store.findings(run_id)
    matched = 0
    trace_counts: dict[str, int] = {}
    unmatched: list[dict[str, Any]] = []
    traces_by_finding: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        enrichments, traces = match_finding_with_trace(
            finding, services.get(finding.host_ip, ()), store, feed_dates
        )
        matched += bool(enrichments)
        serialized = [item.to_json() for item in traces]
        traces_by_finding[finding.id] = serialized
        for item in traces:
            key = f"{item.decision}:{item.method}"
            trace_counts[key] = trace_counts.get(key, 0) + 1
        if not enrichments:
            unmatched.append(
                {
                    "finding_id": finding.id,
                    "reasons": [item.reason for item in traces],
                }
            )
    return {
        "run_id": run_id,
        "findings": len(findings),
        "matched": matched,
        "unmatched_count": len(unmatched),
        "trace_counts": dict(sorted(trace_counts.items())),
        "unmatched": unmatched,
        "traces": dict(sorted(traces_by_finding.items())),
    }
