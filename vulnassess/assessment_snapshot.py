"""Hash-verified frozen assessment bundles.

This protects exported evidence from later store changes. It does not replace the
pending run/snapshot-isolated database migration.
"""

import json
from pathlib import Path
from typing import Any

from vulnassess.audit import load_json_payload
from vulnassess.errors import ConfigError

SNAPSHOT_SCHEMA_VERSION = 1
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024


def _canonical(payload: Any) -> str:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _digest(payload: Any) -> str:
    from hashlib import sha256

    return sha256(_canonical(payload).encode("utf-8")).hexdigest()


def build_snapshot(settings, store, run_id: str, *, model_hash: str | None = None) -> dict[str, Any]:
    run = store.run_info(run_id)
    if run is None:
        raise ConfigError(f"MISSING: run {run_id!r}")
    findings = store.findings(run_id)
    finding_ids = {finding.id for finding in findings}
    scores = store.scores(run_id)
    profiles = store.profiles(run_id)
    hosts = store.hosts(run_id)
    rationales = store.rationales(run_id)
    enrichments = {
        finding.id: [item.to_json() for item in store.enrichments(finding.id)]
        for finding in findings
    }
    score_ids = {score.finding_id for score in scores}
    if score_ids - finding_ids:
        raise ConfigError(
            f"run {run_id!r} has score rows without findings: {sorted(score_ids - finding_ids)}"
        )
    profile_hosts = {profile.host_ip for profile in profiles}
    host_ips = {host.ip for host in hosts}
    if profile_hosts - host_ips:
        raise ConfigError(
            f"run {run_id!r} has context profiles without hosts: {sorted(profile_hosts - host_ips)}"
        )
    rationale_ids = set(rationales)
    if rationale_ids - finding_ids:
        raise ConfigError(
            f"run {run_id!r} has rationales without findings: {sorted(rationale_ids - finding_ids)}"
        )

    feed_meta = {
        key: {
            "path": value.get("path"),
            "sha256": value.get("sha256"),
            "file_date": value.get("file_date"),
            "rows": value.get("rows"),
        }
        for key, value in store.feeds_meta().items()
    }
    core = {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "evidence_status": "NOT RUN",
        "data_kind": "assessment_state",
        "run": run,
        "configuration": {
            "hash_current": settings.config_hash(),
            "hash_at_run_start": run.get("config_hash"),
            "drift": settings.config_hash() != run.get("config_hash"),
            "validated": settings.raw,
        },
        "feed_snapshot": feed_meta,
        "model_hash": model_hash,
        "hosts": [host.to_json() for host in hosts],
        "findings": [finding.to_json() for finding in findings],
        "enrichments": enrichments,
        "profiles": [profile.to_json() for profile in profiles],
        "scores": [score.to_json() for score in scores],
        "rationales": {
            finding_id: rationale.to_json()
            for finding_id, rationale in sorted(rationales.items())
        },
        "limitations": [
            (
                "feed and enrichment tables are global in the current store; this bundle freezes "
                "their state at export time but cannot prove they were unchanged beforehand"
            )
        ],
    }
    return {**core, "snapshot_hash": _digest(core)}


def validate_snapshot(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != SNAPSHOT_SCHEMA_VERSION:
        raise ConfigError(
            f"assessment snapshot schema must be {SNAPSHOT_SCHEMA_VERSION}, got "
            f"{payload.get('schema_version')!r}"
        )
    claimed = payload.get("snapshot_hash")
    core = {key: value for key, value in payload.items() if key != "snapshot_hash"}
    computed = _digest(core)
    if claimed != computed:
        raise ConfigError(
            f"assessment snapshot hash mismatch: artifact says {claimed!r}, computed {computed!r}"
        )
    required = {
        "run",
        "configuration",
        "feed_snapshot",
        "hosts",
        "findings",
        "enrichments",
        "profiles",
        "scores",
        "rationales",
    }
    missing = sorted(required - set(payload))
    if missing:
        raise ConfigError(f"assessment snapshot is missing key {missing[0]!r}")
    finding_ids = {item.get("id") for item in payload["findings"]}
    if any(score.get("finding_id") not in finding_ids for score in payload["scores"]):
        raise ConfigError("assessment snapshot contains a score without its finding")
    return payload


def save_snapshot(payload: dict[str, Any], path: str | Path) -> Path:
    validate_snapshot(payload)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(_canonical(payload) + "\n", encoding="utf-8")
    temporary.replace(path)
    return path


def load_snapshot(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    payload = load_json_payload(
        path, "assessment snapshot", max_bytes=MAX_SNAPSHOT_BYTES
    )
    if not isinstance(payload, dict):
        raise ConfigError(f"invalid assessment snapshot {path}: expected an object")
    return validate_snapshot(payload)
