"""Strict loading of hash-bound artifacts shown in audit reports."""

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from vulnassess.errors import ConfigError

MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_ARTIFACT_DEPTH = 128
MAX_ARTIFACT_NODES = 200_000
EVIDENCE_STATUSES = ("VERIFIED", "TESTED WITH MOCKS", "NOT RUN", "MISSING")
ARTIFACT_SPECS = {
    "scan": ("summary_hash", "run_id", ("executed", "notice")),
    "context": ("evaluation_hash", "run_id", ("rule_role", "exposure", "h1")),
    "ranking": ("evaluation_hash", "run_id", ("methods", "h2", "h3")),
    "ablation": ("experiment_hash", "run_id", ("scenarios", "comparisons", "orders")),
    "stability": ("stability_hash", "run_id", ("deterministic", "score_hashes")),
    "unification": ("preview_hash", "run_id", ("groups", "candidates", "raw_count")),
    "rescan": ("comparison_hash", "after", ("outcomes", "counts", "interpretation")),
}


def _canonical(payload: Any) -> str:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _digest(payload: Any) -> str:
    return sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ValueError(f"non-finite number {value}")


def _guard_structure(payload: Any) -> None:
    stack = [(payload, 1)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_ARTIFACT_NODES:
            raise ValueError(f"artifact exceeds {MAX_ARTIFACT_NODES} JSON nodes")
        if depth > MAX_ARTIFACT_DEPTH:
            raise ValueError(f"artifact exceeds JSON depth {MAX_ARTIFACT_DEPTH}")
        if isinstance(value, dict):
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            stack.extend((item, depth + 1) for item in value)


def load_json_payload(
    path: str | Path,
    label: str,
    *,
    max_bytes: int = MAX_ARTIFACT_BYTES,
) -> Any:
    path = Path(path)
    rendered = str(path)
    if rendered.startswith("\\\\") or rendered.startswith("//"):
        raise ConfigError(f"{label}: network-share artifact paths are forbidden: {path}")
    if not path.is_file():
        raise ConfigError(f"MISSING: {label} {path}")
    try:
        size = path.stat().st_size
        if size > max_bytes:
            raise ConfigError(f"{label} {path} exceeds {max_bytes} bytes")
        content = path.read_bytes()
        payload = json.loads(
            content.decode("utf-8-sig"),
            object_pairs_hook=_object,
            parse_constant=_constant,
        )
        _guard_structure(payload)
    except ConfigError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as error:
        raise ConfigError(f"invalid {label} {path}: {error}") from error
    return payload


@dataclass(frozen=True)
class AuditArtifact:
    kind: str
    path: str
    artifact_hash: str
    evidence_status: str
    summary: str
    payload: dict[str, Any]

    def row(self) -> dict[str, str]:
        return {
            "component": self.kind,
            "evidence_status": self.evidence_status,
            "artifact_hash": self.artifact_hash,
            "summary": self.summary,
            "path": self.path,
        }


def _summary(kind: str, payload: Mapping[str, Any]) -> str:
    if kind == "scan":
        if not payload["executed"]:
            missing = ", ".join(payload.get("missing", [])) or "none reported"
            return f"planned only; missing binaries: {missing}"
        return (
            f"success={payload.get('successful_tools', 0)}, "
            f"failed={payload.get('failed_tools', 0)}, "
            f"skipped={payload.get('skipped_tools', 0)}"
        )
    if kind == "context":
        return (
            f"role accuracy={payload['rule_role'].get('accuracy')}, "
            f"exposure accuracy={payload['exposure'].get('accuracy')}, "
            f"H1 eligible={payload['h1'].get('eligible')}"
        )
    if kind == "ranking":
        ours = payload["methods"].get("ours", payload["methods"].get("full", {}))
        return (
            f"mean tau-b={ours.get('tau_b_mean')}, NDCG@10={ours.get('ndcg_at_10_mean')}, "
            f"H2 eligible={payload['h2'].get('eligible')}, "
            f"H3 eligible={payload['h3'].get('eligible')}"
        )
    if kind == "ablation":
        return (
            f"{len(payload['scenarios'])} scenarios; "
            f"inactive={len(payload.get('inactive_scenarios', []))}"
        )
    if kind == "stability":
        return (
            f"deterministic={payload['deterministic']}; "
            f"{payload.get('unique_score_hashes')} unique hashes across "
            f"{payload.get('repeats')} repeats; input={payload.get('input_evidence_status')}"
        )
    if kind == "unification":
        return (
            f"{payload['raw_count']} raw -> {payload.get('unified_count')} groups; "
            f"{len(payload['candidates'])} review candidates; ranking changed="
            f"{payload.get('downstream_ranking_changed')}"
        )
    counts = payload["counts"]
    return (
        f"still_open={counts.get('still_open')}, fixed_candidate={counts.get('fixed_candidate')}, "
        f"not_observable={counts.get('not_observable')}, "
        f"regression_candidate={counts.get('regression_candidate')}"
    )


def load_artifact(kind: str, path: str | Path, run_id: str) -> AuditArtifact:
    if kind not in ARTIFACT_SPECS:
        raise ConfigError(
            f"unknown audit artifact kind {kind!r}; expected one of {tuple(ARTIFACT_SPECS)}"
        )
    path = Path(path)
    payload = load_json_payload(path, f"{kind} audit artifact")
    if not isinstance(payload, dict):
        raise ConfigError(f"invalid {kind} audit artifact {path}: expected an object")
    hash_field, run_field, required = ARTIFACT_SPECS[kind]
    missing = sorted({hash_field, run_field, "evidence_status", *required} - set(payload))
    if missing:
        raise ConfigError(f"invalid {kind} audit artifact {path}: missing key {missing[0]!r}")
    if str(payload[run_field]) != run_id:
        raise ConfigError(
            f"{kind} audit artifact belongs to run {payload[run_field]!r}, not {run_id!r}"
        )
    evidence_status = str(payload["evidence_status"])
    if evidence_status not in EVIDENCE_STATUSES:
        raise ConfigError(
            f"invalid {kind} audit artifact {path}: unsupported evidence_status {evidence_status!r}"
        )
    claimed = payload[hash_field]
    core = {key: value for key, value in payload.items() if key != hash_field}
    computed = _digest(core)
    if claimed != computed:
        raise ConfigError(
            f"{kind} audit artifact hash mismatch: artifact says {claimed!r}, computed {computed!r}"
        )
    try:
        summary = _summary(kind, payload)
    except (KeyError, TypeError, AttributeError) as error:
        raise ConfigError(f"invalid {kind} audit artifact {path}: {error}") from error
    return AuditArtifact(
        kind=kind,
        path=str(path),
        artifact_hash=str(claimed),
        evidence_status=evidence_status,
        summary=summary,
        payload=payload,
    )


def _missing_row(component: str, requirement: str) -> dict[str, str]:
    return {
        "component": component,
        "evidence_status": "MISSING",
        "artifact_hash": "",
        "summary": f"MISSING: {requirement}",
        "path": "",
    }


def collect_report_audit(
    settings,
    store,
    run_id: str,
    *,
    snapshot_path: str | Path | None = None,
    cohort_manifest_path: str | Path | None = None,
    cohort_evidence_path: str | Path | None = None,
    artifact_paths: Mapping[str, str | Path | None] | None = None,
    model_path: str | Path | None = None,
) -> dict[str, Any]:
    """Validate report attachments and compute read-only diagnostics."""
    from vulnassess import assessment_snapshot, cohort, intel, role_model, unify
    from vulnassess.errors import IntelUnavailable

    if store.run_info(run_id) is None:
        raise ConfigError(f"MISSING: run {run_id!r}")
    rows: list[dict[str, str]] = []
    limitations: list[str] = []
    artifacts: dict[str, dict[str, Any]] = {}
    snapshot = None
    assessment_status = "MISSING"
    if snapshot_path is None:
        rows.append(_missing_row("assessment snapshot", "report --snapshot PATH"))
        limitations.append(
            "The report is not bound to a frozen assessment snapshot; current global feed and "
            "enrichment state may differ from the original run."
        )
    else:
        snapshot = assessment_snapshot.load_snapshot(snapshot_path)
        actual_run = str(snapshot["run"].get("run_id"))
        if actual_run != run_id:
            raise ConfigError(f"assessment snapshot belongs to run {actual_run!r}, not {run_id!r}")
        assessment_status = str(snapshot.get("evidence_status"))
        if assessment_status not in EVIDENCE_STATUSES:
            raise ConfigError(
                f"assessment snapshot has unsupported evidence_status {assessment_status!r}"
            )
        live = assessment_snapshot.build_snapshot(
            settings, store, run_id, model_hash=snapshot.get("model_hash")
        )
        if live["snapshot_hash"] != snapshot["snapshot_hash"]:
            raise ConfigError(
                "live report state no longer matches the supplied assessment snapshot"
            )
        rows.append(
            {
                "component": "assessment snapshot",
                "evidence_status": assessment_status,
                "artifact_hash": str(snapshot["snapshot_hash"]),
                "summary": (
                    f"content hash and live state match; {len(snapshot['hosts'])} hosts, "
                    f"{len(snapshot['findings'])} raw findings"
                ),
                "path": str(snapshot_path),
            }
        )

    if (cohort_manifest_path is None) != (cohort_evidence_path is None):
        raise ConfigError("report needs --cohort-manifest and --cohort-evidence together")
    cohort_manifest = None
    if cohort_manifest_path is None:
        rows.append(
            _missing_row("expert cohort", "report --cohort-manifest PATH --cohort-evidence PATH")
        )
    else:
        cohort_manifest = cohort.load_manifest(cohort_manifest_path)
        if cohort_manifest.run_id != run_id:
            raise ConfigError(
                f"cohort manifest belongs to run {cohort_manifest.run_id!r}, not {run_id!r}"
            )
        assert cohort_evidence_path is not None  # the pairing check above excludes None
        cohort.load_evidence(cohort_evidence_path, cohort_manifest)
        if snapshot is not None:
            cohort.validate_snapshot_against_manifest(snapshot, cohort_manifest)
        rows.append(
            {
                "component": "expert cohort",
                "evidence_status": cohort_manifest.evidence_status,
                "artifact_hash": cohort_manifest.manifest_hash,
                "summary": (
                    f"{len(cohort_manifest.finding_ids)} {cohort_manifest.finding_mode} findings; "
                    f"cohort_id={cohort_manifest.cohort_id}"
                ),
                "path": str(cohort_manifest_path),
            }
        )

    requested_artifacts = artifact_paths or {}
    report_kinds = ("scan", "context", "ranking", "ablation", "stability", "rescan")
    for kind in report_kinds:
        path = requested_artifacts.get(kind)
        if path is None:
            rows.append(_missing_row(kind, f"report --{kind}-artifact PATH"))
            continue
        artifact = load_artifact(kind, path, run_id)
        artifact_snapshot = artifact.payload.get("snapshot_hash")
        if snapshot is not None and artifact_snapshot not in (None, snapshot["snapshot_hash"]):
            raise ConfigError(f"{kind} artifact does not match the report assessment snapshot")
        if cohort_manifest is not None:
            artifact_cohort = artifact.payload.get("cohort_hash")
            if kind == "ablation":
                artifact_cohort = artifact.payload.get("research_binding", {}).get("cohort_hash")
            if artifact_cohort not in (None, cohort_manifest.manifest_hash):
                raise ConfigError(f"{kind} artifact does not match the report cohort")
        artifacts[kind] = artifact.payload
        rows.append(artifact.row())

    unification_path = requested_artifacts.get("unification")
    if unification_path is not None:
        unification_artifact = load_artifact("unification", unification_path, run_id)
        if (
            snapshot is not None
            and unification_artifact.payload.get("snapshot_hash") != snapshot["snapshot_hash"]
        ):
            raise ConfigError("unification artifact does not match the report assessment snapshot")
        unification_payload = unification_artifact.payload
        rows.append(unification_artifact.row())
    else:
        unification_result = unify.unify_run(store, run_id).to_json()
        unification_payload = {
            "run_id": run_id,
            "mode": "live_read_only_preview",
            "downstream_ranking_changed": False,
            **unification_result,
        }
        rows.append(
            {
                "component": "unification",
                "evidence_status": assessment_status,
                "artifact_hash": _digest(unification_payload),
                "summary": _summary("unification", unification_payload),
                "path": "",
            }
        )
    artifacts["unification"] = unification_payload

    try:
        intelligence = intel.trace_run(run_id, store)
    except IntelUnavailable as error:
        intelligence = {"trace_counts": {}, "unmatched": []}
        rows.append(_missing_row("intelligence trace", str(error)))
    else:
        rows.append(
            {
                "component": "intelligence trace",
                "evidence_status": assessment_status,
                "artifact_hash": _digest(intelligence),
                "summary": (
                    f"matched={intelligence['matched']}/{intelligence['findings']}; "
                    f"unmatched={intelligence['unmatched_count']}"
                ),
                "path": "",
            }
        )

    model_cases: list[dict[str, Any]] = []
    if model_path is None:
        rows.append(_missing_row("shadow role model", "report --model PATH"))
    else:
        model = role_model.load_model(model_path)
        profiles = {profile.host_ip: profile for profile in store.profiles(run_id)}
        for host in store.hosts(run_id):
            prediction = model.predict(host)
            profile = profiles.get(host.ip)
            rule_label = None if profile is None else str(profile.role.value)
            if prediction.abstained or prediction.label != rule_label:
                model_cases.append(
                    {
                        "host_ip": host.ip,
                        "rule": rule_label,
                        "model": prediction.label,
                        "confidence": prediction.confidence,
                        "margin": prediction.margin,
                        "abstained": prediction.abstained,
                        "evidence": prediction.evidence,
                    }
                )
        rows.append(
            {
                "component": "shadow role model",
                "evidence_status": "NOT RUN",
                "artifact_hash": model.model_hash,
                "summary": (
                    f"{len(model_cases)} abstention/disagreement cases; shadow only, "
                    "canonical context unchanged"
                ),
                "path": str(model_path),
            }
        )

    return {
        "assessment_evidence_status": assessment_status,
        "snapshot_hash": None if snapshot is None else snapshot["snapshot_hash"],
        "cohort_hash": (None if cohort_manifest is None else cohort_manifest.manifest_hash),
        "rows": rows,
        "intelligence": intelligence,
        "unification": unification_payload,
        "model_cases": model_cases,
        "artifacts": artifacts,
        "limitations": limitations,
    }
