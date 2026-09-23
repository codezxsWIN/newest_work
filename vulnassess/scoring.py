"""The ranking formula. Pure: given the same inputs it returns the same numbers, always.

Imports are limited to hashlib, json and the project's own pure modules so that no clock,
file, socket or random source can reach a rank.
"""

import hashlib
import json
from dataclasses import replace
from typing import Any, cast

from vulnassess import cvss31
from vulnassess.errors import ConfigError
from vulnassess.schema import ContextProfile, Enrichment, Finding, ScoreBreakdown, Service

Weights = dict[str, Any]

STEP_UP = {"L": "M", "M": "H", "H": "H"}
REQUIREMENT_KEYS = ("CR", "IR", "AR")


def weights_hash(weights: Weights) -> str:
    payload = json.dumps(weights, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def environmental_vector(
    base_vector: str, profile: ContextProfile, weights: Weights
) -> tuple[str, dict[str, str]]:
    """Auto-fill the CVSS Environmental metrics from inferred context."""
    metrics = cvss31.parse(base_vector)
    settings = weights["environmental"]
    minimum = float(settings.get("min_confidence_to_apply", 0.5))
    modifications: dict[str, str] = {}

    def apply(changes: dict[str, str] | None) -> None:
        for key, value in (changes or {}).items():
            metrics[key] = value
            modifications[key] = value

    exposure = profile.exposure
    if exposure.value == "internal" and metrics["AV"] == "N" and exposure.confidence >= minimum:
        apply(settings.get("internal_when_av_network"))

    waf = profile.controls.get("waf")
    if waf is not None and waf.value and waf.confidence >= minimum:
        apply(settings.get("waf_present"))

    auth = profile.controls.get("auth_required")
    if auth is not None and auth.value and metrics["PR"] == "N" and auth.confidence >= minimum:
        apply(settings.get("auth_required_when_pr_none"))

    role_requirements = settings.get("role_requirements", {})
    role = profile.role.value if profile.role.confidence >= minimum else "unknown"
    requirements = dict(role_requirements.get(role) or role_requirements.get("unknown") or {})

    environment = profile.manual.get("environment")
    if environment is not None and environment.value == "test":
        requirements = dict(settings.get("environment_test") or requirements)

    criticality = profile.manual.get("criticality")
    if criticality is not None:
        try:
            steps = int(criticality.value) - int(settings.get("criticality_step_above", 3))
        except (TypeError, ValueError):
            steps = 0
        for _ in range(max(steps, 0)):
            requirements = {key: STEP_UP[value] for key, value in requirements.items()}

    apply({key: requirements[key] for key in REQUIREMENT_KEYS if key in requirements})
    return cvss31.to_vector(metrics), modifications


def risk(
    env_score: float | None,
    epss_percentile: float | None,
    kev: bool,
    native_key: float | None,
    weights: Weights,
    internet_facing: bool,
) -> tuple[float, float | None]:
    """Combine environmental severity with observed threat. Missing EPSS stays unscored."""
    threat = weights["threat"]
    if env_score is None:
        base = float(native_key or 0.0)
        multiplier: float | None = None
    else:
        base = float(env_score) * 10.0
        multiplier = (
            None
            if epss_percentile is None
            else float(threat["base_multiplier"])
            + float(threat["epss_weight"]) * float(epss_percentile)
        )
        if kev:
            multiplier = max(multiplier or 0.0, float(threat["kev_multiplier"]))

    value = base if multiplier is None else base * multiplier
    if kev:
        value += float(threat["kev_boost"])
        if internet_facing:
            value = max(value, float(threat["kev_floor_internet_facing"]))
    return round(min(value, 100.0), 1), multiplier


def band(value: float, weights: Weights) -> str:
    bands = weights["bands"]
    if value >= float(bands["Critical"]):
        return "Critical"
    if value >= float(bands["High"]):
        return "High"
    if value >= float(bands["Medium"]):
        return "Medium"
    return "Low"


def _threat_phrase(breakdown_kev: bool, percentile: float | None) -> str:
    if breakdown_kev:
        return "actively exploited (CISA KEV)"
    if percentile is None:
        return "no exploitation data"
    nth = int(round(float(percentile) * 100))
    if percentile >= 0.5:
        return f"exploitation likelihood in the {nth}th percentile"
    return f"low exploitation likelihood ({nth}th percentile)"


def describe(breakdown: ScoreBreakdown, profile: ContextProfile) -> str:
    """The deterministic one-line reason. Stands in for the model; invents nothing."""
    exposure = "internet-facing" if profile.exposure.value == "internet_facing" else "internal"
    role = str(profile.role.value).replace("_", " ")
    parts = [f"{exposure} {role}"]
    environment = profile.manual.get("environment")
    if environment is not None and environment.value == "test":
        parts.append("test environment")
    parts.append(_threat_phrase(breakdown.kev, breakdown.epss_percentile))
    waf = profile.controls.get("waf")
    if waf is not None and waf.value:
        parts.append(f"behind {waf.value}")
    else:
        parts.append("no compensating control observed")
    return f"{breakdown.band}: " + ", ".join(parts) + "."


def fix_text(
    finding: Finding, enrichment: Enrichment | None, host_services: tuple[Service, ...]
) -> str:
    service = next(
        (item for item in host_services if finding.port and item.port == finding.port), None
    )
    if enrichment is not None and enrichment.version_end and service and service.product:
        reference = enrichment.patch_references[0] if enrichment.patch_references else ""
        suffix = f" ({reference})" if reference else ""
        version = service.version or ""
        return (
            f"Upgrade {service.product} {version}".rstrip()
            + f" to {enrichment.version_end} or later{suffix}"
        )
    if enrichment is not None and enrichment.patch_references:
        return f"Apply the vendor fix: {enrichment.patch_references[0]}"
    if finding.reference_urls:
        return f"Review {finding.reference_urls[0]}"
    if finding.cwe_ids:
        return f"Remediate {finding.cwe_ids[0]}: {finding.title}"
    return f"Review: {finding.title}"


def best_enrichment(enrichments: list[Enrichment]) -> Enrichment | None:
    """When several CVEs matched one finding, score the worst of them."""
    if not enrichments:
        return None
    return min(
        enrichments,
        key=lambda item: (not item.kev, -(item.cvss31_base or 0.0), item.cve_id),
    )


def _native_value(finding: Finding, weights: Weights) -> tuple[float | None, str | None]:
    # YAML config is dynamically shaped; the casts name the shapes this formula handles.
    fallback = cast("dict[str, Any] | None", weights.get("native_fallback", {}))
    if fallback is None:
        return None, None
    table = cast("dict[str, Any] | float | int | str | None", fallback.get(finding.tool))
    if table is None:
        return None, None
    if isinstance(table, dict):
        severity = finding.native_severity
        value = table.get(severity or "")
        if value is None:
            value = min(table.values())
            severity = severity or "default"
        return float(value), f"{finding.tool}:{severity}={value}"
    return float(table), f"{finding.tool}:default={table}"


def score(
    finding: Finding,
    enrichment: Enrichment | None,
    profile: ContextProfile,
    host_services: tuple[Service, ...],
    weights: Weights,
) -> ScoreBreakdown:
    features = (
        profile.role,
        profile.exposure,
        *profile.controls.values(),
        *profile.manual.values(),
    )
    if any(feature.source not in {"rule", "manual"} for feature in features):
        raise ConfigError(
            "canonical scoring from learned context requires a human-approved context-source ADR"
        )
    internet_facing = profile.exposure.value == "internet_facing"
    inputs = {
        "role": profile.role.to_json(),
        "exposure": profile.exposure.to_json(),
        "controls": {key: value.to_json() for key, value in sorted(profile.controls.items())},
        "manual": {key: value.to_json() for key, value in sorted(profile.manual.items())},
    }
    digest = weights_hash(weights)

    if enrichment is not None and enrichment.cvss31_vector:
        metrics = cvss31.parse(enrichment.cvss31_vector)
        base = cvss31.base_score(metrics)
        env_vector, modifications = environmental_vector(enrichment.cvss31_vector, profile, weights)
        env = cvss31.environmental_score(cvss31.parse(env_vector))
        value, multiplier = risk(
            env, enrichment.epss_percentile, enrichment.kev, None, weights, internet_facing
        )
        breakdown = ScoreBreakdown(
            finding_id=finding.id,
            host_ip=finding.host_ip,
            cve_id=enrichment.cve_id,
            cvss_version_used="3.1",
            base_vector=enrichment.cvss31_vector,
            base_score=base,
            env_vector=env_vector,
            env_score=env,
            env_modifications=modifications,
            epss_percentile=enrichment.epss_percentile,
            threat_multiplier=multiplier,
            kev=enrichment.kev,
            native_fallback=None,
            risk=value,
            band=band(value, weights),
            inputs=inputs,
            weights_hash=digest,
            reason="",
            fix=fix_text(finding, enrichment, host_services),
        )
    else:
        native_key, label = _native_value(finding, weights)
        percentile = enrichment.epss_percentile if enrichment is not None else None
        kev = enrichment.kev if enrichment is not None else False
        value, multiplier = risk(None, percentile, kev, native_key, weights, internet_facing)
        breakdown = ScoreBreakdown(
            finding_id=finding.id,
            host_ip=finding.host_ip,
            cve_id=enrichment.cve_id if enrichment is not None else None,
            cvss_version_used=None,
            base_vector=None,
            base_score=None,
            env_vector=None,
            env_score=None,
            env_modifications={},
            epss_percentile=percentile,
            threat_multiplier=multiplier,
            kev=kev,
            native_fallback=label,
            risk=value,
            band=band(value, weights),
            inputs=inputs,
            weights_hash=digest,
            reason="",
            fix=fix_text(finding, enrichment, host_services),
        )

    return replace(breakdown, reason=describe(breakdown, profile))
