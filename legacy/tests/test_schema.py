"""Synthetic tests of schema contracts, not scanner or feed integrations."""

from hashlib import sha256
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import pytest
from pydantic import BaseModel, ValidationError

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


@pytest.mark.parametrize(
    ("name", "model"),
    [
        ("finding", Finding),
        ("host", Host),
        ("feature", Feature),
        ("context", ContextProfile),
        ("enrichment", Enrichment),
        ("score", ScoreBreakdown),
        ("rationale", Rationale),
    ],
)
def test_exact_fields_and_json_round_trip(
    schema_data: dict[str, Any], name: str, model: type[BaseModel]
) -> None:
    value = model.model_validate(schema_data[name])

    assert set(model.model_fields) == set(schema_data[name])
    assert model.model_validate_json(value.model_dump_json()) == value


def test_nested_contract_fields(schema_data: dict[str, Any]) -> None:
    service = schema_data["host"]["services"][0]
    provenance = schema_data["finding"]["provenance"]
    assert set(Service.model_fields) == set(service)
    assert set(Provenance.model_fields) == set(provenance)
    del service["tls"]
    assert Service.model_validate(service).tls is False


@pytest.mark.parametrize("port", [None, 0, 443])
def test_fingerprint_exact_contract(port: int | None) -> None:
    expected = sha256(f"198.51.100.42|{port or ''}|tcp|nmap|synthetic-unit-rule|".encode()).hexdigest()
    actual = Finding.fingerprint("198.51.100.42", port, "tcp", "nmap", "synthetic-unit-rule", None)
    assert actual == expected


@pytest.mark.parametrize(
    ("name", "model"),
    [("finding", Finding), ("enrichment", Enrichment), ("score", ScoreBreakdown)],
)
def test_frozen_contracts(schema_data: dict[str, Any], name: str, model: type[BaseModel]) -> None:
    value = model.model_validate(schema_data[name])
    field = "id" if name == "finding" else "finding_id"
    with pytest.raises(ValidationError, match="frozen_instance"):
        setattr(value, field, "changed")


def test_finding_rejects_wrong_identity(schema_data: dict[str, Any]) -> None:
    schema_data["finding"]["id"] = "not-a-fingerprint-derived-uuid"
    with pytest.raises(ValidationError, match="Finding.id"):
        Finding.model_validate(schema_data["finding"])


def test_missing_epss_leaves_the_threat_multiplier_unscored(schema_data: dict[str, Any]) -> None:
    """Decision APPLY-01: no EPSS row means no exploitation evidence, not a default value."""
    schema_data["score"]["epss_percentile"] = None
    schema_data["score"]["threat_multiplier"] = None

    score = ScoreBreakdown.model_validate(schema_data["score"])

    assert score.threat_multiplier is None
    assert ScoreBreakdown.model_validate_json(score.model_dump_json()) == score


def test_finding_rejects_mismatched_provenance(schema_data: dict[str, Any]) -> None:
    schema_data["finding"]["provenance"]["tool"] = "zap"
    with pytest.raises(ValidationError, match="provenance.tool"):
        Finding.model_validate(schema_data["finding"])


@pytest.mark.parametrize("tool", ["nmap", "nikto"])
def test_nmap_and_nikto_have_no_native_severity(
    schema_data: dict[str, Any], tool: str
) -> None:
    finding = schema_data["finding"]
    finding["tool"] = tool
    finding["provenance"]["tool"] = tool
    fingerprint = Finding.fingerprint(
        finding["host_ip"],
        finding["port"],
        finding["protocol"],
        finding["tool"],
        finding["tool_native_id"],
        finding["url"],
    )
    finding["id"] = str(uuid5(NAMESPACE_URL, fingerprint))
    finding["native_severity"] = "High"
    with pytest.raises(ValidationError, match="native_severity"):
        Finding.model_validate(finding)


def test_evidence_is_bounded_without_silent_truncation(schema_data: dict[str, Any]) -> None:
    schema_data["finding"]["evidence"] = "x" * 2048
    assert Finding.model_validate(schema_data["finding"]).evidence == "x" * 2048
    schema_data["finding"]["evidence"] += "x"
    with pytest.raises(ValidationError, match="evidence"):
        Finding.model_validate(schema_data["finding"])


@pytest.mark.parametrize("confidence", [-0.01, 1.01, float("nan"), float("inf")])
def test_feature_confidence_bounds(schema_data: dict[str, Any], confidence: float) -> None:
    schema_data["feature"]["confidence"] = confidence
    with pytest.raises(ValidationError, match="confidence"):
        Feature.model_validate(schema_data["feature"])


@pytest.mark.parametrize("evidence", ["", " \t\n"])
def test_feature_evidence_is_not_blank(schema_data: dict[str, Any], evidence: str) -> None:
    schema_data["feature"]["evidence"] = evidence
    with pytest.raises(ValidationError, match="evidence"):
        Feature.model_validate(schema_data["feature"])


def test_feature_keeps_verbatim_whitespace(schema_data: dict[str, Any]) -> None:
    schema_data["feature"]["evidence"] = "  SYNTHETIC SCHEMA TEST ONLY\n"
    feature = Feature.model_validate(schema_data["feature"])
    assert feature.evidence == schema_data["feature"]["evidence"]


@pytest.mark.parametrize(
    ("field", "value"),
    [("role", "not-a-role"), ("role", {}), ("exposure", "external"), ("exposure", {})],
)
def test_context_rejects_uncontracted_values(
    schema_data: dict[str, Any], field: str, value: Any
) -> None:
    schema_data["context"][field]["value"] = value
    with pytest.raises(ValidationError, match=field):
        ContextProfile.model_validate(schema_data["context"])


@pytest.mark.parametrize(
    ("key", "value", "source"),
    [
        ("criticality", 0, "manual"),
        ("criticality", True, "manual"),
        ("environment", "dev", "manual"),
        ("other", 1, "manual"),
        ("criticality", 3, "invalid-source"),
    ],
)
def test_context_rejects_invalid_manual_tags(
    schema_data: dict[str, Any], key: str, value: Any, source: str
) -> None:
    schema_data["context"]["manual"][key] = {
        "value": value,
        "confidence": 1.0,
        "source": source,
        "evidence": "SYNTHETIC SCHEMA TEST ONLY",
    }
    with pytest.raises(ValidationError, match="manual"):
        ContextProfile.model_validate(schema_data["context"])


def test_context_control_keys_are_fixed(schema_data: dict[str, Any]) -> None:
    schema_data["context"]["controls"]["uncontracted-key"] = schema_data["feature"]
    with pytest.raises(ValidationError, match="controls"):
        ContextProfile.model_validate(schema_data["context"])


@pytest.mark.parametrize("source", ["rule", "llm", "manual"])
def test_generic_features_retain_value_and_provenance(
    schema_data: dict[str, Any], source: str
) -> None:
    schema_data["context"]["controls"]["waf"] = {
        "value": {"synthetic": True},
        "confidence": 0.5,
        "source": source,
        "evidence": "SYNTHETIC SCHEMA TEST ONLY",
    }
    schema_data["context"]["manual"]["criticality"] = {
        "value": 3,
        "confidence": 0.5,
        "source": source,
        "evidence": "SYNTHETIC SCHEMA TEST ONLY",
    }
    profile = ContextProfile.model_validate(schema_data["context"])
    assert profile.controls["waf"].value == {"synthetic": True}
    assert profile.controls["waf"].source == source
    assert profile.manual["criticality"].source == source
