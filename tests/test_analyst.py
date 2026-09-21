import copy
from pathlib import Path

import pytest

from vulnassess import analyst
from vulnassess.errors import LLMUnavailable
from vulnassess.ui.reader import ReadOnlyStore

ROOT = Path(__file__).resolve().parents[1]
DATABASE = ROOT / "data" / "vulnassess.db"


class FakeClient:
    model = "test-local-model"

    def __init__(self, result):
        self.result = result
        self.prompt = None

    def available(self):
        return True

    def generate_structured(self, prompt, schema, **kwargs):
        self.prompt = prompt
        self.kwargs = kwargs
        assert schema == analyst.ANALYSIS_SCHEMA
        return self.result


def demo_payload():
    # The store is gitignored, so CI must rebuild it (same self-heal as the UI contracts,
    # which pytest would otherwise reach only after this module).
    from tests.test_ui import _provision_demo_database

    _provision_demo_database()
    with ReadOnlyStore(DATABASE) as store:
        return store.run("demo")


def valid_result(finding_id, evidence_id):
    return {
        "summary": "The exposed database service and known exploited finding need prompt review.",
        "confidence": "medium",
        "recommended_actions": [
            {
                "order": 1,
                "action": "Restrict exposure and patch the affected service",
                "reason": "The stored evidence combines external exposure with KEV intelligence.",
                "finding_ids": [finding_id],
                "evidence_ids": [evidence_id],
            }
        ],
        "correlations": [],
        "uncertainties": ["No authenticated validation or exploit attempt was performed."],
    }


def test_case_packages_all_target_evidence_without_mutating_records():
    payload = demo_payload()
    original = copy.deepcopy(payload)
    case, evidence, alias_map = analyst.build_case(payload, "172.28.0.12")
    assert payload == original
    assert case["services"]
    assert case["findings"]
    canonical = {finding["id"] for finding in payload["findings"]}
    assert set(alias_map.values()) <= canonical
    assert all(item["id"].startswith("F") for item in case["findings"])
    assert any(item["kind"] == "nmap_service" for item in evidence)
    assert any(item["kind"] == "vulnerability_intelligence" for item in evidence)
    assert any(item["kind"] == "deterministic_priority" for item in evidence)


def test_analysis_runs_local_model_and_preserves_canonical_scores():
    payload = demo_payload()
    case, evidence, alias_map = analyst.build_case(payload, "172.28.0.12")
    client = FakeClient(valid_result(case["findings"][0]["id"], evidence[0]["id"]))
    result = analyst.analyze_target(payload, "172.28.0.12", client)
    assert result["model"] == "test-local-model"
    assert result["canonical_scores_changed"] is False
    assert "untrusted_evidence" in client.prompt
    canonical = {finding["id"] for finding in payload["findings"]}
    cited = result["analysis"]["recommended_actions"][0]["finding_ids"]
    assert cited and set(cited) <= canonical


def test_unknown_model_citation_is_rejected():
    payload = demo_payload()
    case, evidence, _ = analyst.build_case(payload, "172.28.0.12")
    response = valid_result(case["findings"][0]["id"], evidence[0]["id"])
    response["recommended_actions"][0]["evidence_ids"] = ["E999"]
    with pytest.raises(LLMUnavailable, match="unknown evidence"):
        analyst.analyze_target(payload, "172.28.0.12", FakeClient(response))


def test_missing_target_findings_are_explicit():
    with pytest.raises(Exception, match="MISSING"):
        analyst.build_case(demo_payload(), "192.0.2.99")


def test_case_bounds_intel_to_the_sharpest_records_at_real_scale():
    payload = demo_payload()
    finding_id = next(f["id"] for f in payload["findings"] if f["host_ip"] == "172.28.0.12")
    payload["enrichments"] = [
        {
            "finding_id": finding_id,
            "cve_id": f"CVE-2020-{index:04d}",
            "match_method": "cpe",
            "match_confidence": 0.5,
            "cvss31_base": 5.0 + index * 0.1,
            "epss": 0.1,
            "epss_percentile": 0.5,
            "kev": index == 7,
            "description": "x" * 400,
        }
        for index in range(40)
    ]
    original = copy.deepcopy(payload)
    case, evidence, alias_map = analyst.build_case(payload, "172.28.0.12")
    assert payload == original
    target = case["findings"][0]
    assert target["intel_available"] == 40
    assert target["intel_included"] == len(target["intelligence"]) == analyst.MAX_INTEL_PER_FINDING
    kept = {item["cve_id"] for item in target["intelligence"]}
    assert kept == {"CVE-2020-0007", "CVE-2020-0039", "CVE-2020-0038"}
    assert all("description" not in item for item in target["intelligence"])
    prompt = analyst.build_prompt(case, evidence, len(alias_map))
    assert len(prompt) < 60_000


def test_validator_tolerates_small_model_envelope_noise():
    payload = demo_payload()
    case, evidence, alias_map = analyst.build_case(payload, "172.28.0.12")
    response = valid_result(case["findings"][0]["id"], evidence[0]["id"])
    del response["correlations"]
    response["finding_ids"] = [case["findings"][0]["id"]]
    response["evidence_ids"] = [evidence[0]["id"]]
    result = analyst.analyze_target(payload, "172.28.0.12", FakeClient(response))
    assert result["analysis"]["correlations"] == []
    alias = case["findings"][0]["id"]
    canonical = result["analysis"]["recommended_actions"][0]["finding_ids"]
    assert canonical == [alias_map[alias]]
