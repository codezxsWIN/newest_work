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

    def generate_structured(self, prompt, schema):
        self.prompt = prompt
        assert schema == analyst.ANALYSIS_SCHEMA
        return self.result


def demo_payload():
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
    case, evidence = analyst.build_case(payload, "172.28.0.12")
    assert payload == original
    assert case["services"]
    assert case["findings"]
    assert any(item["kind"] == "nmap_service" for item in evidence)
    assert any(item["kind"] == "vulnerability_intelligence" for item in evidence)
    assert any(item["kind"] == "deterministic_priority" for item in evidence)


def test_analysis_runs_local_model_and_preserves_canonical_scores():
    payload = demo_payload()
    case, evidence = analyst.build_case(payload, "172.28.0.12")
    client = FakeClient(valid_result(case["findings"][0]["id"], evidence[0]["id"]))
    result = analyst.analyze_target(payload, "172.28.0.12", client)
    assert result["model"] == "test-local-model"
    assert result["canonical_scores_changed"] is False
    assert "untrusted_evidence" in client.prompt


def test_unknown_model_citation_is_rejected():
    payload = demo_payload()
    case, evidence = analyst.build_case(payload, "172.28.0.12")
    response = valid_result(case["findings"][0]["id"], evidence[0]["id"])
    response["recommended_actions"][0]["evidence_ids"] = ["E999"]
    with pytest.raises(LLMUnavailable, match="unknown evidence"):
        analyst.analyze_target(payload, "172.28.0.12", FakeClient(response))


def test_missing_target_findings_are_explicit():
    with pytest.raises(Exception, match="MISSING"):
        analyst.build_case(demo_payload(), "192.0.2.99")
