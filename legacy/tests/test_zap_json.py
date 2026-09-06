"""ZAP rejection tests and checks gated on genuine human captures."""

import json
from pathlib import Path

import pytest

from vulnassess.adapters.zap_json import parse_zap_json
from vulnassess.errors import AdapterError, ConfigError


def test_missing_zap_capture_names_path(tmp_path: Path) -> None:
    path = tmp_path / "not-provided.json"
    with pytest.raises(ConfigError, match="not-provided.json"):
        parse_zap_json(path, "unit-run")
    assert not path.exists()


def test_directory_is_not_a_zap_capture(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="capture file"):
        parse_zap_json(tmp_path, "unit-run")


def test_malformed_json_is_an_adapter_error(tmp_path: Path) -> None:
    source = Path(__file__).parent / "synthetic" / "synthetic_adapter_inputs.json"
    assert source.is_file(), f"MISSING: {source}"
    data = json.loads(source.read_text(encoding="utf-8"))
    assert data["_comment"].startswith("SYNTHETIC")
    path = tmp_path / "synthetic_invalid.json"
    for content in data["json"]:
        path.write_text(content, encoding="utf-8")
        with pytest.raises(AdapterError, match=path.name):
            parse_zap_json(path, "unit-run")


def test_zap_run_identifier_is_required() -> None:
    path = Path(__file__).parent / "synthetic" / "synthetic_adapter_inputs.json"
    assert path.is_file(), f"MISSING: {path}"
    with pytest.raises(AdapterError, match="run_id"):
        parse_zap_json(path, " ")


@pytest.mark.parametrize(
    "name",
    [
        pytest.param(
            name,
            marks=pytest.mark.needs_fixture(
                f"tests/fixtures/zap/{name}.json", "tests/fixtures/zap/README.md"
            ),
        )
        for name in ("metasploitable2", "dvwa", "juice-shop")
    ],
)
def test_human_zap_capture_preserves_evidence(name: str) -> None:
    path = Path(__file__).parent / "fixtures" / "zap" / f"{name}.json"
    findings = parse_zap_json(path, "capture-test")
    assert findings == parse_zap_json(path, "capture-test")
    text = path.read_text(encoding="utf-8")
    report = json.loads(text)
    expected_count = sum(
        max(len(alert["instances"]), 1) for site in report["site"] for alert in site["alerts"]
    )
    assert len(findings) == expected_count
    for index, finding in enumerate(findings):
        assert finding.evidence and finding.evidence in text
        assert len(finding.evidence) <= 2048
        assert finding.tool == "zap"
        assert finding.provenance.record_index == index
        assert finding.provenance.raw_path == str(path)
        assert finding.provenance.run_id == "capture-test"
    snapshot_path = Path(__file__).parent / "golden" / "zap" / f"{name}.json"
    assert snapshot_path.is_file(), f"MISSING: reviewed parser snapshot {snapshot_path}"
    actual = [finding.model_dump(mode="json") for finding in findings]
    for finding in actual:
        finding["provenance"]["raw_path"] = f"tests/fixtures/zap/{name}.json"
    assert actual == json.loads(snapshot_path.read_text(encoding="utf-8"))
