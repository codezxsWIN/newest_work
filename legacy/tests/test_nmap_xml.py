"""Rejection-path checks plus human-capture-gated Nmap contract checks."""

import json
from pathlib import Path

import pytest

from vulnassess.adapters.nmap_xml import parse_nmap_xml
from vulnassess.errors import AdapterError, ConfigError


def test_missing_nmap_file_names_path(tmp_path: Path) -> None:
    path = tmp_path / "not-provided.xml"
    with pytest.raises(ConfigError, match="not-provided.xml"):
        parse_nmap_xml(path, "unit-run")
    assert not path.exists()


def test_nmap_directory_is_not_a_capture(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="capture file"):
        parse_nmap_xml(tmp_path, "unit-run")


def test_malformed_xml_is_an_adapter_error(tmp_path: Path) -> None:
    source = Path(__file__).parent / "synthetic" / "synthetic_adapter_inputs.json"
    assert source.is_file(), f"MISSING: {source}"
    data = json.loads(source.read_text(encoding="utf-8"))
    assert data["_comment"].startswith("SYNTHETIC")
    path = tmp_path / "synthetic_invalid.xml"
    for content in data["xml"]:
        path.write_text(content, encoding="utf-8")
        with pytest.raises(AdapterError, match=path.name):
            parse_nmap_xml(path, "unit-run")


def test_nmap_run_identifier_is_required() -> None:
    path = Path(__file__).parent / "synthetic" / "synthetic_adapter_inputs.json"
    assert path.is_file(), f"MISSING: {path}"
    with pytest.raises(AdapterError, match="run_id"):
        parse_nmap_xml(path, " ")


@pytest.mark.parametrize(
    "name",
    [
        pytest.param(
            name,
            marks=pytest.mark.needs_fixture(
                f"tests/fixtures/nmap/{name}.xml", "tests/fixtures/nmap/README.md"
            ),
        )
        for name in ("metasploitable2", "dvwa", "juice-shop")
    ],
)
def test_human_nmap_capture_preserves_evidence(name: str) -> None:
    path = Path(__file__).parent / "fixtures" / "nmap" / f"{name}.xml"
    hosts, findings = parse_nmap_xml(path, "capture-test")
    repeated = parse_nmap_xml(path, "capture-test")
    assert (hosts, findings) == repeated
    assert hosts, "The documented lab capture must contain its target host"
    content = path.read_text(encoding="utf-8")
    for index, finding in enumerate(findings):
        assert finding.native_severity is None
        assert finding.evidence and finding.evidence in content
        assert len(finding.evidence) <= 2048
        assert finding.provenance.record_index == index
        assert finding.provenance.raw_path == str(path)
        assert finding.provenance.run_id == "capture-test"
    snapshot_path = Path(__file__).parent / "golden" / "nmap" / f"{name}.json"
    assert snapshot_path.is_file(), f"MISSING: reviewed parser snapshot {snapshot_path}"
    serialized_findings = [finding.model_dump(mode="json") for finding in findings]
    for finding in serialized_findings:
        finding["provenance"]["raw_path"] = f"tests/fixtures/nmap/{name}.xml"
    actual = {
        "hosts": [host.model_dump(mode="json") for host in hosts],
        "findings": serialized_findings,
    }
    assert actual == json.loads(snapshot_path.read_text(encoding="utf-8"))
