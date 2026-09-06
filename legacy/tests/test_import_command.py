"""The import command authorises first, then copies, parses and stores.

SYNTHETIC_NMAP_XML below is invented for unit tests of pure parsing and storage logic.
It is not a capture and is never evidence that the reader works on real Nmap output.
"""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vulnassess.cli import app
from vulnassess.store import Store

CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
IN_SCOPE_IP = "172.28.0.10"
OUT_OF_SCOPE_IP = "10.0.0.5"
runner = CliRunner()

SYNTHETIC_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" start="1725580800" version="7.94">
  <host starttime="1725580800" endtime="1725580860">
    <address addr="172.28.0.10" addrtype="ipv4"/>
    <hostnames><hostname name="synthetic-lab-target"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="SyntheticSSH" version="0.0"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="SyntheticHTTP" version="0.0"/>
        <script id="http-server-header" output="SyntheticHTTP/0.0"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="closed"/>
      </port>
    </ports>
    <os><osmatch name="Synthetic Linux" accuracy="95"/></os>
  </host>
  <runstats><finished time="1725580860" exit="success"/></runstats>
</nmaprun>
"""
SYNTHETIC_FINDING_COUNT = 3


@pytest.fixture
def synthetic_capture(tmp_path: Path) -> Path:
    path = tmp_path / "synthetic_nmap.xml"
    path.write_text(SYNTHETIC_NMAP_XML, encoding="utf-8")
    return path


def _invoke(tmp_path: Path, *arguments: str):
    return runner.invoke(
        app,
        [
            "import",
            "--config-dir",
            str(CONFIG_DIR),
            "--data-dir",
            str(tmp_path / "data"),
            *arguments,
        ],
    )


def test_out_of_scope_target_never_opens_the_capture_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(path: Path) -> bytes:
        raise AssertionError(f"capture opened before the scope check: {path}")

    monkeypatch.setattr("vulnassess.cli.read_capture", refuse)
    missing = tmp_path / "never-read.xml"

    result = _invoke(
        tmp_path, "--run-id", "r-scope", "--target-ip", OUT_OF_SCOPE_IP, "--nmap", str(missing)
    )

    assert result.exit_code == 3
    assert "not authorised" in result.stderr
    assert "no capture file was opened" in result.stderr
    assert missing.name not in result.stderr
    assert not (tmp_path / "data").exists()


def test_out_of_scope_target_is_refused_even_when_the_capture_exists(
    tmp_path: Path, synthetic_capture: Path
) -> None:
    result = _invoke(
        tmp_path,
        "--run-id",
        "r-scope-2",
        "--target-ip",
        OUT_OF_SCOPE_IP,
        "--nmap",
        str(synthetic_capture),
    )

    assert result.exit_code == 3
    assert not (tmp_path / "data").exists()


def test_synthetic_in_scope_capture_stores_hosts_and_findings(
    tmp_path: Path, synthetic_capture: Path
) -> None:
    result = _invoke(
        tmp_path, "--run-id", "r-1", "--target-ip", IN_SCOPE_IP, "--nmap", str(synthetic_capture)
    )

    assert result.exit_code == 0, result.stderr
    assert result.stderr == ""
    line = result.stdout.strip().splitlines()
    assert len(line) == 1
    assert "run=r-1" in line[0]
    assert "hosts=1" in line[0]
    assert f"findings={SYNTHETIC_FINDING_COUNT}" in line[0]
    assert f"nmap={SYNTHETIC_FINDING_COUNT}" in line[0]

    store = Store(tmp_path / "data" / "vulnassess.db")
    try:
        hosts = store.list_hosts("r-1")
        findings = store.list_findings("r-1")
    finally:
        store.close()
    assert [host.ip for host in hosts] == [IN_SCOPE_IP]
    assert [service.port for service in hosts[0].services] == [22, 80]
    assert len(findings) == SYNTHETIC_FINDING_COUNT
    assert {finding.tool for finding in findings} == {"nmap"}


def test_synthetic_import_records_provenance_inside_the_run_raw_directory(
    tmp_path: Path, synthetic_capture: Path
) -> None:
    result = _invoke(
        tmp_path, "--run-id", "r-2", "--target-ip", IN_SCOPE_IP, "--nmap", str(synthetic_capture)
    )

    assert result.exit_code == 0, result.stderr
    raw_dir = tmp_path / "data" / "raw" / "r-2"
    assert (raw_dir / "nmap.xml").read_text(encoding="utf-8") == SYNTHETIC_NMAP_XML

    store = Store(tmp_path / "data" / "vulnassess.db")
    try:
        findings = store.list_findings("r-2")
    finally:
        store.close()
    assert findings
    for finding in findings:
        raw_path = Path(finding.provenance.raw_path)
        assert raw_path.parent == raw_dir
        assert raw_path.is_file()
        assert finding.provenance.run_id == "r-2"


def test_synthetic_import_emits_the_same_summary_as_json(
    tmp_path: Path, synthetic_capture: Path
) -> None:
    result = _invoke(
        tmp_path,
        "--run-id",
        "r-3",
        "--target-ip",
        IN_SCOPE_IP,
        "--nmap",
        str(synthetic_capture),
        "--json",
    )

    assert result.exit_code == 0, result.stderr
    summary = json.loads(result.stdout)
    assert summary["run_id"] == "r-3"
    assert summary["target_ip"] == IN_SCOPE_IP
    assert summary["hosts"] == 1
    assert summary["findings"] == SYNTHETIC_FINDING_COUNT
    assert summary["findings_by_tool"] == {"nmap": SYNTHETIC_FINDING_COUNT}
    assert summary["raw_dir"].endswith("data/raw/r-3")
    assert len(summary["config_hash"]) == 64


def test_synthetic_import_is_repeatable_for_the_same_run_id(
    tmp_path: Path, synthetic_capture: Path
) -> None:
    arguments = ("--run-id", "r-4", "--target-ip", IN_SCOPE_IP, "--nmap", str(synthetic_capture))
    first = _invoke(tmp_path, *arguments)
    repeated = _invoke(tmp_path, *arguments)

    assert first.exit_code == repeated.exit_code == 0
    assert first.stdout == repeated.stdout


def test_missing_capture_for_an_authorised_target_is_a_configuration_error(tmp_path: Path) -> None:
    result = _invoke(
        tmp_path,
        "--run-id",
        "r-5",
        "--target-ip",
        IN_SCOPE_IP,
        "--nmap",
        str(tmp_path / "absent.xml"),
    )

    assert result.exit_code == 2
    assert "MISSING" in result.stderr


def test_unsafe_run_id_is_rejected_before_any_target_check(tmp_path: Path) -> None:
    result = _invoke(
        tmp_path,
        "--run-id",
        "../escape",
        "--target-ip",
        IN_SCOPE_IP,
        "--nmap",
        str(tmp_path / "absent.xml"),
    )

    assert result.exit_code == 2
    assert "--run-id" in result.stderr
    assert not (tmp_path / "data").exists()
