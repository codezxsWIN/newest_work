"""Scaffold commands must fail explicitly without executing a pipeline."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vulnassess.cli import app
from vulnassess.schema import Finding

COMMANDS = ("scan", "enrich", "context", "rank", "explain", "report", "eval", "intel")
runner = CliRunner()


@pytest.mark.parametrize("command", COMMANDS)
def test_command_is_not_implemented(command: str) -> None:
    result = runner.invoke(app, [command])

    assert result.exit_code == 2
    assert result.stdout.strip() == "not implemented"
    assert result.stderr == ""


def test_help_lists_all_commands() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    for command in COMMANDS:
        assert command in result.stdout


def test_unknown_command_is_rejected() -> None:
    result = runner.invoke(app, ["not-a-command"])

    assert result.exit_code == 2
    assert "No such command" in result.stderr


def test_no_command_displays_help() -> None:
    result = runner.invoke(app, [])

    assert result.exit_code == 2
    assert "Usage:" in result.output


def test_schema_export_is_a_deterministic_machine_readable_command() -> None:
    arguments = ["schema", "export", "--json", "--run-id", "contract-check"]
    first = runner.invoke(app, arguments)
    repeated = runner.invoke(app, arguments)

    assert first.exit_code == repeated.exit_code == 0
    assert first.stderr == repeated.stderr == ""
    assert first.stdout == repeated.stdout
    document = json.loads(first.stdout)
    assert document["x-vulnassess-run-id"] == "contract-check"
    assert document["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert set(document["$defs"]) == {
        "Provenance",
        "Service",
        "Host",
        "Finding",
        "Feature",
        "ContextProfile",
        "Enrichment",
        "ScoreBreakdown",
        "Rationale",
    }
    assert set(document["$defs"]["Finding"]["properties"]) == set(Finding.model_fields)
    assert document["$defs"]["Finding"]["properties"]["evidence"]["maxLength"] == 2048


def test_schema_export_does_not_invent_run_metadata() -> None:
    compact = runner.invoke(app, ["schema", "export", "--json"])
    readable = runner.invoke(app, ["schema", "export"])

    assert compact.exit_code == readable.exit_code == 0
    assert json.loads(compact.stdout) == json.loads(readable.stdout)
    assert "x-vulnassess-run-id" not in json.loads(compact.stdout)


def test_schema_export_rejects_blank_run_id_without_traceback() -> None:
    result = runner.invoke(app, ["schema", "export", "--json", "--run-id", " "])

    assert result.exit_code == 2
    assert result.stdout == ""
    assert "schema export --run-id" in result.stderr
    assert "Traceback" not in result.output


def test_schema_export_help_lists_contract_options() -> None:
    result = runner.invoke(app, ["schema", "export", "--help"])

    assert result.exit_code == 0
    assert "--json" in result.stdout
    assert "--run-id" in result.stdout


@pytest.mark.parametrize(
    ("argument", "expected_exit_code", "expected_output"),
    [("--help", 0, "Usage:"), ("scan", 2, "not implemented")],
)
def test_module_entry_point(
    argument: str,
    expected_exit_code: int,
    expected_output: str,
    tmp_path: Path,
) -> None:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    result = subprocess.run(
        [sys.executable, "-m", "vulnassess", argument],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == expected_exit_code, result.stderr
    assert expected_output in result.stdout
    assert result.stderr == ""
