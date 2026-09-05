"""Scaffold commands must fail explicitly without executing a pipeline."""

import os
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vulnassess.cli import app

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
