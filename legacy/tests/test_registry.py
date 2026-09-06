"""The reader registry resolves a tool name to a parser without importing scanners."""

from pathlib import Path

import pytest

from vulnassess.errors import ConfigError
from vulnassess.registry import ReadResult, get_reader, list_readers, register


def test_builtin_readers_are_registered() -> None:
    assert list_readers() == ("nmap", "zap")


def test_get_reader_returns_the_adapter_wrapper() -> None:
    from vulnassess.adapters import read_nmap, read_zap

    assert get_reader("nmap") is read_nmap
    assert get_reader("zap") is read_zap


def test_unregistered_tool_reports_what_is_registered() -> None:
    with pytest.raises(ConfigError) as error:
        get_reader("nikto")

    message = str(error.value)
    assert "MISSING" in message
    assert "nikto" in message
    assert "nmap" in message


def test_register_rejects_a_name_outside_the_canonical_tools() -> None:
    with pytest.raises(ConfigError) as error:
        register("burp")

    assert "burp" in str(error.value)


def test_register_rejects_a_second_reader_for_the_same_tool() -> None:
    def other(path: Path, run_id: str) -> ReadResult:
        raise AssertionError("must not be called")

    with pytest.raises(ConfigError) as error:
        register("nmap")(other)

    assert "already registered" in str(error.value)


def test_registering_the_same_reader_again_is_idempotent() -> None:
    from vulnassess.adapters import read_nmap

    assert register("nmap")(read_nmap) is read_nmap
    assert list_readers() == ("nmap", "zap")


def test_read_result_defaults_to_empty_collections() -> None:
    result = ReadResult(tool="zap")

    assert result.hosts == []
    assert result.findings == []
