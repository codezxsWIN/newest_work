"""Shared synthetic model inputs for pure validation and persistence tests."""

import json
import socket
from pathlib import Path
from typing import Any, NoReturn
from uuid import NAMESPACE_URL, uuid5

import pytest

from vulnassess.schema import Finding


def pytest_runtest_setup(item: pytest.Item) -> None:
    root = item.config.rootpath.resolve()
    permitted = root / "tests" / "fixtures"
    for marker in item.iter_markers(name="needs_fixture"):
        if marker.kwargs or not marker.args:
            raise pytest.UsageError("needs_fixture requires positional fixture paths")
        for name in marker.args:
            if not isinstance(name, str):
                raise pytest.UsageError("needs_fixture paths must be strings")
            relative = Path(name)
            if (
                relative.is_absolute()
                or relative.parts[:2] != ("tests", "fixtures")
                or ".." in relative.parts
            ):
                raise pytest.UsageError(f"needs_fixture path must be under tests/fixtures/: {name}")
            try:
                path = (root / relative).resolve()
            except (OSError, RuntimeError, ValueError) as error:
                raise pytest.UsageError(f"Invalid needs_fixture path: {name}") from error
            if not path.is_relative_to(permitted):
                raise pytest.UsageError(f"needs_fixture path escapes tests/fixtures/: {name}")
            if not path.is_file():
                pytest.skip(f"fixture not provided: {relative.as_posix()}")


def _deny_network(*args: Any, **kwargs: Any) -> NoReturn:
    raise AssertionError("Network access forbidden in tests; mock the network boundary")


@pytest.fixture(autouse=True)
def socket_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "create_connection",
        "create_server",
        "getaddrinfo",
        "gethostbyname",
        "gethostbyname_ex",
        "gethostbyaddr",
    ):
        monkeypatch.setattr(socket, name, _deny_network)
    for name in (
        "connect",
        "connect_ex",
        "bind",
        "listen",
        "accept",
        "send",
        "sendall",
        "sendto",
        "recv",
        "recv_into",
        "recvfrom",
        "recvfrom_into",
        "sendfile",
        "sendmsg",
        "recvmsg",
    ):
        if hasattr(socket.socket, name):
            monkeypatch.setattr(socket.socket, name, _deny_network)


@pytest.fixture
def schema_data() -> dict[str, Any]:
    path = Path(__file__).parent / "synthetic" / "synthetic_schema.json"
    assert path.is_file(), f"MISSING: {path}"
    payload: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    assert payload.get("_comment") == (
        "SYNTHETIC: pure model validation and persistence tests only; "
        "not scanner, feed, or model output."
    ), f"Missing synthetic-data header in {path}"
    finding = payload["finding"]
    fingerprint = Finding.fingerprint(
        finding["host_ip"],
        finding["port"],
        finding["protocol"],
        finding["tool"],
        finding["tool_native_id"],
        finding["url"],
    )
    finding["id"] = str(uuid5(NAMESPACE_URL, fingerprint))
    return payload
