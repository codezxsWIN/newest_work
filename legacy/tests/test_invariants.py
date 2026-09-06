"""Offline enforcement and static architectural checks, not pipeline certification."""

import ast
import socket
from importlib.util import resolve_name
from pathlib import Path

import pytest


def _source_files() -> list[Path]:
    root = Path(__file__).resolve().parents[1] / "src" / "vulnassess"
    assert root.is_dir(), f"MISSING: {root}"
    files = sorted(root.rglob("*.py"))
    assert files, f"MISSING: Python modules under {root}"
    return files


def _import_names(path: Path) -> set[str]:
    source_root = Path(__file__).resolve().parents[1] / "src"
    relative = path.relative_to(source_root).with_suffix("")
    package = ".".join(relative.parts[:-1])
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                module = resolve_name("." * node.level + module, package)
            names.add(module)
            names.update(f"{module}.{alias.name}" for alias in node.names)
    return names


@pytest.mark.parametrize("method", ["connect", "connect_ex", "bind", "sendto"])
def test_socket_guard_blocks_connections_and_datagrams(method: str) -> None:
    with socket.socket() as connection:
        with pytest.raises(AssertionError, match="Network access forbidden"):
            getattr(connection, method)(("synthetic.invalid", 443))


def test_socket_guard_blocks_dns_and_high_level_connections() -> None:
    with pytest.raises(AssertionError, match="Network access forbidden"):
        socket.getaddrinfo("synthetic.invalid", 443)
    with pytest.raises(AssertionError, match="Network access forbidden"):
        socket.create_connection(("synthetic.invalid", 443))


def test_i4_http_imports_only_in_designated_adapters() -> None:
    root = Path(__file__).resolve().parents[1] / "src" / "vulnassess"
    permitted = {root / "intel" / "feeds.py", root / "explain" / "ollama_client.py"}
    violations: list[str] = []
    for path in _source_files():
        if path in permitted:
            continue
        for name in sorted(_import_names(path)):
            if name.split(".", maxsplit=1)[0] in {"httpx", "requests", "urllib"}:
                violations.append(f"{path.relative_to(root)} imports {name}")
    assert not violations, "I4 violations: " + "; ".join(violations)


def test_i5_scoring_does_not_import_impure_ports() -> None:
    root = Path(__file__).resolve().parents[1] / "src" / "vulnassess" / "scoring"
    forbidden = ("vulnassess.explain", "vulnassess.adapters", "vulnassess.intel.feeds")
    paths = [path for path in _source_files() if path.is_relative_to(root)]
    assert paths, f"MISSING: scoring modules under {root}"
    violations: list[str] = []
    for path in paths:
        for name in sorted(_import_names(path)):
            if any(name == prefix or name.startswith(prefix + ".") for prefix in forbidden):
                violations.append(f"{path.name} imports {name}")
    assert not violations, "I5 violations: " + "; ".join(violations)
