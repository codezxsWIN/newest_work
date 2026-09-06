"""Reader registry. Maps a tool name to the parser that turns its capture into canonical records."""

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import get_args

from vulnassess.errors import ConfigError
from vulnassess.schema import Finding, Host, Tool

TOOL_NAMES: tuple[str, ...] = tuple(get_args(Tool))


@dataclass(frozen=True)
class ReadResult:
    """What one capture yielded. Readers that see no hosts return an empty host list."""

    tool: str
    hosts: list[Host] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


Reader = Callable[[Path, str], ReadResult]

_READERS: dict[str, Reader] = {}


def register(name: str) -> Callable[[Reader], Reader]:
    """Register a reader under a canonical tool name."""
    if name not in TOOL_NAMES:
        raise ConfigError(f"Unknown tool name {name!r}; expected one of {', '.join(TOOL_NAMES)}")

    def decorator(reader: Reader) -> Reader:
        existing = _READERS.get(name)
        if existing is not None and existing is not reader:
            raise ConfigError(f"Reader for {name!r} is already registered as {existing.__name__}")
        _READERS[name] = reader
        return reader

    return decorator


def _load_builtin_readers() -> None:
    """Import the adapter package so its decorated readers register themselves."""
    if _READERS:
        return
    import vulnassess.adapters  # noqa: F401  (import for registration side effect)


def get_reader(name: str) -> Reader:
    """Return the registered reader, naming what is missing when there is none."""
    _load_builtin_readers()
    reader = _READERS.get(name)
    if reader is None:
        available = ", ".join(list_readers()) or "none"
        raise ConfigError(f"MISSING: no reader registered for {name!r}; registered: {available}")
    return reader


def list_readers() -> tuple[str, ...]:
    """Every registered tool name, sorted."""
    _load_builtin_readers()
    return tuple(sorted(_READERS))
