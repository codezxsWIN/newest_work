"""Bounded local input and evidence handling shared by file adapters."""

import re
from pathlib import Path

from vulnassess.errors import AdapterError, ConfigError

MAX_CAPTURE_BYTES = 16 * 1024 * 1024
MAX_XML_DEPTH = 128
MAX_XML_ELEMENTS = 200_000
EVIDENCE_CHARS = 2048


def read_capture(path: Path) -> bytes:
    """Read a regular local file without silently substituting empty input."""
    if str(path).startswith(("\\\\", "//")):
        raise ConfigError(f"Network-share capture paths are forbidden: {path}")
    try:
        if not path.is_file():
            raise ConfigError(f"MISSING: capture file {path}")
        with path.open("rb") as stream:
            content = stream.read(MAX_CAPTURE_BYTES + 1)
    except (OSError, ValueError) as error:
        raise ConfigError(f"Cannot read capture file {path}") from error
    if not content:
        raise AdapterError(f"Empty capture file {path}")
    if len(content) > MAX_CAPTURE_BYTES:
        raise AdapterError(f"Capture file {path} exceeds {MAX_CAPTURE_BYTES} bytes")
    return content


def evidence_ids(text: str, prefix: str) -> list[str]:
    """Extract only explicitly written standard identifiers, with stable ordering."""
    expression = r"\bCVE-\d{4}-\d{4,}\b" if prefix == "CVE" else r"\bCWE-\d+\b"
    return sorted({match.upper() for match in re.findall(expression, text, re.IGNORECASE)})


def evidence_urls(text: str) -> list[str]:
    """Keep explicit HTTP references without requesting or resolving them."""
    return sorted(set(re.findall(r"https?://[^\s<>\"']+", text)))
