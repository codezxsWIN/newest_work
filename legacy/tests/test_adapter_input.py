"""Pure source-span and bounded-I/O checks, not successful scanner integration tests."""

import json
from pathlib import Path
from typing import Any

import pytest

from vulnassess.adapters import _input, nmap_xml
from vulnassess.adapters.nmap_xml import _xml_records
from vulnassess.adapters.zap_json import _array_spans, _member_offsets, _next_token
from vulnassess.errors import AdapterError, ConfigError


def _synthetic_data() -> dict[str, Any]:
    path = Path(__file__).parent / "synthetic" / "synthetic_adapter_inputs.json"
    assert path.is_file(), f"MISSING: {path}"
    result: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    assert result["_comment"].startswith("SYNTHETIC")
    return result


@pytest.mark.parametrize("case_index", [0, 1, 2])
def test_xml_excerpts_end_at_their_own_record(case_index: int) -> None:
    case = _synthetic_data()["xml_span_cases"][case_index]
    content = case["document"].encode("utf-8")
    _, excerpts = _xml_records(content, Path("synthetic_span.xml"))

    assert case["expected"] in excerpts.values()
    assert all(value in case["document"] for value in excerpts.values())


def test_json_offsets_preserve_spacing_and_escaped_delimiters() -> None:
    case = _synthetic_data()["json_span_case"]
    text = case["document"]
    json.loads(text)
    root = _member_offsets(text, _next_token(text, 0))
    group_start, _ = next(_array_spans(text, root["groups"]))
    group = _member_offsets(text, group_start)
    excerpts = [text[start:end] for start, end in _array_spans(text, group["entries"])]

    assert excerpts == case["expected"]


@pytest.mark.parametrize("limit", ["MAX_XML_DEPTH", "MAX_XML_ELEMENTS"])
def test_xml_structure_limits_stop_nested_input(limit: str, monkeypatch: pytest.MonkeyPatch) -> None:
    content = _synthetic_data()["xml_span_cases"][1]["document"].encode("utf-8")
    monkeypatch.setattr(nmap_xml, limit, 2)
    with pytest.raises(AdapterError, match="XML structure limit exceeded"):
        _xml_records(content, Path("synthetic_limit.xml"))


def test_capture_byte_limit_has_no_silent_truncation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_input, "MAX_CAPTURE_BYTES", 4)
    path = tmp_path / "synthetic_limit.bin"
    path.write_bytes(b"unit")
    assert _input.read_capture(path) == b"unit"
    path.write_bytes(b"units")
    with pytest.raises(AdapterError, match="exceeds 4 bytes"):
        _input.read_capture(path)


def test_capture_io_error_names_the_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "synthetic_denied.bin"
    path.write_bytes(b"unit")

    def denied(*args: Any, **kwargs: Any) -> Any:
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "open", denied)
    with pytest.raises(ConfigError, match="synthetic_denied.bin"):
        _input.read_capture(path)


@pytest.mark.parametrize(
    "name", ["//not-provided.invalid/share/capture.xml", r"\\not-provided.invalid\share\capture.xml"]
)
def test_network_share_is_rejected_before_filesystem_access(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected_access(path: Path) -> bool:
        raise AssertionError("Network path must be rejected before filesystem access")

    monkeypatch.setattr(Path, "is_file", unexpected_access)
    with pytest.raises(ConfigError, match="Network-share capture paths are forbidden"):
        _input.read_capture(Path(name))
