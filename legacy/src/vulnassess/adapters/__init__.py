"""Scanner parsing and scope-checked execution.

Importing this package registers the built-in readers.
"""

from pathlib import Path

from vulnassess.adapters.nmap_xml import parse_nmap_xml
from vulnassess.adapters.zap_json import parse_zap_json
from vulnassess.registry import ReadResult, register

__all__ = ["read_nmap", "read_zap"]


@register("nmap")
def read_nmap(path: Path, run_id: str) -> ReadResult:
    """Hosts and findings from one Nmap XML capture."""
    hosts, findings = parse_nmap_xml(path, run_id)
    return ReadResult(tool="nmap", hosts=hosts, findings=findings)


@register("zap")
def read_zap(path: Path, run_id: str) -> ReadResult:
    """Findings from one ZAP JSON report. ZAP does not establish host inventory."""
    return ReadResult(tool="zap", hosts=[], findings=parse_zap_json(path, run_id))
