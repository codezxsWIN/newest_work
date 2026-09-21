"""Conservative, evidence-preserving cross-tool finding correlation.

Only compatible records sharing a CVE and affected instance are auto-grouped.
CWE and title similarity create visible candidate links, never merges.
"""

import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Mapping, Sequence

from vulnassess.errors import ConfigError
from vulnassess.schema import Enrichment, Finding

TOKEN = re.compile(r"[a-z0-9]+")


@dataclass(frozen=True)
class UnifiedFinding:
    id: str
    host_ip: str
    port: int | None
    protocol: str | None
    url: str | None
    source_finding_ids: tuple[str, ...]
    tools: tuple[str, ...]
    cve_ids: tuple[str, ...]
    method: str
    confidence: float
    justification: str
    evidence: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "host_ip": self.host_ip,
            "port": self.port,
            "protocol": self.protocol,
            "url": self.url,
            "source_finding_ids": list(self.source_finding_ids),
            "tools": list(self.tools),
            "cve_ids": list(self.cve_ids),
            "method": self.method,
            "confidence": self.confidence,
            "justification": self.justification,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class CandidateLink:
    left_finding_id: str
    right_finding_id: str
    method: str
    confidence: float
    justification: str

    def to_json(self) -> dict[str, Any]:
        return {
            "left_finding_id": self.left_finding_id,
            "right_finding_id": self.right_finding_id,
            "method": self.method,
            "confidence": self.confidence,
            "justification": self.justification,
        }


@dataclass(frozen=True)
class UnificationResult:
    raw_count: int
    unified_count: int
    groups: tuple[UnifiedFinding, ...]
    candidates: tuple[CandidateLink, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "raw_count": self.raw_count,
            "unified_count": self.unified_count,
            "duplicate_reduction": self.raw_count - self.unified_count,
            "groups": [group.to_json() for group in self.groups],
            "candidates": [candidate.to_json() for candidate in self.candidates],
        }


def _canonical_ids(items: Sequence[str]) -> tuple[str, ...]:
    return tuple(sorted(set(items)))


def _group_id(source_ids: Sequence[str]) -> str:
    joined = "|".join(_canonical_ids(source_ids))
    return sha256(f"vulnassess-unified-v1|{joined}".encode("utf-8")).hexdigest()


def _cves(
    finding: Finding,
    enrichments: Mapping[str, Sequence[Enrichment]],
) -> set[str]:
    return set(finding.cve_ids) | {
        enrichment.cve_id for enrichment in enrichments.get(finding.id, ())
    }


def _same_service(left: Finding, right: Finding) -> bool:
    return (
        left.host_ip == right.host_ip
        and left.port == right.port
        and left.protocol == right.protocol
    )


def _same_instance(left: Finding, right: Finding) -> bool:
    return left.url == right.url


def _title_similarity(left: str, right: str) -> float:
    left_tokens = set(TOKEN.findall(left.lower()))
    right_tokens = set(TOKEN.findall(right.lower()))
    if not left_tokens or not right_tokens:
        return 0.0
    return len(left_tokens & right_tokens) / len(left_tokens | right_tokens)


def _merge_reason(
    left: Finding,
    right: Finding,
    enrichments: Mapping[str, Sequence[Enrichment]],
) -> tuple[str, float, str] | None:
    if not _same_service(left, right) or not _same_instance(left, right):
        return None
    shared = sorted(_cves(left, enrichments) & _cves(right, enrichments))
    if not shared:
        return None
    return (
        "shared_cve_same_instance",
        0.95,
        f"same host/service/instance and shared CVE {', '.join(shared)}",
    )


def _candidate_reason(
    left: Finding,
    right: Finding,
    enrichments: Mapping[str, Sequence[Enrichment]],
) -> tuple[str, float, str] | None:
    if not _same_service(left, right):
        return None
    shared_cves = sorted(_cves(left, enrichments) & _cves(right, enrichments))
    if shared_cves and not _same_instance(left, right):
        return (
            "shared_cve_different_instance",
            0.75,
            f"shared CVE {', '.join(shared_cves)} but affected URLs differ",
        )
    shared_cwes = sorted(set(left.cwe_ids) & set(right.cwe_ids))
    if shared_cwes:
        return (
            "shared_cwe_candidate",
            0.65,
            f"shared CWE {', '.join(shared_cwes)}; generic weakness identity is insufficient",
        )
    similarity = _title_similarity(left.title, right.title)
    if similarity >= 0.6:
        return (
            "similar_title_candidate",
            round(similarity, 6),
            f"title token Jaccard similarity {similarity:.3f}; review required",
        )
    return None


def unify_findings(
    findings: Sequence[Finding],
    enrichments: Mapping[str, Sequence[Enrichment]] | None = None,
) -> UnificationResult:
    """Group only justified duplicates and retain every source id exactly once."""
    enrichment_map = enrichments or {}
    by_id = {finding.id: finding for finding in findings}
    if len(by_id) != len(findings):
        raise ConfigError("unification input contains duplicate finding IDs")
    ordered = [by_id[key] for key in sorted(by_id)]
    parent = {finding.id: finding.id for finding in ordered}
    merge_metadata: dict[tuple[str, str], tuple[str, float, str]] = {}
    candidates: list[CandidateLink] = []

    def root(finding_id: str) -> str:
        while parent[finding_id] != finding_id:
            parent[finding_id] = parent[parent[finding_id]]
            finding_id = parent[finding_id]
        return finding_id

    def union(left_id: str, right_id: str) -> None:
        left_root, right_root = root(left_id), root(right_id)
        if left_root == right_root:
            return
        first, second = sorted((left_root, right_root))
        parent[second] = first

    for index, left in enumerate(ordered):
        for right in ordered[index + 1 :]:
            merge = _merge_reason(left, right, enrichment_map)
            if merge is not None:
                union(left.id, right.id)
                merge_metadata[(left.id, right.id)] = merge
                continue
            candidate = _candidate_reason(left, right, enrichment_map)
            if candidate is not None:
                method, confidence, justification = candidate
                candidates.append(
                    CandidateLink(
                        left_finding_id=left.id,
                        right_finding_id=right.id,
                        method=method,
                        confidence=confidence,
                        justification=justification,
                    )
                )

    grouped: dict[str, list[Finding]] = {}
    for finding in ordered:
        grouped.setdefault(root(finding.id), []).append(finding)

    groups: list[UnifiedFinding] = []
    for members in grouped.values():
        members.sort(key=lambda finding: finding.id)
        source_ids = tuple(finding.id for finding in members)
        cves = sorted({cve for finding in members for cve in _cves(finding, enrichment_map)})
        tools = sorted({finding.tool for finding in members})
        evidence: list[str] = []
        for finding in members:
            if finding.evidence not in evidence:
                evidence.append(finding.evidence)
        if len(members) == 1:
            method = "singleton"
            confidence = 1.0
            justification = "no automatic merge was justified"
        else:
            pair_reasons = [
                metadata
                for pair, metadata in merge_metadata.items()
                if pair[0] in source_ids and pair[1] in source_ids
            ]
            method = "shared_cve_same_instance"
            confidence = min(item[1] for item in pair_reasons)
            justification = "; ".join(sorted({item[2] for item in pair_reasons}))
        first = members[0]
        groups.append(
            UnifiedFinding(
                id=_group_id(source_ids),
                host_ip=first.host_ip,
                port=first.port,
                protocol=first.protocol,
                url=first.url,
                source_finding_ids=source_ids,
                tools=tuple(tools),
                cve_ids=tuple(cves),
                method=method,
                confidence=confidence,
                justification=justification,
                evidence=tuple(evidence),
            )
        )

    groups.sort(key=lambda group: group.id)
    candidates.sort(key=lambda item: (item.left_finding_id, item.right_finding_id, item.method))
    covered = sorted(source for group in groups for source in group.source_finding_ids)
    if covered != sorted(by_id):
        raise ConfigError("unification did not preserve every source finding exactly once")
    return UnificationResult(
        raw_count=len(findings),
        unified_count=len(groups),
        groups=tuple(groups),
        candidates=tuple(candidates),
    )


def unify_run(store, run_id: str) -> UnificationResult:
    findings = store.findings(run_id)
    enrichments = {finding.id: store.enrichments(finding.id) for finding in findings}
    return unify_findings(findings, enrichments)
