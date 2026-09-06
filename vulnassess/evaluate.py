"""Agreement metrics between our ranking and expert rankings. Stdlib arithmetic only.

A ranking is a list of finding ids, best first. An entry may itself be a list of ids
sharing one rank.
"""

from collections import Counter
from math import log2, sqrt
from pathlib import Path
from typing import Any, Iterable, Sequence

import yaml

from vulnassess.errors import ConfigError


def _flatten(order: Sequence[Any]) -> list[str]:
    flat: list[str] = []
    for entry in order:
        if isinstance(entry, (list, tuple)):
            flat.extend(str(item) for item in entry)
        else:
            flat.append(str(entry))
    return flat


def positions(order: Sequence[Any]) -> dict[str, float]:
    """Map each id to its 1-based position; tied ids share the average of their slots."""
    result: dict[str, float] = {}
    cursor = 1
    for entry in order:
        group = [str(item) for item in entry] if isinstance(entry, (list, tuple)) else [str(entry)]
        average = (cursor + cursor + len(group) - 1) / 2.0
        for item in group:
            result[item] = average
        cursor += len(group)
    return result


def kendall_tau_b(first: dict[str, float], second: dict[str, float]) -> float | None:
    common = sorted(set(first) & set(second))
    concordant = discordant = tied_first = tied_second = 0
    for index, left in enumerate(common):
        for right in common[index + 1 :]:
            a = first[left] - first[right]
            b = second[left] - second[right]
            if a == 0 and b == 0:
                continue
            if a == 0:
                tied_first += 1
            elif b == 0:
                tied_second += 1
            elif (a > 0) == (b > 0):
                concordant += 1
            else:
                discordant += 1
    denominator = sqrt(
        (concordant + discordant + tied_first) * (concordant + discordant + tied_second)
    )
    if denominator == 0:
        return None
    return round((concordant - discordant) / denominator, 4)


def kendall_w(rankings: Sequence[Sequence[Any]]) -> float | None:
    """Concordance across m >= 2 raters. None when a single annotator supplied the truth."""
    raters = len(rankings)
    if raters < 2:
        return None
    all_positions = [positions(order) for order in rankings]
    items = sorted(set(all_positions[0]).intersection(*[set(p) for p in all_positions[1:]]))
    count = len(items)
    if count < 2:
        return None
    sums = [sum(p[item] for p in all_positions) for item in items]
    mean = sum(sums) / count
    deviation = sum((value - mean) ** 2 for value in sums)
    tie_correction = 0
    for rater_positions in all_positions:
        groups = Counter(rater_positions[item] for item in items)
        tie_correction += sum(size**3 - size for size in groups.values() if size > 1)
    denominator = raters**2 * (count**3 - count) - raters * tie_correction
    if denominator == 0:
        return None
    return round(min(max(12 * deviation / denominator, 0.0), 1.0), 4)


def ndcg_at_k(ours: Sequence[Any], expert: Sequence[Any], k: int = 10) -> float:
    expert_positions = positions(expert)
    count = len(expert_positions)
    if count == 0:
        return 0.0

    def relevance(item: str) -> float:
        position = expert_positions.get(item)
        return 0.0 if position is None else max(count - position, 0.0)

    ours_flat = _flatten(ours)[:k]
    ideal = sorted(expert_positions, key=lambda item: expert_positions[item])[:k]
    gain = sum(relevance(item) / log2(index + 2) for index, item in enumerate(ours_flat))
    best = sum(relevance(item) / log2(index + 2) for index, item in enumerate(ideal))
    if best == 0:
        return 0.0
    return round(gain / best, 4)


def critical_queue_at_full_recall(order: Sequence[Any], critical: Iterable[str]) -> int | None:
    """How far an analyst must read before every expert-critical finding has been seen."""
    wanted = {str(item) for item in critical}
    if not wanted:
        return 0
    seen: set[str] = set()
    queue_size = 0
    for entry in order:
        group = [str(item) for item in entry] if isinstance(entry, (list, tuple)) else [str(entry)]
        queue_size += len(group)
        seen.update(wanted.intersection(group))
        if seen == wanted:
            return queue_size
    return None


def load_truth(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"MISSING: truth file {path}")
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise ConfigError(f"{path}: unreadable YAML ({type(error).__name__})") from error
    if not isinstance(payload, dict):
        raise ConfigError(f"{path}: expected a mapping at the top level")
    if "experts" not in payload:
        raise ConfigError(f"{path}: key 'experts' is required")
    experts = payload["experts"]
    if not isinstance(experts, list) or not experts:
        raise ConfigError(f"{path}: key 'experts' must be a non-empty list")
    for expert in experts:
        if not isinstance(expert, dict) or "name" not in expert or "ranking" not in expert:
            raise ConfigError(f"{path}: every expert needs 'name' and 'ranking'")
        flat = _flatten(expert["ranking"])
        duplicates = {item for item in flat if flat.count(item) > 1}
        if duplicates:
            raise ConfigError(
                f"{path}: expert {expert['name']!r} ranks {sorted(duplicates)[0]!r} twice"
            )
    if "expert_critical" not in payload and not all("critical" in expert for expert in experts):
        raise ConfigError(
            f"{path}: provide top-level 'expert_critical' or 'critical' for every expert"
        )
    if payload.get("evidence_status") == "VERIFIED":
        for expert in experts:
            if not expert.get("reviewer") or not expert.get("provenance"):
                raise ConfigError(
                    f"{path}: VERIFIED expert {expert.get('name')!r} requires reviewer and provenance"
                )
    return payload


def evaluate(methods: dict[str, Sequence[Any]], truth: dict[str, Any]) -> dict[str, Any]:
    experts = truth["experts"]
    default_critical = truth.get("expert_critical", [])
    critical_by_expert = {
        expert["name"]: expert.get("critical", default_critical) for expert in experts
    }
    synthetic = "synthetic" in str(truth.get("_comment", "")).lower()
    verified = truth.get("evidence_status") == "VERIFIED" and all(
        expert.get("reviewer") and expert.get("provenance") for expert in experts
    )
    result: dict[str, Any] = {
        "experts": [expert["name"] for expert in experts],
        "evidence_status": (
            "NOT RUN"
            if synthetic
            else ("VERIFIED" if verified else "NOT RUN")
        ),
        "data_kind": "synthetic" if synthetic else "human",
        "critical_sets": critical_by_expert,
    }

    concordance = kendall_w([expert["ranking"] for expert in experts])
    result["kendall_w"] = concordance
    if concordance is None:
        result["limitation"] = (
            "single-annotator study: inter-rater agreement not available"
        )

    result["methods"] = {}
    for name, order in methods.items():
        our_positions = positions(order)
        taus = {
            expert["name"]: kendall_tau_b(our_positions, positions(expert["ranking"]))
            for expert in experts
        }
        ndcgs = {
            expert["name"]: ndcg_at_k(order, expert["ranking"], 10) for expert in experts
        }
        queues = {
            expert["name"]: critical_queue_at_full_recall(
                order, critical_by_expert[expert["name"]]
            )
            for expert in experts
        }
        defined_taus = [value for value in taus.values() if value is not None]
        defined_queues = [value for value in queues.values() if value is not None]
        result["methods"][name] = {
            "tau_b": taus,
            "tau_b_mean": (
                round(sum(defined_taus) / len(defined_taus), 4) if defined_taus else None
            ),
            "ndcg_at_10": ndcgs,
            "ndcg_at_10_mean": round(sum(ndcgs.values()) / len(ndcgs), 4),
            "critical_queue_by_expert": queues,
            "critical_queue": (
                round(sum(defined_queues) / len(defined_queues), 4)
                if defined_queues
                else None
            ),
            "critical_queue_defined_experts": len(defined_queues),
        }

    primary = "ours" if "ours" in methods else ("full" if "full" in methods else None)
    h2: dict[str, Any] = {
        "eligible": verified and primary is not None,
        "primary_method": primary,
        "targets": {"vs_cvss_only": 0.20, "vs_cvss_epss": 0.10},
        "deltas": {},
        "passes": {},
    }
    if primary is not None:
        primary_tau = result["methods"][primary]["tau_b_mean"]
        for baseline, target in (("cvss_only", 0.20), ("cvss_epss", 0.10)):
            baseline_tau = (
                result["methods"].get(baseline, {}).get("tau_b_mean")
            )
            delta = (
                None
                if primary_tau is None or baseline_tau is None
                else round(primary_tau - baseline_tau, 4)
            )
            h2["deltas"][baseline] = delta
            h2["passes"][baseline] = (
                delta >= target if h2["eligible"] and delta is not None else None
            )
    result["h2"] = h2

    h3_reductions: dict[str, float | None] = {}
    if primary is not None and "cvss_only" in result["methods"]:
        primary_queues = result["methods"][primary]["critical_queue_by_expert"]
        baseline_queues = result["methods"]["cvss_only"]["critical_queue_by_expert"]
        for expert in result["experts"]:
            ours = primary_queues[expert]
            baseline = baseline_queues[expert]
            h3_reductions[expert] = (
                None
                if ours is None or baseline in (None, 0)
                else round(100 * (baseline - ours) / baseline, 4)
            )
    defined_reductions = [value for value in h3_reductions.values() if value is not None]
    h3_mean = (
        round(sum(defined_reductions) / len(defined_reductions), 4)
        if defined_reductions
        else None
    )
    result["h3"] = {
        "eligible": verified and bool(h3_reductions),
        "target_percent": 40.0,
        "reductions_percent": h3_reductions,
        "mean_reduction_percent": h3_mean,
        "defined_experts": len(defined_reductions),
        "pass": (
            h3_mean >= 40.0
            if verified and h3_mean is not None
            else None
        ),
    }
    return result


def markdown_table(result: dict[str, Any]) -> str:
    lines = []
    if result.get("kendall_w") is not None:
        lines.append(f"Kendall's W across {len(result['experts'])} experts: {result['kendall_w']}")
    else:
        lines.append(result.get("limitation", ""))
    lines.append("")
    lines.append("| Method | mean tau-b | mean NDCG@10 | critical queue |")
    lines.append("| --- | --- | --- | --- |")
    for name, scores in result.get("methods", {}).items():
        queue = "n/a" if scores["critical_queue"] is None else scores["critical_queue"]
        tau = "undefined" if scores["tau_b_mean"] is None else scores["tau_b_mean"]
        lines.append(
            f"| {name} | {tau} | {scores['ndcg_at_10_mean']} | {queue} |"
        )
    return "\n".join(lines)
