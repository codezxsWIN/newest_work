# Hypothesis — to be tuned in Stage 4

This v0 is a testable hypothesis, not a validated risk model. Changes require an entry in `docs/decisions.md`, a scoring-version increment, and evaluation against data not used to choose the change.

## Inputs

Each normalized input is in `[0, 1]`:

- `severity`: CVSS base score divided by 10.
- `exploit_likelihood`: current EPSS probability. Missing EPSS is represented as missing, not zero.
- `known_exploitation`: 1 when the CVE is in the dated CISA KEV snapshot, otherwise 0.
- `exposure`: 1 for confirmed or explicitly tagged external exposure, 0.5 for internal reachability, and 0 when isolated; unknown remains missing.
- `asset_criticality`: configured integer criticality from 1 through 5, mapped with `(criticality - 1) / 4`; unknown remains missing.

Explicit configuration outranks inference. An inferred input must include evidence and confidence.

## Formula

For available inputs, renormalize the included weights so missing context does not masquerade as low risk:

```text
base = weighted_mean(
  severity            × 35,
  exploit_likelihood  × 25,
  known_exploitation  × 20,
  exposure            × 10,
  asset_criticality   × 10
)

score = round(100 × base, 1)
```

`weighted_mean` divides the weighted sum by the sum of weights for inputs that are present. A result must include the value, source, weight, contribution, and missing-input list.

## Priority bands

| Band | Score |
|---|---:|
| Critical | `>= 80` |
| High | `>= 60` and `< 80` |
| Medium | `>= 40` and `< 60` |
| Low | `< 40` |

KEV membership is visible as a contribution but does not silently override the formula. Consumers may create a separate operational rule for KEV findings only through a recorded decision.

## Baseline

The evaluation baseline orders findings by CVSS base score descending, then by stable finding identifier. The context-aware ranking orders by `score` descending, then by the same stable identifier.

## Approved role list (v0)

- `database`
- `web-application`
- `web-server`
- `application-server`
- `identity`
- `network-infrastructure`
- `workstation`
- `unknown`

