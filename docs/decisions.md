# Decisions

Durable changes are appended here with a date, rationale, and owner. Scoring or role changes also record the version and evaluation impact.

## Seed decisions — 2026-09-06

1. **Package name:** `vulnassess`.
2. **Runtime and license:** Python 3.11 or newer; MIT License.
3. **Lab scope:** `172.28.0.0/24`, limited to the three targets in `config/scope.yaml`. **Scanning is authorised only against the lab network defined in config/scope.yaml.**
4. **Local model:** `qwen2.5:7b`, `Q4_K_M`. Treat the model and quantisation as selected but not benchmark-verified until the smoke test and model metadata are recorded. Test-machine CPU and RAM remain to be recorded after verification; do not fabricate them.
5. **CVSS policy:** CVSS v4.0 is primary. When v4.0 is absent, translate v3.1 using the versioned project translator and record the original vector, method/version, assumptions, and translated result on the finding.
6. **Roles and bands:** v0 roles and thresholds are those in `docs/scoring.md`. Changes require a dated decision, scoring-version increment where relevant, rationale, and evaluation note.
7. **Evaluation plan:** recruit three experts: the project mentor and two security practitioners independent of score implementation. Ask them before Stage 3 closes. Each receives stable finding IDs and evidence, then returns a full ranking (ties allowed only if documented) and an `expert-critical` set. Identities may be pseudonymised in committed artifacts.
8. **Stage definition of done:** relevant tests pass, Ruff is clean, documentation is updated, and one documented demo command succeeds.
9. **Nine-person team split:** Stage 1 adapters/schema: 2; intelligence: 2; context inference: 2; scoring/explanation: 2; lab/evaluation/docs: 1. One person from the team is designated integrator and owns `main`; the role does not add a tenth person.
10. **Git workflow:** protect `main`; use one branch per prompt; require a teammate review before every merge.
11. **Initial scoring hypothesis:** use scoring v0 in `docs/scoring.md` until Stage 4. It is deliberately labeled a hypothesis and must not be described as validated.
12. **Golden test:** start with `CVE-2012-2122`; fixture evidence must confirm the product/version match. Any replacement requires a recorded decision.

## Verification record

The following items are intentionally not claimed complete until real commands and artifacts exist:

- Development-tool smoke test
- Local-model metadata and machine specification
- Lab startup and authorised manual scans
- Dated NVD, EPSS, and KEV fixture subsets
- Expert-panel acceptance

