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

## Source alignment and Prompt 1 — 2026-09-06

Owner: scaffold integrator; changes remain on the prompt branch for teammate review.

13. **Source of truth:** the supplied implementation prompts replace the provisional project brief. The deck's exact eight steps and final six-section explainer are still unavailable; existing explanatory prose is not represented as verbatim source text.
14. **LLM boundary:** Prompt 0's hard rule (rationales only, no ranking influence) takes precedence over Prompt 5's role-classification fallback. Context remains rule-based unless an explicit later decision changes that boundary.
15. **Scoring correction:** specification `prompt-7-v0` supersedes the day-zero weighted mean. Use CVSS Environmental score, an EPSS-percentile factor of `0.5 + 0.5 * percentile`, and the KEV floor of 90. Bands are 80/60/35. No implementation or evaluation result is claimed yet.
16. **Role correction:** accept Prompt 5's ten role names as listed in `scoring.md`, replacing the provisional hyphenated list. Manual tags remain separate inputs per Prompt 6.
17. **Golden-test inconsistency:** KEV status cannot differ by machine for the same CVE/feed. Identical KEV=true inputs must both be Critical. The candidate CVE is unverified; defer its selection and the exact context-only band assertion until real fixtures exist. Test the KEV floor separately.
18. **Scope interpretation:** retain the existing three fixed lab IPs inside `172.28.0.0/24`; do not widen to CIDR-wide discovery. Empty `allowed_hosts` does not remove the explicitly configured lab targets.
19. **Execution boundary:** implement Prompt 1 only in this change, after applying Prompt 0. CLI commands and lab/e2e targets must fail explicitly as unimplemented. Do not install tools/dependencies, pull images/models, run scans, contact feeds, or fabricate real sample data.
20. **Packaging:** use a setuptools `src` layout, a `vulnassess` console entry point, and `python -m vulnassess` as an equivalent entry point. Development dependencies live in the `dev` extra.
21. **Environmental precedence:** when role and test-environment requirements overlap, apply the test requirements last. This makes Prompt 7's test-context mapping effective without introducing new weights.

### Dependency justifications

- `typer>=0.12`: implement the specified typed CLI and its testable command interface.
- `pydantic>=2,<3`: provide the requested v2 canonical models and validation in later prompts.
- `httpx`: support explicit feed refresh and local Ollama HTTP requests in later prompts; ordinary processing remains offline.
- `rich`: provide readable terminal output and evaluation tables.
- `PyYAML`: read the requested scope, role, weight, and expert-ranking configuration.
- `pytest` (development): run the requested deterministic unit and CLI tests.
- `ruff` (development): enforce the requested Python lint checks.
- `setuptools>=77` (build): package the `src` layout and console script with standardized license metadata.

No packages are installed as part of this change. Libraries requested only in later prompts (`cvss`, Jinja2, SciPy) are not added early.

### Prompt 1 validation commands

Run from the repository root using an environment that already provides the dependencies:

```powershell
python -m ruff check .
python -m pytest
$env:PYTHONPATH = (Join-Path $PWD 'src')
python -m vulnassess --help
python -m vulnassess scan
```

Help must exit 0; every named command must print `not implemented` and exit 2. On a machine with Make, `make lint` and `make test` run the same checks. Bare `make` defaults to tests, not installation. `make install` is an opt-in dependency installation command, not something executed during this task.

### Prompt 1 verification — 2026-09-06

- Python 3.12.10 and the existing runtime dependencies were used without installing or upgrading anything.
- `python -m pytest tests\test_cli.py`: 13 tests passed, including all eight exit-2 stubs, help, invalid commands, and module entry points.
- Built a wheel using the existing setuptools backend without dependency resolution or installation; verified its console entry point (`--help`, exit 0) and module entry point (`scan`, exit 2) directly from the wheel.
- `python -m ruff check .` could not run: Ruff is not installed in the active Python environment, is not on PATH, and no separate uv tools are installed. No lint pass is claimed.
- Make is not on PATH, so the Make wrappers were not executed; their underlying pytest command was verified directly. The install target was never run.
- Full Prompt 1 acceptance remains pending the required Ruff check. Do not mark the stage complete or advance to Prompt 2 on the strength of tests alone.
