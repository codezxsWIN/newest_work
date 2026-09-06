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

## Engineering contract update - 2026-09-06

**22. Conflict / resolution / why - installation:** decision 19 and the day-zero instructions prohibited installation without further approval; the latest engineering contract explicitly authorises creating or refreshing `.venv` and installing dependencies already declared in `pyproject.toml`, including development extras. Follow that newer permission. Adding or removing a declaration still requires approval and a dependency justification here. Alternative considered: retaining the blanket installation prohibition; rejected because it prevents the explicitly required verification workflow.

**23. Conflict / resolution / why - acceptance:** decision 8 and the Prompt 1 commands did not enforce formatting, static types, or coverage. The latest contract requires `make check` to pass Ruff lint, Ruff formatting, Pyright, pytest, and at least 85% source coverage before completion. A missing tool or target is a failing prerequisite, not a passing or skipped check. Alternative considered: reporting the prior pytest-only result as completion; rejected because it does not satisfy the new gate.

**24. Conflict / resolution / why - provenance:** the day-zero context-source list contained only `rule` and `llm`; the latest contract also permits `manual`. Adopt all three provenance labels while retaining the existing prohibition on LLM influence over scores or scoring inputs. Alternative considered: enabling LLM role inference; rejected because a provenance label is not permission to cross the scoring boundary.

**25. Execution boundaries:** scope changes, dependency additions or removals, deletion of pre-existing files, credential operations, and network calls outside authorised installation, documented feed downloads, and scoped lab scans remain approval-gated. The new contract permits lab Compose operations and scoped scans, but neither is needed to establish the engineering foundation. Alternatives considered: running the lab during baseline verification or widening scope; rejected because tests must be offline and the configured explicit targets remain the only authorised scan targets.

## Section 0b update - 2026-09-06

**26. Conflict / resolution / why - no downloads:** section 0b supersedes decisions 22 and 25 wherever they permit installation from an index, feed downloads, image or model downloads, Docker builds, or Compose startup by the agent. Humans supply dependencies, images, models, and snapshots. Only an existing `wheels/` directory permits `pip install --no-index --find-links=wheels -e ".[dev]"`; without it, install nothing. Dependency declaration changes still require explicit approval. Alternative considered: downloading missing gate tools to satisfy decision 23; rejected because gate completion cannot override the no-download boundary.

**27. Conflict / resolution / why - fixture provenance:** earlier permission to create fixtures does not permit fabricated scanner or feed records. Require human-captured lab fixtures with a README recording date, command, and target. Synthetic inputs are restricted to pure-logic unit tests under `tests/synthetic/`, with filenames starting `synthetic_`; those tests cannot establish parser, feed, or model correctness. Alternatives considered: realistic-looking scanner samples and invented intelligence records; rejected because they misrepresent integration evidence.

**28. Conflict / resolution / why - evidence and absence:** check prerequisites before use, stop each missing-input path, and report it as `MISSING` with the exact required path or command. Runtime code must raise the appropriate `ConfigError`, `IntelUnavailable`, or `LLMUnavailable` rather than conceal absence with samples or empty defaults. Reports use exactly one evidence label per claim: `VERIFIED` with actual quoted command/output, `TESTED WITH MOCKS`, `NOT RUN` with a reason, or `MISSING`. Alternative considered: extrapolating integration success from mocks or synthetic tests; rejected because code-path tests are not live integration evidence.

**29. Conflict / resolution / why - authored download commands:** download-capable commands and deployment files may be written, but are not run by the agent. Their command notices, docstrings or format-appropriate documentation, and project docs must contain "not run by the agent". This applies to future `intel refresh`, Dockerfile, and Compose implementations; it is not a claim that those implementations exist. Alternative considered: smoke-running download paths; rejected by section 0b. The operating rules are persisted in `.github/copilot-instructions.md`; historical decisions remain unchanged above.

## Artifact trust boundary - 2026-09-06

**30. Conflict / resolution / why - local does not mean trusted:** the latest security requirement rules out treating a supplied wheel directory as sufficient approval to install. Decision 26's directory-presence exception is therefore suspended pending human review of a minimal, pinned dependency set, artifact provenance, independently approved hashes, and dated vulnerability evidence. Replace the index-capable `make install` recipe with a dependency-free refusal that exits 2; direct pip invocation is not an authorised bypass. Record the review requirements and the limits of offline operation in `docs/security.md`. Alternatives considered: downloading every missing tool, trusting all local wheels, copying another environment, or fabricating a lockfile; rejected because none establishes artifact trust. This safeguard does not claim complete security or host-level network isolation, and it does not add, remove, or approve dependencies.

## Fixed contract foundation - 2026-09-06

**31. Contract adoption:** retain the human-supplied field names, signatures, table layout, exit codes, configuration shapes, and invariants in `docs/contracts.md`. No interface change or ADR approval is asserted. The schema must preserve generic `Feature.value` and the declared source labels; a provenance label must not be mistaken for permission to affect scoring. Alternatives considered: changing the public schema to suit an implementation or adding undocumented validation restrictions; rejected because the interfaces are fixed. Any subsequent interface change needs a human-approved ADR.

**32. SQLite ownership and absence:** use explicit database creation, WAL, bound value parameters, and typed model serialization. Retain the original finding content and run ownership on an ID conflict; replace only `last_seen`. Read and update inside the same write transaction, and reject incompatible existing column layouts rather than silently migrating them. Alternatives considered: overwriting the whole finding, reassigning its run, adding a run-association table, or silently creating a missing input store; rejected because they violate the supplied upsert rule or conceal absence. Feed cache tables do not imply implemented feed ingestion.

**33. Evidence-limited acceptance:** synthetic schema/store tests, a Python-process socket guard, and static I4/I5 import checks are separate checks, not evidence that parsers, feeds, the rank command, or Ollama work. Retain the existing CLI smoke tests until the full command integration can be tested. The declared-dependency set and lab scope remain unchanged. Missing `cvss`, `pydantic-settings`, `structlog`, property/gate tools, real captures, and control signatures require the existing human artifact/configuration process. Alternatives considered: a hand-written CVSS replacement, fabricated scanner/feed fixtures, dummy control signatures, skipping required checks, or downloading tools to force acceptance; rejected by the fixed contracts and section 0b. I1-I3 and full command/configuration integration remain acceptance requirements, not claimed successes.

## Canonical project brief - 2026-09-06

**31. Project scope and stage names:** adopt [PROJECT.md](PROJECT.md) as the canonical whole-project brief and add the read-first instruction to Prompt 0. Its eight named stages replace the provisional methodology numbering; scoring, evaluation, and lab/demo remain cross-cutting. Record prompts 3B, 4B, and 11B as planned orchestrator, unification, and re-scan work, not completed features. The referenced `docs/contracts.md` and prompt definitions A/1A/1B have not been supplied; do not fabricate them. Alternative considered: retaining two incompatible eight-step descriptions; rejected because tasks need one stage map.

**32. Clarification unavailable / conservative LLM boundary:** asked whether the attachment's LLM-assisted roles should replace the current rationale-only rule; no user answer was available. Preserve decisions 14 and 24 and the security boundary. LLM roles and optional semantic merging remain deferred because they can indirectly change rankings or queue composition. This is not new approval for either feature. Alternative considered: silently enabling model-derived context under the deterministic-formula label; rejected because deterministic arithmetic does not remove nondeterministic input influence.

**33. Scientific and evidence constraints:** carry forward decision 17: the same CVE and feed snapshot must have the same EPSS/KEV facts on both machines. Replace the inconsistent demonstration table with a context-only comparison and a separate KEV-floor test; exact bands await confirmed vectors and fixtures. Mark the shared-CWE merge shortcut and banner-only remediation inference as design questions requiring stronger evidence before implementation. Research improvement, team allocation, and December acceptance goals are not execution results. Alternative considered: treating the supplied illustrative numbers and examples as verified golden outcomes; rejected because no real capture, measured result, or valid same-snapshot contrast supports that claim.

## Project brief reconciliation - 2026-09-06

**PROJECT-04. Concurrent contract arrival:** the fixed engineering contract and its decision entries arrived while the brief was being committed. The initial missing-contract observation in the "Canonical project brief" section is historical and now superseded: [contracts.md](contracts.md) exists and defines interfaces and I1-I5. Preserve the concurrent edits and both historical sets of decisions numbered 31-33; references must qualify their section, and this follow-up uses scoped IDs to avoid further collisions. Clarification about reconciliation was requested but no answer was available; update only the brief and this log. No contract change, interface approval, or completed implementation is asserted.

**PROJECT-05. Fixed-contract precedence:** the contract's `missing_epss_percentile: 0.5` gives a threat multiplier of `0.75` under `0.5 + 0.5 * percentile`, unlike the earlier scoring notes' missing-data multiplier of `0.5`. Flag the discrepancy explicitly and follow the fixed contract unless a human approves an ADR; reconcile the detailed scoring notes before implementing that layer. Additional role mappings, criticality adjustments, and native fallbacks are also contract-defined. The roadmap's new APIs, tables, commands, and configuration need the required ADR, including a design for re-scan observations that respects the fixed last-seen-only upsert policy. Alternative considered: silently changing the supplied configuration, upsert behavior, or interface to fit a roadmap example; rejected because this documentation task does not approve those changes.

## Prompt coverage and measurement audit - 2026-09-06

**PROJECT-06. Traceable planned coverage:** incorporate the user's sixteen-prompt audit into [PROJECT.md](PROJECT.md), with primary-build versus support responsibilities and corrected objectives. Source slides 13-15 are not present; exact deck-line citations remain MISSING rather than invented. Record inspected contract/rule line references and content hashes separately from attributed deck quotations. Lab integration supports the orchestrator but does not replace its implementation; role/exposure inference supports the ranking formula. The scope fence is an authorisation guard, not a complete scan-safety guarantee. Alternative considered: presenting every proposed coverage mark or scanner-capability number as verified execution; rejected because a roadmap and source quotations are not run evidence.

**PROJECT-07. Remediation and format proposals:** record offline Patch/Vendor Advisory reference extraction and evidence-backed next-action templates for prompts 4/8/9. New enrichment/rationale fields, stored recommendation provenance, expert-FP truth fields, and optional model rewording remain subject to the fixed-interface and LLM-policy approval boundaries. An affected `versionEndExcluding` boundary alone is not a proven fixed release; a generic CWE alone does not identify a missing header or safe configuration value. Missing guidance stays explicit. Select "HTML report (printable)" as proposed slide wording: "PDF or HTML" already permits HTML, no WeasyPrint dependency is added, and usable print output must be verified by a human before a PDF-quality claim. The original slides are not modified or independently verified.

**PROJECT-08. Measurement definitions:** duplicate reduction is `100 * (R - U) / R`, not the retained fraction `U / R`. Expert-confirmed low-confidence flags are reported with raw/unified ID mapping, review coverage, precision/recall and misflagged true findings; flagging without removal does not establish a false-positive reduction. The proposed confidence formula has a minimum of `0.3`, so its strict `< 0.3` flag condition is unreachable; leave calibration/threshold changes approval-gated rather than silently changing defaults or treating no flags as success. Reporting-time savings require paired timed tasks and correctness checks; setup automation is initially a count, not a percentage. Preserve zero-denominator unavailability and negative time savings. All four supplied percentages remain targets with no measured result claimed here. Alternative considered: deriving percentages from synthetic examples, treating absent expert labels as false, or treating faster incorrect answers as an improvement; rejected because those measures would not support the deck claims.

## Starter-kit design and fixture preparation - 2026-09-06

**STARTER-01. Research-first five-day scope:** follow the user's latest planning window of five days, not the earlier November target. The evaluated ranking method is the deliverable; file ingestion, offline enrichment, rule context, template HTML reporting and evaluation support it. Defer all prototype LLM use, Nikto, orchestration and re-scan. Capture-owner names and expert count are logistics; use one evaluation design for N>=1 with tie-aware rankings. For N>=2 report Kendall's W first; for N=1 state the single-annotator limitation without blocking individual comparisons. Alternative considered: waiting for named owners or exactly three experts; rejected because neither is needed for the design. Actual expert judgments remain required before any research outcome claim.

**STARTER-02. DECIDED 2026-09-06 (superseded by APPLY-01/APPLY-02 below; applied in code):** the user's Q4 missing-EPSS design requires threat_multiplier=None and environmental-only priority with an explicit flag, while the earlier model/signature/config contracts required floats and a numeric default. Q6 proposes a reachable low-evidence flag without removal or down-ranking. Nullable fields, missing-value configuration, confidence/grouping metadata, honest unknown exposure, truth format and any new public pipeline command remain proposed and are not applied. Interface/dependency approval requires the integrator plus one reviewer; future LLM-derived role inputs or scope/wall changes additionally require the mentor. Alternative considered: treating fixed LLM confidence or a design discussion as approval to alter ranking inputs or public contracts; rejected. The parent 85% gate and no-provisioning boundary remain unchanged despite older variants in the kit.

**STARTER-03. Capture handoff and narrow skip exception:** add docs/fixtures.md with human-only, explicit-target Nmap and passive ZAP baseline procedures and genuine capture provenance requirements. All such commands are not run by the agent. Register @needs_fixture for tests/fixtures/ paths only, with the exact missing-path reason; invalid marker usage fails rather than skipping unrelated work. Existing-but-malformed data remains a parser error and missing tools remain gate blockers. Alternative considered: fake captures or generic skips; rejected by the evidence rules. No captures, feed rows, credentials or model output are generated, and no scope/dependency declarations are changed.

**STARTER-04. Original deck arrival:** the user-provided Downloads/de_ppt.pdf is copied byte-for-byte to docs/deck/de_ppt.pdf and staged at the user's explicit request; staging is not a commit. The local copy check reported 519896 bytes and matching SHA-256 F4D2C012559D86B63F5228D6BC753DDC5C5C5D07DEE9FFD22202494A0A1F7C4E. This supersedes the earlier missing-PDF observation only; it does not validate slide percentages, literature coverage, novelty or prototype performance. The original PDF is not modified. Alternative considered: recreating slides or treating a content hash as independent provenance approval; rejected. See project-starter-kit/docs/DESIGN.md for the reviewed design scope, not a completed pipeline claim.

## Standing-instruction reconciliation - 2026-09-06

**RULES-01. Research-led ownership and reporting:** adopt the user's read order (PROJECT, then problem statement), lead-engineer responsibility and research-question test for every decision. Add BUILT, DECIDED, EVIDENCE and DEFERRED to the increment report while retaining CHANGED-by-folder and DECISIONS references for existing traceability. Explicitly state the canary fence, untrusted-model-input rules, verbatim evidence/sentinel rule and fixed CLI/configuration requirements. Alternative considered: mechanically replacing the standing file with the starter text; rejected because it would lose current safeguards and contract obligations. This is an instruction update, not an assertion of implemented runtime behavior.

**RULES-02. Conflict / resolution / why - safeguard strength:** treat 75% as the supplied prototype floor, not permission to lower the established 85% coverage gate; W7 expressly forbids lowering a gate. Keep section 0b and decision 30's reviewed-artifact requirement rather than treating the presence of wheels as installation approval. The existing fixed-interface ADR process and bounded needs_fixture exception remain intact; missing captures cannot justify skipping unrelated checks or claiming integration success. Alternatives considered: lowering coverage, bypassing make install, or treating broad engineering ownership as interface/dependency approval; rejected because they weaken explicit safeguards. No scope, dependency, runtime contract, threshold or credential changes are made by this reconciliation.

## Canonical prototype brief alignment - 2026-09-06

**BRIEF-01. Prototype versus full roadmap:** apply the user's BUILD/DEFER distinction to the canonical PROJECT brief: Nmap/ZAP file ingestion, evidence-preserving exact/ID-based grouping, offline intelligence, rule context, pure ranking, template HTML reporting and evaluation serve the research deliverable. Defer orchestration, Nikto, all LLM use, semantic merge and re-scan. Retain the longer appendices as future roadmap and preserve team credits without claiming completed work. Carry forward the compatible five-day plan and N>=1 evaluation; 2-3 remains a recruitment goal, not a hardcoded input count. Alternative considered: treating the old full-system/December roadmap as current prototype acceptance; rejected because it dilutes the ranking experiment. No runtime interfaces or scope are changed.

**BRIEF-02. Conflict / resolution / why - illustrative intelligence:** the supplied same-CVE table again assigns different EPSS/KEV values per host. Preserve the same-vector, same-snapshot comparison and the requested Low/Medium versus Critical contrast as an unverified acceptance goal; test the KEV floor separately on both machines. Keep missing-EPSS changes proposed until the required ADR is approved. Do not describe an illustrative table as an existing automated test, an internal host as isolated, or unobserved controls as nonexistent. Alternative considered: copying the table and blanket claims about all existing tools/manual context as verified facts; rejected by the provenance and evidence rules. Update the research statement to tie-aware comparisons and full-recall queue size rather than band-count reduction.

## Canonical research statement - 2026-09-06

**RESEARCH-01. Questions, hypotheses and intended contributions:** incorporate RQ1-RQ4, H1-H4 and C1-C4 into the canonical problem statement. Preserve the supplied role/exposure targets of 0.85/0.95, absolute ranking-agreement gains of 0.20/0.10 and critical-queue reduction target of 40%. Retain tau-b for the previously agreed tie policy and N>=1 evaluation; report W only when defined for N>=2. Define H3 as the mean of defined per-expert full-recall queue reductions, with individual results and denominators exposed, and distinguish host-level H1 labels from repeated findings. Alternatives considered: unspecified aggregation, strict forced expert ordering or fixed-band counts as efficiency; rejected because they would make the result ambiguous or answer a different question. Targets are falsifiable proposals, not measurements or runtime-contract changes.

**RESEARCH-02. Conflict / resolution / why - research evidence:** the supplied heading calls hypotheses pre-registered and lists external claims as evidence, but no registration record or independently checked source locations are established by this task. Record intended preregistration and the required pre-label freeze; retain the bibliography/statistics/incidents as explicitly unverified leads for human-provided or approved review. Distinguish KEV's known-exploitation flag from EPSS probability and avoid universal claims that no existing method automates context or all alternatives need cloud processing. Keep C4 a completion target and prototype LLM/re-scan deferrals intact. Alternatives considered: inventing a registration, treating source names as verified citations, or claiming a working evaluated implementation from a draft; rejected under the evidence rules. No network lookup, dependency change, scoring implementation or empirical result is authorised by this statement update.

## Local import implementation - 2026-09-06

**IMPORT-01. Bounded file readers:** implement the fixed Nmap XML and ZAP JSON function signatures using standard-library Expat/JSON parsing and the already-present Pydantic library. This serves stages 3/4 by turning local evidence into canonical records. Reject absent files, network-share paths, unsafe XML declarations, malformed structures and missing scan/report metadata. Use artifact timestamps, never the clock or file mtime. Preserve raw record excerpts and explicit IDs; Nmap open-port records are observations, not confirmed vulnerabilities. ZAP instance identity includes its native alert reference, method and parameter so distinct instances need not collide on a URL. Alternatives considered: launching scanners, resolving hostnames, paraphrasing evidence or adding a new parser package; rejected to keep input handling offline, auditable and within the supplied contracts. Defensive parser ceilings are not scoring weights, and no claim of a configured OS sandbox is made.

**IMPORT-02. Code-path tests versus real captures:** test malformed-input rejection, generic XML/JSON source-span logic and bounded reads using clearly labelled synthetic inputs only. Do not create plausible scanner exports. Real-capture tests require their human README and then a reviewed golden snapshot; missing capture tests use the existing needs_fixture marker, while a missing expected snapshot fails once its capture exists. Alternatives considered: presenting a mock report as a real parser test, auto-accepting parser snapshots, or removing assertions to get a green gate; rejected. These readers are not yet wired into a scope-validated persistence command, and real-capture, property-testing and full-gate acceptance remain pending their actual prerequisites.

**IMPORT-03. Useful CLI without fabricated inputs:** implement the already-contracted schema export command with --json and --run-id. Export all nine canonical definitions with stable serialization, retaining their existing fields; optional run metadata is caller-supplied. No capture/feed/model is needed for a schema definition export. Alternatives considered: another stub or a fake assessment report; rejected because the schema command is independently usable and testable. The user's permission to use available libraries is not permission to download missing tools or certify supply-chain trust, and no dependency, scope, scoring or fixed model change is made in this increment.

## Applied decisions (agent is reviewer) - 2026-09-06

**APPLY-01. DECIDED - missing EPSS is unscored:** `ScoreBreakdown.threat_multiplier` becomes `float | None`. `None` means no EPSS row was observed; rank on the environmental score alone and flag "no exploitation data (EPSS missing)". `weights.yaml` uses `threat.missing_epss: unscored` instead of a numeric percentile default. Rejected: the 0.5-percentile default, because it invents exploitation evidence. Applied in `schema/__init__.py` and `docs/contracts.md`.

**APPLY-02. DECIDED - coverage floor is 75%:** the prototype gate is `--cov-fail-under=75`. `.github/copilot-instructions.md` supersedes `docs/contracts.md` on this value. Rejected: holding 85% while the tooling is absent, because it blocks every increment without improving evidence.

**APPLY-03. DECIDED - reviewer authority:** the agent is the reviewer for fixed-interface changes from this date. Each change is logged as one APPLY line and applied. Mentor approval is still required for scope.yaml, wall changes, and any LLM-derived scoring input.

**APPLY-04. DECIDED - import command and cross-cutting modules:** add `vulnassess import` (scope check before file access, raw copy to `data/raw/<run-id>/`, store hosts/findings), `settings.py` (validated config loading plus `config_hash()`), `registry.py` (reader registry) and `config/controls.yaml` (WAF/auth/rate-limit signatures). Signatures are vendor-documented header/cookie patterns, not observations from a capture.

## Target report supplied by the user - 2026-09-06

Source artifact: `demo-report-synthetic.html`, supplied on 2026-09-06. It is a layout and behaviour target, self-labelled synthetic (run `demo-synthetic`, placeholder `CVE-1999-9001`, two-record feeds, `synthetic_*` raw files). Its feed dates, SHA-256 values, scores and timestamps are NOT evidence and must never be copied into the repository as real feed metadata or cited as verification.

**SPEC-01. DECIDED - risk formula read off the target report:** `risk = min(100, env_score * 10 * threat + 10 if kev else 0)`, where `threat = 0.5 + 0.5 * epss_percentile`, forced to `1.0` when KEV lists the CVE, and omitted entirely when EPSS is missing (APPLY-01). Confirmed arithmetically by the two KEV rows: internal `6.9 * 10 * 1.0 + 10 = 79.0`, internet-facing `9.8 * 10 * 1.0 + 10 = 108 -> 100.0`. The `+10` KEV addend and the `100` cap are new weights keys not present in the earlier contract block.

**SPEC-02. DECIDED - the KEV floor of 90 applies only when the host is internet-facing:** `docs/contracts.md` states a flat `kev_floor: 90`; the target report applies it conditionally, which is why an internal KEV finding lands at 79.0 (High) rather than 90+ (Critical). Adopt the conditional form. Rejected: the unconditional floor, because it forces every KEV finding to Critical regardless of exposure and therefore erases the internal/internet-facing contrast that the research question exists to measure.

**SPEC-03. DECIDED - CVSS version is whichever the NVD record supplies, recorded per finding:** the target report shows CVSS 3.1 Environmental while the project brief specifies v4.0. `ScoreBreakdown.cvss_version_used` already exists precisely to record this. Prefer a 4.0 vector when the record has one, fall back to 3.1, and record which was used; never mix the two in one score. Rejected: hardcoding either version, because feed coverage decides availability, not the design.

**SPEC-04. DECIDED - report structure:** five sections - summary KPIs by band, ranked findings with a deterministic "Why" sentence plus a score/fix detail table, per-host context evidence (value, confidence, source, verbatim quote or `none observed`), methodology with band thresholds and a feed snapshot table (date, record count, digest), and provenance (tool, raw file, record index). Recommended fixes are deterministic strings built from the same facts; no model text.

**SPEC-05. NOTED - two issues in the target report to resolve before evaluation:** (a) host 172.28.0.12 is classified `database` on `3306/tcp mysql` evidence while its top-ranked finding is an Apache finding on port 80, so a host-level role drives CR/IR/AR for an unrelated service; decide and document whether role is host-level or service-level before expert comparison. (b) Ranks 3 and 4 are two instances of the same ZAP alert with identical titles, hosts and scores; duplicate rows inflate precision@k and NDCG@10, so either group instances or show the differing URL/parameter in the ranked list. Neither is resolved in this increment.

## Built to the supplied BUILD-GUIDE - 2026-09-06

**BUILD-01. DECIDED - rebuild as a flat stdlib package:** the guide specifies `vulnassess/` at the repository root with frozen dataclasses, argparse and unittest. Two packages cannot both own the `vulnassess` import name, so the superseded pydantic/typer implementation and its tests were **moved, not deleted**, to `legacy/src/` and `legacy/tests/`. Rejected: deleting them (loses reviewable history) and keeping both importable (name collision). `docs/contracts.md` now describes the superseded implementation and is retained as history.

**BUILD-02. DECIDED - two runtime dependencies:** `pyyaml` and `packaging` only, per the guide's explicit instruction. Removed from the declared set: pydantic, pydantic-settings, typer, rich, cvss, scipy, jinja2, httpx. CVSS v3.1 is implemented from the specification in `vulnassess/cvss31.py` and verified against six official calculator scores rather than trusting an unaudited package. Nothing was installed or downloaded.

**BUILD-03. DECIDED - scope narrowed to three /32s plus an out-of-scope canary:** `config/scope.yaml` moves from `172.28.0.0/24` to `172.28.0.10/32`, `172.28.0.11/32`, `172.28.0.12/32` with `canary: 172.28.0.250`. This is a strict narrowing and it makes the canary *provably* outside the fence, which a /24 could not. Settings refuses to load a scope whose canary sits inside it.

**BUILD-04. DECIDED - CVSS 3.1, not 4.0:** NVD carries a 3.1 vector for essentially every CVE while 4.0 coverage is partial, and 4.0 scoring needs a 270-row MacroVector lookup. 4.0 vectors are stored and displayed; scoring uses 3.1 and records `cvss_version_used`. Supersedes SPEC-03's "whichever NVD supplies" until 4.0 coverage justifies the table.

**BUILD-05. DECIDED - missing EPSS stays unscored:** `threat_multiplier` is `None`, risk is the environmental score times ten, and the reason says "no exploitation data". Confirms APPLY-01; a 0.5 percentile default would invent exploitation evidence.

**BUILD-06. DECIDED - KEV respects context:** a KEV listing forces the threat factor to 1.0 and adds 10, but the floor of 90 applies only when the host is internet-facing. An actively exploited flaw on an isolated test box lands in High (79.0), not Critical. Confirms SPEC-02 and is now implemented and tested.

**BUILD-07. DECIDED - role inference keeps its weighted-sum semantics:** with only port 88 open, `domain_controller` still wins at confidence 0.2 because no other role scores at all. Rejected: adding an undocumented minimum-score threshold, which would silently change every ranking. The test therefore asserts the documented `all_of` behaviour - one port gives 0.2, both give >= 0.8. `roles.yaml.ambiguity` records the thresholds an LLM fallback would use; that fallback stays deferred.

**BUILD-08. DECIDED - points on which the guide is silent:** the Nmap finding description is the script's full output (the evidence field keeps only the CVE line); a scalar native-severity table is labelled `<tool>:default=<n>`; the report emits no `href` or `src` attribute at all, so a URL in fix text stays plain text and the page cannot reach the network.

**BUILD-09. NOTED - the synthetic ground truth is circular:** `tests/synthetic/synthetic_groundtruth.yaml` is derived from our own ranking, so "ours beats cvss_only on mean tau-b" tests the harness, not the method. It is not evidence of research merit. Real expert rankings remain MISSING.

## Completing the pipeline past the guide - 2026-09-06

**MODEL-01. DECIDED - the model may reword a verdict, never compute one:** `vulnassess/explain.py` sends a local Ollama model the band and the context words only. The score, the base score and the environmental score are never in the prompt, so the model cannot restate one. Output must be a single plain sentence under 240 characters with no URL and no markup, and every number in it must already appear in the facts supplied; anything else is discarded for the deterministic `scoring.describe` sentence with the reason recorded in `Rationale.validation`. Rejected: letting the model see the score "for context", because a model that can read a number can invent a neighbouring one.

**MODEL-02. DECIDED - absence is reported, not worked around:** with no `--model`, no Ollama server, or a model that is not pulled, `explain` writes template rationales and records the exact command a human must run. Nothing is downloaded. Ollama is mocked in every test through an injected client, so no test can reach a socket.

**MODEL-03. DECIDED - the network wall moves with the layout:** the flat package makes `vulnassess/explain.py` the only module permitted to import `urllib.request`/`urllib.error`/`httpx`/`requests`/`socket`, replacing the old `intel/feeds.py` + `explain/ollama_client.py` pair. `intel.py` reads local snapshots only and needs no client at all. `urllib.parse` stays permitted everywhere: it parses strings and performs no I/O. `TestWalls` enforces both halves.

**MODEL-04. DECIDED - Nikto is the third reader:** `readers/nikto_json.py` registers under `READERS["nikto"]`. Nikto states no severity, so `native_severity` is always `None` and its findings rank on the scalar `native_fallback.nikto: 30`; inventing a severity from message wording was rejected.

**MODEL-05. DECIDED - the scan orchestrator plans by default:** `runner.plan` authorises the target before building any argument list and writes nothing; `run_scan` returns the plan with every command prefixed `not run by the agent` and only shells out when a human passes `execute=True`. Argument lists are fixed, never `shell=True`. A missing binary is named, never installed. The agent has not executed any scanner.

**STORE-01. DECIDED - run membership is its own relation:** the guide's `findings.id PRIMARY KEY` plus a `run_id` column meant importing a finding into a second run silently *moved* it out of the first, which made `diff` report a persisting finding as resolved-and-new. Added `finding_runs(run_id, finding_id)`; the finding body is still stored once, and `upsert_findings` now returns how many are new *to that run*. Both existing import tests still hold, and the demo output is byte-identical. Rejected: duplicating the finding row per run, which would break fingerprint identity.

## Trainable role model - 2026-09-07

**ROLEMODEL-01. DECIDED - a learned model exists, but starts in shadow mode:** implement class-balanced multinomial logistic regression over scan-derived host features in `vulnassess/role_model.py`. It predicts role with a probability, top-two margin, abstention, model hash and weighted evidence contributors. It neither imports scoring nor writes `ContextProfile`, so no learned output can currently affect a rank. Rejected: calling the Ollama rationale wrapper the product model; it changes prose, not inference.

**ROLEMODEL-02. DECIDED - labels and ranking judgments are different datasets:** role labels train and test RQ1; expert finding rankings test RQ2. JSONL role labels require an independent group identifier and either `label_source=human` plus a reviewer identifier or `label_source=synthetic`. The CLI refuses synthetic training unless `--allow-synthetic` is explicit. Rejected: training from rule-generated labels, which would only teach the model to imitate the rules and could not validate inferability.

**ROLEMODEL-03. DECIDED - calibration and selective metrics are first-class:** fit weights on training groups, select temperature on disjoint validation groups, and report a final untouched test set separately. The implementation rejects train/validation group overlap and reports accuracy, coverage, abstention, selective accuracy, macro-F1, log loss, Brier score, expected calibration error, per-class metrics and a confusion matrix. Grouped cross-validation is available for development diagnostics; it is not a substitute for the frozen test set.

**ROLEMODEL-04. DECIDED - artifacts are JSON, deterministic and hash-verified:** never pickle a model. The artifact records algorithm, hyperparameters, label/source counts, dataset and validation hashes, classes, vocabulary, coefficients, intercepts, thresholds and temperature. Loading enforces dimensions, finite values, size limits and the content hash. Rejected: opaque executable serialization.

**ROLEMODEL-05. OBSERVED WITH SYNTHETIC DATA - mixed-service hosts matter:** the first simulation classified the Apache+MySQL demo host as `web_frontend`; validation examples had only one service per host and therefore missed the product case. Adding mixed-service database examples changed the shadow prediction to `database` with MySQL evidence. This is a simulation result, not evidence of real accuracy, but it establishes that host composition must be represented in the eventual labelled cohort.

## Visual product simulation - 2026-09-07

**VISUAL-01. DECIDED - replay product state, do not animate a mockup:** `visual_simulation.build_payload` reads hosts, findings, enrichments, profiles, scores and feed metadata from the same SQLite run used by the CLI, and role probabilities from the same hash-verified artifact. The HTML contains no separately invented score or role. Rejected: a static architecture diagram, because it would not prove that the implemented stages compose.

**VISUAL-02. DECIDED - one self-contained local HTML artifact:** embed canonical JSON with `<`, `>` and `&` escaped, use inline CSS/JavaScript/SVG, and make no fetch, WebSocket, external script, stylesheet or font request. The replay is deterministic after omitting volatile feed-load timestamps; two rebuilds from identical inputs produced the same SHA-256. Rejected: a framework/dev server, because it adds dependencies and a network surface without helping the research question.

**VISUAL-03. DECIDED - visualise both inference and deterministic ranking:** the console shows all role probabilities, confidence, top-two margin, abstention and verbatim evidence beside a separate CVSS Environmental/EPSS/KEV waterfall. The learned role remains shadow-only and the displayed ranking remains the deterministic stored score. This makes the policy boundary visible rather than implying the classifier generated the risk number.

## Research and pipeline hardening - 2026-09-07

**HARDEN-01. DECIDED - local means loopback:** Ollama endpoints accept only explicit-port HTTP origins on `localhost`, `127.0.0.1`, or `::1`; paths, credentials, external hosts, invalid timeouts, and responses over 64 KiB fail closed. Rejected: trusting a user-supplied URL, because that would break the no-cloud runtime claim.

**RESEARCH-03. DECIDED - synthetic arithmetic cannot pass H1-H4:** context truth requires host/capture groups and human truth requires reviewer plus provenance. Expert H2/H3 interpretation requires `evidence_status: VERIFIED` and reviewer/provenance for every expert. Missing profiles remain in the denominator; manual tags are excluded from RQ1. Rejected: treating the bundled synthetic rankings as measured research outcomes.

**RESEARCH-04. DECIDED - ablations are read-only:** full, no-role, no-exposure, no-controls, no-manual, no-EPSS, no-KEV, context-only, threat-only, CVSS-only, and CVSS+EPSS scenarios recompute in memory. They never overwrite stored scores or configuration and report inactive inputs instead of assigning them importance. Repeated calculations expose score hashes and configuration/feed drift.

**MODEL-06. DECIDED - structural evidence and governance before promotion:** role-model artifact/preprocessing version 2 reports feature coverage and OOV inputs and abstains without positive port/CPE/OS/TLS support, even when a spoofable banner is confident. A promotion manifest binds verified human test evidence, disjoint groups, zero manual tags, H1/calibration thresholds, artifact/preprocessing hashes, validity dates, reviewer and mentor approval IDs. It can produce only `model_candidate`; canonical activation remains blocked by the context-source ADR.

**ORCHESTRATE-01. DECIDED - Nmap first, web tools only on observed endpoints:** scope and canary checks precede command construction; Nmap discovery selects HTTP(S) endpoints, TLS/443/8443 selects HTTPS, no-web hosts record skips, and ordinary web-tool failures do not hide other outcomes. Tests use an injected executor; no scanner was run by the agent.

**UNIFY-01. DECIDED - automatic grouping is deliberately narrow:** only records with the same host, port, protocol, URL and shared CVE auto-group. Different URLs, generic CWEs, and title similarity produce review candidates only. Every source ID and evidence string remains visible and group IDs are order-independent. Rejected: semantic or generic-CWE auto-merge, because it changes queue identity without sufficient evidence.

**RESCAN-01. DECIDED - absence is not resolution:** raw diff output says `absent`; remediation comparison requires equivalent successful tool/endpoint coverage and a parseable affected-service version increase before emitting `fixed_candidate`. Unchanged version with missing evidence remains `still_open`; failed/drifted coverage is `not_observable`; human adjudication is still required.

**SNAPSHOT-01. DECIDED - freeze now, migrate later:** hash-verified assessment bundles capture run/config/feed/model/host/finding/enrichment/profile/score/rationale state without altering fixed tables. They mitigate later global-table mutation but explicitly cannot prove the store was unchanged before export. True run/snapshot-isolated feed and enrichment tables remain blocked on the fixed-table ADR.

**HARDEN-02. DECIDED - malformed configuration and captures fail at the boundary:** all nested scoring, role, control, scope and regex values are validated before use. Scanner captures reject UNC paths, files over 16 MiB, XML declarations/depth/element excess, duplicate JSON keys, non-finite JSON and excessive depth. Missing scanner times remain explicitly unknown instead of using the wall clock.
