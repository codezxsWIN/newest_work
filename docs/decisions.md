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

**STARTER-04. Original deck arrival:** the user-provided Downloads/de_ppt.pdf is copied byte-for-byte to docs/deck/de_ppt.pdf and staged at the user's explicit request; staging is not a commit. The local copy check reported 519896 bytes and matching SHA-256 F4D2C012559D86B63F5228D6BC753DDC5C5C5D07DEE9FFD22202494A0A1F7C4E. This supersedes the earlier missing-PDF observation only; it does not validate slide percentages, literature coverage, novelty or prototype performance. The original PDF is not modified. Alternative considered: recreating slides or treating a content hash as independent provenance approval; rejected. See DESIGN.md (moved from the starter kit) for the reviewed design scope, not a completed pipeline claim.

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

**FIXTURE-02. DECIDED - example filenames cannot satisfy real-capture gates:** files beginning `EXAMPLE-`, `synthetic_`, or `synthetic-` are excluded from real Nmap/ZAP fixture discovery even when placed under `tests/fixtures/`. Rejected: relying only on the parent directory, because the pulled `EXAMPLE-synthetic-*` files would turn missing human captures into false integration passes.

**RESEARCH-05. DECIDED - expert cohorts are blind and snapshot-bound:** cohort evidence contains stable raw finding IDs, scanner/host evidence and provenance, but excludes system scores, bands, ranks, reasons, inferred context and model predictions. The manifest binds the complete assessment snapshot, aggregate configuration, weights, feed state, model artifact, each evidence item, raw self-grouping map, metric definitions and tie policy. A `VERIFIED` confirmatory cohort requires 20-50 findings, reviewer and approval ID; expert rankings must cover exactly the frozen IDs. Raw mode remains mandatory until unification precision and its interface are approved. Rejected: exporting from mutable live tables or letting non-cohort findings enter NDCG/queue metrics, because either can change the experiment after labels are collected.

**RESEARCH-06. DECIDED - public research commands rebuild before comparing:** additive `research` commands expose snapshot/cohort export and verification, RQ1 context evaluation, cohort-filtered RQ2/RQ3 evaluation, RQ4 ablations and repeated-score stability. Ranking and expert ablation refuse a live store whose complete snapshot hash differs from the frozen manifest. Rejected: accepting a matching run ID alone, because global feed/enrichment changes can preserve the ID while changing the evaluated method.

**OPERATIONS-01. DECIDED - new operational surfaces are non-mutating previews:** unification publishes deterministic raw-to-group mappings while downstream ranking stays raw; model promotion can validate an attestation and emit shadow hybrid recommendations but cannot write context; re-scan accepts size-limited hash-verified observation artifacts and emits only `fixed_candidate` pending human adjudication. No table layout or scoring input changed. Rejected: persisting inferred groups, learned roles or remediation states without the required fixed-interface ADR.

**ORCHESTRATE-02. DECIDED - the public scan command uses the Nmap-first engine:** `scan` now requires a run ID, plans only mandatory Nmap discovery, defers Nikto/ZAP until observed HTTP(S) endpoints, checks binaries without installing them, records before/after canary evidence and can write a hash-bound summary. `--execute` remains an explicit human-only action, uses fixed argument arrays with `shell=False`, and prints `not run by the agent`; agent verification used injected executors only. Rejected: the previous simultaneous all-tools plan, because it invented web endpoints before discovery and could not support comparable coverage records.

**AUDIT-01. DECIDED - reports expose evidence gaps instead of hiding them:** generated artifacts use only `VERIFIED`, `TESTED WITH MOCKS`, `NOT RUN`, or `MISSING`; synthetic data kind is recorded separately and cannot establish H1-H4. The report accepts only run-matched, hash-verified, bounded JSON attachments and shows missing snapshot/cohort/scan/evaluation/ablation/stability/re-scan/model inputs explicitly. It also computes read-only intelligence traces and conservative unification mappings, preserving escaped offline HTML. Rejected: attaching arbitrary JSON or calling synthetic arithmetic `TESTED WITH SYNTHETIC`, because neither meets the evidence ladder.

**VISUAL-03. DECIDED - the replay is a stage-owned investigation workbench:** replace the always-visible topology, event stream and decorative packet motion with one active transformation at a time. Each stage now exposes its actual input, deterministic decision and output; tables use canonical IDs, raw provenance, enrichment confidence, model contributors/OOV state, context evidence, vectors, threat arithmetic and CVSS-only rank movement from the generated payload. A persistent inspector and six-step finding trace preserve identity across stages. Rejected: polishing the original graph, because its stage control changed opacity rather than the information being inspected and therefore did not demonstrate the pipeline.

## Read-only interface, phase 1 - 2026-09-09

**UI-01. DECIDED - a viewer for Stage 7, not another assessment pipeline:** this increment serves PROJECT.md Stage 7 (Report) and cross-cutting ranking/evaluation auditability for RQ2-RQ4. Read stored JSON through a separate SQLite connection opened with `uri=True` and `mode=ro`; do not construct the existing writable `Store`, run scoring, or change tables. Expose unavailable stored evaluation, diff or refusal records explicitly instead of calculating replacements or inventing empty history. Alternatives: reuse `Store.__init__`, which runs DDL and commits, or rebuild scores for display; rejected under U2/U4/U5. The inspected local `verify` run references synthetic feed inputs; its existence is not real scanner or feed verification.

**UI-ADR-01. PROPOSED - one additive public command, awaiting human approval:** add `python -m vulnassess ui [--run ID | --run-id ID] [--port 8765] [--db PATH] [--config PATH] [--json]`. Bind only the literal IPv4 address `127.0.0.1`; print the URL, serve read-only JSON/static content, and shut down on Ctrl-C. Preserve all existing commands, models, exits, configuration schemas and tables. The export option belongs to a later phase and is not built now. Conflict / resolution / why: the new prompt requests `ui`, but the standing rule requires a human-approved ADR; request approval of this recorded command before wiring it into the CLI. APPLY-03's older agent-reviewer statement is not treated as current human approval.

**UI-ADR-02. PROPOSED - loopback verification without network in tests, awaiting human approval:** keep unittest HTTP checks on injected in-memory request/response streams with socket use forbidden. Supplement them with `python scripts/check_ui_server.py`, a separate local smoke check that starts the viewer on an ephemeral `127.0.0.1` port, requests `/` and `/api/runs`, and shuts it down. This script is not run until the human approves these loopback-only requests. Conflict / resolution / why: G1 asks a unittest to open a socket, while I4 prohibits network in tests; the smallest alternative is a clearly distinguished live smoke script, not weakening I4 or claiming mocks prove a listening server. No scanner, feed or model endpoint may be contacted.

**UI-ADR-03. HUMAN APPROVAL - UI-ADR-01 and UI-ADR-02:** on 2026-09-09 the user explicitly selected "Approve UI-ADR-01" and "Approve UI-ADR-02" in the approval questions. Implement the recorded additive command and the separate loopback-only smoke check. Socket-free unittests remain mandatory. No other wall or fixed interface is changed by these approvals.

**UI-02. DECIDED - name and phase boundary:** choose Doors, with the promise "Same weakness, different urgency, and the clue behind every decision." Use only an unstyled entry page in phase 1. Defer the metaphor drawings, tokens, analyst screens, export and screenshots to the requested later phases. Rejected: expanding the existing visual simulation now, because this increment establishes a separately inspectable, stored-number-only read boundary before any visual design. No dependency was added or removed.

**UI-03. DECIDED - unavailable is not zero or an empty history:** the phase-1 JSON contract includes all requested routes, but evaluation and diff return HTTP 409 with `status: MISSING`, `records: null` and a reason when the corresponding persisted result is unavailable. Refusals use the same envelope inside the run response until G40. Current global feed metadata is explicitly labelled `current_store_not_frozen_per_run`; stored score JSON stays authoritative and is never recomputed against mutable enrichment rows. Rejected: call existing evaluation/diff routines or imply current feed metadata is historical, because U4 forbids new metrics and neither claim is supported by these tables. `docs/ui-contract.md` documents the field-level contract and these limitations.

**UI-04. DECIDED - test discovery and local evidence:** add `tests/__init__.py` so the requested `python -m unittest -v` discovers the repository suite rather than depending on namespace-package resolution. UI contract tests read the existing `verify` demo without invoking parsers or loading feeds; missing demo inputs fail with an explicit path instead of creating substitute data. Rejected: regenerate synthetic captures or relax fixture gates. The approved separate smoke script checks actual loopback HTTP and database-byte preservation; handler unit tests remain labelled mock verification.

## Interface identity, phase 2 - 2026-09-09

**UI-05. HUMAN DIRECTION - bounded behavioural acceptance while tools are missing:** the user accepted phase 1 and instructed that, until human-provisioned Ruff, Pyright and pytest-cov exist, UI-phase acceptance means all named phase tests pass, `python -m unittest -v` ends `OK (skipped=2)`, and `python scripts/check_ui_server.py` passes. Keep the quality gate labelled MISSING. Conflict / resolution / why: the standing full-gate acceptance requirement is not represented as satisfied; this explicit temporary UI acceptance criterion permits progress without provisioning packages, weakening assertions or changing the coverage floor. The known visual-simulation file-write flake remains outside UI scope; a recurrence is reported with its traceback, not repaired here.

**UI-06. DECIDED - G10 before G11 before G9:** phase 2 serves PROJECT.md Stage 7 (Report) and evidence auditability for the context/ranking research. Centralize paper/ink surfaces, severity colours, spacing and typography in `tokens.css`. Generate reference, protanopia and deuteranopia swatches locally with standard-library Python using full-severity linear-sRGB Machado matrices and D65 CIELAB distances. Require text contrast of at least 4.5:1 and pairwise severity distance of at least 15 in each simulation; the distance is a local design guard, not a universal accessibility standard. The first palette failed deuteranopia separation; darken Critical rather than lower the threshold. Rejected: downloaded swatches, a red/green-only distinction or colours without text labels. Simulation does not establish every person's perception.

**UI-07. DECIDED - one escaped evidence surface:** render the selected run on the existing entry route with system sans for inferred role/exposure and monospace `.evidence` blocks with source labels for recorded quotes, identifiers, banners, paths, hashes and vectors. Retain a collapsible source ledger containing every evidence string returned by the run API. Reuse the existing read-only reader and keep static styles external under CSP; no JS, recomputation, new API fields or pipeline edits. Rejected: hardcoded example records, client HTML interpolation or building the later stage screens. The G11 test retains its requested `TestUiExport` name but tests this shared entry markup; the one-file export command is still deferred.

**UI-08. DECIDED - role drawings do not assign risk:** use a shed for unknown, an office for web/application/mail/workstation, a vault for database/domain-controller/file-share and a cabinet for embedded/network-device roles. Context inference takes role labels from configuration, so coverage is checked against every configured and validated role. A test environment does not overwrite the stored role or change its silhouette. Each actual finding has its own door and stored band; a host gets no inferred aggregate severity. Unknown unmapped roles or bands fail explicitly. The legend is an asset key, not additional hosts or findings. Rejected: mapping test tags to a new role, inventing sample host rows or colouring buildings as risk aggregates. Local SVGs use simple currentColor strokes, a 240-unit building viewBox and a 48-unit door viewBox.

**UI-09. DECIDED - local capture failure stays visible:** the user authorized installed Edge headless screenshots. `scripts/capture_ui_phase2.py` attempts them with a disposable profile, disabled background services and external-name resolution blocked, targeting only an ephemeral loopback viewer. Edge returned zero without producing PNGs; report saved screenshots as NOT RUN, preserve no fake image and describe the page instead. Live integrated-browser inspection is separate from persisted screenshot evidence. Rejected: installing a browser/driver or claiming the absent PNGs exist. No later UI phase was started.

## Resumed model workbench - 2026-09-13

**UI-10. USER-DIRECTED - retain flow, replace the passive Doors concept:** the user rejected the Doors metaphor and required a UI that clearly explains the workflow and is connected to the actual model, so the model works through the UI. Preserve the original visual replay as a separate historical artifact. Build the live interface in the same `vulnassess/ui/` files, with explicit model execution rather than a timed replay. No building illustration or simulated progress establishes computation.

**UI-11. USER-DIRECTED BOUNDARY - explicit local inference, not learned scoring:** the latest request for model execution supersedes U2/U4 only for a user-triggered `POST /api/model/run` and its transient model outputs. The follow-up boundary question received delegated-autonomy text, not a selected approval; no broader approval is inferred. Run the existing hash-validated local `RoleModel.predict` on the selected run's stored hosts. Return predictions, extracted features, evidence, model/input hashes and actual execution timing. GET never invokes prediction. Require exact loopback Host, same Origin, JSON and an explicit action header; reject unknown fields, paths, oversized requests and concurrent execution. SQLite remains `mode=ro`; canonical context and scores are unchanged. No scan, feed fetch, retraining, Ollama call, new dependency or model promotion is authorized. The existing model's synthetic training provenance remains visible and cannot establish real-world accuracy. Rejected: rewording saved predictions as live, or letting learned roles change risk without the separate promotion approval.

## Reference-driven viewer boundary - 2026-09-13

**UI-12. USER-DIRECTED - restore U2/U4 and supersede UI-11:** the UI-UPGRADE-PROMPT explicitly rejects browser-triggered backend/model execution. Remove both model routes and the inference import from the viewer; all non-GET methods return 405, including previously valid same-origin model requests. Preserve the earlier runtime helper file without exposing it, and retain its isolated tests while adding stronger HTTP refusal checks. Scores, profiles and tables remain unchanged. Any future stored shadow prediction may appear only beside rule context, labelled "shadow - does not affect scores", never in risk or priorities. Conflict / resolution / why: the latest explicit read-only instruction overrides the earlier model-action direction; a claimed UI action is not authorization to recompute assessment results.

**UI-13. MISSING - reference parity input:** `doors-reference.html` was not present in the workspace when this increment began. Step 1 serves PROJECT.md Stage 7 (Report) and cross-cutting evidence auditability, but the visual port, export-text parity test and reference screenshots are blocked until the human supplies that exact file. Do not synthesize a replacement from the prompt, substitute `demo-report-synthetic.html` or the saved visual replay, copy claimed evaluation metrics into the store, or start later steps. Alternative: approximate the four-stage design from prose; rejected because the user made the actual file authoritative. Read-only boundary restoration is independent of the missing reference.

## Four-stage UI checkpoint - 2026-09-13

**UI-14. BUILD-NOW INTERPRETATION - implementation without a parity claim:** after the reference-file blocker was reported, the user again requested that the UI be built and continued the work. The direction question returned delegated-autonomy text, not a selected reference-parity approval. Build a working four-stage surface from the written direction in the same files; do not create a stand-in `doors-reference.html` or claim a comparison with an unseen file. Conflict / resolution / why: this proceeds with the user's build-now request while exact visual/text parity remains MISSING. Stage 7 and research auditability remain the purpose, rather than accumulating unrelated operational features.

**UI-15. IMPLEMENTED - written four-stage structure and requested CLI export:** use Evidence, Context, Risk and Priorities with one inspector and a six-step finding tour. System serif identifies headings/inferences, monospace identifies quoted evidence, and sans identifies labels. Keep colour literals in tokens, add a dark token set, and use the original local SVG assets. Implement the explicitly requested `ui --export PATH` as a CLI-only output, not an HTTP write path; bundle the same assessment JSON/styles/module code behind hash-based CSP with network connections disabled. All other pipeline commands, score models, tables and weights are unchanged. Alternatives: a parallel data model, client model execution, or copying the reference's evaluation placeholder; rejected under U2/U4/U5/U7. Retain older assets/helpers without loading their old layout.

**UI-16. DECIDED - browser arithmetic exists only in the sandbox:** port the repository's CVSS arithmetic and configuration-driven context/threat formula to a pure browser module. The banner permanently labels the result as hypothetical, with current configuration rather than reconstructed historical weights. Eleven fixed regression vectors plus 200 seeded valid vectors, and 144 context/threat combinations, are checked against Python. Synthetic arithmetic fixtures remain under `tests/synthetic/synthetic_*`, not real scanner-fixture folders. Missing EPSS stays explicit; sandbox inputs never overwrite stored scores. Rejected: approximate arithmetic, a numeric model output affecting rank, or reporting Python parity as independent model/scoring certification.

**UI-17. CHECKPOINT - stop and preserve the incomplete review state:** the user authorized pushing changes to `https://github.com/codezxsWIN/privwork` and continuing later. Save source, named tests, design/contract notes and local documentation captures on `audit-no-assumptions`; do not merge to main or commit environments, credentials, databases, raw artifacts or generated assessment reports. `docs/ui.md` records startup/export commands, pending exact reference parity and the tour-capture limitation. The full quality gate remains separate from the temporary UI behavioral gate. Browser tests found and fixed explicit Escape handling and Back/Forward inspector synchronization; the tour keeps already-visible targets in place. The saved Edge tour PNG remains an unaccepted capture, not a fabricated pass.

## Repository simplification and real-feed provisioning - 2026-09-17

**CLEANUP-01. DECIDED - remove the parallel narratives:** delete `legacy/` (the superseded pydantic/typer prototype), `project-starter-kit/` (a duplicate mini-repo including a paste-into-Copilot PROMPT.md), `PROJECT_PROVISIONING_COMPLETE.md` and `PROVISIONING_SUMMARY.md` (which claimed pip-installed feeds and tooling that the project charter forbids an agent from installing and that were never committed). Git history preserves all four for review, which supersedes BUILD-01's "moved, not deleted" rationale now that the repository itself is the history. `project-starter-kit/docs/DESIGN.md` is retained as `docs/DESIGN.md` because three documents cite it as the reviewed design scope. The three root-level guides moved into `docs/`. Alternative considered: keeping everything "for reference"; rejected because roughly half the repository volume was narrative about the project rather than the project, and the provisioning manifests contradicted DOWNLOADS_REQUIRED.txt written the same week.

**FEED-01. DECIDED - real public feed snapshots provisioned with recorded provenance:** at the repository owner's explicit instruction, real public feed snapshots were fetched by the agent on 2026-09-17 and placed under gitignored `data/feeds/`: the CISA KEV catalog JSON, the EPSS daily CSV (score date 2026-09-17), and a full NVD API 2.0 mirror (rate-limited paged fetch). Each artifact's URL, fetch date, SHA-256 and row count are recorded in `docs/FEED_PROVENANCE.md` and the local `data/feeds/PROVENANCE.md`. This narrows, but does not close, the evidence gap: feed data is now real, while scanner captures, host-context truth, expert rankings and model labels remain MISSING, so RQ1-RQ4 outcomes remain ineligible. No pip installation was performed; the supply-chain rule for code dependencies is unchanged.

**CI-01. DECIDED - enforce the quality gate in CI:** add a GitHub Actions workflow running the same stages as `make check` / `scripts/check.py` (Ruff lint, Ruff format, Pyright, pytest with the 75% coverage floor) on push and pull request, with dependencies pinned in the workflow. The gate was previously advisory and local-only, so nothing prevented regressions. Alternative considered: continuing with a local-only gate; rejected as unenforced.

**TEST-01. DECIDED - the UI contracts must not depend on author workspace state:** tests/test_ui.py required a gitignored `data/vulnassess.db` containing a run named "verify" that nothing in the repository could build; a fresh clone failed 18 tests. `setUpModule` now runs `run_demo.py`'s pipeline when the database is absent and inserts a "verify" runs-table row the way the contract test itself creates `synthetic_ui_other`. DEMO_RUN changes from "verify" to "demo"; the "verify" id remains a probe target for the eval/diff 409 contracts. Alternative considered: skipping UI tests on a fresh clone; rejected because it would report a green gate over untested contracts.

**FEED-02. DECIDED - a committed real-feed subset for reproducible integration tests:** `tests/fixtures/intel/` now holds a curated slice of genuine NVD API 2.0 records (CVE-2021-44228, CVE-2014-6271, CVE-2017-0143, fetched by cveId), the matching EPSS rows (score date 2026-09-17) and KEV entries, with hashes in tests/fixtures/intel/PROVENANCE.md. `tests/test_real_intel.py` proves the loader, matcher (explicit and CPE range over real configuration data) and scoring accept official formats inside CI, which cannot download full feeds. This narrows, but does not close, the parser-verification gap: it is still not scan evidence.

**DEMO-01. DECIDED - one-command real-feeds demonstration:** `run_real_demo.py` runs the pipeline against `data/feeds/` using `examples/real_lab_nmap.xml`, a hand-built lab capture whose hosts are invented but whose CVE evidence, EPSS scores and KEV listings are real; the file says so in its header. The demonstration output (Log4Shell on an internet-facing host ranks Critical at 100.0; Shellshock on an internal test host ranks High at 79.0) is an acceptance case over real enrichment data, not research evidence.

## Real local scan - 2026-09-17/18

**SCAN-01. DECIDED - reader accepts real Nmap output; entity risk stays fenced:** the first real execution of `vulnassess scan --execute` (Nmap 7.80, loopback lab) exposed a parser defect: `_input.reject_xml_declarations` rejected ANY `<!DOCTYPE`, and real Nmap always writes a bare `<!DOCTYPE nmaprun>` header, so the reader had never accepted genuine Nmap XML - the synthetic fixtures omit it. The check now rejects `<!ENTITY` declarations and any DOCTYPE carrying an internal subset, and accepts only a bare (optionally SYSTEM-id) DOCTYPE, which `xml.etree.ElementTree` neither fetches nor expands. Security tests cover: entity rejection, internal-subset rejection, bare-header acceptance. Alternatives: post-processing strips the header (rejected: mutating capture bytes), or keeping the blanket ban (rejected: forbids all real Nmap output).

**SCAN-02. DECIDED - real captures committed with provenance; zero findings stated honestly:** two real Nmap captures from the owner's own loopback-bound lab (Juice Shop 20.2.0 on 172.28.0.12:3000, Windows SMB/RPC + Python 3.12.10 SimpleHTTP on 172.28.0.10:8000) executed via `vulnassess scan --execute` with an empty canary access log, and committed under `tests/fixtures/nmap/` with provenance rows. `tests/test_real_captures.py` parses them. Both captures contain zero explicit CVE evidence: the vulners NSE ran keyless and found no nameable vulnerable software. The pipeline imported both hosts and services, inferred context from real service evidence (`file_share 0.8` from the quoted `445/tcp microsoft-ds`), and produced an honest empty ranked queue - raw absence is not remediated or inflated (see rescan policy). Unlocking CVE-level evidence requires a free Vulners API key (`~/.nmap/vulners.key`) or Nikto/ZAP provisioning; both remain optional human actions.

**UI-18. IMPLEMENTED - additive analytics layer on the risk stage:** research into professional threat-prioritisation surfaces (EPSS x CVSS quadrant framing, risk-formation waterfalls, exploit-intelligence strips, workflow-aligned motion) produced four additions, all rendered from stored values with no rescoring: a threat strip (stored counts: findings, CVEs, KEV, internet-facing, top EPSS percentile, animated count-up), a quadrant map (stored CVSS base vs stored EPSS percentile, KEV-ring and internet-facing fill distinctions, an explicit lane for findings with no EPSS row instead of a fake percentile, points open the existing inspector), a risk waterfall (the stored arithmetic formation of the highest risk: environmental x 10, exploitation multiplier, KEV boost, cap - labelled with the weights), and a motion layer (IntersectionObserver staggered reveals, door hover lift, stage-link progress fill, all disabled under prefers-reduced-motion). Nothing existing was removed or reworded; export parity tests extend to the new figures, and the sandbox arithmetic self-check still reports 211/211 vectors and 144/144 sandbox cases matching Python. Alternatives considered: client-side recomputation for the map (rejected: UI-16 confines arithmetic to the sandbox), and a pipeline-flow ribbon (deferred: no analytical content beyond decoration).

**UI-19. IMPLEMENTED - formation engine and hero layer strengthen the risk stage:** the UI-18 additions were strengthened after review: the threat strip became a hero with a band-composition meter (Critical/High/Medium/Low segments animated from the store), the quadrant gained danger/watch zone fills, crosshair guides and drop-in point animation, and a new formation engine pairs a 240-degree risk gauge (stroke-dashoffset driven by a CSS variable set on reveal) with a four-station beam diagram (Base -> Context -> Threat -> Risk, flowing dashes, values and terms straight from the store). All values remain stored-only; the sandbox stays the only arithmetic surface; prefers-reduced-motion disables every animation; the offline exports embed the same module and re-hash their CSP. Verification: full gate green, 55 UI tests pass, in-page sandbox self-check 211/211 vectors and 144/144 sandbox cases match Python, dial animates from 0 to the stored risk on reveal.

**TEST-02. IMPLEMENTED - UI self-provisioning heals stale databases:** an external review reported 41 test failures caused by `data/vulnassess.db` existing without the demo run; `_provision_demo_database` only checked that the file existed. It now verifies the runs table and the demo run, deletes a stale, partial or foreign database (including WAL/SHM sidecars) and rebuilds via `run_demo.py`, then ensures the `verify` runs row. Verified by dropping the runs table and rerunning: 55 UI tests pass after self-healing. Related staleness corrected: the README limits paragraph and evidence table now state that two real loopback captures exist with zero explicit CVE evidence (they previously said there was no real scan evidence), and HANDOFF.md gained a scope note that its machine-state section describes the operator machine only - fresh clones carry no gitignored `data/` and no machine tools, and inventories differ between machines (this one: Nmap yes, Java/Docker no).

**EVID-01. IMPLEMENTED - the evidence ladder advanced on every fillable front (2026-09-19):** multi-host lab evidence: three loopback lab hosts scanned (nginx 1.20.0 on 172.28.0.11:80, Python 3.12.10 SimpleHTTP on 172.28.0.10:8000, OWASP Juice Shop 20.2.0 on 172.28.0.12:3000), each bound to its single loopback address and netstat-verified. Real CVE-bearing findings: the nginx capture (Nmap 7.99.1 + keyless vulners) carries three explicit CVE findings (CVE-2026-42945/42055/42533, base 8.1) with real EPSS enrichment (99th/93rd/91st percentile), ranked 74.7/72.5/71.6 High. Committed as tests/fixtures/nmap/real-lab-172.28.0.11-nginx.xml with provenance. Real ZAP capture: ZAP 2.16.1 daemon + spider + passive scan against Juice Shop produced the official JSON report (278 findings); parse_zap_json verified against it; committed under tests/fixtures/zap/ with provenance; ZAP findings rank through the honest native-fallback path (no invented EPSS). Persisted evaluation: the full frozen-cohort chain ran on lab3 (snapshot -> 25-finding cohort-freeze -> ranking-eval) producing a hash-bound evaluation artifact (evaluation_hash b6ddf459...) attached to the report's evidence ledger; evidence_status stays NOT RUN because the truth is a labelled synthetic echo, not expert judgment. LLM rationale: Ollama + llama3.2:3b installed; explain stored real llm rationales for lab3 - wording only, scores byte-identical by design. Tooling incidents: Nmap 7.80 (i686) developed a deterministic segfault in its vulners path; upgraded in place to 7.99.1 + Npcap 1.79; 7.99.1 requires -sT for loopback raw scans until an Npcap driver reload (reboot), so the .11 capture used the documented manual route with -sT; orchestrator scans resume after reboot. Remaining blockers are human-only: expert rankings/labels/context truth and the Vulners API key.

**UI-20. DECIDED - one renderer, multiple evidence modes:** the four-stage workbench is the sole active interactive interface. `run_visual_simulation.py`, `vulnassess visualize`, live `vulnassess ui` and `ui --export` now share `UiApplication` plus `export_html`; the simulation differs only by building an explicitly synthetic run first. The historical eight-stage replay remains unreferenced source history, not a second product. The active Evidence stage replaces door controls with explicit finding cards and the tour traces one finding. Offline analytics no longer emit or mutate inline styles: proportional bars use CSP-safe SVG or repeated units and the gauge uses an SVG presentation attribute, preserving hash-pinned `style-src` without `unsafe-inline`. Alternatives considered: maintain both UIs or weaken CSP; rejected because they create divergent behavior and conceal blocked presentation code.

**UI-21. DECIDED - adapt proof-first hierarchy, not TypeSafe AI branding:** use the reference site's transferable interaction principles on the Risk stage: one thesis per viewport, oversized stored proof values, sparse technical framing, strict label/value typography and restrained stage-entry motion. Keep VulnAssess's professional token palette, evidence density, four-stage analyst navigation and read-only semantics; copy no brand assets, wording, fonts, colours or marketing composition. The Risk thesis and run metrics gain hierarchy while finding controls and provenance remain immediately inspectable. Reduced-motion removes the new transition. Alternative considered: restyle the workbench as a landing page; rejected because an operational security viewer must optimize repeated evidence inspection rather than conversion.

**UI-22. IMPLEMENTED - context ledger, chain of custody and command palette:** styling alone did not make the research legible, so three data-grounded surfaces were added, all rendered from stored values with no rescoring. (1) Context ledger on the Risk stage: for the highest-risk scored finding it shows the published CVSS vector beside the context-adjusted vector with changed tokens marked, then one row per stored `env_modifications` entry giving the metric, published value, adjusted value, the weights rule that applied and the driving context feature with its value, source, confidence and verbatim evidence quote; a rollup lists every scored finding with published/environmental scores, delta and rewrite count. Rule attribution is derived by matching each stored modified metric against the metric sets declared in `config/weights.yaml` (`internal_when_av_network`, `waf_present`, `auth_required_when_pr_none`, role/test-environment requirements), so the displayed cause comes from configuration rather than a hardcoded narrative. (2) Chain of custody in every inspector panel: a six-hop lineage from captured raw file and record index, to canonical finding id and host/port, to CVE match method and confidence, to the context features used, to base-to-environmental rescoring, to stored risk, band, threat multiplier and weights hash. (3) Command palette (Ctrl/Cmd-K): a keyboard-driven modal searching stages, hosts and findings from the embedded bootstrap only, with arrow/Enter/Escape navigation, aria combobox semantics and no network access; selecting a finding opens the existing inspector through the existing hash state. Vector strings are split into tokens for display only - no score is computed outside the sandbox, preserving UI-16. Verified: 251 tests and 348 subtests pass; the offline export contains the ledger, 3 attributed metric rows, 36 chain hops and the palette with 0 inline styles, so the hash-pinned CSP is unaffected. Alternatives considered: computing the rule attribution in the browser (rejected: keeps arithmetic and interpretation server-side from stored data), and a static prose explanation of environmental changes (rejected: it would not be traceable to the stored modification set). DEFERRED: presentation styling for the three new sections (they currently inherit base table/list styling) is the next increment.

## Grounded local analyst - 2026-09-21

**AI-01. USER-DIRECTED - replace the bootstrap priority imitation with target-level local analysis:** the user rejected an instant six-row ridge-regression model as materially inadequate and required a real model operating on the complete idea. Remove that bootstrap model, its artifact and its UI route. The explicit Context-stage action now invokes the already installed local `llama3.2:3b` through Ollama with the selected host's complete stored services, scanner findings, context, CVSS, EPSS, KEV and deterministic scores. Model output is advisory and transient: canonical scores and records remain unchanged. The response must be valid JSON, use the bounded analyst shape, and cite only finding/evidence IDs present in the request; malformed output or unknown citations fail closed. Scanner/model text is delimited as untrusted and rendered with DOM text nodes. No model runs during page load or offline export. Verified on the live loopback UI: the database target completed local CPU inference in 49.36 seconds and returned a cited remediation action; the full quality gate passes. Rejected: retaining the bootstrap predictor as a competing product model, allowing AI to manufacture scores, or displaying unvalidated free-form prose.

## Independent workflow visualization - 2026-09-21

**WF-01. USER-DIRECTED - Make-style canvas over the real project flow:** the user requested a complete node-and-connection visualization independent of the current notebook UI. Add `/workflow` and isolated local HTML/CSS/ES modules, sharing the existing record APIs. Cover authorized targets, scanner ingestion, normalization/storage, local feeds, enrichment, context, optional learned roles, deterministic risk, priority, rationale, reports, analyst output, expert evaluation and re-scan comparison. This serves PROJECT.md Stage 7 and cross-cutting ranking/evaluation auditability: the viewer can trace the inputs behind a priority rather than reading a wall of tables. Conflict / resolution / why: UI-20's sole-interface statement predates the explicit request for a distinct visualization; retain its shared backend/assessment renderer but add a new view, not a second pipeline. The independent circle-node visual vocabulary uses new scoped neutral tokens and local SVG paths, not external libraries, downloaded imagery or copied Make assets. Alternatives: restyle the four-stage page or animate a replay; rejected because the user explicitly rejected the existing UI style and needs real dependency relationships.

**WF-02. DECIDED - dependencies are not execution evidence:** nodes say stored records, current configuration, no attached output or transient analyst-request state. They never become complete merely because selected; no timers, fake throughput, made-up counts or automatic model calls. Target/finding selections filter existing records and preserve stored score values. The local analyst is downstream of evidence and ranking with no edge back to scoring; its button reuses the existing AI-01 endpoint, with run/host-bound transient state, text-only output and explicit errors. Testing uses mocked analyst failures; no real Ollama request or scanner is run for this change. Optional report, evaluation and re-scan nodes remain visibly unattached rather than deriving metrics or asserting fixes. Alternatives: infer artifact existence from scores, execute the whole pipeline from the canvas or recalculate metrics; rejected under the remaining data, scoring and execution boundaries. The project venv lacked pytest, so full tests used the already-installed system interpreter; no provisioning or dependency change occurred. Validation and screenshots are recorded in docs/ui.md.

## Workflow design review - 2026-09-22

**WF-03. USER-DIRECTED - Integration Card visual reference, directional workflow:**
the user selected ShadcnSpace's Integration Card at
[its 21st.dev preview](https://21st.dev/@shadcnspace/components/integration-card), requested dark styling
close to the reference, and delegated the layout choice after comparison. This
serves PROJECT.md Stage 7 and cross-cutting context/ranking auditability: larger
readable nodes and a selected evidence path make the inputs behind a priority
inspectable. Retain the 18 existing stage identities and dependency edges. Adopt
dark raised icon tiles, compact navigation, scoped color tokens and selected-edge
tracing, with a Canvas / Stages switch and a readable list by default below
961 CSS pixels. Keep node details, native scrolling, keyboard focus return,
target/finding filtering and the existing explicit analyst boundary. Motion
indicates the selected dependency only, never execution, and respects reduced
motion. The run summary counts existing arrays, not completed stages.

Conflict / resolution / why: WF-01's pale circular presentation is superseded
only for this independent workflow by the user's approved dark reference. The
assessment renderer, APIs, model fields, scores, scope and offline export remain
outside this redesign. A literal single-hub copy was rejected because it erases
pipeline direction; hiding optional stages was rejected because missing outputs
must remain visible. Installing the React component and its dependencies was
rejected in favor of the existing offline modules and local icons. No template
source or brand assets are copied. Reference installation commands were
**not run by the agent**. Other templates still require separate user review.

TESTED WITH MOCKS: the available regression suite passed; VERIFIED: browser and
loopback smoke evidence is quoted in docs/ui.md. MISSING: Ruff, Pyright and
pytest-cov; this decision does not assert a complete quality gate.

**WF-04. USER-DIRECTED - soften the workflow palette, retain the accepted layout
(2026-09-22):** the user found the background too dark and accepted the rest of
the workflow. Lift the near-black canvas to neutral charcoal, lighten tile faces
and connectors, and reduce shadow opacity through workflow-scoped tokens only.
This serves PROJECT.md Stage 7 by improving readability of the existing evidence
path; it makes no research-performance claim. Alternatives: switch to a full
light theme or redesign the graph again; rejected because the request is a small
appearance refinement, not a new layout or mode. No HTML, JavaScript, scoring,
record, dependency or assessment-theme change belongs to this follow-up.
VERIFIED: live color/contrast and viewport measurements are quoted in docs/ui.md.
TESTED WITH MOCKS: nine existing UI asset tests passed. The required gate remains
blocked by the previously named missing tools.

## Project-first explanation website - 2026-09-22

**UI-23. USER-DIRECTED - explain the project before exposing its records:** the
user identified the visitor's task as understanding and exploring the project,
explicitly dropped the Doors direction, supplied
[Hero by Berat](https://21st.dev/@beratberkayg/components/hero-1), and requested
desktop-first work. This serves PROJECT.md Stage 7 and cross-cutting ranking
auditability: explain why deployment context matters, then let the visitor
inspect the evidence behind an existing priority. Use a project introduction,
a guided comparison and links into the accepted workflow. Preserve the detailed
assessment behind explicit `#stage-*` links and in print.

Conflict / resolution / why: UI-20 and UI-21's operational-first entry predates
the user's explicit explanatory-website request. Change the default presentation,
not the pipeline, scoring model, stored records or approved workflow. Repeating
the Doors/orbit/card-stack composition was rejected because it obscured the
project's purpose. A separate React/shadcn application was rejected because it
would add a second frontend and require unapproved provisioning. Adapt the supplied
hero composition in the existing offline HTML/CSS/JavaScript, with original
decorative bitmap artwork embedded in exports. Reference installation commands
were **not run by the agent**; no new dependency is requested by this decision.

**UI-24. DECIDED - a guided example must come from existing records:** compare
two different hosts only when stored CVE, base vector, base score, EPSS percentile
and KEV membership match. Reveal the recorded context and priorities in three
user-controlled steps; never calculate new scores for the story. Label synthetic
provenance and distinguish equal stored values from a controlled historical-feed
experiment. Preserve source evidence in disclosures. No suitable pair means an
explicit unavailable message, not an invented example. Alternatives: fixed
demonstration numbers or picking a visually dramatic pair with different threat
inputs; rejected because either would undermine the context-attribution research
question. This display does not establish inference accuracy or ranking quality.

**UI-25. USER-DIRECTED - explanation sections connect to the existing analyst:**
add plain-language local-analyst, priority/reason/source and questions sections.
Let visitors select only hosts in the current stored assessment; link that host
to the workflow's existing analyst node. Opening the link must not execute the
model. The existing explicit AI-01 action remains advisory, transient and separate
from deterministic scoring. Offline exports disable these live actions and retain
the explanation. Use native select/disclosure controls, visible keyboard focus,
restrained button depth and reduced-motion-aware arrow movement.

Control-level reference review considered
[Interactive Hover Button](https://21st.dev/@dillionverma/components/interactive-hover-button)
and [Accordion Space](https://21st.dev/@shadcnspace/components/accordion-space).
Use the interaction ideas, not their component code, dependencies or a new page
template. The hover-button embedded preview was blank during capture; exact
reference behavior is not claimed. Alternatives: automatic analysis on navigation
or a fabricated answer preview; rejected because they would blur execution and
evidence boundaries. This decision extends presentation only, not AI-01's scope.

**UI-26. USER-DIRECTED - defer the globe only:** the user selected option 2 after
the local COBE renderer/provisioning blocker was reported: continue the useful
website sections and leave the globe for a separately approved artifact. A remote
CDN, sibling-package copy or imitation renderer is not a provisioning workaround.
Decorative geography is not needed to inspect context or evaluate ranking, so this
deferral does not block the research question. MISSING: approved local renderer
bundle with exact dependency versions, provenance, license, independently approved
hashes and dated vulnerability review. No globe installation or model execution
was performed for this increment; verification and remaining gates are recorded
in docs/ui.md.

## Doors as a section and explicit analysis - 2026-09-22

**UI-27. USER-DIRECTED - restore the useful doors metaphor as one section:** the
user now requests parts of Doors with a clear depiction, not the previous whole
interface. This serves PROJECT.md Stage 7 and context/ranking auditability: one
selected recorded system, its stored role/exposure, and one selectable door per
finding lead to the exact source and stored priority. Reuse the existing local
building/door drawings and band mapping. Unknown context and absent findings stay
explicit. Synthetic records remain labelled; a door does not establish an
exploitable entrance and an unknown role does not imply low importance.

Conflict / resolution / why: UI-23 dropped Doors as the organizing interface;
the latest user request permits the metaphor inside the explanatory website.
Keep the project-first hero and approved workflow, not the old Doors page, orbit
or a second dashboard. A decorative collection of invented buildings/findings
was rejected because it would break the connection to evidence. The drawings
depict existing records; they do not score, infer context or establish research
performance.

**UI-28. DECIDED - preserve selection through the workflow round trip:** all
project workflow links retain the selected recorded host, and a door link also
retains its finding ID. The return link restores that host/finding in the doors
section, or the host in the workflow section when no finding is selected. Shared
host controls and input summaries follow the restored selection. Use fragment
state only; no assessment query shape or API fields change. Alternatives:
unfiltered links or independent unsynchronized selectors; rejected because they
can show a different system's evidence after a visitor follows a priority.

**UI-29. DECIDED - run the existing analyst explicitly, not an invented pipeline:**
interpret the request for a model-running section within the existing AI-01
boundary. Offer the existing local analyst for a selected system or all systems
in the stored assessment, using the same endpoint sequentially. Review the exact
target list before starting. Reject duplicate starts and mismatched responses;
stop later requests after a failure, and let the user stop after the current
request without claiming to cancel inference already running. Responses remain
transient, cited and rendered as text; stored scores and model code stay untouched.
The earlier Context-stage action now opens this same review flow. A small shared
client supplies validation to both the project and workflow; offline exports
embed it but disable every execution control.

Alternatives: automatic execution when visiting a section, parallel inference,
a new backend batch route, or training/running a second ranking model; rejected
because none is needed to explain existing evidence, and these would expand the
execution/interface boundary. This choice does not authorize scanner orchestration,
feed refresh, rescoring, training or additional model types. Those are not hidden
behind an "all models" control. No dependency or fixed schema change is made.

TESTED WITH MOCKS: sequential, duplicate, stop, failure, response-identity and
citation cases are covered by the existing synthetic workflow check. Browser
execution checks ultimately used an in-page fetch fake. VERIFIED: an earlier
browser-route interception failed and one local analyst request returned an
Ollama-unavailable error; that request is not described as mocked or successful
inference. The incident, missing service and quality prerequisites are recorded
in docs/ui.md. Future browser model checks must use in-page fakes, not rely on
route interception being retained through a timed-out check.

## Globe land map under the viewer CSP - 2026-09-23

**UI-30. DECIDED - allow `data:` images only, and keep inline styles blocked:**
PROJECT.md Stage 7 (Report). The vendored Cobe 2.0.1 globe loads its land map
from an embedded `data:image/png`. The server CSP had no `img-src`, so
`default-src 'self'` blocked it and the globe showed no continents. The CSP now
adds `img-src 'self' data:`, which the offline export already allowed with
`img-src data:`. Scripts, styles and connections are unchanged, and
`unsafe-inline` is still absent.
Cobe also writes label visibility into an inline `<style>`, which `style-src
'self'` blocks on every frame. The adapter detaches that element and copies its
`--cobe-visible-*` values onto the globe root through CSSOM. Labels on the far
side now hide, and the per-frame CSP violations stop.

Alternatives rejected: adding `'unsafe-inline'` to `style-src` (weakens the page
policy); editing the vendored library, or extracting its texture to a patched
static file (breaks parity with upstream 2.0.1). No dependency, API, schema or
scoring change.

**UI-31. USER-DIRECTED - the globe depicts the recorded assessment, not CDN
traffic:** PROJECT.md Stage 7. The user rejected the copied 21st.dev content
(edge regions, "req/s" counters) and asked for project context. Markers are now
the recorded systems of the selected run. Each label gives the hostname or IP,
the inferred role and the stored top band, and marker colours use the band
tokens. Arcs join systems with the same CVE, vector, base score, EPSS and KEV,
which is the `_project_story` like-for-like rule. The arc label shows the base
score and the two stored bands. The readout names the run and its provenance
(synthetic or source unlabelled), and states that positions are illustrative.

Conflict / resolution / why: a globe implies geography, but lab systems have
private addresses and no location. Rejected: geolocating addresses (impossible
for RFC1918, and it would be invented evidence); placing systems on arbitrary
real cities (reads as geolocation). Chosen: a deterministic layout disclosed as
illustrative. The globe spins a full 360 degrees; labels on the far side hide,
and the recorded systems are front-facing when the page loads. The random traffic counter is removed
as fabricated data. No run shows continents only, with an explicit notice.
Reduced motion stops the spin. No backend, API, schema or scoring change.

**UI-32. USER-DIRECTED - desktop scroll parallax on the hero:** PROJECT.md Stage
7. The user asked for a proper scroll animation on the hero, after reviewing the
21st.dev scroll heroes: Container Scroll Animation, Scroll Morph Hero and Parallax
Scrolling. A first version pinned the hero and slid the globe section over it as
a rounded, shadowed sheet. The user rejected it as a mobile-app pattern that
doesn't suit a desktop product; it was removed. A second version, a generic
layered fade-and-tilt parallax, was rejected as boring.

Current: a scroll-scrubbed desktop scene that plays the research thesis from
stored records. The hero is held on screen for about 190vh of scroll. Nothing
slides over it, and the page scrolls on normally afterwards. The beats are:
1. The title dissolves into one card for the stored like-for-like weakness
   (`tour_finding` and its partner: same CVE, vector, base, EPSS and KEV).
2. The card splits across the two recorded systems.
3. Each card shows its stored role, exposure and Environmental modifications,
   and the Environmental score moves from the base to the stored value.
4. The priority meters fill to the stored risk and band, and "Not the same
   priority." links to the evidence.
Final numbers equal the stored values; the scene says "stored scores, not
recalculated here" and labels the run synthetic or recorded. There is no scene
without a pair, under 900px width, or with reduced motion; the hero then stays
as it was. Native CSS/JS only, text via textContent, no model call.

**UI-33. USER-DIRECTED - 21st.dev interaction components, rebuilt natively:**
PROJECT.md Stage 7. The user asked for good hover effects, buttons and components
from 21st.dev instead of a restrained style. The React/Tailwind/framer-motion
sources cannot be imported, since they need dependencies, a build chain and
downloads. Their behaviour was re-implemented in plain CSS and JS on the current
project page:
- Primary buttons, after Magic UI / designali's Shiny Button and Border Beam: a
  rotating conic beam just outside the button (CSS `@property` angle), a shine
  sweep on hover and a lift.
- Framed panels (model panels, doors, door records, scene cards), after
  Aceternity's Glowing Effect: a masked conic border glow in the signal and
  critical tokens that faces the pointer when it comes within 70px.
- List rows (outcomes, analyst path, workflow steps, FAQ): a spotlight that
  follows the cursor.
- Text links: an underline that draws in with the arrow moving.
- Header navigation, after Cnippet's letter swap: each label's own letters
  shuffle deterministically and then settle, with `aria-label` keeping the real
  name.
Constraints: colours come from existing tokens, with no inline styles (CSSOM
only) and no `unsafe-inline`. The global reduced-motion rule stops the beam and
the transitions, and the letter swap is skipped. The old workbench is untouched
at the user's request.

**UI-34. USER-DIRECTED - a plain-language scenario replaces the hero scroll
scene:** PROJECT.md Stage 7. The user rejected the pinned two-card scene (UI-32)
because showing two technical "surroundings" cards didn't explain anything to a
non-technical visitor. They asked for a small scenario that can be understood by
looking at it. The scene, its sticky track and its script are removed, and the
hero scrolls normally. A new `#project-scenario` section follows the hero as
three illustrated steps on a timeline:
1. "Mon 09:00": two identical computers, each showing the same 9.8/10 warning.
2. "09:01": one is open to the internet, the other is inside the office.
3. "09:02": the order is "Fix first · Company database · Critical", then "Fix
   next · Staff test page · High".
The art is inline SVG line drawing, and the timeline draws in once when the
section first scrolls into view (IntersectionObserver). The steps carry the
UI-33 glow.
Evidence boundary: the section is labelled "An illustration of the synthetic
demo run". The outcome matches the stored demo pair: the internet-facing
database is Critical, and the internal test web frontend is High. "Company" and
"staff" are illustrative wording, not recorded facts. Rejected: a
scroll-scrubbed version of the same story (the user called the pinned scroll
stupid) and stock illustrations (downloads, licensing).

**UI-35. USER-DIRECTED - the hero planet travels to the globe:** PROJECT.md
Stage 7. The user specified the scroll animation: the planet on the hero's
horizon moves down to become the background of the scenario, then shrinks into
the small Cobe globe. A pinned, scroll-scrubbed scenario was tried first and
reverted; the user said the animation belongs to the hero.
Implementation:
- A fixed, `contain: strict` layer holds a CSS planet: one radial gradient whose
  stops copy the measured brightness profile of `project-horizon.png`. That
  profile is a rim circle of radius 2000, centred at (800, 2732) in the
  1600x1050 image, with a 1px rim, a 50px bright band and a 240px falloff.
- The planet is resized in pixels every frame, not scaled, so its edge stays
  sharp at any size.
- Handover from the artwork: at 4px of scroll the lower part of the artwork is
  masked away. Captures match the rim row exactly, glow within 3 grey levels
  and body within 1, in both themes.
- Behind the scenario, the rim sits at 70% of the viewport and dims to 65%.
- Landing: the size settles before the position, and the position tracks the
  visible rim so the planet never leaves the screen. Motion ends at 80% of the
  landing; the last 20% crossfades in place onto Cobe's measured rim (0.797 of
  the canvas radius, same radius and centre), and Cobe fades in as the planet
  fades out.
- Every frame is a pure function of scroll position, so scrolling back up
  reverses it exactly. Reduced motion and widths under 900px keep the static
  artwork and globe.
Rejected: scaling a raster planet (blurred rim, expensive blurred shadows);
pushing the planet sideways to avoid text (a visible jump). Text that can cross
the planet gets a soft halo instead.

## Standalone export asset bundling - 2026-09-23

**UI-36. DECIDED - embed the existing globe and fonts in offline HTML:**
PROJECT.md Stage 7 (Report) and cross-cutting reproducibility. The purpose is
to let reviewers inspect the same stored assessment without a running server;
this is not new evidence for the ranking hypotheses.

Chosen: extend the existing explicit module bundler with the local Cobe adapter
and its vendored renderer, isolating their names in function scopes. Refuse an
unexpected import/export shape rather than silently emitting a broken bundle.
Embed the three existing WOFF2 fonts as data URLs. Keep exact script/style hashes
and `connect-src 'none'`; allow only `data:` font sources.
Rejected: external module/font requests (break standalone operation), a new
bundler dependency (unnecessary provisioning), and removing the globe (changes
the shared view). No canonical model, API, scoring, dependency or live UI change.

TESTED WITH MOCKS: the added assertion in
`TestUiExport.test_export_is_self_contained` first failed on the unresolved
`import { initialiseCobeGlobe } from './cobe-globe.js';`. After repair, the
isolated-copy command `python -m pytest -q -p no:cacheprovider
tests/test_ui.py::TestUiExport tests/test_ui.py::TestUiAssets
tests/test_ui.py::TestAnalystChoices` returned
`38 passed, 17 subtests passed in 9.72s`. The export test also runs
`node --input-type=module --check` on the emitted JavaScript. These checks use
synthetic stored records, not real scanner/feed/model integration evidence.

VERIFIED: `python -m vulnassess ui --run demo --export <local HTML path> --json`
against the isolated database returned `read_only: true`, `run_id: demo` and
`EXPORT_EXIT 0`. Browser `page.reload()` and DOM/canvas probes on that file at
1440x1000 and 390x844 returned `errors: []`, `blockedFetches: 0`, `csp: []`.
All three fonts reported `loaded`; the desktop canvas sample had 4096 nonzero
bytes, and the mobile draw-time sample had 256 nonzero RGB pixels. Selecting
the Light and Dark buttons returned `themesWorking: true`. Fetch was replaced
with a non-forwarding guard; no model or scanner integration was exercised.

TESTED WITH MOCKS: the broader isolated run called
`pytest.main(['-q', '--tb=no', '-ra', '-p', 'no:cacheprovider'])` with socket
creation, connection and DNS blocked. It returned
`8 failed, 295 passed, 375 subtests passed in 48.77s`, with zero skips. Five
failures attempted sockets; three assert the previously removed UI. They remain
unresolved and were not weakened or suppressed to make this checkpoint green.

MISSING: `python scripts/check.py` reported
`GATE INCOMPLETE: missing prerequisites: ruff lint, ruff format, pyright, pytest + coverage`.
Source coverage remains unmeasured. `tests/fixtures/nikto/` still has no real
human-captured Nikto JSON. That absence does not prevent testing offline asset
bundling, but prevents a claim of real Nikto integration verification.

## Full two-prompt pipeline recheck - 2026-09-23

**RECHECK-01. DECIDED - actual discovery and normalized persistence:** PROJECT.md
stages 1-4. An exit-zero Nmap process without the requested host is failed
discovery, not a completed assessment. Preserve its exit code, timing and raw
path. The existing scan command now imports successful captures and retains all
outcomes in the existing run summary; later web imports retain Nmap services.
Apply the explicit named-target requirement to the older runner and importer as
well as the main orchestrator. Rejected: counting every skip as success, treating
a CIDR as target authorization, or leaving successful scans outside the store.
No command shape, scope entry, SQL layout or exit code changes.

**RECHECK-02. DECIDED - enforce the already-recorded model boundary:** PROJECT.md
stage 5 and RQ1. MODEL-06/OPERATIONS-01 authorize shadow candidates only, even
after a promotion attestation. Canonical profile construction and the pure
scoring function now reject unapproved learned/LLM context. Training, prediction,
evaluation and shadow recommendations remain available. Label templates leave
independent groups unfilled; loading rejects null/blank groups instead of making
`run:IP` look like reviewed independence. Rejected: silently enabling learned
scoring, silently ignoring a model argument, or inventing independent hosts.
Conflict / resolution / why: the requested canonical trained-context flow needs
the human-approved context-source ADR; this pass does not fabricate that approval.

**RECHECK-03. DECIDED - bounded, truthfully partial analyst cases:** PROJECT.md
stage 5. Clean all model-facing strings, escape delimiters, include the required
untrusted-data prefix, and never reuse a citation when its budget is exhausted.
Use stored-risk ordering with stable finding-ID ties and expose included/omitted
finding, service and intelligence counts. Partial coverage forces an uncertainty
notice and conservative confidence. Preserve scanner provenance, match confidence,
feed dates and weight hashes in included evidence. Rejected: pretending an
oversized case was fully reviewed, silently dropping rows, or increasing an
unmeasured context window until a demo passes. A bounded partial analysis still
does not meet the original complete-case acceptance requirement.

**RECHECK-04. DECIDED - injectable providers and shared grounding guards:**
Keep the default provider local-only. A typed provider boundary preserves the
injected source identity; it is not a cloud-provider implementation or approval.
Validate a case before contacting its provider. Reject unsupported CVEs/numbers
and malformed citations, including in corpus supervision. Bound streamed events,
wire bytes and decoded content; require explicit completion and transmit the
requested output schema. Rejected: false Ollama provenance, trusted streaming
content, citation-only claims of factual truth, and corpus-only validation bypasses.
These guards do not prove semantic entailment, useful reasoning or live inference.

**RECHECK-05. DECIDED - preserve known threat inputs and isolate baselines:**
Cross-cutting risk ranking and RQ2/RQ4. Missing CVSS must not erase observed EPSS
or KEV. Keep the native-severity base and apply the existing configured KEV boost
and exposure floor; do not apply an EPSS multiplier to a native fallback. Severity
baselines use recorded native-severity provenance rather than final adjusted risk;
absent EPSS remains unscored rather than being treated as an observed zero. Validate
all required host context and calculate all scores before writing score rows.
Rejected: discarding known threat data, contaminating baselines with KEV/context,
and silently omitting findings without a context profile. Weights, thresholds,
CVSS version policy and canonical fields are unchanged. This is a correctness
repair, not a measured improvement against expert rankings.

**RECHECK-06. DECIDED - network-free tests and visible shadow uncertainty:**
Cross-cutting reproducibility and PROJECT.md stage 7. Reuse the existing in-memory
HTTP harness for assessment-route tests and retain their assertions. Pytest blocks
Python socket connection/bind/send and DNS operations by default; that is not a
sandbox or permission for network-capable child processes. The detailed report
includes all shadow predictions, including rule agreements, with coverage, OOV
features, confidence, margin, abstention and model hash. Rejected: hiding low-coverage
agreements, live sockets in unit tests, or weakening assertions to obtain a green gate.

**RECHECK-07. NOT APPROVED - remaining product contracts and research inputs:**
Writable intake/resolution and its identity record, canonical model activation,
and durable structured-analysis/report bindings still need the prescribed review.
No new authorization, cloud data flow, dependency provisioning, model-quality claim
or unseen-environment result is implied. The complete evidence, remaining failures,
and both prompts' acceptance checks are recorded in HANDOFF.md. Concurrent commits
6f51bb5/b3e5dae were preserved; the removed offline-export bundling is reported as
a regression, not silently restored during this backend-focused pass.

**RECHECK-08. DECIDED - preserve and validate incoming model infrastructure:**
Remote checkpoint 5b13059 added feature-family ablation and optional training-run
registration. These were retained when rebasing the unpublished recheck. The
ablation CLI now forwards its declared training options and rejects conflicting
family selectors. Any synthetic labels classify the registered dataset as
synthetic, rather than allowing one human-tagged row to label a mixed dataset
`real_authorised`. Rejected: silently ignoring hyperparameters, overstating data
provenance, or dropping the incoming work. Registration remains draft metadata;
it is not independent test evidence, authorization verification or model promotion.
