# HANDOFF — state of the project as of 2026-09-18

Written for a developer/agent resuming work with knowledge of the repository's
**earlier state** (before commit `c88e822`). Read this top to bottom; it maps
old→new, documents the machine the work ran on, and lays out the continuation
plan in phases with acceptance criteria. The project's own rules still govern:
`.github/copilot-instructions.md` (evidence ladder, no unpinned pip, scope
fence) and `docs/decisions.md`, which now also contains the dated entries for
everything below (CLEANUP-01, FEED-01/02, CI-01, TEST-01, DEMO-01, SCAN-01/02).

---

## 1. Where the project now stands (one paragraph)

The engine is unchanged in its scoring semantics and still fully tested
(233 tests, 87.6% coverage, pyright 0 errors incl. strict mode on
scoring/schema, ruff clean, gate green, enforced in CI). Around it, four
structural gaps closed: the narrative bloat is deleted, the offline feeds are
REAL (NVD 376,424 / EPSS 375,610 / KEV 1,713 records), real Nmap captures
exist (loopback lab, honestly zero-CVE), and the quality gate runs in GitHub
Actions on 3.11+3.12. A separate demo repo presents it. What remains open is
what only humans or more tooling can supply: web-scanner captures, LLM
rationale, and the research inputs (expert rankings, labels, context truth)
that gate every RQ1–RQ4 claim.

## 2. What changed vs. the old state (old → new)

| Old state (pre-`c88e822`) | New state |
| --- | --- |
| `legacy/` full duplicate package | **Deleted**; git history preserves it (BUILD-01 superseded by CLEANUP-01) |
| `project-starter-kit/` with Copilot `PROMPT.md` | **Deleted**; only its `docs/DESIGN.md` retained as `docs/DESIGN.md` (3 docs cite it) |
| `PROJECT_PROVISIONING_COMPLETE.md`, `PROVISIONING_SUMMARY.md` | **Deleted** (claimed pip-installed feeds the charter forbade) |
| Root-level `SCAN_FORMAT_REFERENCE.md`, `FIXTURE_*_GUIDE.md` | Moved into `docs/` |
| Feeds `[MISSING]`, synthetic only | **Real snapshots** under gitignored `data/feeds/`; fetchers `scripts/fetch_feeds.py` + `scripts/fetch_nvd.py` (rate-limited, resumable); provenance `docs/FEED_PROVENANCE.md`; curated committed subset `tests/fixtures/intel/` + `tests/test_real_intel.py` |
| No CI; `.github/` only had copilot-instructions | `.github/workflows/ci.yml`: ruff lint+format, pyright, pytest `--cov-fail-under=75`, pinned versions, 3.11+3.12 |
| `pyproject.toml` had no lint/type config | `[tool.ruff]` explicit ruleset (`E4,E7,E9,F,I`, line-length 100) — **required**: ruff ≥0.16 broadened implicit defaults; `[tool.pyright]` include vulnassess+scripts, **strict** on `scoring.py`/`schema.py` per charter |
| Reader rejected ALL real Nmap XML | `vulnassess/readers/_input.py`: only `<!ENTITY` and DOCTYPE-with-internal-subset rejected; bare `<!DOCTYPE nmaprun>` accepted (real Nmap always writes it; synthetic fixtures never did — found by the first real scan) |
| UI tests needed author's leftover DB (18 failures on fresh clone) | `tests/test_ui.py` `setUpModule` self-provisions via `run_demo.py` + inserts the `verify` runs row; `DEMO_RUN = "demo"` |
| No real captures | `tests/fixtures/nmap/real-lab-*.xml` ×2 (provenance rows in that README) + `tests/test_real_captures.py`; executed via `vulnassess scan --execute` with empty canary log |
| `models/` trained on self-generated synthetic | unchanged (shadow-only by design) — still synthetic, still honest |
| Dense README | Rewritten: quickstart (incl. `run_real_demo.py` over `examples/real_lab_nmap.xml`), real-vs-not table, safety model |
| `DOWNLOADS_REQUIRED.txt` everything `[MISSING]` | Rewritten status: feeds PROVISIONED, gate PASSING, human-only items still MISSING |

**Commits** (branch `audit-no-assumptions`): `c88e822` (cleanup + feeds + CI +
gate fixes), `6f4e323` (first real captures + reader DOCTYPE fix). **Not yet
pushed to GitHub.**

**Separate demo repo** `C:\Users\aksha\Downloads\vulnassess-demo` (own git):
`2c0ad7a` Streamlit showcase (6 tabs, live sandbox on production
`scoring.environmental_vector`/`risk`), `002adcc` self-contained HTML
workbenches in `standalone/` (single file, zero dependencies, offline; sandbox
arithmetic embedded + Python-parity vectors). Demo DB is built by
`prepare_data.py` through the production CLI. Streamlit runs loopback-only:
`streamlit run app.py --server.address 127.0.0.1`.

## 3. Machine state this ran on (not in any repo)

**Scope note:** this section describes the operator machine where the session ran
(`C:\Users\aksha\Downloads\fragmented`). A fresh clone of the repository contains
**no `data/` directory** (gitignored: feeds, captures, lab, demo database) and no
machine tools — re-provision with `python scripts/fetch_feeds.py` plus the gate
tooling, which CI installs for itself from the pinned versions. Do not assume
another machine's inventory matches this one: this machine has Nmap but no
Java/Docker; other environments reported the exact reverse.

- Windows 11, Python 3.12.10 at `%LOCALAPPDATA%\Programs\Python\Python312`.
- Gate tools installed: ruff 0.16.6, pyright 1.1.411, pytest 9.1.1,
  pytest-cov 7.1.0, streamlit 1.61. CI pins these exact versions.
- **Known local quirk:** the `hypothesis` pytest plugin is installed but broken
  (Windows App Control blocks its `_native` DLL). It is NOT a project
  dependency. Run tests locally with `-p no:hypothesispytest` (or
  `PYTEST_ADDOPTS="-p no:hypothesispytest"`); CI is unaffected.
- Nmap 7.80 (`C:\Program Files (x86)\Nmap`) + `vulners.nse` in its scripts dir
  (keyless → no CVE output; a free key at `~/.nmap/vulners.key` unlocks it).
- Loopback aliases on "Loopback Pseudo-Interface 1": 172.28.0.10/.11/.12
  (matches `config/scope.yaml`; canary .250 unbound). Undo:
  `netsh interface ipv4 delete address "Loopback Pseudo-Interface 1" <ip>`.
- Lab apps under gitignored `data/lab/`: OWASP Juice Shop 20.2.0 portable
  (`juice-shop/`), portable Node v22.21.1, canary log `canary.log` (empty).
- **Security lessons (do not repeat):**
  - Juice Shop's `server.listen(port)` takes no host; `--host` is ignored. The
    lab copy is patched in `build/server.js` to bind `172.28.0.12` ONLY. First
    launch bound `0.0.0.0` for ~25 min — killed. Always `netstat -ano | grep
    LISTEN` after starting any listener and confirm the bind address.
  - Its startup reachability probes (Alchemy/LLM) hang on flaky networks; the
    lab copy short-circuits them in
    `build/lib/startup/validatePreconditions.js`. If it stalls anyway: delete
    `data/juiceshop.sqlite*` and restart.
- Background services may or may not still be running: Juice Shop
  (172.28.0.12:3000), Python http.server (172.28.0.10:8000), Streamlit
  (127.0.0.1:8601). All loopback-bound; safe.

## 4. Rules that still govern (unchanged charter)

Evidence ladder `VERIFIED / TESTED WITH MOCKS / NOT RUN / MISSING`; synthetic
data never proves a real claim; no unpinned pip installs as supply-chain
approval (CI's pinned dev-deps are the deliberate, documented exception —
CI-01); scope fence checked before any file read; canary refused by name;
scanner execution only via human `--execute`; LLM may reword a rationale but
never a rank. New decisions get dated entries in `docs/decisions.md`.

## 5. Continuation plan

### Phase 0 — publish (≤30 min, do first)
1. Push `audit-no-assumptions` to GitHub (origin exists: `codezxsWIN/privwork`);
   open PR to main so CI runs on the PR. **Accept:** both 3.11 and 3.12 matrix
   jobs green. If pyright/ruff drift in CI vs local, align pins in
   `.github/workflows/ci.yml` (they are the passing set).
2. Optionally publish the demo repo similarly (separate repo or `demo/` subdir
   later).

### Phase 1 — unlock real CVE findings (minutes of human time)
3. Human registers at vulners.com, puts the free key in `~/.nmap/vulners.key`.
4. Ensure lab targets up (Juice Shop on .12; optionally another banner-rich
   service on .10), then rerun:
   `python -m vulnassess --config config --db data/lab.db scan --run-id lab3
   --target-ip 172.28.0.12 --tool nmap --canary-log data/lab/canary.log
   --out-dir data/captures --execute`
   then the usual `import/enrich/context/rank/report`.
   **Accept:** ≥1 finding with a real CVE enriched from real NVD/EPSS/KEV;
   provenance row appended in `tests/fixtures/nmap/README.md`; commit capture
   if useful.
5. For version-rich targets, consider running a deliberately old portable app
   (e.g., an old Python/OpenSSL/Node build serving on .11) so `-sV` yields a
   version NVD can CPE-match — that exercises `match_method=cpe_range` on real
   data end to end.

### Phase 2 — web-scanner evidence (Nikto/ZAP)
6. Options on this machine (no Docker/WSL/Java present): install Temurin JRE
   (winget) for ZAP, and either Strawberry Perl for Nikto or use ZAP only.
   Prefer ZAP-only if you must pick one: `zap-baseline.py -t URL -J out.json`
   matches the orchestrator's planned command exactly.
7. Run `scan --tool zap` after Nmap proves the endpoint (orchestration already
   handles this), commit captures under `tests/fixtures/zap/` with provenance.
   **Accept:** `parse_zap_json` verified on real output (the reader's
   `tests/fixtures/zap/README.md` table gets its first rows); findings flow
   through enrich→rank.

### Phase 3 — LLM rationale (optional but cheap)
8. Install Ollama, pull ONE model (charter default `llama3.2:3b`), record the
   decision in `docs/decisions.md` (model, digest, license, smoke test).
9. `vulnassess explain --run-id ... --ollama-host http://127.0.0.1:11434`.
   **Accept:** report footer shows the model reworded sentences AND the
   validation/fallback counts; scores byte-identical to `--no-model` run.

### Phase 4 — research evidence (the real blocker: humans)
10. Recruit 2–3 practitioners for expert rankings (format: `experts: [{name,
    ranking}]` + `expert_critical`); freeze the cohort with `research
    cohort-freeze`; run `eval/context-eval`, `eval/ranking-eval`, `ablate`,
    `stability`. **Accept:** RQ1–RQ4 move from NOT RUN to actual decisions —
    the first time any hypothesis claim becomes eligible.
11. Human role-model labels via `model labels` → disjoint splits → `model
    train/evaluate`. Promotion out of shadow mode stays gated by the existing
    manifest workflow (do not bypass).

### Phase 5 — polish (as needed)
12. Demo upkeep: after any pipeline change, `python prepare_data.py` and
    re-export `standalone/*.html` (commands in the demo repo README/commit).
13. Optional: `uv`/venv documentation for newcomers, PDF export (deferred by
    decision), pre-commit hooks (deferred).

### Standing don'ts
- Don't reintroduce "provisioning complete" style manifests; status lives in
  `DOWNLOADS_REQUIRED.txt` + evidence ladder only.
- Don't loosen the reader's security checks to make a capture parse; if a real
  scanner format trips them, extend the allowlist narrowly (SCAN-01 pattern)
  with a test.
- Don't let anything bind non-loopback without an explicit reason and a
  netstat check.
- Don't upgrade ruff/pyright pins casually; the ruleset is version-stable by
  config, but re-run the full gate before pushing.

## Execution ledger - 2026-09-23

This ledger records the new end-to-end audit. Earlier machine inventories and
completion statements above are historical, not evidence for this machine.
Scope: PROJECT.md stages 1-8, trained context inference, deterministic ranking,
and independent evaluation. The final user directive requests an adversarial
audit; no product completion or policy approval is inferred from its goals.

### Cycle 1 - locate the target-first execution path

- Objective: trace a new authorized target from application input to report.
- Current blocker: no joined target-first path has been established.
- Evidence: VERIFIED, `git status --short --branch` returned
  `## audit-no-assumptions...privwork/audit-no-assumptions` with nine modified
  files; `git log -6 --format="%h %s"` identified HEAD as
  `89ec696 docs: database schema, data flow, retention, and migration summary`.
  Existing UI work is preserved.
- Evidence: VERIFIED, local source reads of `vulnassess/ui/server.py` show
  `if self.command != "GET"` returning `405, "UI supports GET only"`;
  `vulnassess/cli.py::cmd_scan` emits outcomes after `orchestrator.orchestrate`
  without invoking `pipeline.do_import` or downstream processing.
- Change made: this ledger only; no runtime, scope, provider, dependency, or
  fixed-interface change.
- Test performed: NOT RUN, isolated target-intake and orchestration probes are
  next; the source observations do not establish runtime integration.
- Result: NOT RUN, end-to-end acceptance remains unproved. A writable assessment
  API, new authorization schema, and remote reasoning would require resolving
  the standing fixed-contract and local-only restrictions, not silently
  replacing them with a new document.
- Next action: verify installed tooling, run the supported local gate, and
  exercise target intake and scanner-to-import boundaries without network use.

### Cycle 2 - execute the target and scanner boundaries

- Objective: distinguish a real assessment lifecycle from scanner-only success.
- Current blocker: the HTTP application is a viewer; scan execution has no
  automatic handoff to import or persistence.
- Evidence: TESTED WITH MOCKS, socket-free `UiApplication`/`request` probes
  returned `INTAKE {"new_assessment_get": 404, "create_post": 405}`. Planning
  `portal.example.invalid` raised `ScopeError`, with `DNS_CALLS 0`. A configured
  CIDR contains `192.168.0.116`, but the planner rejects it because it is not an
  explicitly listed target. The canary was also rejected before execution.
- Evidence: TESTED WITH MOCKS, the injected scanner probe returned
  `MOCK_SCAN_HANDOFF {"exit": 0, "complete": true, "database_created": false,
  "summary_created": true, "outcomes": 1}`. A second probe returned
  `complete: true` while both web tools said
  `successful Nmap output did not contain target 172.28.0.11`.
- Change made: copied 228 tracked paths, including current edits, into a local
  temporary source snapshot; backed up SQLite with a read-only source
  connection. No original data or runtime code changed.
- Test performed: TESTED WITH MOCKS, system Python ran pytest against
  `tests/test_orchestrator.py tests/test_operations_cli.py
  tests/test_reader_security.py tests/test_intel_trace.py
  tests/test_settings_strict.py`, with socket creation and DNS blocked.
- Result: TESTED WITH MOCKS, `39 passed, 4 subtests passed in 5.50s` and
  `OFFLINE_FOCUSED_EXIT 0`. This is not live scanner verification.
- Result: MISSING, `nmap`, `nikto`, `zap-baseline.py`, `ollama`, `make`,
  `data/feeds`, `data/lab/canary.log`, and `lab/canary_access.log` were absent
  from the checked PATH or paths. Both inspected Python environments lack
  Ruff, Pyright, pytest-cov, and psycopg; only system Python has pytest.
- Result: VERIFIED, system Python `scripts/check.py` exited 1 with
  `GATE INCOMPLETE: missing prerequisites: ruff lint, ruff format, pyright,
  pytest + coverage`. Coverage is unmeasured, not a passing threshold.
- Next action: audit AI1 source, dataset independence, and the AI1-to-AI2
  uncertainty handoff; run the broader suite in the isolated snapshot.

### Cycle 3 - test the trained-context claim

- Objective: determine which model is present and whether canonical use is
  gated by independent validation.
- Current blocker: the only artifact in `models/` is synthetic, and the
  optional canonical-context path bypasses the promotion workflow.
- Evidence: VERIFIED, structured reads of `models/synthetic-role-model.json`
  returned hash `d1a13c5e7302dca5`, task `asset_role_shadow`, 9 classes, 134
  features, 54 synthetic examples/54 declared groups, and temperature 0.25
  selected on 18 synthetic calibration examples/18 declared groups.
- Evidence: VERIFIED, system Python evaluated the existing synthetic datasets:
  `TRAINING` and `CALIBRATION` both returned accuracy/macro-F1/coverage 1.0,
  abstention 0.0 and ECE 0.0000003. These are synthetic replay measurements,
  not independent model-quality evidence. `SPLITS` returned
  `shared_group_ids: 0`, `identical_feature_vectors_across_splits: 17`, and
  `evaluate_accepts_training_dataset: true`.
- Evidence: VERIFIED, `pipeline.do_context(..., model_path=...)` on the isolated
  stored synthetic demo changed two role sources from `rule` to `model` without
  a promotion manifest. The persisted role has only `confidence`, `evidence`,
  `source`, and `value`; it drops model hash, margin, abstention, coverage, and
  OOV details. This contradicts an unconditional shadow-only claim.
- Change made: no runtime/model changes; observations recorded here. The
  isolated demo context was restored through the default rule path afterward.
- Test performed: VERIFIED, artifact loading checked its hash; real model
  inference was executed only against existing synthetic records. No training
  labels, scanner evidence, approvals, or real-world metrics were invented.
- Result: MISSING, independently human-labelled train/calibration/held-out data
  and an unseen-environment evaluation have not been found in the inspected
  model/data locations. Their absence is not permission to promote this model.
- Next action: inspect structured analyst grounding, persistence and report
  paths, then execute the available real-capture replay with its limits stated.

### Cycle 4 - probe the reasoning analyst

- Objective: determine whether AI2 is a grounded analyst and whether its
  guards hold under adversarial input.
- Current blocker: the case builder loses model uncertainty, and three guards
  fail on bounded synthetic probes.
- Evidence: TESTED WITH MOCKS, `analyst.build_case` produced a structured case
  with `services`, `context`, `findings`, per-item `evidence_id` citations,
  CVSS/EPSS/KEV/`match_method` intelligence and the deterministic score. This is
  more than sentence rewriting. The role object carried only `confidence`,
  `evidence`, `evidence_id`, `source`, `value`: no model hash, margin,
  abstention, feature coverage, or OOV list reaches AI2.
- Evidence: TESTED WITH MOCKS, `required_untrusted_prefix: false`. The analyst
  prompt uses `<untrusted_evidence>` and never emits contract I2's required
  `untrusted data follows` prefix, unlike `explain.build_prompt`.
- Evidence: TESTED WITH MOCKS, with 140 synthetic services the evidence budget
  filled and the finding cited `E128`, whose stored text is a service banner.
  A citation can therefore point at unrelated evidence instead of failing.
- Evidence: TESTED WITH MOCKS, a 24,043-character service banner with a
  `\x01` control character reached the case unsanitised and closed the
  untrusted block early: `closing_delimiters: 2`. `_clean` is applied to the
  finding/score/intel text, not to `services`.
- Evidence: TESTED WITH MOCKS, `validate_analysis` accepted a summary claiming
  a fabricated CVE and a replacement priority, because only citation IDs and
  field shapes are checked. Stored scores were unchanged.
- Evidence: TESTED WITH MOCKS, a mocked 66,560-byte structured response was
  accepted although `MAX_RESPONSE_BYTES` is 65,536: the streaming path never
  enforces the declared limit.
- Evidence: TESTED WITH MOCKS, an unavailable provider raised `LLMUnavailable`
  and left the assessment byte-identical, with no structured fallback.
- Change made: none in runtime code; the probes used synthetic inputs and a
  non-forwarding mocked transport. No model endpoint was contacted.
- Result: TESTED WITH MOCKS, AI2 is grounded but not defended; provider
  selection is also hard-coded to `OllamaClient` at the analyst boundary.
- Next action: replay the available real captures through the report path.

### Cycle 5 - replay real captures end to end

- Objective: measure how far the current pipeline runs on recorded evidence.
- Current blocker: live scanning and live inference cannot run here.
- Evidence: VERIFIED, in the isolated copy the existing `demo` command replayed
  the three committed real Nmap captures plus the real ZAP capture against the
  curated real feed subset and exited 0: 3 hosts, 225 findings, 225 scores,
  `epss 3, kev 3, nvd 3`, `enrich: 3/225 findings matched`, and a 191,267-byte
  report. Re-ranking reproduced byte-identical stored scores
  (`repeat_rank_equal: true`), and the three baseline orders each had 225 items.
- Evidence: VERIFIED, the same run printed `No CVE appears on two or more hosts
  in this run; the two-machine comparison needs one.` The signature experiment
  currently has no real-capture instance.
- Evidence: VERIFIED, the hash-verified model predicted `file_share` for the
  Juice Shop web host `172.28.0.12` at confidence 0.855 without abstaining
  (coverage 0.348, 15 OOV features), and `file_share` for `172.28.0.10` at
  0.994. The rule path independently produced `file_share` for `172.28.0.12`,
  and the stored reason reads `internet-facing file share`. This is a real
  generalisation failure on real evidence, not a fixture artifact.
- Result: MISSING, live target intake, resolution, scanner execution and model
  inference remain unproved. `nmap`, `nikto`, `zap-baseline.py` and `ollama`
  are absent from PATH and the checked install locations, and nothing is
  listening on the local model port.
- Result: NOT RUN, no scan, DNS query, feed download, or model request was
  issued during this audit; a socket/DNS guard was active for every probe.

### Audit verdict - 2026-09-23

STATUS: EXTERNAL BLOCKER for the live end-to-end objective, plus repository
defects that are fixable here. The acceptance criteria are NOT met.

Blocked outside the repository, with the exact human action required:

1. Scanner execution: install Nmap, and Nikto or ZAP, then supply an empty
   canary log path for `scan --execute`.
2. Reasoning provider: run a local model service, or supply approved
   credentials and an approved policy change for a remote provider. The
   current documents require local-only inference.
3. Quality gate: provision Ruff, Pyright and pytest-cov; `scripts/check.py`
   reports `GATE INCOMPLETE` and coverage is unmeasured.
4. Real labels and expert rankings: no human-labelled role dataset and no
   expert judgment file exist, so AI1 promotion and RQ2/RQ3 stay unevaluated.
5. Authorisation: a new unseen target requires an owner-approved scope entry.

Requires human decision before implementation, because the request conflicts
with recorded contracts:

1. Writable target intake contradicts the GET-only viewer contract in
   `docs/ui-contract.md`; the assessment schema already has the tables, but no
   approved write path or ADR exists.
2. Canonical model-derived context is blocked by MODEL-06 and OPERATIONS-01,
   yet `context --model` already overrides the rule role without a manifest.

Repository defects to fix under existing contracts, in priority order:

1. `orchestrate` reports `complete: true` when discovery omits the requested
   target; incomplete coverage must not read as success.
2. `cmd_scan --execute` writes a summary but never imports or persists; the
   scan-to-store handoff is missing.
3. Analyst evidence overflow reuses the last ID, service text is unsanitised,
   the I2 prefix is absent, the response-size limit is unenforced on the
   streaming path, and validation permits fabricated CVEs and scores in prose.
4. `context --model` bypasses `model_governance.validate_promotion` and drops
   model hash, margin, abstention, coverage and OOV from the stored profile.
5. `tests/test_assessment_store.py::NoBrowserWriteAccess` opens real sockets,
   contradicting invariant I4; three `test_ui` contract tests still fail from
   the earlier merge.
6. The bundled model is synthetic-only: 54 training and 18 calibration
   examples, all `label_source: synthetic`, with 17 identical feature vectors
   shared across the two splits despite distinct group IDs.
