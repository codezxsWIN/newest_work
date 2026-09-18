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
