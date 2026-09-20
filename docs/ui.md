# VulnAssess UI

## Workflow canvas - 2026-09-21

The user requested a separate Make-style visualization of the entire project,
not a restyle of the four-stage notebook. This serves PROJECT.md Stage 7 and
cross-cutting context/ranking/evaluation auditability. The workflow is a second
view of the existing records, not a second pipeline or a new scoring model.

```text
python -m vulnassess ui --run demo --port 8766
```

Open `http://127.0.0.1:8766/workflow?run=demo`. The assessment header also has an
Open workflow canvas link; Open assessment returns to the original view with the
same run. Existing offline exports remain unchanged and do not show the live link.

The canvas connects target/scope, Nmap/ZAP/Nikto imports, canonical records,
NVD/EPSS/KEV enrichment, context, optional role classification, deterministic risk,
priorities, recorded explanations, reporting, local analysis, expert evaluation
and re-scan comparison. Click a node for input, operation, output and source
records. Choose a target or a single finding to follow only its evidence.
The diagram supports pan, zoom, Fit, keyboard panning and an Escape-close inspector.

Node states mean exactly what they say: import recorded, stored output, current
configuration, output not attached, or local request status. Edges are data
dependencies, never execution evidence. Missing report/evaluation/re-scan artifacts
are not called completed. No queue metrics or synthetic scanner results are invented.
The current demo remains visibly labelled synthetic.

The Local AI analyst node reuses the already-existing `/api/analyst/<run>/<host>`
route. It requires an explicit Analyze target click and uses the whole selected
host, even when the diagram traces one finding. Merely opening the page, selecting
a node, filtering or refreshing does not invoke a model. The returned advisory
confidence is separate from deterministic risk. There is no analyst-to-scoring
edge, no timer-driven stage completion and no scanner action on this page.

The workflow has its own HTML, stylesheet and JavaScript modules, with neutral
circle nodes, local SVG icons and curved dependency lines. Its palette is scoped
in the common tokens file. It loads no framework, CDN or new dependency. It is a
live visualization; it is not included in the existing single-file export.

### Verification

VERIFIED: existing system Python was used for the full test suites because the
project venv lacks pytest. No dependency was installed or copied.

```text
& 'C:\Users\amitdamle\AppData\Local\Microsoft\WindowsApps\python.exe' -m unittest -v
Ran 254 tests in 17.142s
OK

& 'C:\Users\amitdamle\AppData\Local\Microsoft\WindowsApps\python.exe' -m pytest -q
259 passed, 353 subtests passed in 15.47s
```

There were no test failures or fixture skips in those completed runs. The initial
venv unittest attempt had a missing-pytest import error, not a workflow assertion
failure. The available system interpreter resolved that test-execution blocker.

TESTED WITH MOCKS: new focused checks:

```text
& '.\.venv\Scripts\python.exe' -m unittest -v tests.test_ui.TestUiContract.test_workflow_graph_is_grounded_and_read_only tests.test_ui.TestUiContract.test_workflow_is_independent_and_does_not_run_analyst
test_workflow_graph_is_grounded_and_read_only (tests.test_ui.TestUiContract.test_workflow_graph_is_grounded_and_read_only) ... ok
test_workflow_is_independent_and_does_not_run_analyst (tests.test_ui.TestUiContract.test_workflow_is_independent_and_does_not_run_analyst) ... ok
Ran 2 tests in 0.277s
OK
```

The graph test checks every node and edge, preserves stored score values, narrows
context to the traced host, marks missing outputs and isolates analyst state by
run/host. It executes only pure JavaScript through the already-installed Node.

VERIFIED: live loopback smoke, `& '.\.venv\Scripts\python.exe' scripts/check_ui_server.py --run demo`:

```text
GET /workflow -> 200
GET /static/workflow.css -> 200
GET /static/workflow.js -> 200
GET /static/workflow-data.js -> 200
SCORES: 6 API records equal stored JSON
DATABASE: SHA-256 unchanged
SERVER: stopped
UI LOOPBACK SMOKE PASSED
```

VERIFIED: browser checks exercised node selection, stored risk inspection, zoom/Fit,
keyboard panning and the inspector at a device-emulated 390px width. Browsing
made no analyst request. `page.goto('/workflow?run=verify')` showed
`No stored output` and no host options beyond the empty selector;
`page.goto('/workflow?run=__workflow_missing_run__')` showed
`Records unavailable` after the expected HTTP 409. Both checks used the local
`http://127.0.0.1:8766` origin and restored the demo afterward.
TESTED WITH MOCKS: an intercepted analyst failure was
rendered as text, did not execute HTML-like content, permitted retry and did not
leak to another host. Pointer-pan logic was tested with synthetic pointer events
and mocked pointer capture. The integrated hidden tab delivered pointer moves but
not pointer-down through its mouse harness; physical dragging was not established
by that harness. NOT RUN: real Ollama inference and scanner execution in this change.

MISSING: the venv's pytest; Ruff lint/format, Pyright and pytest-cov in the checked
environments. Source coverage is unmeasured. The existing gate script reported:

```text
GATE INCOMPLETE: missing prerequisites: ruff lint, ruff format, pyright, pytest + coverage
```

The blocked gate commands are `python -m ruff check .`,
`python -m ruff format --check .`, `python -m pyright`, and
`python -m pytest --cov=vulnassess --cov-fail-under=75`. Human-approved provisioning
is required before rerunning `python scripts/check.py`; no installation command
was run. VERIFIED: `git diff --check` returned no output (exit 0).

MISSING: a human-captured Nikto JSON file under `tests/fixtures/nikto/` with a
provenance row in [its README](../tests/fixtures/nikto/README.md), which currently
lists no real capture. Existing synthetic examples are not real-tool evidence.
The completed test run reported zero skips; that is not a Nikto integration claim.

### Screenshots

VERIFIED: `& '.\.venv\Scripts\python.exe' scripts/capture_ui_phase2.py --workflow --run demo`
uses installed Edge and an ephemeral loopback viewer. It only reads records and
opens node inspectors; it never clicks Analyze target.

| View | Image | Size |
| --- | --- | --- |
| Entire workflow | [Workflow overview](ui/screenshots/workflow-overview.png) | 1600x1000 |
| Stored risk inputs | [Score inspector](ui/screenshots/workflow-inspector.png) | 1440x1000 |
| Optional local analysis | [Analyst inspector](ui/screenshots/workflow-analyst.png) | 1440x1000 |
| Narrow inspector | [Narrow workflow](ui/screenshots/workflow-narrow.png) | 500x900 |

### Increment status

STATUS: visualization implemented and left running locally; no model-quality or
fully green quality-gate claim. BRANCH / COMMIT: `audit-no-assumptions` based on
`33f1293`; changes uncommitted. GATE: available tests pass as quoted above;
lint/type/coverage prerequisites remain MISSING.

BUILT: independent workflow canvas, evidence inspector, target/finding tracing
and a clearly separate existing analyst action. CHANGED: `vulnassess/ui/`,
`tests/`, `scripts/`, `docs/`. DECIDED: data dependencies and recorded states over
animated progress theatre; reuse backend contracts over new pipeline execution.
DECISIONS: WF-01 and WF-02 below in the decision log. EVIDENCE: commands and
captures above. DEFERRED: real-model/scanner verification and attachment of
persisted report/evaluation/re-scan results; these do not prevent inspection of
stored context and ranking evidence. NEXT: user review of the new canvas.

## One-interface consolidation - 2026-09-19

This section records the earlier consolidation, before the later workflow request.
The four-stage workbench remains the assessment renderer. The synthetic
simulation now builds a labelled assessment and exports this same renderer; the
`visualize` command is a compatibility alias for the same export path. The historical
eight-stage replay remains unreferenced source history, not a second product. The
printable assessment report remains a report, not a second UI.

The active Evidence stage uses explicit finding cards (scanner, stored band, title,
CVE/native identity and endpoint) rather than the rejected door metaphor. The guided
action is "Trace one finding." Offline analytics use no inline style attributes or
JavaScript style mutation, so the hash-pinned CSP remains strict and animations work
without `unsafe-inline`.

The Risk stage uses a proof-first hierarchy inspired by TypeSafe AI's sequencing, not
its branding: a large thesis, oversized stored metrics, sparse technical framing and
one mechanism at a time. VulnAssess retains its own palette, typography, evidence
density and analyst navigation; no external visual assets or marketing copy are used.

## Resume checkpoint - 2026-09-13

The user requested a commit/push checkpoint and a pause. This is a work-in-progress
four-stage interface, not an accepted reference-parity release. Ownership remains
PROJECT.md Stage 7 (Report), supporting evidence auditability for context and risk.
The old [phase 1](ui-phase-1.md) and [phase 2](ui-phase-2.md) reports are historical.

The current UI is in the `vulnassess/ui/` package. `reports/visual-simulation.html`
is now a synthetic export of that same workbench.

## Run and export

```text
python -m vulnassess ui --run demo --port 8765
python -m vulnassess ui --run demo --export reports/ui-demo.html
```

The live address is `http://127.0.0.1:8765/`; Ctrl-C stops it. Use an unused port
if occupied. `--run-id` aliases `--run`. `--db` and `--config` accept existing
local inputs. With no selected run, the page provides a stored-run selector.
The single-file HTML opens directly from disk and has no external assets.

The local `demo` run is rebuilt from the existing labelled synthetic demo
fixtures when absent or stale; it is not recovered historical timing or real lab
evidence. The local database and generated assessment reports remain ignored and
are not included in the source checkpoint. A clean checkout needs its actual
local input artifacts; the UI never creates substitute records.

## What is built

| Surface | What it teaches | Current behavior |
| --- | --- | --- |
| Evidence | Facts start with observations | Stored hosts, explicit finding cards, scanner quotes, scope configuration and feed provenance |
| Context | Every inference needs a clue | Role, exposure, controls, confidence, source, manual tags and evidence |
| Risk | Same weakness can have different urgency | Shared-CVE comparison using stored scores, differing inputs, weights and a labelled browser-only sandbox |
| Priorities | Each priority can be inspected | Stored risk order, facets and an inspector retaining source identity |
| Inspector | Trace the result to its inputs | Recorded reason, score chain, context, supported fix references and provenance |
| Tour | Follow one finding across the stages | Six captions pinned to the lower-risk host of the first shared CVE |

The demo comparison displays stored 79.0/High and 100.0/Critical scores. This is
record fidelity, not evidence of improved triage. Palatino/system serif identifies
headings and inferred values; monospace identifies quoted data; sans identifies
labels. Severity uses the existing token colours. The live page loads
`workbench.css` and external `app.js`, not the retained phase-2 `entry.css`.

Hash state restores stages, filters and finding selection. Examples:

```text
#stage-priorities?band=High
#stage-risk?theme=dark
#stage-evidence?theme=light&tour=1
```

The inspector has explicit Escape handling and synchronizes with Back/Forward.
The tour only scrolls a target when needed. A missing model is irrelevant to
viewing the stored assessment: both temporary model routes remain withdrawn.

## Read-only boundary

Only GET is accepted. SQLite is opened with `mode=ro`, and the viewer does not
scan, enrich, score, evaluate or train. Stored-record routes do not invoke a
model; the later AI-01 analyst action is the explicit local-inference exception.
The old runtime helper is retained but not imported by the HTTP server.
All recorded scores stay separate
from sandbox output. A future shadow prediction must remain beside rule context
and be labelled as having no effect on scores.

The sandbox recomputes locally under its fixed banner: "Sandbox. Nothing stored
changes." It uses current configuration, not an invented historical weight set.
Its fixture lives under `tests/synthetic/`, not among real-capture fixtures.
The export embeds its data, stylesheet, JavaScript and arithmetic fixture, with
hash-based CSP and `connect-src 'none'`. Refresh is disabled for offline exports.

## Verified checks

VERIFIED: `python scripts/check_ui_cvss.py --generate` returned:

```text
PYTHON CVSS: 211 of 211 match
JAVASCRIPT CVSS: 211 of 211 match Python
SANDBOX FORMULA: 144 of 144 context/threat cases match Python
```

The 211 vectors are eleven fixed regression cases and 200 seeded valid vectors.
This establishes parity with the repository's Python implementation, not an
independent certification of CVSS. The 144 cases cover context/threat combinations.

VERIFIED: `python scripts/check_ui_server.py` returned:

```text
SCORES: 6 API records equal stored JSON
GET /api/model -> 404
GET /api/model/run -> 404
POST /api/model/run -> 405
DATABASE: SHA-256 unchanged
SERVER: stopped
UI LOOPBACK SMOKE PASSED
```

Browser checks exercised stage navigation, filtered reloads, the inspector,
Back/Forward, Escape handling, the six-step tour and sandbox reset/isolation.
The export was exercised from `file://` with HTTP(S) blocked; no request was
attempted. Simulated physical keypress delivery in the integrated browser was
inconsistent; the explicit Escape handler and native button click were checked.

VERIFIED: final checkpoint run, `python -m unittest -v`:

```text
Ran 235 tests in 13.327s
OK (skipped=2)
```

VERIFIED: final checkpoint run, `python -m pytest -q`:

```text
SKIPPED [1] tests\test_all.py:1035: fixture not provided: tests/fixtures/nmap/*.xml
SKIPPED [1] tests\test_all.py:1044: fixture not provided: tests/fixtures/zap/*.json
233 passed, 2 skipped, 342 subtests passed in 16.52s
```

VERIFIED: `python scripts/check.py` reported:

```text
GATE INCOMPLETE: missing prerequisites: ruff lint, ruff format, pyright, pytest + coverage
```

Repeat the local checks with:

```text
python -m unittest -v tests.test_ui
python -m unittest -v
python scripts/check_ui_server.py
python scripts/check_ui_cvss.py
python scripts/check.py
```

MISSING at the last gate check: Ruff lint/format, Pyright and pytest-cov. A human
will provision them; do not install or download them. The UI's temporary
behavioral acceptance criterion does not claim a green full quality gate or
measured source coverage. Real Nmap and ZAP capture tests remain the two skips;
synthetic examples do not satisfy those capture requirements.

## Current screenshots

VERIFIED: `python scripts/capture_ui_phase2.py --workbench` created these local
Edge PNGs. Each linked file was opened for visual inspection. No images were
downloaded. The script name is retained from phase 2; `--workbench` selects the
current interface.

| View | Image | Capture dimensions |
| --- | --- | --- |
| Evidence | [Evidence screenshot](ui/screenshots/workbench-evidence.png) | 1280x900 |
| Context | [Context screenshot](ui/screenshots/workbench-context.png) | 1280x900 |
| Risk | [Risk screenshot](ui/screenshots/workbench-risk.png) | 1280x900 |
| Priorities | [Priorities screenshot](ui/screenshots/workbench-priorities.png) | 1280x900 |
| Inspector | [Inspector screenshot](ui/screenshots/workbench-inspector.png) | 1280x900 |
| Dark theme | [Dark screenshot](ui/screenshots/workbench-dark.png) | 1280x900 |
| Narrow layout | [Narrow screenshot](ui/screenshots/workbench-mobile.png) | 500x844 |

The 390px window-size capture was clipped because the browser reported a wider
viewport. The narrow PNG is therefore honestly labelled 500px; a separate device
emulation check used an actual 390px viewport with no page overflow.

NOT RUN: an accepted tour screenshot. Edge produced `workbench-tour.png`, but its
caption was clipped in the saved image even though live tour bounds fit. That
attempt is retained for diagnosis and is not a visual acceptance result. Recheck
the saved tour image after resuming; do not claim it passed or replace it with a
fabricated screenshot.

## Resume next

Review the current live UI with the user before another design change.

Refresh `reports/ui-verify.html` after the final JavaScript changes; the local
export generated earlier may predate the last tour/navigation fixes.

Resolve the tour capture framing and rerun the browser interactions. Do not
fix the known unrelated visual-simulation flake during UI work; report its
traceback if it recurs.

Obtain the authoritative reference before claiming exact text/visual parity:

```text
C:\Users\amitdamle\Downloads\fragmented\doors-reference.html
```

Keep missing data explicit. Feed ages, most stage totals, per-file import
timestamps/scanner versions, refusal history, modification rule names and
persisted evaluation/critical-queue metrics are not all stored. Do not derive
or copy them from reference placeholders to make a screen look complete.

The G25 Self-check is under the sandbox disclosure. A dedicated `#selfcheck`
screen, the score-travel scale/animation, and an existing report-of-record
link in the export still need a requirements review before claiming full
parity. UI-UPGRADE steps 2-6 have not been started as separate increments.

MISSING: exact reference parity, real `tests/fixtures/nmap/*.xml` and
`tests/fixtures/zap/*.json` with provenance, real Nikto captures and `data/feeds/`.
No research improvement or validated model accuracy is asserted by this UI.
