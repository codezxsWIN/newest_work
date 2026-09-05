# PROJECT - The whole idea

**AI-Based Network Vulnerability Assessment Tool**

**Research focus: Context Is Not Free**

Design Experience project, MPSTME, SVKM's NMIMS, 2026. Nine students, one industry mentor.

This is the canonical project brief, based on the project description supplied on
2026-09-06. Read it before planning implementation. Every task must name the
pipeline stage or cross-cutting research component it serves.

This document describes requirements and planned behavior, not completed features
or measured results. The [operating rules](../.github/copilot-instructions.md),
[fixed contracts](contracts.md), [security boundary](security.md), and append-only
[decisions](decisions.md) remain binding. The contracts arrived during preparation
of this brief and have been incorporated without changing them. No installation,
download, scan, or broader LLM permission is granted here.

## 1. What this is

A local-first system that collects authorised scan evidence, identifies security
weaknesses, matches evidence to locally cached vulnerability intelligence, ranks
findings by risk in their deployment context, explains priorities, reports them,
and re-scans after fixes to assess whether they worked.

Assessment processing and the local model run on hardware inside the organisation.
No scan data is sent to a cloud model or service. The current implementation scope
is **the explicitly authorised isolated lab only**, not an organisation's production
network. Offline operation is a requirement to verify, not a security guarantee.

## 2. The problem it solves

1. **Fragmented output.** Multiple scanners use different formats and names.
   Correlated alerts can describe the same underlying issue, while superficially
   similar alerts can also describe different weaknesses.
2. **Context-blind ranking.** A CVSS base score is not an assessment of a specific
   deployment. The same flaw on a test asset and an internet-facing customer
   database can have different operational significance. Environmental metrics
   permit context, but collecting and maintaining that context costs effort.
3. **Unverified fixes.** A report alone does not establish that remediation worked,
   that a disappearing finding was actually fixed, or that posture improved.

Cloud-based analysis can introduce disclosure, recurring-cost, and connectivity
concerns. Local-first operation addresses those concerns without claiming that all
existing products require cloud processing or that local software is inherently safe.

## 3. The research focus: Context Is Not Free

The headline contribution is automatic, evidence-backed deployment-context
inference: asset role, exposure, and observed compensating controls. A deterministic,
published formula combines that context with CVSS Environmental metrics, EPSS, and
CISA KEV. A local model supplies a validated one-line reason, never a risk score.

The published risk formula remains a hypothesis. Under the current
[fixed weight configuration](contracts.md), it is:

```text
base = environmental_score * 10
percentile = epss_percentile if available else 0.5
threat = 0.5 + 0.5 * percentile
risk = base * threat
if kev:
    risk = max(risk, 90)
```

EPSS percentile is in `[0, 1]`; it is not EPSS probability. Bands are Critical
`>= 80`, High `>= 60`, Medium `>= 35`, otherwise Low. Context mappings, missing-data
policies, translation provenance, and any later changes belong in the scoring
specification and decision log. The fixed contract's missing percentile of `0.5`
produces a threat multiplier of `0.75`; the earlier [scoring notes](scoring.md)
instead specified a missing-data multiplier of `0.5`. This discrepancy must be
reconciled before scoring implementation; do not silently conflate probability,
percentile, and multiplier. The fixed contract governs unless a human approves an
ADR. It also defines additional role mappings, criticality adjustments, and
native-evidence fallbacks absent from the older notes.

Evaluate against 2-3 practitioners' full rankings and `expert-critical` sets:

- **Kendall's tau:** ranking agreement, per expert and in aggregate.
- **NDCG@10:** quality of the first ten findings using a documented relevance mapping.
- **Critical-queue size at full recall:** the shortest ranked queue containing every
  expert-critical finding. Report this separately from fixed-threshold band counts.
- **Baselines, ablation, and variance:** compare CVSS-only, CVSS+EPSS, and the proposed
  method; disable context/threat features individually and report variability.

Weights are hypotheses until evaluated. Do not tune on the evaluation judgments or
claim an improvement before measuring it. Negative and inconclusive results must be
reported honestly. Everything else in the tool exists to make this experiment
possible, reproducible, and auditable.

## 4. The pipeline

The eight stage names below follow the supplied deck-derived brief. The module
column names intended destinations, **not implementation status**. Paths marked
planned must not be assumed to exist.

| Stage | Name | Responsibility | Module or planned destination | Prompt |
|---|---|---|---|---|
| 1 | Target input | Accept an IP, hostname, or subnet only within explicit authorisation; reject scope violations before scanner execution. | `settings.py` (planned), [runner.py](../src/vulnassess/adapters/runner.py), [scope.yaml](../config/scope.yaml) | 1A, 3 |
| 2 | Scan orchestrator | Discover with Nmap first, derive web endpoints, select web tools, and record the complete run plan and outcomes. | `orchestrator.py` (planned) | 3B |
| 3 | Safe scanning | Run Nmap, Nikto, and ZAP with non-destructive settings, per-process scope checks, bounded execution, and impact evidence. | [adapters](../src/vulnassess/adapters/) | 3 |
| 4 | Unified result engine | Normalize observations, merge only justified duplicates, preserve every source, and expose evidence-based confidence. | [schema](../src/vulnassess/schema/), [store](../src/vulnassess/store/), `unify.py` (planned) | 2, 4B |
| 5 | AI security analyst | Infer context with rules and produce validated local-model rationales; do not let model output determine scoring inputs or hide findings. | [context](../src/vulnassess/context/), [explain](../src/vulnassess/explain/) | 5, 6, 8 |
| 6 | CVE intelligence | Read human-provided NVD, EPSS, and KEV snapshots offline, match carefully, and record feed dates and provenance. | [intel](../src/vulnassess/intel/) | 4 |
| 7 | Report | Present ranks, bands, reasons, evidence, formula inputs, provenance, low-confidence findings, and later re-scan trends. | [report](../src/vulnassess/report/) | 9 |
| 8 | Re-scan validation | Compare runs after remediation; distinguish fixed, still open, regressed, and not observable; show posture trends. | `rescan.py` (planned) | 11B |

Cross-cutting components:

| Component | Purpose | Destination | Prompt |
|---|---|---|---|
| Risk ranking | The research formula and audited Environmental mappings | [scoring](../src/vulnassess/scoring/) | 7 |
| Evaluation | Expert comparison, baselines, ablation, and variance | [eval](../src/vulnassess/eval/) | 10 |
| Lab and demo | Three vulnerable targets, an out-of-scope canary, and reproducible demonstrations | `lab/` (planned) | 11 |

These are **pipeline stages**, not the four implementation phases: Foundations
(1-4, including 3B/4B), Context inference (5-6), Scoring/explanation (7-9), and
Evaluation/lab (10-11B). Stage numbering is conceptual, not a strict execution order:
intelligence matching precedes final unification, context, ranking, and reporting.

## 5. Where the implementation differs from the slides

| Deck or proposed brief | Implementation boundary | Why |
|---|---|---|
| AI prioritises risks | A deterministic formula prioritises; the LLM writes no score or scoring input. | Reproducibility and an auditable research claim. |
| AI filters false positives | Evidence-based confidence and visible flags; source findings are never silently deleted. | Avoid invisible false negatives and preserve reviewable evidence. |
| AI explains vulnerabilities | One sentence from a fixed, delimited fact list, validated against unsupported claims, numbers, CVE IDs, and length. | Keep explanations tied to evidence. |
| AI resolves ambiguous roles | **Deferred.** Current policy is rule-based roles; unresolved cases remain explicit. | An LLM-selected role indirectly changes Environmental scoring. |
| AI performs semantic duplicate merging | **Deferred; disabled by default.** Deterministic, evidence-backed unification comes first. | Model-driven merging can change finding identity, queue size, and ranking. |
| CVE layer supplies CVSS | Include dated EPSS and KEV as well as CVSS. | Add exploitation intelligence without pretending it describes the local asset. |

The attachment proposes LLM-assisted roles, but existing hard rules forbid that
ranking influence. Clarification was requested and no answer was available.
The conservative current boundary is retained, not presented as a newly approved
change. Any expansion needs an explicit decision, provenance, reproducibility
controls, and revised evaluation. See the "Canonical project brief" and
"Project brief reconciliation" sections in [decisions.md](decisions.md).

## 6. The two-machine test

The test must isolate the effect of context. For the **same CVE and feed snapshot**,
both machines necessarily have the same EPSS percentile and KEV membership.
The supplied illustration's percentiles of 30 versus 95 and KEV "no" versus "yes"
cannot describe that experiment; they would require different intelligence states
or different CVEs and would confound the context comparison.

Use the following acceptance design, with human-confirmed fixture evidence:

| Input | Machine A | Machine B |
|---|---|---|
| CVE and base vector | Same confirmed CVE/vector | Same confirmed CVE/vector |
| CVSS base score | Same verified score; 9.8 only if the vector supports it | Same verified score |
| Asset role | Workstation | Database |
| Environment tag | Test | Production |
| Exposure | Internal | Internet-facing, explicitly simulated in lab scope |
| Controls | Only evidence-backed observations | Only evidence-backed observations |
| EPSS percentile | Same dated percentile `p` | Same dated percentile `p` |
| KEV for context-only comparison | False, confirmed from the same snapshot | False, confirmed from the same snapshot |
| Expected result | Lower priority for suitable validated inputs | Higher priority for those same inputs |

Print both complete breakdowns. Verify exact bands from the actual vectors and
formula; do not assert Medium versus Critical just because the illustration does.
If that exact contrast is required for the demo, demonstrate it with consistent,
confirmed inputs before adopting it as a golden assertion.

**Separate KEV-floor test:** with `kev=true`, both machines must have risk at least
90 and both must be Critical. Never change a CVE's KEV status per host to force a
desired result.

Rationales must not turn "no control observed" into "no control exists", or
"internal" into "isolated". The earlier candidate CVE remains unverified; see the
[explainer](explainer.md). Synthetic scoring cases may test pure logic, but cannot
be presented as real scanner or feed captures.

## 7. Non-negotiables

1. Scan only explicit targets permitted by [scope.yaml](../config/scope.yaml).
   CIDRs constrain authorisation; they do not authorise sweeping every host.
   Refuse violations before a scanner subprocess. A canary outside scope must
   receive no requests; missing canary logs are not proof of that requirement.
2. No cloud calls during assessment. Humans provide reviewed dependencies, images,
   models, and dated feed snapshots. Ollama runs locally. Installation, feed
   refresh, image/model pulls, Docker builds, and Compose startup are
   **not run by the agent**. Local artifact presence alone is not installation approval.
3. Scoring is pure and does not import from `explain/`. The LLM must neither compute
   scores nor select inputs that alter them under the current policy.
4. All scanner, feed, and model content is untrusted. Invariant I2 in
   [contracts.md](contracts.md) requires delimited, length-capped, control-character-
   stripped scanner content prefixed `untrusted data follows`, and schema-validated
   model output. A specified guard is not proof that its implementation passed.
5. Every inferred feature carries confidence, source (`rule`, `llm`, or `manual`),
   and a verbatim evidence quote. A provenance label does not authorise LLM scoring
   inputs. Record manual tags separately from inferred observations. Invariant I3
   requires a raw-record substring or the exact sentinel `none observed`; that
   sentinel does not prove a control or weakness is absent.
6. Preserve tool, raw path, record index, original finding IDs, and all evidence.
   Identical evidence, configuration, and pinned feed snapshots produce identical
   ranks, with deterministic tie-breaking.
7. Nothing is downloaded by the agent and nothing absent is assumed present.
   Humans capture real fixtures with a README naming capture date, command, and
   authorised target. Pure-logic synthetic data belongs in `tests/synthetic/`,
   with filenames starting `synthetic_`. Tests use no network; Ollama is mocked.
8. Missing input is an explicit error, not an empty-success result or generated
   substitute. Report exactly one evidence level per factual execution claim:
   **VERIFIED** (actual command/output), **TESTED WITH MOCKS**, **NOT RUN** (reason),
   or **MISSING** (exact prerequisite).
9. Use the current quality contract: Ruff lint/format, Pyright, pytest, and at least
   85% source coverage for implementation changes. Missing gate tools are blockers,
   never permission to install. Documentation-only changes do not establish a
   passing application gate.

## 8. What "done" looks like in December 2026

These are acceptance goals, not claims that the project has reached them:

- A human-run `make e2e` on the authorised lab prints the validated two-machine
  comparison, top priorities, and a report path.
- Every reported rank exposes its reason, evidence, context, formula inputs,
  scoring version, and feed dates. Low-confidence findings remain visible.
- `eval run` compares the method with CVSS-only and CVSS+EPSS using 2-3
  practitioners' rankings, critical sets, ablation, and variance. The research goal
  is better agreement and a smaller queue at full recall; report the measured
  outcome even if that goal is not achieved.
- A real remediation followed by a comparable successful scan is distinguished
  from unchanged exposure, evidence loss, an unavailable service, and regression.
  Do not claim that banner-only evidence proves a genuine fix.
- A human demonstrates offline operation after providing the required artifacts.
  Internet disconnection must not disable the isolated lab's own connectivity.
- The mentor can reproduce the run and audit its provenance. No result is inferred
  from a mock, a hypothetical table, or a missing capture.

## 9. Out of scope and open decisions

Future work credited in the supplied brief:

- Attack-path chaining across hosts: Arsh.
- Adversarial analyst manipulation via spoofed banners beyond the specified input
  guard: Ananya N.
- Autonomous exploitation of any kind: out of scope.
- Detecting AI-driven attackers: Shravani.

Before the relevant implementation, resolve:

- Whether to permit LLM-assisted roles or semantic merging at all; both remain
  deferred under the rationale-only rule.
- A human-confirmed golden CVE, common feed snapshot, vectors, and measured bands.
- Safe duplicate identity: a shared CWE or similar title is not sufficient proof
  that different URLs, instances, or vulnerabilities are the same weakness.
- Re-scan proof: a changed banner or missing CVE match alone cannot establish a
  patch; record scan success, comparable coverage, and vulnerability evidence.
- Align the older scoring notes with the supplied fixed weight configuration,
  including the missing-EPSS discrepancy described in section 3.
- The definitions of prompts A/1A/1B are still not supplied by this attachment.
  The [engineering contract](contracts.md), including I1-I5, now exists; its
  presence does not establish that its gates have run.
- Obtain human-approved ADRs for roadmap extensions to fixed commands, signatures,
  configuration, and storage. In particular, re-scan history must coexist with the
  fixed upsert rule that changes only `last_seen` and preserves original run
  ownership; do not invent a cross-run association table or migration.

## 10. Who did what

The following credits and work allocation are supplied by the team; they are not
a claim that the corresponding implementation has been completed.

| Contribution | Credited team members |
|---|---|
| Context-aware ranking | Arsh, Ananya K, Akshay |
| Local-first design | Akshay |
| Unified findings and evidence-based confidence | Maanya, Ananya K, Akshay |
| Re-scan and continuous assessment | Maanya |
| Evaluation rigour | Ananya N |
| Scan safety measurement | Shravani |
| Lab, expert study, and runs | Mahir, Shardul, Rudra |

The industry mentor and confirmed expert panel are not named in the supplied
brief. Do not invent identities or claim panel acceptance.

## Appendix A. Implementation sequence and missing stages

Supplied order:

```text
A -> 1A -> 1B -> 2 -> 3 -> 3B -> 4 -> 4B -> 5 -> 6 -> 7 -> 8 -> 9 -> 10 -> 11 -> 11B
```

The initial Prompt 1 scaffold predates this expanded sequence. The definitions of
A/1A/1B remain unspecified in this attachment. [contracts.md](contracts.md) is now
present and governs fixed interfaces. This roadmap does not imply those
prerequisites are implemented or passed.

Each implementation plan must name its branch, served stage, dependencies,
objective, tests, acceptance evidence, decisions, and next prompt. Read this brief,
the operating rules, and the engineering contract. Preserve one-prompt-at-a-time
review gates. New orchestrator/unification/re-scan APIs, commands, configuration
keys, and tables below are proposals: any extension to the fixed contract requires
a human-approved ADR before implementation. The brief is not that approval.

### Prompt 3B - Scan orchestrator

**Branch:** `prompt-3b-orchestrator`

**Serves:** pipeline stage 2; depends on Prompt 3.

Plan `orchestrator.py` with `plan(target, scope) -> ScanPlan` and
`execute(plan, run_id) -> RunSummary`.

- Resolve requested targets and reject any out-of-scope expansion before scanner
  execution. Maintain the explicit-host boundary.
- Discover with Nmap first. Derive HTTP endpoints from observed services/banners;
  use HTTPS for observed TLS or the documented 443/8443 rule.
- Run Nikto and ZAP baseline on those endpoints, never blindly on database ports.
  If no HTTP service is observed, record an explicit web-tool skip reason.
- Persist each tool's argv, start/end, exit code, raw path, finding count, and
  failure detail in the run summary. Ordinary tool failures may allow other tools
  to continue, but scope/canary violations fail the run and incomplete coverage
  must remain visible downstream.
- Route `scan <target>` through the orchestrator and retain an explicit `--tools`
  subset. Check an available `lab/canary_access.log`; non-empty access fails the
  safety check, while a missing log means safety evidence is missing.

Tests cover endpoint selection, no-web skips, TLS schemes, rejection before
subprocesses, recorded failures, complete summaries, and canary violations.
Synthetic plan tests are **TESTED WITH MOCKS**, not evidence that scanners ran.
Next: Prompt 4.

### Prompt 4B - Unified result engine

**Branch:** `prompt-4b-unify`

**Serves:** pipeline stage 4 and evidence-based false-positive handling; depends on
Prompt 4.

Plan `unify.py`, `UnifiedFinding`, and a `unified(run_id, id, json, confidence)`
store. Match within an asset/service block, preserve every source finding and
evidence string, and use stable, order-independent identities.

The supplied proposal uses shared CVE, shared CWE, or normalized title to identify
merge candidates. Before implementation, resolve the distinct-instance issue in
section 9; never treat generic CWE agreement alone as proof of a single root cause.

Proposed confidence hypothesis for future `config/unify.yaml`:

```text
start at 0.5
+0.3 for corroboration from two or more tools
+0.2 for a version-matched CVE
+0.1 for ZAP High or User Confirmed native confidence
-0.2 for an uncorroborated single Nikto/ZAP informational check
clamp to [0.05, 1.0]
below 0.3: flag likely_false_positive, retain visibly
```

These are proposed confidence weights, not risk weights or verified calibration.
Confirm their interaction before use. The attachment's optional token-similarity
`>= 0.6` / model-confidence `>= 0.8` semantic merge is **deferred** under the current
LLM boundary; `unify.semantic=false` does not authorise implementing a bypass.

After matching, `enrich` will invoke deterministic unification and downstream
stages will consume unified findings. Tests must cover non-merges across blocks
and distinct instances, justified merges, confidence, no deletion, full provenance,
and order independence. Do not claim real duplicate-reduction percentages from
synthetic examples. Next: Prompt 5.

### Prompt 11B - Re-scan validation and posture trend

**Branch:** `prompt-11b-rescan`

**Serves:** pipeline stage 8; depends on Prompt 11.

Plan `rescan.py` and:

```text
vulnassess rescan --baseline RUN_A --run-id RUN_B [--targets ...]
```

- Default to previously affected hosts/ports using a restricted orchestrator plan.
  An explicit full scan still obeys the same approved scope.
- Compare fingerprints and unified identities. `fixed` requires successful,
  comparable observations and justified remediation evidence; `still_open` means
  the weakness persists. `not_observable` includes missing service/host or failed
  coverage and must never count as fixed.
- Record new findings separately; identify regressions on previously observed,
  clean asset/service instances. A new finding is not a previously open finding.
- If matching disappears while the vulnerable detected version is unchanged,
  retain `still_open` and flag evidence loss. A banner-only change is insufficient
  to prove a fix; distinguish the illustrative rule from real remediation proof.
- Store band counts, mean risk, KEV counts, and changes since baseline. Treat
  `B.started - A.started` as an observed time-to-confirmation proxy, not the exact
  remediation time. Keep scope, feed, scoring, and scan-coverage changes visible
  so posture comparisons are interpretable.
- Extend the report with "Since last run" and chronologically ordered trends.

Tests cover justified fixes, unavailable services, failed coverage, regressions,
fake fixes/evidence loss, restricted plans, metrics, and trend ordering. Synthetic
comparisons do not establish successful real remediation. A human supplies the
first real end-to-end re-scan evidence.

## Appendix B. Corrections to the existing prompt sequence

- Prompt 0: read this document first and name the served stage in every plan.
- Prompt 3: serve stage 3; keep the runner single-tool and callable by 3B.
- Prompts 5, 6, 8: serve stage 5 as constrained in section 5.
- Prompt 7: serve the research focus; use the scientifically consistent tests in
  section 6, not the conflicting same-CVE/different-feed illustration.
- Prompt 9: include the low-confidence appendix from 4B and, once implemented,
  the "Since last run" section from 11B.
- Prompt 11: finish the human-run demonstration with the verified comparison and,
  once 11B exists, re-scan against a baseline. Any download-capable lab command is
  **not run by the agent**.
