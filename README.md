# AI-Based Network Vulnerability Assessment Tool

A local-first prototype that ranks vulnerabilities by **risk to this network**, not by CVSS
severity alone. It reads scanner output you already have, enriches it from offline snapshots of
three public feeds, infers deployment context from the scan evidence itself, and produces a
ranked list with a one-line reason, a recommended fix, an offline HTML report and an evaluation
table against expert rankings.

## The claim, in one table

```text
Same CVE, same CVSS base - different risk:  CVE-1999-9001

                                 172.28.0.12       172.28.0.10
CVSS base                                9.8               9.8
Role                                database      web_frontend
Exposure                     internet_facing          internal
WAF                                       no                no
EPSS percentile                          100               100
KEV                                      yes               yes
CVSS environmental                       9.8               6.9
RISK                                   100.0              79.0
BAND                                Critical              High
```

Same CVE, same 9.8 base score. What the machine is, whether it faces the internet and whether it
is a test system are inferred from the scan and change the answer. That is the research claim.

## Install and run

Python 3.11+. Two runtime dependencies: `pyyaml` and `packaging`. Everything else is standard
library.

```bash
python run_demo.py                    # whole pipeline over the labelled synthetic inputs
python run_model_simulation.py        # train, calibrate, save and run the role model locally
python run_research_simulation.py     # run RQ1-RQ4 metrics, ablations, and stability
python run_visual_simulation.py       # build the animated, self-contained pipeline replay
python -m unittest discover -s tests -p "test*.py" -v
```

## Commands

```text
vulnassess scan         --target-ip IP [--tool nmap|nikto|zap] [--execute]
vulnassess import       --run-id R --target-ip IP --nmap out.xml [--zap out.json] [--nikto out.json]
vulnassess intel load   --from-dir data/feeds
vulnassess intel status
vulnassess enrich       --run-id R
vulnassess context      --run-id R
vulnassess rank         --run-id R [--top N]
vulnassess explain      --run-id R [--model NAME] [--ollama-host URL] [--no-model]
vulnassess report       --run-id R --out reports/R.html
vulnassess eval         --run-id R --truth truth.yaml | --live
vulnassess diff         --before R1 --after R2
vulnassess two-machine  --run-id R [--cve CVE-ID]
vulnassess model labels --run-id R --out labels.jsonl
vulnassess model train  --data train.jsonl --validation validation.jsonl --out role-model.json
vulnassess model cross-validate --data labels.jsonl [--folds 5]
vulnassess model evaluate --model role-model.json --data test.jsonl
vulnassess model predict --run-id R --model role-model.json
vulnassess model inspect --model role-model.json
vulnassess visualize     --run-id R --model role-model.json --model-report metrics.json --out replay.html
vulnassess demo         --target IP:nmap.xml[:zap.json] --feeds DIR --out PATH [--truth PATH]
```

Every command takes `--json`. Global `--config` (default `config`) and `--db`
(default `data/vulnassess.db`).

Exit codes: `2` configuration, `3` scope, `4` scanner file, `5` missing feed snapshot,
`6` model unavailable.

`scan` **plans** by default: it prints each command prefixed `not run by the agent` and executes
nothing. Only a human passing `--execute` runs the scanners, and only against an address the scope
fence already allowed.

## What you must provide

The tool downloads nothing. A human supplies:

| Input | Where | How |
| --- | --- | --- |
| Nmap XML | anywhere | `nmap -sV -O --script vulners -oX out.xml <authorised target>` |
| Nikto JSON | anywhere | `nikto -h http://<authorised target> -Format json -output out.json` |
| ZAP JSON | anywhere | `zap-baseline.py -t http://<authorised target> -J out.json` |
| NVD pages | `<feeds>/nvd/*.json` | NVD API 2.0 responses |
| EPSS | `<feeds>/epss.csv[.gz]` | the EPSS daily CSV |
| KEV | `<feeds>/kev.json` | the CISA Known Exploited Vulnerabilities catalog |
| Local model | optional | `ollama serve` and `ollama pull llama3.2:3b` |
| Expert rankings | your own path | `experts: [{name, ranking}]` plus `expert_critical` |

`vulnassess scan --target-ip <ip>` prints these commands for you with the right flags and paths.

Scanning is authorised only against the hosts listed in `config/scope.yaml`. An address outside
that fence is refused **before any file is read**, and the canary address is refused by name.

## How the score is built

1. Match each finding to a CVE (explicit id from the scanner, or a CPE version range).
2. Auto-fill the CVSS v3.1 **Environmental** metrics from inferred context: an internal host
   softens `AV:N` to `MAV:A`; an observed WAF raises `MAC`; observed authentication raises `MPR`;
   the inferred role sets the C/I/A Requirements; a test environment overrides them downward; a
   manual criticality above 3 steps them upward. An inference below `min_confidence_to_apply`
   changes nothing.
3. `risk = environmental x 10 x threat`, where `threat = 0.5 + 0.5 x EPSS percentile`.
   **No EPSS row means the threat component is unscored**, not defaulted: the environmental score
   alone ranks the finding and the reason says "no exploitation data".
4. A CISA KEV listing forces the threat factor to 1.0 and adds 10 - and applies the floor of 90
   **only when the host is internet-facing**. An actively exploited flaw on an isolated test box
   belongs in High, not Critical.
5. Findings with no CVE fall back to the tool's own severity table.

The formula lives in `config/weights.yaml` and is hashed into every report footer.

## Where the model fits

`vulnassess explain` may hand a finding to a local Ollama model to reword the verdict. What it
sends is the band and the context words only &mdash; never a score &mdash; delimited, length-capped,
stripped of control characters and prefixed `untrusted data follows`. What comes back must be one
plain sentence under 240 characters with no URL, no markup, and **no number that was not in the
facts we supplied**. Anything else is discarded and the deterministic sentence is used instead,
with the reason recorded in the rationale. The model can change the wording of a rank. It cannot
change a rank.

With no model configured, or with Ollama absent, every sentence is the deterministic one and the
report says so.

## Trainable role model

`vulnassess model` is the learned part of the product. It extracts binary features from scan
evidence (ports, service/product/banner tokens, CPE vendor/product, operating-system tokens and
TLS), fits deterministic class-balanced multinomial logistic regression, calibrates probabilities
on an independent validation set, abstains to `unknown` below configured confidence or margin,
and preserves the strongest positive feature weights with their verbatim scan evidence.

The artifact is canonical JSON, hash-verified when loaded and inspectable without executing code.
Evaluation reports accuracy, coverage, abstention rate, selective accuracy, macro-F1, multiclass
log loss, Brier score, expected calibration error, per-class precision/recall/F1 and a confusion
matrix. Cross-validation is deterministic and grouped by host/capture unit to prevent the same
asset leaking across folds.

The label workflow is deliberately separate from expert ranking truth:

```bash
python -m vulnassess model labels --run-id my-run --out data/model-labels.jsonl
# A human fills label, label_source="human", and a reviewer identifier.
python -m vulnassess model train --data train.jsonl --validation validation.jsonl \
   --out models/role-model.json
python -m vulnassess model evaluate --model models/role-model.json --data test.jsonl
python -m vulnassess model predict --run-id my-run --model models/role-model.json
```

Synthetic labels are refused unless `--allow-synthetic` is explicit. Predictions currently run in
**shadow mode**: they are printed with confidence, margin, abstention and evidence but are not
written to `ContextProfile` and cannot affect a score. Promoting them into ranking requires real
independent labels, the declared RQ1 evaluation, and approval of the existing scoring-input wall.

## Visual pipeline replay

`python run_visual_simulation.py` rebuilds the synthetic data pipeline and role model in isolated
local files, then writes `reports/visual-simulation.html`. Open that file directly; it requires no
server. The visual console includes an eight-stage play/pause/scrub timeline, animated scanner and
feed topology, event stream, selectable hosts, all nine role probabilities, confidence/margin and
abstention evidence, a CVSS Environmental/EPSS/KEV score waterfall, the two-machine comparison,
and the final remediation queue. It is responsive down to 390 px and respects reduced motion.

For an existing run, render the same interface with `vulnassess visualize`. The generated HTML
embeds the local store snapshot, contains no external asset or network call, escapes scanner/model
text before embedding it, and is byte-identical when the inputs are unchanged.

## Research and operational hardening

`python run_research_simulation.py` executes the currently available RQ1-RQ4 machinery and writes
`reports/research-simulation.json` plus the hash-verified
`reports/research-assessment-snapshot.json`. It reports rule and shadow-model role accuracy,
exposure accuracy, tie-aware baseline comparisons, per-expert queue reduction, ten in-memory
ablations, inactive inputs, and repeated-run hashes. Its bundled labels are synthetic, so all
hypothesis decisions remain explicitly ineligible until independently reviewed inputs arrive.

The supporting modules also provide Nmap-first endpoint planning with injected execution,
conservative same-CVE/same-instance correlation, bounded match-decision traces, and re-scan
classification that distinguishes `still_open`, `fixed_candidate`, `regression_candidate`, and
`not_observable`. Raw absence is never called remediation. The learned model remains shadow-only;
a promotion manifest can only recommend a candidate and rejects synthetic evidence, weak metrics,
dataset leakage, expired approvals, model/hash drift, and strong rule/model conflicts.

## Layout

```text
vulnassess/   schema, settings, store, readers/ (nmap, nikto, zap), intel, cvss31, context,
              context_eval, role_model, model_governance, scoring, experiments, orchestrator,
              unify, rescan, assessment_snapshot, explain, report, evaluate, diff, runner,
              pipeline, cli
config/       scope.yaml (the fence), weights.yaml (the formula), roles.yaml, controls.yaml
tests/        test_all.py, synthetic/ (labelled synthetic inputs), fixtures/ (real captures)
legacy/       the superseded pydantic/typer prototype, kept for reference
```

## Evidence rules

Every inferred fact carries a confidence, a source (`rule` | `manual`) and a verbatim quote from
the scan - or the literal `none observed`. Every finding keeps its tool, raw file and record
index. Anything under `tests/synthetic/` is invented for unit tests and is never evidence that a
parser, feed or score works on real data.
