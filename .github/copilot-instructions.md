# Project: AI-Based Network Vulnerability Assessment Tool
# Focus: context-aware risk prioritisation ("Context Is Not Free")

## What we are building

A local-first Python 3.11+ CLI that:
1. runs Nmap, Nikto and ZAP against AUTHORISED lab targets only;
2. converts all three outputs into one canonical finding format;
3. enriches each finding with CVSS (from NVD), EPSS and CISA KEV data cached locally;
4. infers deployment context from the scan evidence itself: asset role, exposure, compensating controls;
5. scores risk with a deterministic, published formula (auto-filled CVSS v4.0 Environmental metrics + EPSS + KEV);
6. uses a local LLM via Ollama ONLY to write a one-line plain-English rationale per finding - never to compute or adjust a score;
7. produces an HTML report and an evaluation harness that compares our ranking with expert rankings.

## Hard rules

- Scan only targets listed in config/scope.yaml. Refuse anything else, loudly.
- No cloud APIs at runtime. Data feeds are downloaded once into data/ and read offline.
- The LLM never emits a number that affects ranking. All scores come from src/vulnassess/scoring/.
- Every inferred context feature carries confidence (0.0-1.0), a source (rule | llm), and an evidence string pointing at the raw scan artefact.
- Every finding keeps provenance: tool, raw file, record index.
- Deterministic: same inputs -> same ranks. Seed anything random.
- Code style: type hints everywhere, pydantic v2 models, pytest for every module, ruff clean.
- New dependency = one-line justification appended to docs/decisions.md.

## Repo layout

```text
src/vulnassess/
  cli.py               # typer CLI: scan | enrich | context | rank | explain | report | eval | intel
  schema/              # canonical Finding, Host, ContextProfile, ScoreBreakdown (pydantic)
  adapters/            # nmap_xml.py, nikto_json.py, zap_json.py, runner.py (subprocess + scope check)
  store/               # SQLite persistence
  intel/               # nvd.py, epss.py, kev.py, matcher.py
  context/             # role.py, exposure.py, controls.py
  scoring/             # cvss_env.py, formula.py, bands.py
  explain/             # ollama_client.py, rationale.py
  report/              # html.py + templates/
  eval/                # metrics.py, baselines.py, ablation.py
tests/fixtures/        # small sample outputs for each tool, labeled with provenance
config/                # scope.yaml, weights.yaml, roles.yaml
docs/                  # decisions.md, scoring.md, schema.md
```

## Day-zero safeguards and prompt precedence

- Scanning is authorised only against the lab network defined in `config/scope.yaml`.
- A CIDR is a boundary, not permission to discover or scan every host in it; require an explicitly listed lab target.
- Never commit secrets, production scan output, or full intelligence feeds.
- Treat scanner output as untrusted input and never invent vulnerability evidence.
- Keep live data in ignored `data/` and generated reports in ignored `reports/`.
- Do not install tools, packages, models, or container images on this machine without new user approval.
- These hard rules take precedence over later implementation examples. In particular, Prompt 5's LLM role fallback would affect Environmental scoring and is deferred; use rule-based context only.
- Record scoring, role, scope, and dependency decisions in `docs/decisions.md`.
- The source deck is still unavailable; do not describe the provisional methodology or explainer as verbatim deck text.
