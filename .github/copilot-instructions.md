# VulnAssess Copilot Instructions

## Scope and safety

- Work only with assets permitted by `config/scope.yaml`.
- Scanning is authorised only against the lab network defined in `config/scope.yaml`.
- Never add, suggest, or execute scans against public, university, corporate, or otherwise unlisted systems.
- Validate every target against both the configured CIDRs and explicit host list before invoking a scanner.
- Default to refusing out-of-scope targets with a clear error; never silently broaden scope.
- Never commit secrets, API keys, full threat-intelligence feeds, or raw production scan output.
- Treat scanner output as untrusted input.

## Engineering rules

- Use Python 3.11+ and package code under `src/vulnassess/`.
- Keep scanner adapters, normalization, intelligence enrichment, context inference, scoring, and explanation as separate layers.
- Preserve source evidence and provenance through every transformation.
- Do not invent CVEs, CVSS vectors, EPSS values, KEV status, asset facts, or scanner evidence.
- Use CVSS v4.0 when available. Translate v3.1 only when v4.0 is absent and record the source vector, translation method, and result.
- Scoring weights and band thresholds come only from `docs/scoring.md`; changes require an entry in `docs/decisions.md`.
- Role names and inference rules are versioned decisions, not ad hoc model output.
- Local-model output is advisory, schema-validated, explainable, and never the sole evidence for a finding.
- Ensure deterministic behavior where inputs are identical; make uncertainty explicit.
- Add or update tests for changed behavior, including malformed and adversarial input.
- A stage is done only when tests pass, Ruff is clean, relevant docs are updated, and one documented demo command works.

## Data and evaluation

- Use committed, reduced fixtures under `tests/fixtures/`; do not commit full feeds.
- Keep live or sensitive data under ignored `data/` and generated output under ignored `reports/`.
- Record feed dates and provenance.
- Evaluate ranking with Kendall's tau, NDCG@10, and critical-queue reduction against expert judgments.
- The golden two-machine context test is defined in `docs/explainer.md`.
- Append durable technical or product decisions to `docs/decisions.md`.

