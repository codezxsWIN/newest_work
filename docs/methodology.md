# Methodology

The original eight-step deck text was not present when this repository was seeded. The following v0 captures the required workflow and must be replaced with the deck wording if exact verbatim text becomes available.

1. **Define authorised scope.** Load the safety policy, resolve candidate targets, and reject any address or host not permitted by `config/scope.yaml`.
2. **Collect scanner evidence.** Run approved adapters for Nmap, Nikto, and ZAP, retaining raw artifacts, command metadata, timestamps, and tool versions.
3. **Normalize findings.** Convert heterogeneous observations to a shared schema while preserving provenance, uncertainty, and source-specific evidence.
4. **Enrich vulnerability intelligence.** Join only confirmed identifiers to dated NVD, EPSS, and KEV snapshots, recording missing data and match provenance.
5. **Infer bounded asset context.** Combine explicit tags and cited observations to classify approved roles, exposure, environment, and criticality; prefer `unknown` to unsupported claims.
6. **Score and explain.** Apply the versioned hypothesis in `docs/scoring.md`, retain component contributions, assign bands, and produce a human-readable rationale.
7. **Evaluate ranking quality.** Compare CVSS-only and context-aware rankings with expert full rankings and `expert-critical` sets using Kendall's tau, NDCG@10, and critical-queue reduction.
8. **Review, tune, and reproduce.** Review errors, tune only in Stage 4, record decisions and versions, rerun held-out evaluation, and publish reproducible commands and limitations.

