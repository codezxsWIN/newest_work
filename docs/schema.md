# Canonical schema

Status: reserved for Prompt 2. The Prompt 1 scaffold does not implement models
or persistence.

Prompt 2 will define `Finding`, `Host`, scanner provenance, stable identifiers,
and SQLite upsert behavior here. Later prompts will document `ContextProfile`,
`Enrichment`, and `ScoreBreakdown` alongside their implementations.

Nmap and Nikto findings must retain `native_severity=None`. Model fields must
preserve missing data and source evidence rather than inventing values.
