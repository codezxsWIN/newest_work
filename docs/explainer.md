# VulnAssess Explainer

## 1. The prioritisation gap

CVSS measures technical severity, not the complete urgency of a finding on a particular machine. Scanner labels also differ, and duplicated observations can make a queue look larger than the underlying risk. VulnAssess separates evidence collection from prioritisation so that every rank can be traced back to scanner, intelligence, and asset facts.

## 2. Inputs and normalization

Nmap, Nikto, and ZAP provide heterogeneous observations. Adapters preserve the raw source reference and map observations into a common finding schema. Normalization identifies assets, services, vulnerabilities, confidence, timestamps, and evidence without upgrading guesses into facts. Duplicate observations may be linked, but source evidence remains independently inspectable.

## 3. Intelligence

Normalized CVEs are enriched from dated, reduced snapshots:

- NVD supplies CVSS and vulnerability metadata.
- EPSS supplies an estimated probability of exploitation.
- CISA KEV supplies evidence of known exploitation.

Every enrichment records its source, retrieval or publication date, and match key. Missing intelligence remains missing rather than becoming zero.

## 4. Context

Context includes environment, exposure or vantage, asset role, business criticality, and inference confidence. Explicit inventory tags outrank inferred values. Inference must cite its evidence and may return `unknown`. The local model can help classify bounded evidence into the approved role list, but its output must pass schema validation and cannot create technical facts.

## 5. Figure 2 — why identical vulnerabilities rank differently

Figure 2 is a two-branch evidence flow:

1. An identical normalized vulnerability enters both branches with the same CVE, CVSS, EPSS, and KEV facts.
2. Branch A joins the finding to an internal test asset with low business criticality and no external exposure.
3. Branch B joins it to an internet-facing production database with high business criticality.
4. The scoring function applies the same published formula to both evidence bundles.
5. Technical severity stays constant. Only documented context terms differ.
6. Branch B ranks higher, and each contribution is shown in the explanation.

This demonstrates that context changes priority without rewriting vulnerability evidence.

## 6. Evaluation and limits

Experts receive the same lab findings and return a full ranking plus an `expert-critical` set. The study compares CVSS-only and context-aware rankings with Kendall's tau, NDCG@10, and critical-queue reduction. Results apply to this lab and panel; they do not establish universal weights. Stage 4 may tune the hypothesis only with a recorded decision and a held-out evaluation.

## Golden two-machine example

**Golden CVE:** `CVE-2012-2122`, the MySQL authentication bypass associated with versions found in common Metasploitable 2 lab images. The fixture scan must confirm the affected product/version before the test treats it as a matched finding.

| Input | Machine A | Machine B |
|---|---|---|
| Vulnerability evidence | Identical confirmed CVE evidence | Identical confirmed CVE evidence |
| Environment | `test` | `prod` |
| Exposure | Internal-only | Internet-facing |
| Role | Database | Database |
| Criticality | 1 | 5 |
| Expected relation | Lower score and rank | Higher score and rank |

The golden test asserts the ordering and explanation contributions, not a hard-coded absolute score. If real fixture evidence does not support this CVE, replace it through a recorded decision before implementing the test.

