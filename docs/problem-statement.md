# Context Is Not Free

Vulnerability scanners and public intelligence feeds describe technical weakness, but they do not fully describe operational risk. The same CVE can deserve very different treatment depending on exposure, environment, asset role, business criticality, compensating controls, and current exploitation evidence. Collecting that context has a cost: it requires trusted inventory, inference, validation, provenance, and expert review. Context is therefore not free, and an assessment method must show that the context it adds improves prioritisation enough to justify its complexity.

VulnAssess is an open, reproducible method for combining scanner evidence, public vulnerability intelligence, and bounded asset context into an explainable ranked queue. It must preserve source evidence, state uncertainty, avoid invented facts, and remain safe to run against an explicitly authorised lab.

## Research question

Does context-aware prioritisation rank lab findings closer to expert judgment and produce a smaller, more useful critical queue than severity-only prioritisation?

## Measurable outcome

Compare the context-aware ranking with a CVSS-only baseline using the same normalized findings:

- **Kendall's tau:** agreement between each system ranking and the experts' full ranking. Success means the context-aware method has a higher mean tau.
- **NDCG@10:** quality of the first ten ranked findings using expert relevance judgments. Success means the context-aware method has a higher mean NDCG@10.
- **Critical-queue reduction:** percentage reduction in findings assigned to the critical response queue while retaining every item in the experts' `expert-critical` set. Success means a smaller queue with 100% recall of that set.

Report per-expert results, aggregate results, ties, confidence intervals where the sample supports them, and all scoring/configuration versions. Do not tune and evaluate on the same expert judgments.

## Boundaries

The initial study uses only the isolated targets in `config/scope.yaml`. It is a prioritisation experiment, not a production scanner, penetration-testing service, or autonomous remediation system.

