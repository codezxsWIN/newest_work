# Security boundary

This is a policy and review checklist, not a security certification. No system can be guaranteed completely secure. Offline operation reduces some risks; local packages, scanner output, models, and feed snapshots can still be malicious or compromised.

## Provisioning is closed by default

- Dependency installation is **not run by the agent**. The `make install` entry point delegates to `scripts/install.py`, which reports the refusal to stderr and exits with code 2. It does not call pip, inspect or install wheel files, or offer an override flag.
- The presence of `wheels/` is not approval. Do not bypass the refusal through direct pip commands, another project's environment, a package cache, source builds, or a different package manager.
- Do not add packages merely to obtain a passing gate. Missing tooling remains an explicit blocker until a human approves and provides it through the artifact review process.
- This repository guard is not an operating-system security boundary: someone with shell access can run other commands. A human must configure and verify host or sandbox egress restrictions, filesystem permissions, and isolation separately. No such configuration is claimed here.

## Human artifact review

Before authorising a future provisioning process, the responsible reviewer must:

1. Select the smallest necessary dependency set. Review runtime, development, transitive, and build dependencies separately; document each addition and consider standard-library or existing-package alternatives.
2. Record exact versions, Python/platform compatibility, artifact origin, publisher identity, licenses, and the reviewer. Broad version constraints in packaging metadata are not an approved lockfile.
3. Obtain artifacts through the organisation's approved process. Review signatures or provenance attestations when available. Missing provenance requires an explicit risk decision, not an invented verification result.
4. Approve SHA-256 hashes through an independently trusted record. Comparing an artifact with a hash supplied alongside that same untrusted artifact establishes consistency, not authenticity. Even an authentic, correctly hashed package can contain unsafe code.
5. Review known vulnerabilities using identified, dated advisory data and record the outcome. An empty vulnerability report does not prove safety or exclude undisclosed vulnerabilities.
6. Produce a complete, reviewed lock and local artifact bundle. A future installer must prohibit index access, unpinned dependencies, unexpected artifacts, and source builds during installation; it must fail on missing or mismatched artifacts. Editable installs and automatic build isolation are not a substitute for reviewing build-time code.
7. Exercise the approved bundle in an isolated environment without production credentials and with independently enforced egress restrictions. Record the commands, results, and remaining risks before approving its use.

The agent must not create plausible-looking versions, hashes, signatures, approvals, advisory results, or substitute artifacts to satisfy this checklist. No approved bundle or lockfile is asserted by this document.

## Runtime requirements

These remain acceptance requirements for subsequent implementation, not claims that the scaffold already enforces them:

- Deny scans outside the explicitly configured lab targets before starting any subprocess. A subnet boundary does not authorise discovery of every host.
- Keep scanner processes isolated from production networks and credentials. Constrain their network destinations and writable paths using independently configured sandbox or host controls.
- Treat scanner output, feed contents, and model output as untrusted data. Validate structure and bound input sizes, subprocess duration, and output sizes; do not execute evidence as commands or render it as trusted HTML.
- Keep scoring deterministic and independent of the LLM. The local model only produces explanatory text; model output is not authorisation to execute a command or change a score.
- Keep secrets and raw scan data out of source control and logs. Reports must preserve provenance without leaking credentials or overstating inferred evidence.
- Report missing inputs explicitly. Never replace them with generated vulnerability evidence or silent empty results.

## Evidence limits

Passing unit tests demonstrate their tested behavior, not supply-chain trust, parser correctness against real captures, sandbox enforcement, or end-to-end security. A direct test of the refusal script does not prove that GNU Make executed the target. Report each separately under `VERIFIED`, `TESTED WITH MOCKS`, `NOT RUN`, or `MISSING`, following the project evidence rules.
