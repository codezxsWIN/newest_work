# Getting started with VulnAssess

VulnAssess imports scanner output, enriches CVE evidence from local feed snapshots,
infers host context from scan evidence, computes deterministic risk rankings, and
serves a local read-only assessment UI. It is a research prototype, not a substitute
for an authorized scanner or a security certification.

## 1. Prerequisites and dependency policy

- Python 3.11 or newer.
- Nmap only if you intend to execute scans; otherwise, use existing Nmap XML.
- Optional local Ollama installation/model only if you want the explicit AI analysis
  or explanation features.

The runtime dependencies are listed in `requirements.txt`. However, this repository
deliberately disables automatic dependency provisioning: `make install` exits with a
refusal, and `docs/security.md` requires human review and an approved artifact bundle
before packages are installed. Do not bypass that guard with `pip install` or another
package manager. Once dependencies have been approved and made available in your
Python environment, continue below.

## 2. Open the repository and verify Python

Run commands from the repository root (the directory containing `pyproject.toml`).

Windows PowerShell:

```powershell
py -3.11 --version
```

macOS/Linux:

```bash
python3.11 --version
```

If the `vulnassess` console command is not installed, use `python -m vulnassess` in
all commands below. From the repository root, first verify that the package imports:

```powershell
py -3.11 -m vulnassess --help
```

```bash
python3.11 -m vulnassess --help
```

## 3. Run the labelled demo

The demo uses synthetic inputs and does not scan a network. It is the quickest way to
see the ranking/report pipeline:

```powershell
py -3.11 run_demo.py
```

```bash
python3.11 run_demo.py
```

The generated report is written to `reports/demo.html`. Demo data is synthetic and
must not be cited as evidence about a real target.

## 4. Review the scope fence before any real scan

Open `config/scope.yaml` and ensure it contains only targets you own or are explicitly
authorized to assess. The configured allowlist is a software safety fence, not proof
of authorization. Never scan a public or third-party host based only on the fact that
the address appears in that file. VulnAssess can print a scan plan without running
anything; actual scanner execution requires `--execute` and is limited by the
configured scope and available scanner tools.

Preview a plan first (replace the example with an authorized IP from your scope):

```powershell
py -3.11 -m vulnassess --config config --db data/vulnassess.db scan `
  --run-id lab-2026-01 --target-ip 172.28.0.10
```

On macOS/Linux, use the same command on one line:

```bash
python3.11 -m vulnassess --config config --db data/vulnassess.db scan --run-id lab-2026-01 --target-ip 172.28.0.10
```

The default is plan-only. To execute a scan, first confirm authorization, target,
scope, scanner availability, and the plan; then explicitly add `--execute`:

```powershell
py -3.11 -m vulnassess --config config --db data/vulnassess.db scan `
  --run-id lab-2026-01 --target-ip 172.28.0.10 --execute
```

Nmap output is written under `data/captures/` by default. Raw scan exports can be
sensitive; keep them local and do not commit them.

## 5. Import existing scan output instead

If you already have an authorized Nmap XML capture, import it without launching a
scanner. For example:

```powershell
py -3.11 -m vulnassess --config config --db data/vulnassess.db import `
  --run-id lab-2026-01 --target-ip 172.28.0.10 --nmap data/captures/172.28.0.10-nmap.xml
```

The equivalent command works in macOS/Linux shells on one line. Optional ZAP or
Nikto JSON can be supplied using `--zap PATH` and `--nikto PATH`. Imported targets
are subject to the same scope checks.

## 6. Enrich, infer context, rank, and report

Feed enrichment uses local snapshots; the scoring and ranking stages do not fetch
remote intelligence while running. Fetching NVD, EPSS, and CISA KEV snapshots is an
optional, separate network operation and can require substantial disk space and time.
Review `docs/FEED_PROVENANCE.md` and `scripts/fetch_feeds.py` before fetching. Then:

```powershell
py -3.11 scripts/fetch_feeds.py
py -3.11 -m vulnassess intel load --from-dir data/feeds
```

Run the remaining stages for the same run ID:

```powershell
py -3.11 -m vulnassess --config config --db data/vulnassess.db enrich --run-id lab-2026-01
py -3.11 -m vulnassess --config config --db data/vulnassess.db context --run-id lab-2026-01
py -3.11 -m vulnassess --config config --db data/vulnassess.db rank --run-id lab-2026-01
py -3.11 -m vulnassess --config config --db data/vulnassess.db report --run-id lab-2026-01 --out reports/lab-2026-01.html
```

macOS/Linux users can substitute `python3.11` for `py -3.11`. If feeds are not
loaded, enrichment can report that its snapshots are unavailable; do not interpret
missing intelligence as a zero-risk result. A ports/services-only scan may produce
no CVE findings, in which case there is nothing vulnerability-specific to rank.

## 7. Open the local assessment UI

Start the read-only viewer from the repository root:

```powershell
py -3.11 -m vulnassess --config config --db data/vulnassess.db ui --run lab-2026-01 --port 8765
```

```bash
python3.11 -m vulnassess --config config --db data/vulnassess.db ui --run lab-2026-01 --port 8765
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765). Stop the server with Ctrl+C.
The UI is bound to loopback and is read-only. The workflow canvas is at
`http://127.0.0.1:8765/workflow?run=lab-2026-01`.

An optional local Ollama model can be provided with `--model MODEL_NAME`. AI analysis
is an explicit advisory action; it does not replace or modify deterministic scores.
See the README's “Where the LLM fits” section and `vulnassess ui --help` for options.

## 8. Tests and troubleshooting

Run the unit test suite (requires the approved test/runtime dependencies):

```powershell
py -3.11 -m unittest discover -s tests -p "test*.py" -v
```

Useful checks:

```powershell
py -3.11 -m vulnassess --help
py -3.11 -m vulnassess ui --help
py -3.11 -m vulnassess intel status
```

- **Missing module:** verify you are using the Python environment provisioned under
  the repository's dependency review policy; do not bypass the install guard.
- **Scope rejected:** inspect `config/scope.yaml`, confirm the target is authorized,
  and use an address explicitly present in the configured scope.
- **No findings:** confirm the scanner output contains vulnerability evidence. Open
  ports alone are not proof of a vulnerability.
- **No enrichment:** check whether feed snapshots were fetched and loaded with
  `vulnassess intel status`.
- **Port in use:** select another local port with `--port`, for example `--port 8766`.

For the full command list, evidence limitations, and scanner safety behavior, see the
root README and `docs/security.md`.
