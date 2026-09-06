# Real Nmap captures

Empty until a human puts a capture here. `tests/test_all.py` skips its Nmap fixture test with
`fixture not provided: tests/fixtures/nmap/*.xml` while this directory holds no `.xml` file, and a
skipped test is never evidence that the reader works on real output.

## How to capture

**Not run by the agent.** A human runs these against an address listed in `config/scope.yaml`,
with written authorisation, and never against the canary `172.28.0.250`.

```bash
nmap -sV -O --script vulners -oX tests/fixtures/nmap/<target-name>.xml <authorised-ip>
```

Drop `--script vulners` if the NSE script is not installed; the reader then finds no CVE ids and
those hosts contribute services and context only.

## Provenance

Add one row per file before committing it. A capture without a row is not usable as evidence.

| File | Capture date | Command | Target | Tool version | Captured by |
| --- | --- | --- | --- | --- | --- |
| _(none yet)_ | | | | | |

## What must not be committed here

Production or third-party scan output, anything captured without written authorisation, and any
file whose command, date or operator cannot be stated in the table above.
