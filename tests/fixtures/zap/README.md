# Real ZAP reports

Empty until a human puts a report here. `tests/test_all.py` skips its ZAP fixture test with
`fixture not provided: tests/fixtures/zap/*.json` while this directory holds no `.json` file, and a
skipped test is never evidence that the reader works on real output.

## How to capture

**Not run by the agent.** A human runs this against an address listed in `config/scope.yaml`, with
written authorisation. The baseline scan is passive: it does not attack the target.

```bash
zap-baseline.py -t http://<authorised-ip> -J tests/fixtures/zap/<target-name>.json
```

## Provenance

Add one row per file before committing it. A report without a row is not usable as evidence.

| File | Capture date | Command | Target | Tool version | Captured by |
| --- | --- | --- | --- | --- | --- |
| _(none yet)_ | | | | | |

## What must not be committed here

Production or third-party scan output, reports containing session tokens or credentials in the
`instances[].uri` values, and any file whose command, date or operator cannot be stated above.
