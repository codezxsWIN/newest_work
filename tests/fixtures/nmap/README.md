# Real Nmap Captures & Examples

This directory contains both **real Nmap XML captures** (for validation) and **synthetic examples** (for testing).

## 📋 Real Captures Provenance

Add one row per file before committing. A capture without a row is not usable as evidence.

| File | Capture Date | Command | Target(s) | Tool Version | Captured By | Authorization | Lab Network | Canary Status |
|------|--------------|---------|-----------|--------------|-------------|----------------|-------------|----------------|
| _(none yet)_ | | | | | | | | |

## 📚 Synthetic Examples (Testing Only)

These are **never produced by Nmap** and never evidence. Use only for unit/integration testing:

| File | Purpose | Hosts | Services | CVE Count |
|------|---------|-------|----------|-----------|
| `EXAMPLE-synthetic-lab-two-machines.xml` | Demonstrate Nmap XML structure with vulners script output | 2 (172.28.0.10, 172.28.0.12) | SSH, HTTP, MySQL | 1 (CVE-1999-9001) |

## ✅ How to Capture Real Data

**Not run by the agent.** A human runs these against an address listed in `config/scope.yaml`,
with written authorisation, and never against the canary `172.28.0.250`.

### Standard Command

```bash
nmap -n -Pn -sT -sV --version-light -T2 --max-retries 1 --host-timeout 180s \
  -p 21,22,23,25,53,80,88,110,135,139,143,389,443,445,465,587,636,993,995,1433,2049,3000,3306,5432,6379,8080,8443,27017 \
  -oX tests/fixtures/nmap/<target-name>-<date>.xml <authorised-ip-or-range>
```

### With Vulners Script (requires NSE script)

```bash
nmap -n -Pn -sT -sV --script vulners --version-light \
  -oX tests/fixtures/nmap/<target-name>-<date>.xml <authorised-ip-or-range>
```

**Note:** Drop `--script vulners` if not installed; reader still extracts findings from CPE/version matching.

## 🔒 Safety Checklist (Before Any Scan)

- [ ] Target(s) explicitly listed in `config/scope.yaml`
- [ ] Canary `172.28.0.250` verified **NOT** in scope
- [ ] Isolated lab network confirmed
- [ ] Written authorization obtained and dated
- [ ] Scan command, version, operator, timestamp recorded
- [ ] Lab access log provided and verified empty of canary

## 📝 Validation Checklist (Before Commit)

- [ ] Provenance table row filled in above
- [ ] All IPs/hostnames in output are lab-only (no production data)
- [ ] No credentials, tokens, PII, or sensitive data in XML
- [ ] XML is well-formed (validated locally with parser)
- [ ] SHA-256 hash calculated and noted
- [ ] File size reasonable (<16 MB)
- [ ] Authorization reference is valid and dated

## 🔍 Expected XML Structure

Real Nmap output follows this pattern:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap ..." start="<timestamp>" version="<version>">
  <host starttime="..." endtime="...">
    <status state="up|down" reason="..."/>
    <address addr="<IP>" addrtype="ipv4|ipv6"/>
    <hostnames><hostname name="<hostname>" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp|udp" portid="<port>">
        <state state="open|closed|filtered" reason="..."/>
        <service name="<service>" product="<product>" version="<version>" conf="<0-10>">
          <cpe>cpe:/a:vendor:product:version</cpe>
        </service>
        <script id="vulners" output="...CVE-XXXX-XXXXX..."/>
      </port>
    </ports>
    <os><osmatch name="..." accuracy="..."/></os>
  </host>
</nmaprun>
```

## 🧪 Local Testing

Before committing:

```python
from vulnassess.readers.nmap_xml import read_nmap_xml
from vulnassess.settings import Config

config = Config("config/scope.yaml")
hosts, findings = read_nmap_xml("tests/fixtures/nmap/your-file.xml", config)
print(f"✓ Parsed: {len(hosts)} hosts, {len(findings)} findings")
```

## 📖 References

- [SCAN_FORMAT_REFERENCE.md](../../docs/SCAN_FORMAT_REFERENCE.md) — Full technical specs
- [FIXTURE_CREATION_GUIDE.md](../../docs/FIXTURE_CREATION_GUIDE.md) — Step-by-step guide  
- [docs/fixtures.md](../../docs/fixtures.md) — ADR #27 (fixture policy)
- [docs/decisions.md](../../docs/decisions.md) — Project decisions
- [config/scope.yaml](../../config/scope.yaml) — Approved scan targets
