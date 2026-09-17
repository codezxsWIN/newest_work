"""Parsing tests over committed REAL Nmap captures (see tests/fixtures/nmap/README.md).

These two captures were produced by real Nmap 7.80 executions on 2026-09-17 via
`vulnassess scan --execute` against the owner's own loopback-bound lab hosts. They
prove the reader accepts genuine scanner output — including the bare
`<!DOCTYPE nmaprun>` header real Nmap always writes. They carry no explicit CVE
evidence: vulners ran keyless and the lab hosts expose no vulnerable versions,
and the pipeline must treat that honestly rather than invent findings.
"""

import unittest
from pathlib import Path

from vulnassess.readers import parse_nmap_xml

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "nmap"


class TestRealCaptures(unittest.TestCase):
    def test_real_juice_shop_capture_parses_with_services(self) -> None:
        hosts, findings = parse_nmap_xml(FIXTURES / "real-lab-172.28.0.12-juiceshop.xml", "real")
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].ip, "172.28.0.12")
        ports = {service.port for service in hosts[0].services}
        self.assertIn(3000, ports)
        self.assertIn(445, ports)
        self.assertEqual(findings, [])

    def test_real_windows_capture_parses_with_named_product(self) -> None:
        hosts, findings = parse_nmap_xml(FIXTURES / "real-lab-172.28.0.10-windows.xml", "real")
        self.assertEqual(len(hosts), 1)
        banners = " ".join(
            (service.banner or "") + (service.product or "") for service in hosts[0].services
        )
        self.assertIn("Python", banners)
        self.assertEqual(findings, [])

    def test_real_captures_carry_the_bare_nmap_doctype(self) -> None:
        for name in (
            "real-lab-172.28.0.12-juiceshop.xml",
            "real-lab-172.28.0.10-windows.xml",
        ):
            with self.subTest(name=name):
                head = (FIXTURES / name).read_bytes()[:200]
                self.assertIn(b"<!DOCTYPE nmaprun>", head)


if __name__ == "__main__":
    unittest.main()
