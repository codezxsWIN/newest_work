"""Nmap-first orchestration tests with an injected scanner executor."""

import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from vulnassess.errors import ScopeError
from vulnassess.orchestrator import (
    Execution,
    check_canary_log,
    derive_endpoints,
    orchestrate,
    plan,
    web_plan,
)
from vulnassess.schema import Host, Service
from vulnassess.settings import Settings

ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC = ROOT / "tests" / "synthetic"
SETTINGS = Settings(ROOT / "config")


def service(port: int, name: str, *, tls: bool = False) -> Service:
    return Service(
        port=port,
        protocol="tcp",
        name=name,
        banner=f"{port}/tcp {name}",
        tls=tls,
    )


class FakeExecutor:
    def __init__(self, fail: set[str] | None = None, nmap_source: Path | None = None):
        self.fail = fail or set()
        self.nmap_source = nmap_source or SYNTHETIC / "synthetic_nmap_two_machines.xml"
        self.calls = []

    def __call__(self, command):
        self.calls.append(command)
        if command.tool in self.fail:
            return Execution(7, "2026-09-07T00:00:00Z", "2026-09-07T00:00:01Z", "synthetic failure")
        source = {
            "nmap": self.nmap_source,
            "zap": SYNTHETIC / "synthetic_zap_dvwa.json",
            "nikto": SYNTHETIC / "synthetic_nikto_dvwa.json",
        }[command.tool]
        command.output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, command.output)
        return Execution(0, "2026-09-07T00:00:00Z", "2026-09-07T00:00:01Z")


class TestOrchestrator(unittest.TestCase):
    def test_scope_and_canary_are_rejected_before_output_or_execution(self):
        for target in ("8.8.8.8", "172.28.0.250"):
            with self.subTest(target=target), TemporaryDirectory() as directory:
                output = Path(directory) / "captures"
                with self.assertRaises(ScopeError):
                    plan(SETTINGS, target, output)
                self.assertFalse(output.exists())

    def test_discovery_derives_only_observed_http_endpoints(self):
        host = Host(
            ip="172.28.0.11",
            services=(
                service(22, "ssh"),
                service(80, "http"),
                service(443, "https", tls=True),
                service(8443, "ssl/http", tls=True),
                service(3306, "mysql"),
            ),
        )

        endpoints = derive_endpoints(host)

        self.assertEqual(
            [endpoint.url for endpoint in endpoints],
            [
                "http://172.28.0.11",
                "https://172.28.0.11",
                "https://172.28.0.11:8443",
            ],
        )
        self.assertEqual(
            [endpoint.evidence for endpoint in endpoints],
            ["80/tcp http", "443/tcp https", "8443/tcp ssl/http"],
        )

    def test_no_web_service_records_explicit_web_tool_skips(self):
        with TemporaryDirectory() as directory:
            scan_plan = plan(SETTINGS, "172.28.0.10", Path(directory) / "captures")
            commands, skips = web_plan(
                scan_plan,
                Host(ip="172.28.0.10", services=(service(22, "ssh"),)),
            )

        self.assertEqual(commands, [])
        self.assertEqual([item.tool for item in skips], ["nikto", "zap"])
        self.assertTrue(all("no HTTP service" in item.skip_reason for item in skips))

    def test_successful_run_is_nmap_first_and_records_every_outcome(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "captures"
            empty_log = Path(directory) / "synthetic_canary.log"
            empty_log.write_text("", encoding="utf-8")
            scan_plan = plan(
                SETTINGS,
                "172.28.0.10",
                output,
                tools=("nmap", "nikto", "zap"),
                canary_log=empty_log,
            )
            executor = FakeExecutor()

            result = orchestrate(scan_plan, "synthetic-run", executor)

        self.assertEqual([call.tool for call in executor.calls], ["nmap", "nikto", "zap"])
        self.assertEqual(result["canary_evidence"]["status"], "VERIFIED")
        self.assertEqual(result["successful_tools"], 3)
        self.assertEqual(result["failed_tools"], 0)
        self.assertEqual(result["skipped_tools"], 0)
        self.assertTrue(result["complete"])
        self.assertEqual(result["endpoints"][0]["url"], "http://172.28.0.10")
        self.assertEqual([item["status"] for item in result["outcomes"]], ["success"] * 3)
        self.assertTrue(all(item["started_at"] for item in result["outcomes"]))
        self.assertTrue(all(item["raw_path"] for item in result["outcomes"]))

    def test_web_tool_failure_does_not_hide_other_tool_success(self):
        with TemporaryDirectory() as directory:
            scan_plan = plan(SETTINGS, "172.28.0.10", Path(directory) / "captures")
            executor = FakeExecutor(fail={"nikto"})

            result = orchestrate(scan_plan, "synthetic-run", executor)

        outcomes = {item["tool"]: item for item in result["outcomes"]}
        self.assertEqual(outcomes["nmap"]["status"], "success")
        self.assertEqual(outcomes["nikto"]["status"], "failed")
        self.assertEqual(outcomes["nikto"]["exit_code"], 7)
        self.assertEqual(outcomes["zap"]["status"], "success")
        self.assertEqual(result["failed_tools"], 1)
        self.assertFalse(result["complete"])

    def test_discovery_failure_skips_every_web_tool(self):
        with TemporaryDirectory() as directory:
            scan_plan = plan(SETTINGS, "172.28.0.10", Path(directory) / "captures")
            executor = FakeExecutor(fail={"nmap"})

            result = orchestrate(scan_plan, "synthetic-run", executor)

        self.assertEqual([call.tool for call in executor.calls], ["nmap"])
        self.assertEqual(result["failed_tools"], 1)
        self.assertEqual(result["skipped_tools"], 2)
        self.assertTrue(
            all(
                "discovery failed" in item["skip_reason"]
                for item in result["outcomes"][1:]
            )
        )

    def test_successful_ssh_only_discovery_skips_web_tools(self):
        with TemporaryDirectory() as directory:
            scan_plan = plan(SETTINGS, "172.28.0.10", Path(directory) / "captures")
            executor = FakeExecutor(nmap_source=SYNTHETIC / "synthetic_nmap_ssh_only.xml")

            result = orchestrate(scan_plan, "synthetic-run", executor)

        self.assertEqual([call.tool for call in executor.calls], ["nmap"])
        self.assertEqual(result["successful_tools"], 1)
        self.assertEqual(result["skipped_tools"], 2)
        self.assertEqual(result["endpoints"], [])
        self.assertTrue(result["complete"])

    def test_canary_log_is_missing_empty_or_a_hard_failure(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "synthetic_missing.log"
            empty = root / "synthetic_empty.log"
            nonempty = root / "synthetic_nonempty.log"
            empty.write_text("", encoding="utf-8")
            nonempty.write_text("request observed", encoding="utf-8")

            self.assertEqual(check_canary_log(None)["status"], "MISSING")
            self.assertEqual(check_canary_log(missing)["status"], "MISSING")
            self.assertEqual(check_canary_log(empty)["status"], "VERIFIED")
            with self.assertRaises(ScopeError):
                check_canary_log(nonempty)


if __name__ == "__main__":
    unittest.main(verbosity=2)
