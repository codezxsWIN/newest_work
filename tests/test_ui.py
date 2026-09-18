"""UI contracts over existing stored demo records; no scanner, feed or model execution."""

import ast
import io
import json
import re
import sqlite3
import unittest
from contextlib import closing
from html.parser import HTMLParser
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
from xml.etree import ElementTree

from scripts.check_ui_cvss import verify_javascript, verify_python
from scripts.generate_ui_swatches import (
    MATRICES,
    contrast,
    read_tokens,
    svg_document,
    validate_palette,
)
from vulnassess.cli import build_parser, main
from vulnassess.errors import ConfigError
from vulnassess.role_model import RoleModel, load_model
from vulnassess.schema import Host
from vulnassess.settings import ROLE_NAMES, Settings
from vulnassess.ui.drawings import DRAWINGS, ROLE_BUILDINGS, building, door
from vulnassess.ui.entry import evidence, evidence_items
from vulnassess.ui.export import export_html
from vulnassess.ui.reader import ReadOnlyStore, _object
from vulnassess.ui.runtime import run_model
from vulnassess.ui.server import CSP, UiApplication, UiRequestHandler, UiServer

ROOT = Path(__file__).resolve().parents[1]
DATABASE = ROOT / "data" / "vulnassess.db"
SYNTHETIC = ROOT / "tests" / "synthetic"
DEMO_RUN = "demo"

SOCKET_GUARD = patch("socket.socket", side_effect=AssertionError("network forbidden in UI tests"))


def _provision_demo_database() -> None:
    """Build the demo records the UI contracts run against, exactly as run_demo.py does.

    The database is gitignored, so a fresh clone (and CI) must rebuild it here rather
    than depending on an author's leftover workspace state. A database that exists but
    lacks the demo run - stale, partial, or foreign - is rebuilt from scratch, because
    the contracts cannot run against an empty store. The contracts also probe a second
    run id, "verify": like the synthetic_ui_other row they create themselves, it only
    needs its runs-table row to exist.
    """
    needs_build = True
    if DATABASE.is_file():
        with closing(sqlite3.connect(DATABASE)) as connection:
            has_runs_table = (
                connection.execute(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='runs'"
                ).fetchone()[0]
                > 0
            )
            has_demo_run = (
                connection.execute("SELECT count(*) FROM runs WHERE run_id = 'demo'").fetchone()[0]
                if has_runs_table
                else 0
            )
        needs_build = not has_demo_run
    if needs_build:
        for stale in (DATABASE, Path(str(DATABASE) + "-wal"), Path(str(DATABASE) + "-shm")):
            stale.unlink(missing_ok=True)
        from run_demo import run as run_demo_pipeline

        code = run_demo_pipeline()
        if code != 0:
            raise RuntimeError(f"demo pipeline exited {code}; UI contracts need its records")
    with closing(sqlite3.connect(DATABASE)) as connection:
        connection.execute(
            "INSERT OR IGNORE INTO runs "
            "SELECT 'verify', started_at, config_hash, summary_json FROM runs "
            "WHERE run_id = 'demo'"
        )
        connection.commit()


def setUpModule() -> None:
    SOCKET_GUARD.start()
    _provision_demo_database()


def tearDownModule() -> None:
    SOCKET_GUARD.stop()


class MemoryConnection:
    def __init__(self, request: bytes) -> None:
        self.input = io.BytesIO(request)
        self.output = bytearray()

    def makefile(self, *_args: object, **_kwargs: object) -> io.BytesIO:
        return self.input

    def sendall(self, data: bytes) -> None:
        self.output.extend(data)

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout


def request(
    application: UiApplication,
    path: str,
    method: str = "GET",
    host: str = "127.0.0.1:8765",
    extra_headers: str = "",
    body: bytes = b"",
) -> tuple[int, dict[str, str], bytes]:
    connection = MemoryConnection(
        f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n{extra_headers}\r\n".encode("ascii") + body
    )
    server = SimpleNamespace(application=application, server_address=("127.0.0.1", 8765))
    UiRequestHandler(connection, ("127.0.0.1", 1), server)
    header_bytes, body = bytes(connection.output).split(b"\r\n\r\n", 1)
    lines = header_bytes.decode("ascii").split("\r\n")
    headers = dict(line.split(": ", 1) for line in lines[1:])
    return int(lines[0].split()[1]), headers, body


class TestUiContract(unittest.TestCase):
    def test_top_level_keys_are_pinned(self) -> None:
        application = UiApplication(DATABASE, ROOT / "config", DEMO_RUN)
        status, _, body = request(application, f"/api/run/{DEMO_RUN}")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(
            set(payload),
            {
                "run",
                "hosts",
                "findings",
                "context",
                "scores",
                "enrichments",
                "rationales",
                "feeds_meta",
                "feeds_meta_scope",
                "refusals",
                "config_hashes",
            },
        )
        self.assertEqual(set(payload["run"]), {"run_id", "started_at", "config_hash", "summary"})

    def test_every_host_and_finding_key_is_pinned(self) -> None:
        application = UiApplication(DATABASE, ROOT / "config", DEMO_RUN)
        status, _, body = request(application, f"/api/run/{DEMO_RUN}")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(len(payload["hosts"]), 3)
        self.assertEqual(len(payload["findings"]), 6)
        for host in payload["hosts"]:
            self.assertEqual(set(host), {"ip", "hostname", "os_guess", "services"})
            for service in host["services"]:
                self.assertEqual(
                    set(service),
                    {
                        "port",
                        "protocol",
                        "name",
                        "product",
                        "version",
                        "cpe",
                        "banner",
                        "tls",
                    },
                )
        for finding in payload["findings"]:
            self.assertEqual(
                set(finding),
                {
                    "id",
                    "host_ip",
                    "port",
                    "protocol",
                    "url",
                    "tool",
                    "tool_native_id",
                    "title",
                    "description",
                    "evidence",
                    "cve_ids",
                    "cwe_ids",
                    "reference_urls",
                    "native_severity",
                    "native_confidence",
                    "first_seen",
                    "last_seen",
                    "provenance",
                },
            )
            self.assertEqual(
                set(finding["provenance"]),
                {
                    "tool",
                    "raw_path",
                    "record_index",
                    "run_id",
                },
            )

    def test_every_score_matches_sqlite(self) -> None:
        application = UiApplication(DATABASE, ROOT / "config", DEMO_RUN)
        status, _, body = request(application, f"/api/run/{DEMO_RUN}")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        connection = sqlite3.connect(f"{DATABASE.as_uri()}?mode=ro", uri=True)
        try:
            rows = connection.execute(
                "SELECT finding_id, json, risk, band FROM scores WHERE run_id = ? "
                "ORDER BY risk DESC, finding_id",
                (DEMO_RUN,),
            ).fetchall()
        finally:
            connection.close()
        self.assertEqual(len(rows), len(payload["scores"]))
        for stored, actual in zip(rows, payload["scores"], strict=True):
            self.assertEqual(stored[0], actual["finding_id"])
            self.assertEqual(json.loads(stored[1]), actual)
            self.assertEqual(stored[2], actual["risk"])
            self.assertEqual(stored[3], actual["band"])
            for key in ("risk", "band", "env_score", "base_score", "threat_multiplier"):
                self.assertEqual(json.loads(stored[1])[key], actual[key])

    def test_unknown_record_keys_are_rejected(self) -> None:
        with self.assertRaisesRegex(ConfigError, "unknown=.*extra"):
            _object('{"name":"synthetic","extra":true}', "synthetic record", frozenset({"name"}))

    def test_missing_records_are_not_invented(self) -> None:
        with ReadOnlyStore(DATABASE) as store:
            payload = store.run(DEMO_RUN)
            with self.assertRaisesRegex(ConfigError, "MISSING: run"):
                store.run("synthetic_missing_run")
        self.assertEqual(payload["refusals"]["status"], "MISSING")
        self.assertIsNone(payload["refusals"]["records"])
        self.assertEqual(payload["feeds_meta_scope"], "current_store_not_frozen_per_run")

    def test_connection_is_read_only_and_never_creates_database(self) -> None:
        with ReadOnlyStore(DATABASE) as store:
            store.connection.execute("PRAGMA query_only = OFF")
            with self.assertRaises(sqlite3.OperationalError):
                store.connection.execute("DELETE FROM runs WHERE 0")
        with TemporaryDirectory(dir=SYNTHETIC, prefix="synthetic_ui_") as directory:
            missing = Path(directory) / "synthetic_missing.db"
            with self.assertRaisesRegex(ConfigError, "MISSING: SQLite database"):
                ReadOnlyStore(missing)
            self.assertFalse(missing.exists())

    def test_api_routes_have_explicit_contracts(self) -> None:
        directory = TemporaryDirectory(dir=SYNTHETIC, prefix="synthetic_ui_")
        self.addCleanup(directory.cleanup)
        database = Path(directory.name) / "synthetic_api.db"
        with closing(sqlite3.connect(f"{DATABASE.as_uri()}?mode=ro", uri=True)) as original:
            with closing(sqlite3.connect(database)) as copied:
                original.backup(copied)
                copied.execute(
                    "INSERT INTO runs (run_id, started_at, config_hash, summary_json) "
                    "SELECT ?, started_at, config_hash, '{}' FROM runs WHERE run_id = ?",
                    ("synthetic_ui_other", DEMO_RUN),
                )
                copied.commit()
        application = UiApplication(database, ROOT / "config", DEMO_RUN)
        expected = {
            "/api/runs": (200, {"runs", "selected_run"}),
            "/api/scope": (200, {"path", "sha256", "values", "yaml"}),
            "/api/weights": (200, {"path", "sha256", "values", "yaml"}),
            "/api/eval/verify": (409, {"run_id", "status", "records", "reason"}),
            "/api/diff/verify/synthetic_ui_other": (
                409,
                {"run_ids", "status", "records", "reason"},
            ),
        }
        for path, (expected_status, keys) in expected.items():
            with self.subTest(path=path):
                status, _, body = request(application, path)
                self.assertEqual(status, expected_status)
                self.assertEqual(set(json.loads(body)), keys)
                if status == 409:
                    self.assertEqual(json.loads(body)["status"], "MISSING")
                    self.assertIsNone(json.loads(body)["records"])


class TestUiServer(unittest.TestCase):
    def setUp(self) -> None:
        self.application = UiApplication(DATABASE, ROOT / "config", DEMO_RUN)

    def test_serves_index_and_api_on_loopback(self) -> None:
        for path in ("/", "/api/runs"):
            with self.subTest(path=path):
                status, _, body = request(self.application, path)
                self.assertEqual(status, 200)
                self.assertTrue(body)
        with patch(
            "vulnassess.ui.server.ThreadingHTTPServer.__init__", return_value=None
        ) as constructor:
            UiServer(self.application, port=0)
        constructor.assert_called_once_with(("127.0.0.1", 0), UiRequestHandler)

    def test_refuses_non_loopback_bind(self) -> None:
        for host in ("0.0.0.0", "localhost", "::1", "127.0.0.2", "172.28.0.10", ""):
            with self.subTest(host=host), self.assertRaisesRegex(ConfigError, "bind address"):
                UiServer(self.application, port=0, host=host)

    def test_only_get_is_served(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"):
            for path in ("/api/runs", "/api/model/run"):
                with self.subTest(method=method, path=path):
                    status, headers, _ = request(self.application, path, method)
                    self.assertEqual(status, 405)
                    self.assertEqual(headers["Allow"], "GET")

    def test_traversal_is_refused(self) -> None:
        for path in (
            "/static/../../config/scope.yaml",
            "/static/%2e%2e/%2e%2e/config/scope.yaml",
            "/static/%252e%252e/config/scope.yaml",
            "/static/..%5c..%5cconfig%5cscope.yaml",
            "/static/index.html::$DATA",
            "/static/%00index.html",
            "/static/",
            "/static",
            "/static/.env",
            "/config/scope.yaml",
        ):
            with self.subTest(path=path):
                status, _, body = request(self.application, path)
                self.assertEqual(status, 404)
                self.assertNotIn(b"allowed_cidrs", body)

    def test_csp_header_present(self) -> None:
        for path in ("/", "/api/runs", "/missing", "/api/eval/verify"):
            with self.subTest(path=path):
                _, headers, _ = request(self.application, path)
                self.assertEqual(headers["Content-Security-Policy"], CSP)
                self.assertIn("default-src 'self'", CSP)
                self.assertNotIn("unsafe-inline", CSP)
                self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_rebinding_and_cross_origin_requests_are_refused(self) -> None:
        self.assertEqual(
            request(self.application, "/api/runs", host="untrusted.invalid:8765")[0], 403
        )
        for header in (
            "Origin: null\r\n",
            "Origin: https://untrusted.invalid\r\n",
            "Sec-Fetch-Site: cross-site\r\n",
            "Host: untrusted.invalid\r\n",
        ):
            self.assertEqual(request(self.application, "/api/runs", extra_headers=header)[0], 403)

    def test_cli_selects_run_and_closes_on_interrupt(self) -> None:
        arguments = [
            "ui",
            "--db",
            str(DATABASE),
            "--config",
            str(ROOT / "config"),
            "--run",
            DEMO_RUN,
            "--port",
            "8765",
            "--json",
        ]
        output = io.StringIO()
        with patch("vulnassess.ui.server.UiServer") as server_class, patch("sys.stdout", output):
            server = server_class.return_value.__enter__.return_value
            server.server_port = 8765
            server.serve_forever.side_effect = KeyboardInterrupt
            self.assertEqual(main(arguments), 0)
        self.assertEqual(
            json.loads(output.getvalue()),
            {
                "url": "http://127.0.0.1:8765/",
                "run_id": DEMO_RUN,
                "read_only": True,
            },
        )
        server_class.return_value.__exit__.assert_called_once()
        self.assertEqual(build_parser().parse_args(["ui", "--run-id", DEMO_RUN]).run_id, DEMO_RUN)

    def test_cli_missing_database_is_config_error_without_traceback(self) -> None:
        with TemporaryDirectory(dir=SYNTHETIC, prefix="synthetic_ui_") as directory:
            path = Path(directory) / "synthetic_missing.db"
            output = io.StringIO()
            with patch("sys.stderr", output):
                self.assertEqual(main(["ui", "--db", str(path)]), ConfigError.exit_code)
            self.assertIn(str(path), output.getvalue())
            self.assertNotIn("Traceback", output.getvalue())
            self.assertFalse(path.exists())

    def test_invalid_port_is_rejected_before_socket_creation(self) -> None:
        for port in (-1, 65536, True, "8765"):
            with self.subTest(port=port), self.assertRaises(ConfigError):
                UiServer(self.application, port=port)

    def test_static_index_and_no_inline_executable_code(self) -> None:
        status, headers, body = request(self.application, "/static/index.html")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")
        document = body.decode("utf-8")
        scripts = re.findall(r"<script([^>]*)>(.*?)</script>", document, re.DOTALL)
        self.assertTrue(scripts)
        for attributes, content in scripts:
            if 'type="application/json"' in attributes:
                json.loads(content)
                self.assertNotIn("</script", content.lower())
            else:
                self.assertIn('type="module"', attributes)
                self.assertIn('src="/static/app.js"', attributes)
                self.assertFalse(content.strip())
        self.assertNotIn(b"onclick=", body)
        self.assertNotIn(b"eval(", body)

    def test_unknown_and_injected_run_ids_do_not_return_other_runs(self) -> None:
        for path in ("/api/run/missing", "/api/run/%27%20OR%201%3D1--"):
            status, _, body = request(self.application, path)
            self.assertEqual(status, 409)
            self.assertEqual(set(json.loads(body)), {"error"})
            self.assertNotIn(b"CVE-1999-9001", body)


class TestUiModel(unittest.TestCase):
    def setUp(self) -> None:
        self.application = UiApplication(DATABASE, ROOT / "config", DEMO_RUN)

    def infer(self, payload: dict) -> tuple[int, dict[str, str], bytes]:
        body = json.dumps(payload).encode("utf-8")
        return request(
            self.application,
            "/api/model/run",
            "POST",
            extra_headers=(
                "Origin: http://127.0.0.1:8765\r\n"
                "X-Vulnassess-Action: run-model\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
            ),
            body=body,
        )

    def test_model_action_is_refused_without_inference_or_record_changes(self) -> None:
        with ReadOnlyStore(DATABASE) as store:
            before = store.run(DEMO_RUN)
        with patch.object(
            RoleModel, "predict", side_effect=AssertionError("UI inference forbidden")
        ) as predictor:
            status, headers, body = self.infer({"run_id": DEMO_RUN})
        self.assertEqual(status, 405)
        self.assertEqual(headers["Allow"], "GET")
        self.assertEqual(json.loads(body)["error"]["message"], "UI supports GET only")
        predictor.assert_not_called()
        with ReadOnlyStore(DATABASE) as store:
            self.assertEqual(before, store.run(DEMO_RUN))

    def test_retained_helper_matches_classifier_without_changing_records(self) -> None:
        with ReadOnlyStore(DATABASE) as store:
            before = store.run(DEMO_RUN)
        actual_predict = RoleModel.predict
        with patch.object(
            RoleModel, "predict", autospec=True, side_effect=actual_predict
        ) as predictor:
            result = run_model(DATABASE, ROOT / "models" / "synthetic-role-model.json", DEMO_RUN)
        self.assertEqual(predictor.call_count, len(before["hosts"]))
        self.assertEqual(result["source"], "live_local_inference")
        self.assertEqual(result["status"], "completed")
        self.assertFalse(result["canonical_scores_changed"])
        model = load_model(ROOT / "models" / "synthetic-role-model.json")
        self.assertEqual(result["model"]["model_hash"], model.model_hash)
        self.assertGreaterEqual(result["elapsed_ms"], 0)
        for stored, live in zip(before["hosts"], result["hosts"], strict=True):
            self.assertEqual(live["input"], stored)
            self.assertEqual(live["prediction"], model.predict(Host.from_json(stored)).to_json())
            self.assertTrue(live["features"] or live["prediction"]["abstained"])
        with ReadOnlyStore(DATABASE) as store:
            self.assertEqual(before, store.run(DEMO_RUN))

    def test_loading_page_and_removed_model_routes_does_not_run_inference(self) -> None:
        with patch.object(RoleModel, "predict", side_effect=AssertionError("implicit inference")):
            for path, status in (
                ("/", 200),
                ("/api/model", 404),
                ("/api/model/run", 404),
                ("/api/run/verify", 200),
            ):
                self.assertEqual(request(self.application, path)[0], status)

    def test_model_request_is_refused_regardless_of_origin_and_action(self) -> None:
        self.assertEqual(request(self.application, "/api/model/run", "POST")[0], 405)
        self.assertEqual(
            request(
                self.application,
                "/api/model/run",
                "POST",
                extra_headers="Origin: http://127.0.0.1:8765\r\n",
            )[0],
            405,
        )
        self.assertEqual(
            request(
                self.application,
                "/api/model/run",
                "POST",
                extra_headers="Origin: https://untrusted.invalid\r\nX-Vulnassess-Action: run-model\r\n",
            )[0],
            405,
        )

    def test_model_request_cannot_select_paths_or_write_scores(self) -> None:
        for payload in (
            {"run_id": DEMO_RUN, "model_path": "other.json"},
            {"run_id": DEMO_RUN, "write_scores": True},
            {"run_id": []},
            {},
        ):
            self.assertEqual(self.infer(payload)[0], 405)
        self.assertEqual(self.infer({"run_id": "synthetic_missing_run"})[0], 405)

    def test_missing_model_is_named_by_retained_helper_without_fallback(self) -> None:
        with self.assertRaisesRegex(ConfigError, "synthetic_missing.json"):
            run_model(DATABASE, ROOT / "models" / "synthetic_missing.json", DEMO_RUN)

    def test_viewer_does_not_load_models(self) -> None:
        with patch(
            "vulnassess.ui.runtime.load_model", side_effect=AssertionError("model load forbidden")
        ):
            application = UiApplication(DATABASE, ROOT / "config", DEMO_RUN)
            self.assertEqual(request(application, "/")[0], 200)
            self.assertEqual(request(application, "/api/model")[0], 404)
        source = (ROOT / "vulnassess" / "ui" / "server.py").read_text(encoding="utf-8")
        imports = [
            node.module for node in ast.walk(ast.parse(source)) if isinstance(node, ast.ImportFrom)
        ]
        self.assertNotIn("vulnassess.ui.runtime", imports)
        self.assertNotIn("vulnassess.role_model", imports)
        self.assertFalse(hasattr(self.application, "infer"))


class EvidenceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.blocks: list[str] = []
        self.labels: list[str] = []
        self.active: str | None = None
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        classes = (dict(attrs).get("class") or "").split()
        if "evidence" in classes or "source-label" in classes:
            self.active = "blocks" if "evidence" in classes else "labels"
            self.text = []

    def handle_data(self, data: str) -> None:
        if self.active is not None:
            self.text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if self.active is not None:
            getattr(self, self.active).append("".join(self.text))
            self.active = None


class TestUiExport(unittest.TestCase):
    """Test shared live/offline markup against stored assessment records."""

    def test_export_is_self_contained(self) -> None:
        application = UiApplication(DATABASE, ROOT / "config", DEMO_RUN)
        with ReadOnlyStore(DATABASE) as store:
            before = store.run(DEMO_RUN)
        with TemporaryDirectory(dir=SYNTHETIC, prefix="synthetic_ui_") as directory:
            path = export_html(application, Path(directory) / "synthetic_export.html")
            document = path.read_text(encoding="utf-8")
        attributes = []

        class AssetParser(HTMLParser):
            def handle_starttag(self, tag, attrs):
                attributes.extend(
                    (tag, key, value) for key, value in attrs if key in {"src", "href"}
                )

        AssetParser().feed(document)
        for tag, key, value in attributes:
            self.assertFalse(value.startswith(("http://", "https://", "//")), (tag, key, value))
            self.assertFalse(tag == "script" and key == "src")
            self.assertFalse(value.startswith("/static/"))
        self.assertIn("connect-src 'none'", document)
        bootstrap = json.loads(
            re.search(
                r'<script id="assessment-data" type="application/json">(.*?)</script>',
                document,
                re.DOTALL,
            ).group(1)
        )
        self.assertEqual(bootstrap["assessment"], before)
        self.assertTrue(bootstrap["offline"])
        self.assertEqual(len(bootstrap["cvss_fixture"]["vectors"]), 211)
        self.assertNotIn("import { scoreVector", document)
        with ReadOnlyStore(DATABASE) as store:
            self.assertEqual(store.run(DEMO_RUN), before)

    def test_export_and_live_view_share_compare_queue_and_inspector_text(self) -> None:
        application = UiApplication(DATABASE, ROOT / "config", DEMO_RUN)
        live = request(application, "/")[2].decode("utf-8")
        with TemporaryDirectory(dir=SYNTHETIC, prefix="synthetic_ui_") as directory:
            offline = export_html(application, Path(directory) / "synthetic_export.html").read_text(
                encoding="utf-8"
            )
        for identifier, end in (
            ("compare-table", "</table>"),
            ("ranked-list", "</table>"),
            ("inspector", "</dialog>"),
        ):
            self.assertEqual(
                live.split(f'id="{identifier}"', 1)[1].split(end, 1)[0],
                offline.split(f'id="{identifier}"', 1)[1].split(end, 1)[0],
            )

    def test_cli_export_does_not_start_server(self) -> None:
        with TemporaryDirectory(dir=SYNTHETIC, prefix="synthetic_ui_") as directory:
            path = Path(directory) / "synthetic_export.html"
            output = io.StringIO()
            with (
                patch(
                    "vulnassess.ui.server.UiServer",
                    side_effect=AssertionError("export must not listen"),
                ),
                patch("sys.stdout", output),
            ):
                code = main(["ui", "--run", DEMO_RUN, "--export", str(path), "--json"])
            self.assertEqual(code, 0)
            self.assertTrue(path.is_file())
            self.assertTrue(json.loads(output.getvalue())["read_only"])

    def test_sandbox_banner_present(self) -> None:
        document = request(UiApplication(DATABASE, ROOT / "config", DEMO_RUN), "/")[2].decode(
            "utf-8"
        )
        self.assertIn("Sandbox. Nothing stored changes.", document)
        self.assertIn("Calculated in this browser", document)
        self.assertIn('id="sandbox-form"', document)

    def test_four_connected_stages_render_the_actual_run(self) -> None:
        application = UiApplication(DATABASE, ROOT / "config", DEMO_RUN)
        document = request(application, "/")[2].decode("utf-8")
        for stage in ("evidence", "context", "risk", "priorities"):
            self.assertIn(f'id="stage-{stage}"', document)
            self.assertIn(f'data-stage="{stage}"', document)
        for name in ("compare-table", "ranked-list", "inspector", "tour"):
            self.assertIn(f'id="{name}"', document)
        data = re.search(
            r'<script id="assessment-data" type="application/json">(.*?)</script>',
            document,
            re.DOTALL,
        )
        self.assertIsNotNone(data)
        self.assertEqual(
            json.loads(data.group(1))["assessment"],
            json.loads(request(application, f"/api/run/{DEMO_RUN}")[2]),
        )

    def test_facets_cover_all_values_in_run(self) -> None:
        application = UiApplication(DATABASE, ROOT / "config", DEMO_RUN)
        document = request(application, "/")[2].decode("utf-8")
        with ReadOnlyStore(DATABASE) as store:
            payload = store.run(DEMO_RUN)
        for facet in ("band", "host", "scanner", "exposure", "kev", "cve", "unscored"):
            self.assertIn(f'data-facet="{facet}"', document)
        for finding in payload["findings"]:
            self.assertIn(f'<option value="{finding["host_ip"]}">', document)
            self.assertIn(f'<option value="{finding["tool"]}">', document)

    def test_drawer_contains_all_finding_fields(self) -> None:
        application = UiApplication(DATABASE, ROOT / "config", DEMO_RUN)
        document = request(application, "/")[2].decode("utf-8")
        with ReadOnlyStore(DATABASE) as store:
            payload = store.run(DEMO_RUN)
        from html import escape

        for finding in payload["findings"]:
            panel = document.split(f'data-inspection="{finding["id"]}"', 1)[1].split(
                "</article>", 1
            )[0]
            for key in finding:
                self.assertIn(escape(f'"{key}"'), panel)
            self.assertIn(escape(finding["evidence"]), panel)

    def test_missing_evaluation_is_never_a_made_up_metric(self) -> None:
        application = UiApplication(DATABASE, ROOT / "config", DEMO_RUN)
        document = request(application, "/")[2].decode("utf-8")
        self.assertIn("No persisted expert-evaluation result", document)
        self.assertIn("critical queue are unavailable", document)

    def test_run_strip_shows_hash_and_feed_dates(self) -> None:
        application = UiApplication(DATABASE, ROOT / "config", DEMO_RUN)
        payload = json.loads(request(application, f"/api/run/{DEMO_RUN}")[2])
        document = request(application, "/")[2].decode("utf-8")
        strip = document.split('id="run-strip"', 1)[1].split("</section>", 1)[0]
        for value in payload["config_hashes"]["score_weights"]:
            self.assertIn(value, strip)
        for feed in payload["feeds_meta"]:
            self.assertIn(feed["file_date"], strip)
        self.assertIn(payload["run"]["started_at"], strip)
        self.assertIn("Version not recorded", strip)
        self.assertIn("not frozen per run", strip)

    def test_pipeline_map_counts_match_api(self) -> None:
        application = UiApplication(DATABASE, ROOT / "config", DEMO_RUN)
        payload = json.loads(request(application, f"/api/run/{DEMO_RUN}")[2])
        document = request(application, "/")[2].decode("utf-8")
        expected = []
        for record in payload["run"]["summary"]["imports"]:
            expected.append(("hosts", str(record["hosts"])))
            expected.extend(
                (f"findings.{tool}", str(count))
                for tool, count in sorted(record["findings"].items())
            )
        self.assertEqual(
            re.findall(r'data-stored-count="([^"]+)">([^<]+)</span>', document), expected
        )
        self.assertIn("Stage totals and completion events are not stored", document)
        for stage in ("import", "intel", "enrich", "context", "rank", "explain", "report"):
            self.assertIn(f'href="#stage-{stage}"', document)
            self.assertIn(f'id="stage-{stage}"', document)

    def test_evidence_strings_are_in_evidence_blocks(self) -> None:
        application = UiApplication(DATABASE, ROOT / "config", DEMO_RUN)
        status, _, body = request(application, "/")
        self.assertEqual(status, 200)
        payload = json.loads(request(application, f"/api/run/{DEMO_RUN}")[2])
        parser = EvidenceParser()
        parser.feed(body.decode("utf-8"))
        quoted = evidence_items(payload)
        self.assertTrue(quoted)
        for value, source in quoted:
            self.assertIn(value, parser.blocks)
            self.assertIn(source, parser.labels)
        self.assertEqual(len(parser.blocks), len(parser.labels))
        self.assertIn('class="inferred"', body.decode("utf-8"))

    def test_evidence_is_escaped_and_not_interpreted_as_markup(self) -> None:
        quote_text = '<script>alert("synthetic")</script>&<img src=x onerror=alert(1)>'
        rendered = evidence(quote_text, "<synthetic source>")
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("<img", rendered)
        parser = EvidenceParser()
        parser.feed(rendered)
        self.assertEqual(parser.blocks, [quote_text])
        self.assertEqual(parser.labels, ["<synthetic source>"])


class TestCvss31(unittest.TestCase):
    def test_fixture_matches_python(self) -> None:
        verify_python()

    def test_js_port_matches_python(self) -> None:
        verify_javascript()


class TestUiUpgrades(unittest.TestCase):
    """Additive analytics visuals: quadrant map, risk waterfall, threat strip, motion."""

    def test_risk_stage_places_every_scored_finding_on_the_quadrant(self) -> None:
        application = UiApplication(DATABASE, ROOT / "config", DEMO_RUN)
        document = request(application, "/")[2].decode("utf-8")
        self.assertIn('id="quadrant-map"', document)
        with ReadOnlyStore(DATABASE) as store:
            scored = [
                score for score in store.run(DEMO_RUN)["scores"] if score["base_score"] is not None
            ]
        self.assertEqual(document.count('class="quad-point'), len(scored))
        for score in scored:
            self.assertIn(f'data-inspect="{score["finding_id"]}"', document)

    def test_quadrant_labels_exploitation_and_honest_unscored_lane(self) -> None:
        application = UiApplication(DATABASE, ROOT / "config", DEMO_RUN)
        document = request(application, "/")[2].decode("utf-8")
        self.assertIn("high severity", document)
        self.assertIn("no EPSS row", document)
        self.assertIn("never from this map", document)

    def test_waterfall_reconstructs_formation_from_stored_values(self) -> None:
        application = UiApplication(DATABASE, ROOT / "config", DEMO_RUN)
        document = request(application, "/")[2].decode("utf-8")
        self.assertIn('id="risk-waterfall"', document)
        self.assertIn("Context-adjusted severity", document)
        with ReadOnlyStore(DATABASE) as store:
            scored = [score for score in store.run(DEMO_RUN)["scores"] if score["base_vector"]]
        if not scored:
            return
        top = max(scored, key=lambda score: score["risk"])
        self.assertIn(str(top["risk"]), document)
        if top["kev"]:
            self.assertIn("KEV boost", document)

    def test_threat_strip_counts_match_the_store(self) -> None:
        application = UiApplication(DATABASE, ROOT / "config", DEMO_RUN)
        document = request(application, "/")[2].decode("utf-8")
        with ReadOnlyStore(DATABASE) as store:
            scores = store.run(DEMO_RUN)["scores"]
        kev = sum(1 for score in scores if score["kev"])
        self.assertIn(f'data-count="{kev}"', document)
        self.assertIn('data-count="' + str(len(scores)) + '"', document)

    def test_motion_layer_guards_reduced_motion(self) -> None:
        static = ROOT / "vulnassess" / "ui" / "static"
        javascript = (static / "app.js").read_text(encoding="utf-8")
        stylesheet = (static / "workbench.css").read_text(encoding="utf-8")
        self.assertIn("prefers-reduced-motion", javascript)
        self.assertIn("IntersectionObserver", javascript)
        self.assertIn("prefers-reduced-motion", stylesheet)
        self.assertIn("[data-reveal]", stylesheet)

    def test_new_visuals_survive_the_offline_export(self) -> None:
        from vulnassess.ui.export import export_html

        application = UiApplication(DATABASE, ROOT / "config", DEMO_RUN)
        with TemporaryDirectory(dir=SYNTHETIC, prefix="synthetic_ui_") as directory:
            path = export_html(application, Path(directory) / "upgrade_export.html")
            document = path.read_text(encoding="utf-8")
        self.assertIn('id="quadrant-map"', document)
        self.assertIn('id="risk-waterfall"', document)
        self.assertIn("data-reveal", document)


class TestUiAssets(unittest.TestCase):
    def test_active_styles_use_serif_inference_and_dark_tokens(self) -> None:
        static = ROOT / "vulnassess" / "ui" / "static"
        template = (static / "index.html").read_text(encoding="utf-8")
        stylesheet = (static / "workbench.css").read_text(encoding="utf-8")
        self.assertIn('href="/static/workbench.css"', template)
        self.assertRegex(stylesheet, r"h1, h2, h3, \.inferred\s*\{[^}]*var\(--font-display\)")
        self.assertRegex(stylesheet, r"\.evidence\s*\{[^}]*var\(--font-evidence\)")
        self.assertIn("prefers-reduced-motion: reduce", stylesheet)
        tokens = read_tokens()
        for prefix in ("", "night-"):
            for foreground in ("ink", "muted", "critical", "high", "medium", "low"):
                for background in ("paper", "surface", "wash"):
                    self.assertGreaterEqual(
                        contrast(tokens[prefix + foreground], tokens[prefix + background]), 4.5
                    )

    def test_tour_steps_reference_existing_anchors(self) -> None:
        application = UiApplication(DATABASE, ROOT / "config", DEMO_RUN)
        document = request(application, "/")[2].decode("utf-8")
        source = (ROOT / "vulnassess" / "ui" / "static" / "app.js").read_text(encoding="utf-8")
        targets = re.findall(r"target: '([^']+)'", source)
        self.assertEqual(len(targets), 6)
        identifiers = set(re.findall(r'\bid="([^"]+)"', document))
        classes = {
            name for names in re.findall(r'\bclass="([^"]+)"', document) for name in names.split()
        }
        for target in targets:
            self.assertIn(target[1:], identifiers if target.startswith("#") else classes)
        bootstrap = json.loads(
            re.search(
                r'<script id="assessment-data" type="application/json">(.*?)</script>',
                document,
                re.DOTALL,
            ).group(1)
        )
        followed = next(
            score
            for score in bootstrap["assessment"]["scores"]
            if score["finding_id"] == bootstrap["tour_finding"]
        )
        self.assertEqual(followed["host_ip"], "172.28.0.10")
        self.assertIn(f"host-{followed['host_ip']}", identifiers)
        self.assertIn(f"context-{followed['host_ip']}", identifiers)
        self.assertIn(f'data-inspect="{followed["finding_id"]}"', document)

    def test_every_role_has_a_building(self) -> None:
        roles = set(Settings(ROOT / "config").roles["roles"]) | {"unknown"}
        self.assertEqual(roles, set(ROLE_NAMES))
        self.assertEqual(roles, set(ROLE_BUILDINGS))
        self.assertEqual(set(ROLE_BUILDINGS.values()), {"shed", "office", "vault", "cabinet"})
        for role in sorted(roles):
            path = DRAWINGS / f"{ROLE_BUILDINGS[role]}.svg"
            self.assertTrue(path.is_file(), f"MISSING: {path}")
            document = ElementTree.fromstring(building(role))
            self.assertEqual(document.attrib["viewBox"], "0 0 240 240")
            self.assertEqual(document.attrib["role"], "img")
            self.assertTrue(document.attrib["aria-label"])

    def test_buildings_and_doors_have_small_and_large_dimensions(self) -> None:
        stylesheet = (ROOT / "vulnassess" / "ui" / "static" / "entry.css").read_text(
            encoding="utf-8"
        )
        self.assertRegex(
            stylesheet,
            r"\.building-drawing,\s*\.door-drawing\s*\{[^}]*width:\s*48px;[^}]*height:\s*48px;",
        )
        self.assertRegex(
            stylesheet, r"\.drawing-sample \.building-drawing\s*\{[^}]*width:\s*240px;"
        )
        document = ElementTree.parse(DRAWINGS / "door.svg").getroot()
        self.assertEqual(document.attrib["viewBox"], "0 0 48 48")
        self.assertIn('class="door-badge"', door("Critical"))

    def test_every_finding_door_uses_its_stored_band(self) -> None:
        application = UiApplication(DATABASE, ROOT / "config", DEMO_RUN)
        document = request(application, "/")[2].decode("utf-8")
        payload = json.loads(request(application, f"/api/run/{DEMO_RUN}")[2])
        for score in payload["scores"]:
            self.assertIn(door(score["band"], score["finding_id"]), document)
        self.assertEqual(document.count('data-finding-id="'), len(payload["findings"]))
        self.assertEqual(document.count('id="legend-heading"'), 1)

    def test_evidence_and_inference_have_distinct_typefaces(self) -> None:
        static = ROOT / "vulnassess" / "ui" / "static"
        tokens = (static / "tokens.css").read_text(encoding="utf-8")
        stylesheet = (static / "entry.css").read_text(encoding="utf-8")
        self.assertIn('--font-prose: "Segoe UI", system-ui, sans-serif;', tokens)
        self.assertIn('--font-evidence: Consolas, "Liberation Mono", monospace;', tokens)
        self.assertRegex(stylesheet, r"\.evidence\s*\{[^}]*font-family:\s*var\(--font-evidence\)")
        self.assertRegex(stylesheet, r"\.inferred\s*\{[^}]*font-family:\s*var\(--font-prose\)")
        self.assertNotIn("@font-face", tokens + stylesheet)

    def test_no_hardcoded_colours_outside_tokens(self) -> None:
        static = ROOT / "vulnassess" / "ui" / "static"
        tokens = static / "tokens.css"
        self.assertTrue(tokens.is_file())
        for path in static.rglob("*"):
            if path.suffix not in {".css", ".js"} or path == tokens:
                continue
            self.assertIsNone(
                re.search(r"#[0-9a-fA-F]{3,8}\b", path.read_text(encoding="utf-8")), path
            )

    def test_severity_colours_survive_simulations_and_text_contrast(self) -> None:
        results = validate_palette(read_tokens())
        self.assertEqual(len(results), 4)

    def test_simulated_swatches_are_reproducible_svg(self) -> None:
        for mode in MATRICES:
            path = ROOT / "docs" / "ui" / "colour-check" / f"{mode}.svg"
            self.assertTrue(path.is_file(), f"MISSING: {path}")
            document = path.read_text(encoding="utf-8")
            self.assertEqual(document, svg_document(read_tokens(), mode))
            element = ElementTree.fromstring(document)
            self.assertEqual(element.attrib["viewBox"], "0 0 960 340")
            self.assertIsNotNone(element.find("{http://www.w3.org/2000/svg}title"))


class TestWalls(unittest.TestCase):
    def test_ui_imports_no_network_or_subprocess(self) -> None:
        forbidden = {
            "subprocess",
            "urllib.request",
            "urllib.error",
            "httpx",
            "requests",
            "socket",
            "vulnassess.explain",
            "vulnassess.pipeline",
            "vulnassess.scoring",
            "vulnassess.context",
            "vulnassess.intel",
            "vulnassess.evaluate",
            "vulnassess.diff",
        }
        for path in (ROOT / "vulnassess" / "ui").rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""] + [
                        f"{node.module}.{alias.name}" for alias in node.names
                    ]
                else:
                    continue
                for name in names:
                    self.assertFalse(
                        any(name == item or name.startswith(item + ".") for item in forbidden),
                        (path, name),
                    )


if __name__ == "__main__":
    unittest.main(verbosity=2)
