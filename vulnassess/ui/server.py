"""GET-only loopback workbench with explicit local analysis and no writable Store."""

import json
import os
from dataclasses import dataclass
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from socketserver import TCPServer
from typing import Any, cast
from urllib.parse import parse_qs, unquote, urlsplit

import yaml

import vulnassess.analyst as analyst
from vulnassess.errors import ConfigError, LLMUnavailable
from vulnassess.repository import ENV_VAR, AssessmentRepository
from vulnassess.settings import CONFIG_FILES, Settings
from vulnassess.ui.entry import render_entry
from vulnassess.ui.reader import local_path, open_read_store

STATIC_ROOT = Path(__file__).resolve().parent / "static"
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
)
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".woff2": "font/woff2",
}
MAX_STATIC_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes
    content_type: str = "application/json; charset=utf-8"


def json_response(status: int, payload: Any) -> Response:
    return Response(status, json.dumps(payload, sort_keys=True, allow_nan=False).encode("utf-8"))


def error_response(status: int, message: str) -> Response:
    return json_response(
        status,
        {
            "error": {
                "type": "ConfigError",
                "message": message,
                "exit_code": ConfigError.exit_code,
            },
        },
    )


class UiApplication:
    def __init__(
        self,
        database: str | Path,
        config_dir: str | Path,
        run_id: str | None = None,
        analyst_model: str = analyst.DEFAULT_MODEL,
        ollama_host: str = analyst.DEFAULT_HOST,
    ) -> None:
        resolved = str(database)
        if os.environ.get(ENV_VAR) and not resolved.startswith(
            ("postgres://", "postgresql://", "env:")
        ):
            # The backend-only env var takes precedence over the default SQLite
            # path so the same server can read the Supabase cloud store.
            resolved = f"env:{ENV_VAR}"
        self.database = (
            resolved
            if resolved.startswith(("postgres://", "postgresql://", "env:"))
            else local_path(resolved)
        )
        self.config_dir = local_path(config_dir)
        self.run_id = run_id
        self.analyst_model = analyst_model
        self.ollama_host = ollama_host
        for name in CONFIG_FILES:
            path = local_path(self.config_dir / name)
            if not path.is_relative_to(self.config_dir):
                raise ConfigError(f"configuration file leaves its local directory: {path}")
        settings = Settings(self.config_dir)
        self.configurations: dict[str, dict[str, Any]] = {}
        for name in ("scope", "weights"):
            path = self.config_dir / f"{name}.yaml"
            try:
                content = path.read_bytes()
                document = content.decode("utf-8")
                values = yaml.safe_load(document)
            except (OSError, UnicodeError, yaml.YAMLError) as error:
                raise ConfigError(f"cannot read configuration file {path}") from error
            if values != settings.raw[path.name]:
                raise ConfigError(f"configuration file changed during validation: {path}")
            self.configurations[name] = {
                "path": str(path),
                "sha256": sha256(content).hexdigest(),
                "values": values,
                "yaml": document,
            }
        with open_read_store(self.database) as store:
            if run_id is None:
                store.runs()
            else:
                store.run_info(run_id)
        if not (STATIC_ROOT / "index.html").is_file():
            raise ConfigError(f"MISSING: UI entry point {STATIC_ROOT / 'index.html'}")

    def _static(self, parts: list[str]) -> Response:
        path = STATIC_ROOT.joinpath(*parts).resolve()
        if not path.is_relative_to(STATIC_ROOT) or path.suffix not in CONTENT_TYPES:
            return error_response(404, "UI static file not found")
        try:
            if not path.is_file() or path.stat().st_size > MAX_STATIC_BYTES:
                return error_response(404, "UI static file not found")
            return Response(200, path.read_bytes(), CONTENT_TYPES[path.suffix])
        except OSError:
            return error_response(404, "UI static file not found")

    def _entry(self, requested_run: str | None = None) -> Response:
        template = self._static(["index.html"])
        if template.status != 200:
            return template
        try:
            with open_read_store(self.database) as store:
                run_id = self.run_id if requested_run is None else requested_run
                payload = None if run_id is None else store.run(run_id)
                runs = store.runs() if payload is None else []
            document = render_entry(
                template.body.decode("utf-8"), payload, runs, self.configurations
            )
        except ConfigError as error:
            return error_response(409, str(error))
        return Response(200, document.encode("utf-8"), "text/html; charset=utf-8")

    def cvss_fixture(self) -> dict[str, Any]:
        path = (
            Path(__file__).resolve().parents[2]
            / "tests"
            / "synthetic"
            / "synthetic_cvss31_vectors.json"
        )
        if not path.is_file():
            raise ConfigError(f"MISSING: CVSS arithmetic fixture {path}")
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise ConfigError(f"cannot read CVSS arithmetic fixture {path}") from error

    def analyst_report(self, run_id: str, host_ip: str) -> dict[str, Any]:
        with open_read_store(self.database) as store:
            payload = store.run(run_id)
        return {
            "run_id": run_id,
            **analyst.analyze_target(
                payload,
                host_ip,
                model=self.analyst_model,
                ollama_host=self.ollama_host,
            ),
        }

    def _repository(self) -> AssessmentRepository:
        """Open the expanded assessment store strictly read-only."""
        value = self.database if isinstance(self.database, str) else str(self.database)
        return AssessmentRepository(value, read_only=True)

    def _assessment_api(self, parts: list[str], query: dict[str, list[str]]) -> Response | None:
        """Read-only assessment-store routes; the browser never sees the DB URL."""
        if tuple(parts) in (
            ("api", "assessment-runs"),
            ("api", "assets"),
            ("api", "model-evaluations"),
            ("api", "ablations"),
        ):
            with self._repository() as repo:
                if parts == ["api", "assessment-runs"]:
                    payload: Any = {"runs": repo.assessment_runs()}
                elif parts == ["api", "assets"]:
                    payload = {"assets": repo.asset_inventory(self._first(query, "run"))}
                elif parts == ["api", "model-evaluations"]:
                    payload = repo.model_evaluations()
                else:
                    payload = {"ablations": repo.ablation_summaries()}
            return json_response(200, payload)
        if parts == ["api", "findings"]:
            try:
                limit = int(self._first(query, "limit") or 200)
            except ValueError:
                limit = 200
            with self._repository() as repo:
                findings = repo.findings_queue(
                    run_id=self._first(query, "run"),
                    status=self._first(query, "status"),
                    severity=self._first(query, "severity"),
                    decision=self._first(query, "decision"),
                    limit=limit,
                )
            return json_response(200, {"findings": findings})
        if len(parts) == 3 and parts[1] == "asset":
            with self._repository() as repo:
                return json_response(200, repo.asset_details(parts[2]))
        if len(parts) == 3 and parts[1] == "finding":
            with self._repository() as repo:
                return json_response(200, repo.finding_evidence(parts[2]))
        if len(parts) == 4 and parts[1] == "finding" and parts[3] == "score-history":
            with self._repository() as repo:
                return json_response(200, repo.finding_score_history(parts[2]))
        return None

    @staticmethod
    def _first(query: dict[str, list[str]], name: str) -> str | None:
        values = query.get(name)
        return values[0] if values else None

    def get(self, target: str) -> Response:
        try:
            parsed = urlsplit(target)
            decoded = unquote(parsed.path, errors="strict")
        except (ValueError, UnicodeError):
            return error_response(404, "UI path not found")
        if (
            parsed.scheme
            or parsed.netloc
            or parsed.fragment
            or not decoded.startswith("/")
            or any(ord(character) < 32 or ord(character) == 127 for character in decoded)
            or any(character in decoded for character in ("\\", ":", "%"))
        ):
            return error_response(404, "UI path not found")
        if decoded == "/workflow":
            return self._static(["workflow.html"])
        if decoded == "/":
            parameters = parse_qs(parsed.query, keep_blank_values=True)
            if parameters:
                if (
                    set(parameters) != {"run"}
                    or len(parameters["run"]) != 1
                    or not parameters["run"][0]
                ):
                    return error_response(400, "Entry query accepts exactly one non-empty run")
                return self._entry(parameters["run"][0])
            return self._entry()
        parts = decoded[1:].split("/")
        if any(not part or part.startswith(".") for part in parts):
            return error_response(404, "UI path not found")
        if parts == ["static", "index.html"]:
            return self._entry()
        if parts[0] == "static":
            return self._static(parts[1:])
        if parts in (["api", "scope"], ["api", "weights"]):
            return json_response(200, self.configurations[parts[1]])
        if parts == ["api", "cvss-fixture"]:
            try:
                return json_response(200, self.cvss_fixture())
            except ConfigError as error:
                return error_response(409, str(error))
        if parts[0] != "api":
            return error_response(404, "UI route not found")
        try:
            if len(parts) == 4 and parts[1] == "analyst":
                return json_response(200, self.analyst_report(parts[2], parts[3]))
            assessment = self._assessment_api(parts, parse_qs(parsed.query, keep_blank_values=True))
            if assessment is not None:
                return assessment
            with open_read_store(self.database) as store:
                if parts == ["api", "runs"]:
                    return json_response(200, {"runs": store.runs(), "selected_run": self.run_id})
                if len(parts) == 3 and parts[1] == "run":
                    return json_response(200, store.run(parts[2]))
                if len(parts) == 3 and parts[1] == "eval":
                    store.run_info(parts[2])
                    return json_response(
                        409,
                        {
                            "run_id": parts[2],
                            **store.unavailable("evaluation result", parts[2]),
                        },
                    )
                if len(parts) == 4 and parts[1] == "diff":
                    store.run_info(parts[2])
                    store.run_info(parts[3])
                    return json_response(
                        409,
                        {
                            "run_ids": parts[2:],
                            **store.unavailable("diff result", f"{parts[2]} / {parts[3]}"),
                        },
                    )
        except (ConfigError, LLMUnavailable) as error:
            return error_response(409, str(error))
        return error_response(404, "UI route not found")


class UiRequestHandler(BaseHTTPRequestHandler):
    server_version = "VulnAssess"
    sys_version = ""
    timeout = 5.0

    def log_message(self, format: str, *args: Any) -> None:
        return None

    def _reply(self, response: Response) -> None:
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(response.body)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        if response.status == 405:
            self.send_header("Allow", "GET")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(response.body)

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        self._reply(error_response(code, message or "Invalid UI request"))

    def parse_request(self) -> bool:
        if not super().parse_request():
            return False
        if self.command != "GET":
            self.close_connection = True
            self._reply(error_response(405, "UI supports GET only"))
            return False
        return True

    def _same_origin(self) -> bool:
        server = cast(UiServer, self.server)
        authority = f"127.0.0.1:{server.server_address[1]}"
        if self.headers.get_all("Host", []) != [authority]:
            self._reply(error_response(403, "UI Host must match its loopback address and port"))
            return False
        origin = self.headers.get("Origin")
        allowed = (None, f"http://{authority}")
        if origin not in allowed or self.headers.get("Sec-Fetch-Site") == "cross-site":
            self._reply(error_response(403, "Cross-origin UI requests are refused"))
            return False
        return True

    def do_GET(self) -> None:
        if not self._same_origin():
            return
        server = cast(UiServer, self.server)
        self._reply(server.application.get(self.path))


class UiServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self, application: UiApplication, port: int = 8765, host: str = "127.0.0.1"
    ) -> None:
        if host != "127.0.0.1":
            raise ConfigError(f"UI bind address {host!r} is forbidden; use 127.0.0.1")
        if type(port) is not int or not 0 <= port <= 65535:
            raise ConfigError(f"UI port must be an integer in 0..65535, got {port!r}")
        self.application = application
        try:
            super().__init__((host, port), UiRequestHandler)
        except OSError as error:
            raise ConfigError(
                f"cannot bind UI to 127.0.0.1:{port}; choose another --port ({error})"
            ) from error

    def server_bind(self) -> None:
        TCPServer.server_bind(self)
        self.server_name = "127.0.0.1"
        self.server_port = self.server_address[1]
