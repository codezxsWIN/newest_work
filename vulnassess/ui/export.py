"""CLI-only, single-file export of the same read-only assessment view."""

import base64
import json
import re
from hashlib import sha256
from pathlib import Path

from vulnassess.errors import ConfigError
from vulnassess.ui.reader import local_path
from vulnassess.ui.server import STATIC_ROOT, UiApplication


def _asset(name: str) -> str:
    path = STATIC_ROOT / name
    if not path.is_file():
        raise ConfigError(f"MISSING: UI asset {path}")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ConfigError(f"cannot read UI asset {path}") from error


def _hash_source(text: str) -> str:
    return base64.b64encode(sha256(text.encode("utf-8")).digest()).decode("ascii")


def export_html(application: UiApplication, destination: str | Path) -> Path:
    if application.run_id is None:
        raise ConfigError("UI export requires --run or --run-id naming an existing assessment")
    target = local_path(destination)
    if target.suffix.lower() != ".html":
        raise ConfigError(f"UI export requires an .html output path: {target}")
    if target.is_relative_to(STATIC_ROOT) or target.is_relative_to(application.config_dir):
        raise ConfigError(f"UI export must not overwrite source or configuration files: {target}")
    response = application.get("/")
    if response.status != 200:
        raise ConfigError(
            f"UI export cannot read run {application.run_id!r}: {response.body.decode('utf-8')}"
        )
    document = response.body.decode("utf-8")
    script_match = re.search(
        r'<script id="assessment-data" type="application/json">(.*?)</script>', document, re.DOTALL
    )
    if script_match is None:
        raise ConfigError("UI export is missing the assessment-data element")
    bootstrap = json.loads(script_match.group(1))
    bootstrap["offline"] = True
    bootstrap["cvss_fixture"] = application.cvss_fixture()
    serialized = (
        json.dumps(bootstrap, sort_keys=True, ensure_ascii=True, allow_nan=False)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )
    document = document[: script_match.start(1)] + serialized + document[script_match.end(1) :]
    style = _asset("tokens.css") + "\n" + _asset("workbench.css")
    import_line = "import { scoreVector, sandbox } from './cvss31.js';"
    app = _asset("app.js")
    if app.count(import_line) != 1:
        raise ConfigError("UI export requires the known local CVSS module import")
    script = _asset("cvss31.js") + "\n" + app.replace(import_line, "", 1)
    for name in ("tokens.css", "workbench.css"):
        document = document.replace(f'<link rel="stylesheet" href="/static/{name}">', "")
    document = document.replace('<script type="module" src="/static/app.js"></script>', "")
    policy = (
        f"default-src 'none'; script-src 'sha256-{_hash_source(script)}'; "
        f"style-src 'sha256-{_hash_source(style)}'; img-src data:; connect-src 'none'; "
        "base-uri 'none'; form-action 'none'"
    )
    document = document.replace(
        "</head>",
        f'<meta http-equiv="Content-Security-Policy" content="{policy}"><style>{style}</style></head>',
    )
    document = document.replace("</body>", f'<script type="module">{script}</script></body>')
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(document, encoding="utf-8", newline="\n")
    except OSError as error:
        raise ConfigError(f"cannot write UI export {target}: {error}") from error
    return target
