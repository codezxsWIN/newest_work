"""Build the complete local visual pipeline replay.

The replay uses labelled synthetic scanner/feed/model inputs and is not evidence of
accuracy on real captures. It makes no network calls and needs no web server.
"""

import argparse
import io
import json
import webbrowser
from contextlib import redirect_stdout
from pathlib import Path

from run_model_simulation import main as run_role_model
from vulnassess.cli import main as run_cli
from vulnassess.role_model import load_model
from vulnassess.settings import Settings
from vulnassess.store import Store
from vulnassess.visual_simulation import build_payload, render

ROOT = Path(__file__).resolve().parent
DATABASE = ROOT / "data" / "visual-simulation.db"
ARTIFACT = ROOT / "models" / "synthetic-role-model.json"
MODEL_REPORT = ROOT / "reports" / "model-simulation.json"
OUTPUT = ROOT / "reports" / "visual-simulation.html"
RUN_ID = "visual-sim"
SYNTHETIC = ROOT / "tests" / "synthetic"


def _fresh_database() -> None:
    for suffix in ("", "-wal", "-shm"):
        path = Path(str(DATABASE) + suffix)
        if path.exists():
            path.unlink()


def _run_data_pipeline() -> str:
    arguments = [
        "--config",
        str(ROOT / "config"),
        "--db",
        str(DATABASE),
        "demo",
        "--run-id",
        RUN_ID,
        "--target",
        f"172.28.0.10:{SYNTHETIC / 'synthetic_nmap_two_machines.xml'}",
        "--target",
        f"172.28.0.12:{SYNTHETIC / 'synthetic_nmap_two_machines.xml'}",
        "--target",
        (
            f"172.28.0.11:{SYNTHETIC / 'synthetic_nmap_two_machines.xml'}:"
            f"{SYNTHETIC / 'synthetic_zap_dvwa.json'}"
        ),
        "--feeds",
        str(SYNTHETIC / "feeds"),
        "--out",
        str(ROOT / "reports" / "visual-simulation-report.html"),
    ]
    output = io.StringIO()
    with redirect_stdout(output):
        code = run_cli(arguments)
    if code != 0:
        raise RuntimeError(f"data pipeline exited {code}: {output.getvalue()}")
    return output.getvalue()


def build() -> Path:
    role_output = io.StringIO()
    with redirect_stdout(role_output):
        model_code = run_role_model()
    if model_code != 0:
        raise RuntimeError(f"role-model simulation exited {model_code}: {role_output.getvalue()}")

    _fresh_database()
    _run_data_pipeline()

    settings = Settings(ROOT / "config")
    model = load_model(ARTIFACT)
    model_report = json.loads(MODEL_REPORT.read_text(encoding="utf-8"))
    with Store(DATABASE) as store:
        payload = build_payload(store, RUN_ID, model, model_report, settings.weights)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(render(payload), encoding="utf-8")
    return OUTPUT


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the local visual VulnAssess replay")
    parser.add_argument("--open", action="store_true", help="open the generated local HTML file")
    args = parser.parse_args()

    path = build()
    payload = json.loads(MODEL_REPORT.read_text(encoding="utf-8"))
    print("VISUAL PRODUCT SIMULATION")
    print("  status: TESTED WITH SYNTHETIC; real labelled captures are MISSING")
    print(f"  role model: {payload['model']['hash']} ({len(payload['model']['classes'])} classes)")
    print(f"  output: {path}")
    print(f"  open: {path.as_uri()}")
    if args.open:
        webbrowser.open(path.as_uri())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
