"""Regression tests for the self-contained visual pipeline replay."""

import hashlib
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from run_visual_simulation import build
from vulnassess.cli import main
from vulnassess.visual_simulation import render

ROOT = Path(__file__).resolve().parents[1]


def embedded_data(html: str) -> dict:
    prefix = "<script>const DATA="
    suffix = ";\nconst state="
    start = html.index(prefix) + len(prefix)
    end = html.index(suffix, start)
    return json.loads(html[start:end])


class TestVisualSimulation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.path = build()
        cls.html = cls.path.read_text(encoding="utf-8")
        cls.data = embedded_data(cls.html)

    def test_build_replays_actual_store_and_model_data(self):
        self.assertEqual(self.data["run_id"], "visual-sim")
        self.assertEqual(len(self.data["hosts"]), 3)
        self.assertEqual(len(self.data["ranked"]), 6)
        self.assertEqual(len(self.data["comparison"]), 2)
        self.assertEqual(len(self.data["model"]["classes"]), 9)
        self.assertEqual(self.data["model"]["features"], 134)
        self.assertEqual(
            {item["ip"]: item["prediction"]["label"] for item in self.data["hosts"]},
            {
                "172.28.0.10": "web_frontend",
                "172.28.0.11": "unknown",
                "172.28.0.12": "database",
            },
        )

    def test_all_eight_stages_and_visual_surfaces_are_present(self):
        self.assertEqual(len(self.data["stages"]), 8)
        for text in (
            "Evidence moving through the pipeline",
            "What just happened",
            "Probability and evidence",
            "Score construction",
            "Same CVE. Same base. Different operational risk.",
            "Remediation queue",
        ):
            self.assertIn(text, self.html)
        for control in ('id="play"', 'id="restart"', 'id="scrubber"', 'data-speed="460"'):
            self.assertIn(control, self.html)

    def test_visual_replay_is_self_contained_and_offline(self):
        self.assertNotIn("<script src=", self.html)
        self.assertNotIn("<link", self.html)
        self.assertNotIn("href=", self.html)
        self.assertNotIn("fetch(", self.html)
        self.assertNotIn("WebSocket", self.html)
        self.assertIn("No external assets, scripts, feeds or model calls", self.html)

    def test_embedded_untrusted_text_cannot_close_the_data_script(self):
        attack = "</script><script>alert(1)</script>"
        html = render({"run_id": attack})
        self.assertNotIn(attack, html)
        self.assertIn("&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertIn("\\u003c/script\\u003e", html)

    def test_same_cve_comparison_contains_the_golden_divergence(self):
        comparison = {item["host_ip"]: item for item in self.data["comparison"]}
        self.assertEqual(comparison["172.28.0.12"]["base_score"], 9.8)
        self.assertEqual(comparison["172.28.0.10"]["base_score"], 9.8)
        self.assertEqual(comparison["172.28.0.12"]["risk"], 100.0)
        self.assertEqual(comparison["172.28.0.12"]["band"], "Critical")
        self.assertEqual(comparison["172.28.0.10"]["risk"], 79.0)
        self.assertEqual(comparison["172.28.0.10"]["band"], "High")

    def test_repeated_visual_builds_are_byte_identical(self):
        first = hashlib.sha256(self.path.read_bytes()).hexdigest()
        second_path = build()
        second = hashlib.sha256(second_path.read_bytes()).hexdigest()
        self.assertEqual(first, second)

    def test_mobile_layout_rules_are_shipped(self):
        self.assertIn("@media (max-width:700px)", self.html)
        self.assertIn("width:90px;min-width:90px", self.html)
        self.assertIn(".queue td .micro{display:none}", self.html)
        self.assertIn("prefers-reduced-motion:reduce", self.html)

    def test_visualize_command_renders_an_existing_run(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "replay.html"
            with redirect_stdout(io.StringIO()):
                code = main(
                    [
                        "--db",
                        str(ROOT / "data" / "visual-simulation.db"),
                        "visualize",
                        "--run-id",
                        "visual-sim",
                        "--model",
                        str(ROOT / "models" / "synthetic-role-model.json"),
                        "--model-report",
                        str(ROOT / "reports" / "model-simulation.json"),
                        "--out",
                        str(output),
                    ]
                )
            self.assertEqual(code, 0)
            self.assertEqual(embedded_data(output.read_text())["run_id"], "visual-sim")


if __name__ == "__main__":
    unittest.main(verbosity=2)
