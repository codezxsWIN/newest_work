"""Exercise the real provisioning refusal without Make or third-party packages."""

import subprocess
import sys
from pathlib import Path


def test_make_install_delegates_only_to_refusal() -> None:
    makefile = Path(__file__).resolve().parents[1] / "Makefile"
    assert makefile.is_file()

    contents = makefile.read_text(encoding="utf-8")
    install_section = contents.split("\ninstall:\n", maxsplit=1)[1]
    install_recipe = install_section.split("\nlint:\n", maxsplit=1)[0]

    assert install_recipe.strip() == "@$(PYTHON) scripts/install.py"


def test_install_refuses_without_loading_site_packages(tmp_path: Path) -> None:
    install_script = Path(__file__).resolve().parents[1] / "scripts" / "install.py"
    assert install_script.is_file()

    result = subprocess.run(
        [sys.executable, "-I", "-S", str(install_script)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert "Dependency installation is disabled: not run by the agent." in result.stderr
    assert "pinned, hash-verified dependencies" in result.stderr
    assert "Traceback" not in result.stderr
