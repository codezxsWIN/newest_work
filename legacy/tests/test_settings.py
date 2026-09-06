"""Configuration must be validated locally, and every failure must name its file and key."""

from pathlib import Path

import pytest

from vulnassess.errors import ConfigError
from vulnassess.settings import Scope, Settings, load_controls, load_scope, read_yaml

REPO_CONFIG = Path(__file__).resolve().parents[1] / "config"

VALID_SCOPE = """
allowed_cidrs: [192.0.2.0/24]
allowed_hosts: [198.51.100.7]
vantage: internal
lab_targets:
  - name: synthetic-target
    ip: 192.0.2.10
    tags: {environment: test, criticality: 2}
"""


def _write(directory: Path, name: str, text: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(text, encoding="utf-8")
    return path


def test_repository_scope_and_controls_load() -> None:
    scope = load_scope(REPO_CONFIG)
    controls = load_controls(REPO_CONFIG)

    assert scope.allowed_cidrs
    assert scope.lab_targets
    assert {signature.vendor for signature in controls.waf.signatures} >= {
        "Cloudflare",
        "Akamai",
        "F5 BIG-IP",
        "AWS WAF",
        "ModSecurity",
        "Imperva",
    }
    assert controls.auth_required.signatures
    assert controls.rate_limiting.signatures


def test_missing_configuration_file_names_the_path(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as error:
        read_yaml(tmp_path / "scope.yaml")

    assert "MISSING" in str(error.value)
    assert "scope.yaml" in str(error.value)


def test_unknown_key_names_the_file_and_the_key(tmp_path: Path) -> None:
    _write(tmp_path, "scope.yaml", VALID_SCOPE + "\nallowed_ports: [22]\n")

    with pytest.raises(ConfigError) as error:
        load_scope(tmp_path)

    message = str(error.value)
    assert "scope.yaml" in message
    assert "allowed_ports" in message


def test_unparsable_cidr_is_rejected(tmp_path: Path) -> None:
    _write(tmp_path, "scope.yaml", "allowed_cidrs: [172.28.0.0/33]\n")

    with pytest.raises(ConfigError) as error:
        load_scope(tmp_path)

    assert "172.28.0.0/33" in str(error.value)


def test_lab_target_outside_every_allowed_cidr_is_rejected(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "scope.yaml",
        "allowed_cidrs: [192.0.2.0/24]\nlab_targets:\n  - {name: stray, ip: 10.0.0.4}\n",
    )

    with pytest.raises(ConfigError) as error:
        load_scope(tmp_path)

    message = str(error.value)
    assert "lab_targets.stray.ip" in message
    assert "outside every allowed CIDR" in message


def test_canary_inside_an_allowed_cidr_is_rejected(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "scope.yaml",
        "allowed_cidrs: [192.0.2.0/24]\ncanary: {ip: 192.0.2.250}\n",
    )

    with pytest.raises(ConfigError) as error:
        load_scope(tmp_path)

    assert "canary.ip" in str(error.value)


def test_top_level_sequence_is_not_a_configuration_file(tmp_path: Path) -> None:
    _write(tmp_path, "scope.yaml", "- 192.0.2.0/24\n")

    with pytest.raises(ConfigError) as error:
        read_yaml(tmp_path / "scope.yaml")

    assert "expected a mapping" in str(error.value)


def test_permits_only_authorised_addresses() -> None:
    scope = Scope.model_validate(
        {
            "allowed_cidrs": ["192.0.2.0/24"],
            "allowed_hosts": ["198.51.100.7"],
            "canary": {"ip": "203.0.113.9"},
        }
    )

    assert scope.permits("192.0.2.10")
    assert scope.permits("198.51.100.7")
    assert not scope.permits("203.0.113.9")
    assert not scope.permits("10.0.0.4")
    assert not scope.permits("not-an-address")
    assert not scope.permits("")


def test_config_hash_is_stable_and_changes_with_content(tmp_path: Path) -> None:
    first = Settings.load(REPO_CONFIG)
    repeated = Settings.load(REPO_CONFIG)

    assert first.config_hash() == repeated.config_hash()
    assert len(first.config_hash()) == 64

    for name in ("roles.yaml", "weights.yaml", "controls.yaml"):
        _write(tmp_path, name, (REPO_CONFIG / name).read_text(encoding="utf-8"))
    _write(tmp_path, "scope.yaml", VALID_SCOPE)

    assert Settings.load(tmp_path).config_hash() != first.config_hash()


def test_missing_configuration_directory_is_reported(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as error:
        Settings.load(tmp_path / "absent")

    assert "MISSING" in str(error.value)


def test_empty_placeholder_files_are_accepted(tmp_path: Path) -> None:
    _write(tmp_path, "scope.yaml", VALID_SCOPE)
    _write(tmp_path, "controls.yaml", (REPO_CONFIG / "controls.yaml").read_text(encoding="utf-8"))
    _write(tmp_path, "roles.yaml", "# placeholder\n")
    _write(tmp_path, "weights.yaml", "{}\n")

    settings = Settings.load(tmp_path)

    assert settings.roles == {}
    assert settings.weights == {}


def test_unknown_control_location_is_rejected(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "controls.yaml",
        "waf:\n  signatures:\n    - {where: dns, regex: 'x', vendor: Invented}\n"
        "auth_required:\n  signatures: []\nrate_limiting:\n  signatures: []\n",
    )

    with pytest.raises(ConfigError) as error:
        load_controls(tmp_path)

    assert "controls.yaml" in str(error.value)
    assert "waf.signatures.0.where" in str(error.value)
