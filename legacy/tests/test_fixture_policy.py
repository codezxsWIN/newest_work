"""Marker policy tests; mocked file availability is not a real capture or parser test."""

from pathlib import Path

import pytest
from conftest import pytest_runtest_setup as check_fixture_requirements


def test_unmarked_test_does_not_check_capture_files(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    checked: list[Path] = []

    def is_file(path: Path) -> bool:
        checked.append(path)
        return False

    monkeypatch.setattr(Path, "is_file", is_file)
    check_fixture_requirements(request.node)
    assert checked == []


def test_missing_capture_has_exact_skip_reason(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    relative = "tests/fixtures/nmap/capture.xml"
    request.node.add_marker(pytest.mark.needs_fixture(relative))
    monkeypatch.setattr(Path, "is_file", lambda path: False)

    with pytest.raises(pytest.skip.Exception) as skipped:
        check_fixture_requirements(request.node)

    assert str(skipped.value) == f"fixture not provided: {relative}"


def test_present_files_are_not_parsed_or_replaced_by_marker(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = ("tests/fixtures/zap/capture.json", "tests/fixtures/zap/README.md")
    request.node.add_marker(pytest.mark.needs_fixture(*paths))
    checked: list[Path] = []

    def is_file(path: Path) -> bool:
        checked.append(path)
        return True

    monkeypatch.setattr(Path, "is_file", is_file)
    check_fixture_requirements(request.node)
    assert checked == [(request.config.rootpath / path).resolve() for path in paths]


def test_missing_readme_is_reported_as_its_own_path(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    request.node.add_marker(
        pytest.mark.needs_fixture(
            "tests/fixtures/zap/capture.json", "tests/fixtures/zap/README.md"
        )
    )
    monkeypatch.setattr(Path, "is_file", lambda path: path.suffix == ".json")

    with pytest.raises(pytest.skip.Exception) as skipped:
        check_fixture_requirements(request.node)

    assert str(skipped.value) == "fixture not provided: tests/fixtures/zap/README.md"


@pytest.mark.parametrize(
    "path",
    ["data/feeds/nvd.json", "tests/fixtures/../test_cli.py", "/outside.xml", "", 123],
)
def test_marker_cannot_hide_unrelated_prerequisites(
    request: pytest.FixtureRequest, path: object
) -> None:
    request.node.add_marker(pytest.mark.needs_fixture(path))
    with pytest.raises(pytest.UsageError):
        check_fixture_requirements(request.node)


def test_empty_marker_is_a_configuration_error(request: pytest.FixtureRequest) -> None:
    request.node.add_marker(pytest.mark.needs_fixture())
    with pytest.raises(pytest.UsageError, match="positional fixture paths"):
        check_fixture_requirements(request.node)


def test_custom_skip_reason_is_not_allowed(request: pytest.FixtureRequest) -> None:
    request.node.add_marker(
        pytest.mark.needs_fixture("tests/fixtures/zap/capture.json", reason="different")
    )
    with pytest.raises(pytest.UsageError, match="positional fixture paths"):
        check_fixture_requirements(request.node)
