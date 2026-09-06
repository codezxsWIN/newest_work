"""Exercise real SQLite transactions with explicitly synthetic model data."""

import json
import sqlite3
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import pytest

from vulnassess.errors import ConfigError
from vulnassess.schema import ContextProfile, Enrichment, Finding, Host, Rationale, ScoreBreakdown
from vulnassess.store import Run, Store


def _run(finding: Finding) -> Run:
    return Run(
        run_id=finding.provenance.run_id,
        started_at=finding.first_seen,
        config_hash="synthetic-unit-value-not-an-artifact-approval",
        feeds={},
    )


def test_missing_database_requires_explicit_creation(tmp_path: Path) -> None:
    path = tmp_path / "missing.sqlite"
    with pytest.raises(ConfigError, match="missing.sqlite"):
        Store(path)
    assert not path.exists()
    with pytest.raises(ConfigError, match="parent directory"):
        Store(tmp_path / "missing-parent" / "store.sqlite", create=True)
    assert not (tmp_path / "missing-parent").exists()


def test_wal_tables_and_indexes(tmp_path: Path) -> None:
    path = tmp_path / "store.sqlite"
    with Store(path, create=True):
        with sqlite3.connect(path) as connection:
            assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = ?", ("table",)
                )
            }
            assert tables == {
                "runs",
                "hosts",
                "findings",
                "enrichments",
                "context_profiles",
                "scores",
                "rationales",
                "cve",
                "epss",
                "kev",
                "feeds_meta",
            }
            expected_columns = {
                "runs": ["run_id", "started_at", "config_hash", "feeds_json"],
                "hosts": ["run_id", "ip", "json"],
                "findings": ["id", "run_id", "json", "first_seen", "last_seen"],
                "enrichments": ["finding_id", "cve_id", "json"],
                "context_profiles": ["run_id", "host_ip", "json"],
                "scores": ["run_id", "finding_id", "json", "risk", "band"],
                "rationales": ["run_id", "finding_id", "json"],
                "cve": ["id", "json", "cvss31_base", "cvss40_base"],
                "epss": ["cve", "epss", "percentile", "score_date"],
                "kev": ["cve", "json"],
                "feeds_meta": ["feed", "path", "sha256", "file_date", "rows", "loaded_at"],
            }
            for table, columns in expected_columns.items():
                rows = connection.execute(
                    "SELECT name FROM pragma_table_info(?) ORDER BY cid", (table,)
                )
                assert [row[0] for row in rows] == columns
            indexed_columns = {
                "hosts": {"run_id", "ip"},
                "findings": {"id", "run_id"},
                "enrichments": {"finding_id", "cve_id"},
                "context_profiles": {"run_id", "host_ip"},
                "scores": {"run_id", "finding_id", "risk"},
                "rationales": {"run_id", "finding_id"},
                "cve": {"id"},
                "epss": {"cve"},
                "kev": {"cve"},
            }
            for table, columns in indexed_columns.items():
                rows = connection.execute(
                    "SELECT indexed_columns.name FROM pragma_index_list(?) AS indexes "
                    "JOIN pragma_index_info(indexes.name) AS indexed_columns "
                    "WHERE indexed_columns.seqno = ?",
                    (table, 0),
                )
                assert columns <= {row[0] for row in rows}


def test_incomplete_existing_schema_is_rejected_without_migration(tmp_path: Path) -> None:
    path = tmp_path / "incomplete.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE runs (run_id TEXT PRIMARY KEY, started_at TEXT, "
            "config_hash TEXT, feeds_json TEXT)"
        )
    with pytest.raises(ConfigError, match="table hosts"):
        Store(path)
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = ?", ("table",)
        ).fetchall()
        assert tables == [("runs",)]


def test_finding_repeat_only_changes_last_seen(tmp_path: Path, schema_data: dict[str, Any]) -> None:
    path = tmp_path / "store.sqlite"
    original = Finding.model_validate(schema_data["finding"])
    repeat = original.model_copy(
        update={
            "title": "a replacement that must not win",
            "evidence": "a replacement that must not win",
            "first_seen": original.first_seen + timedelta(hours=1),
            "last_seen": original.last_seen + timedelta(days=1),
            "provenance": original.provenance.model_copy(update={"run_id": "synthetic-second-run"}),
        }
    )
    with Store(path, create=True) as store:
        store.add_run(_run(original))
        store.add_run(_run(repeat))
        store.upsert_finding(original)
        store.upsert_finding(repeat)
        store.upsert_finding(repeat)
        saved = store.get_finding(original.id)
        assert saved == original.model_copy(update={"last_seen": repeat.last_seen})
        assert store.list_findings() == [saved]
        with sqlite3.connect(path) as connection:
            row = connection.execute(
                "SELECT run_id, first_seen, last_seen, json FROM findings WHERE id = ?", (original.id,)
            ).fetchone()
            assert row[0] == original.provenance.run_id
            assert row[1] == original.first_seen.isoformat()
            assert row[2] == repeat.last_seen.isoformat()
            assert Finding.model_validate_json(row[3]) == saved
    with Store(path) as reopened:
        assert reopened.get_finding(original.id) == saved


def test_run_collision_does_not_change_metadata(tmp_path: Path, schema_data: dict[str, Any]) -> None:
    finding = Finding.model_validate(schema_data["finding"])
    run = _run(finding)
    with Store(tmp_path / "store.sqlite", create=True) as store:
        store.add_run(run)
        store.add_run(run)
        with pytest.raises(ConfigError, match="runs.run_id"):
            store.add_run(run.model_copy(update={"config_hash": "different"}))
        assert store.get_run(run.run_id) == run


def test_model_persistence_is_idempotent(tmp_path: Path, schema_data: dict[str, Any]) -> None:
    finding = Finding.model_validate(schema_data["finding"])
    host = Host.model_validate(schema_data["host"])
    profile = ContextProfile.model_validate(schema_data["context"])
    enrichment = Enrichment.model_validate(schema_data["enrichment"]).model_copy(
        update={"finding_id": finding.id}
    )
    score = ScoreBreakdown.model_validate(schema_data["score"]).model_copy(
        update={"finding_id": finding.id}
    )
    rationale = Rationale.model_validate(schema_data["rationale"]).model_copy(
        update={"finding_id": finding.id}
    )
    run = _run(finding)
    with Store(tmp_path / "store.sqlite", create=True) as store:
        store.add_run(run)
        store.upsert_finding(finding)
        for _repeat in range(2):
            store.upsert_host(run.run_id, host)
            store.upsert_context(run.run_id, profile)
            store.upsert_enrichment(enrichment)
            store.upsert_score(run.run_id, score)
            store.upsert_rationale(run.run_id, rationale)
        assert store.list_hosts(run.run_id) == [host]
        assert store.get_context(run.run_id, host.ip) == profile
        assert store.list_enrichments(finding.id) == [enrichment]
        assert store.list_scores(run.run_id) == [score]
        assert store.get_rationale(run.run_id, finding.id) == rationale


def test_bound_values_cannot_execute_sql(tmp_path: Path, schema_data: dict[str, Any]) -> None:
    finding = Finding.model_validate(schema_data["finding"])
    run = _run(finding).model_copy(update={"run_id": "synthetic'; DROP TABLE runs; --"})
    with Store(tmp_path / "store.sqlite", create=True) as store:
        store.add_run(run)
        assert store.get_run(run.run_id) == run
        with pytest.raises(ConfigError, match="runs.run_id"):
            store.get_run("' OR 1=1 --")


def test_missing_parents_and_results_are_explicit(tmp_path: Path, schema_data: dict[str, Any]) -> None:
    finding = Finding.model_validate(schema_data["finding"])
    profile = ContextProfile.model_validate(schema_data["context"])
    with Store(tmp_path / "store.sqlite", create=True) as store:
        with pytest.raises(ConfigError, match="runs.run_id"):
            store.upsert_finding(finding)
        store.add_run(_run(finding))
        with pytest.raises(ConfigError, match="SQLite write failed"):
            store.upsert_context(finding.provenance.run_id, profile)
        with pytest.raises(ConfigError, match="findings.id"):
            store.get_finding(finding.id)
        with pytest.raises(ConfigError, match="context_profiles"):
            store.get_context(finding.provenance.run_id, finding.host_ip)
        with pytest.raises(ConfigError, match="rationales"):
            store.get_rationale(finding.provenance.run_id, finding.id)
        store.upsert_finding(finding)
        assert store.get_finding(finding.id) == finding


@pytest.mark.parametrize(
    ("host_json", "error_key"), [(None, "hosts.ip"), ("{}", "Host.json")]
)
def test_context_requires_a_host_model_without_relying_on_foreign_keys(
    tmp_path: Path,
    schema_data: dict[str, Any],
    host_json: str | None,
    error_key: str,
) -> None:
    path = tmp_path / "store.sqlite"
    finding = Finding.model_validate(schema_data["finding"])
    profile = ContextProfile.model_validate(schema_data["context"])
    run = _run(finding)
    with Store(path, create=True) as store:
        store.add_run(run)
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE context_profiles")
        connection.execute(
            "CREATE TABLE context_profiles (run_id TEXT NOT NULL, host_ip TEXT NOT NULL, "
            "json TEXT NOT NULL, PRIMARY KEY (run_id, host_ip))"
        )
        if host_json is not None:
            connection.execute(
                "INSERT INTO hosts (run_id, ip, json) VALUES (?, ?, ?)",
                (run.run_id, profile.host_ip, host_json),
            )
    with Store(path) as store:
        with pytest.raises(ConfigError, match=error_key):
            store.upsert_context(run.run_id, profile)
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM context_profiles").fetchone()[0] == 0


def test_corrupt_model_is_not_an_empty_result(tmp_path: Path, schema_data: dict[str, Any]) -> None:
    path = tmp_path / "store.sqlite"
    finding = Finding.model_validate(schema_data["finding"])
    with Store(path, create=True) as store:
        store.add_run(_run(finding))
        store.upsert_finding(finding)
        with sqlite3.connect(path) as connection:
            connection.execute("UPDATE findings SET json = ? WHERE id = ?", ("{}", finding.id))
        with pytest.raises(ConfigError, match="Finding.json"):
            store.list_findings()


def test_stable_sorting_and_json_bytes(tmp_path: Path, schema_data: dict[str, Any]) -> None:
    path = tmp_path / "store.sqlite"
    finding = Finding.model_validate(schema_data["finding"])
    payload = finding.model_dump()
    payload["tool_native_id"] = "synthetic-second-rule"
    fingerprint = Finding.fingerprint(
        payload["host_ip"],
        payload["port"],
        payload["protocol"],
        payload["tool"],
        payload["tool_native_id"],
        payload["url"],
    )
    payload["id"] = str(uuid5(NAMESPACE_URL, fingerprint))
    other = Finding.model_validate(payload)
    run = _run(finding)
    with Store(path, create=True) as store:
        store.add_run(run)
        for item in sorted([finding, other], key=lambda value: value.id, reverse=True):
            store.upsert_finding(item)
            score = ScoreBreakdown.model_validate(schema_data["score"]).model_copy(
                update={"finding_id": item.id}
            )
            store.upsert_score(run.run_id, score)
        ids = sorted([finding.id, other.id])
        assert [item.id for item in store.list_findings(run.run_id)] == ids
        assert [item.finding_id for item in store.list_scores(run.run_id)] == ids
        with sqlite3.connect(path) as connection:
            before = connection.execute("SELECT json FROM scores ORDER BY finding_id").fetchall()
            for item in store.list_scores(run.run_id):
                store.upsert_score(run.run_id, item)
            after = connection.execute("SELECT json FROM scores ORDER BY finding_id").fetchall()
            assert before == after
            assert all(json.loads(row[0])["inputs"]["synthetic"] is True for row in after)
