"""SQLite persistence. Parametrised queries only; payloads are JSON text."""

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from vulnassess.schema import ContextProfile, Enrichment, Finding, Host, Rationale, ScoreBreakdown

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY, started_at TEXT NOT NULL,
    config_hash TEXT NOT NULL, summary_json TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS hosts (
    run_id TEXT NOT NULL, ip TEXT NOT NULL, json TEXT NOT NULL,
    PRIMARY KEY (run_id, ip));
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY, run_id TEXT NOT NULL, host_ip TEXT NOT NULL, tool TEXT NOT NULL,
    json TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS findings_run ON findings (run_id);
CREATE TABLE IF NOT EXISTS finding_runs (
    run_id TEXT NOT NULL, finding_id TEXT NOT NULL, seen_at TEXT NOT NULL,
    PRIMARY KEY (run_id, finding_id));
CREATE INDEX IF NOT EXISTS finding_runs_finding ON finding_runs (finding_id);
CREATE TABLE IF NOT EXISTS enrichments (
    finding_id TEXT NOT NULL, cve_id TEXT NOT NULL, json TEXT NOT NULL,
    PRIMARY KEY (finding_id, cve_id));
CREATE TABLE IF NOT EXISTS context_profiles (
    run_id TEXT NOT NULL, host_ip TEXT NOT NULL, json TEXT NOT NULL,
    PRIMARY KEY (run_id, host_ip));
CREATE TABLE IF NOT EXISTS scores (
    run_id TEXT NOT NULL, finding_id TEXT NOT NULL, json TEXT NOT NULL,
    risk REAL NOT NULL, band TEXT NOT NULL, PRIMARY KEY (run_id, finding_id));
CREATE INDEX IF NOT EXISTS scores_risk ON scores (run_id, risk);
CREATE TABLE IF NOT EXISTS rationales (
    run_id TEXT NOT NULL, finding_id TEXT NOT NULL, json TEXT NOT NULL,
    PRIMARY KEY (run_id, finding_id));
CREATE TABLE IF NOT EXISTS cve (
    id TEXT PRIMARY KEY, json TEXT NOT NULL, cvss31_base REAL, cvss40_base REAL);
CREATE TABLE IF NOT EXISTS epss (
    cve TEXT PRIMARY KEY, epss REAL, percentile REAL, score_date TEXT);
CREATE TABLE IF NOT EXISTS kev (cve TEXT PRIMARY KEY, json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS feeds_meta (
    feed TEXT PRIMARY KEY, path TEXT NOT NULL, sha256 TEXT NOT NULL,
    file_date TEXT, rows INTEGER NOT NULL, loaded_at TEXT NOT NULL);
"""


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _dumps(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class Store:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(self.path))
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.executescript(SCHEMA)
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # runs -------------------------------------------------------------
    def start_run(self, run_id: str, config_hash: str) -> None:
        self.connection.execute(
            "INSERT INTO runs (run_id, started_at, config_hash, summary_json) VALUES (?, ?, ?, '{}') "
            "ON CONFLICT(run_id) DO NOTHING",
            (run_id, _now(), config_hash),
        )
        self.connection.commit()

    def set_run_summary(self, run_id: str, summary: dict[str, Any]) -> None:
        self.connection.execute(
            "UPDATE runs SET summary_json = ? WHERE run_id = ?", (_dumps(summary), run_id)
        )
        self.connection.commit()

    def run_info(self, run_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:
            return None
        return {
            "run_id": row["run_id"],
            "started_at": row["started_at"],
            "config_hash": row["config_hash"],
            "summary": json.loads(row["summary_json"]),
        }

    # hosts ------------------------------------------------------------
    def upsert_host(self, run_id: str, host: Host) -> None:
        self.connection.execute(
            "INSERT INTO hosts (run_id, ip, json) VALUES (?, ?, ?) "
            "ON CONFLICT(run_id, ip) DO UPDATE SET json = excluded.json",
            (run_id, host.ip, _dumps(host.to_json())),
        )
        self.connection.commit()

    def hosts(self, run_id: str) -> list[Host]:
        rows = self.connection.execute(
            "SELECT json FROM hosts WHERE run_id = ? ORDER BY ip", (run_id,)
        ).fetchall()
        return [Host.from_json(json.loads(row["json"])) for row in rows]

    # findings ---------------------------------------------------------
    def upsert_findings(self, run_id: str, findings: Iterable[Finding]) -> int:
        """Store each finding once, link it to this run, and return how many are new to the run."""
        linked = 0
        for finding in findings:
            self.connection.execute(
                "INSERT INTO findings (id, run_id, host_ip, tool, json, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET last_seen = ?",
                (
                    finding.id,
                    run_id,
                    finding.host_ip,
                    finding.tool,
                    _dumps(finding.to_json()),
                    finding.first_seen,
                    finding.last_seen,
                    finding.last_seen,
                ),
            )
            cursor = self.connection.execute(
                "INSERT INTO finding_runs (run_id, finding_id, seen_at) VALUES (?, ?, ?) "
                "ON CONFLICT(run_id, finding_id) DO NOTHING",
                (run_id, finding.id, finding.last_seen),
            )
            linked += bool(cursor.rowcount)
        self.connection.commit()
        return linked

    def findings(self, run_id: str, host_ip: str | None = None) -> list[Finding]:
        query = (
            "SELECT f.json FROM findings f JOIN finding_runs r ON r.finding_id = f.id "
            "WHERE r.run_id = ?"
        )
        parameters: tuple[str, ...] = (run_id,)
        if host_ip is not None:
            query += " AND f.host_ip = ?"
            parameters += (host_ip,)
        rows = self.connection.execute(query + " ORDER BY f.id", parameters).fetchall()
        return [Finding.from_json(json.loads(row["json"])) for row in rows]

    # enrichments ------------------------------------------------------
    def upsert_enrichment(self, enrichment: Enrichment) -> None:
        self.connection.execute(
            "INSERT INTO enrichments (finding_id, cve_id, json) VALUES (?, ?, ?) "
            "ON CONFLICT(finding_id, cve_id) DO UPDATE SET json = excluded.json",
            (enrichment.finding_id, enrichment.cve_id, _dumps(enrichment.to_json())),
        )
        self.connection.commit()

    def enrichments(self, finding_id: str) -> list[Enrichment]:
        rows = self.connection.execute(
            "SELECT json FROM enrichments WHERE finding_id = ? ORDER BY cve_id", (finding_id,)
        ).fetchall()
        return [Enrichment.from_json(json.loads(row["json"])) for row in rows]

    # context ----------------------------------------------------------
    def upsert_profile(self, run_id: str, profile: ContextProfile) -> None:
        self.connection.execute(
            "INSERT INTO context_profiles (run_id, host_ip, json) VALUES (?, ?, ?) "
            "ON CONFLICT(run_id, host_ip) DO UPDATE SET json = excluded.json",
            (run_id, profile.host_ip, _dumps(profile.to_json())),
        )
        self.connection.commit()

    def profile(self, run_id: str, host_ip: str) -> ContextProfile | None:
        row = self.connection.execute(
            "SELECT json FROM context_profiles WHERE run_id = ? AND host_ip = ?", (run_id, host_ip)
        ).fetchone()
        return None if row is None else ContextProfile.from_json(json.loads(row["json"]))

    def profiles(self, run_id: str) -> list[ContextProfile]:
        rows = self.connection.execute(
            "SELECT json FROM context_profiles WHERE run_id = ? ORDER BY host_ip", (run_id,)
        ).fetchall()
        return [ContextProfile.from_json(json.loads(row["json"])) for row in rows]

    # scores -----------------------------------------------------------
    def upsert_score(self, run_id: str, score: ScoreBreakdown) -> None:
        self.connection.execute(
            "INSERT INTO scores (run_id, finding_id, json, risk, band) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(run_id, finding_id) DO UPDATE SET "
            "json = excluded.json, risk = excluded.risk, band = excluded.band",
            (run_id, score.finding_id, _dumps(score.to_json()), score.risk, score.band),
        )
        self.connection.commit()

    def scores(self, run_id: str) -> list[ScoreBreakdown]:
        rows = self.connection.execute(
            "SELECT json FROM scores WHERE run_id = ? ORDER BY risk DESC, finding_id", (run_id,)
        ).fetchall()
        return [ScoreBreakdown.from_json(json.loads(row["json"])) for row in rows]

    # rationales -------------------------------------------------------
    def upsert_rationale(self, run_id: str, rationale: Rationale) -> None:
        self.connection.execute(
            "INSERT INTO rationales (run_id, finding_id, json) VALUES (?, ?, ?) "
            "ON CONFLICT(run_id, finding_id) DO UPDATE SET json = excluded.json",
            (run_id, rationale.finding_id, _dumps(rationale.to_json())),
        )
        self.connection.commit()

    def rationales(self, run_id: str) -> dict[str, Rationale]:
        rows = self.connection.execute(
            "SELECT json FROM rationales WHERE run_id = ? ORDER BY finding_id", (run_id,)
        ).fetchall()
        items = [Rationale.from_json(json.loads(row["json"])) for row in rows]
        return {item.finding_id: item for item in items}

    # feeds ------------------------------------------------------------
    def put_cves(self, records: Iterable[dict[str, Any]]) -> int:
        rows = [
            (record["id"], _dumps(record), record.get("cvss31_base"), record.get("cvss40_base"))
            for record in records
        ]
        self.connection.executemany(
            "INSERT INTO cve (id, json, cvss31_base, cvss40_base) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET json = excluded.json, "
            "cvss31_base = excluded.cvss31_base, cvss40_base = excluded.cvss40_base",
            rows,
        )
        self.connection.commit()
        return len(rows)

    def cve(self, cve_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT json FROM cve WHERE id = ?", (cve_id,)).fetchone()
        return None if row is None else json.loads(row["json"])

    def all_cves(self) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT json FROM cve ORDER BY id").fetchall()
        return [json.loads(row["json"]) for row in rows]

    def put_epss(self, rows: Iterable[tuple[str, float, float, str]]) -> int:
        payload = list(rows)
        self.connection.executemany(
            "INSERT INTO epss (cve, epss, percentile, score_date) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(cve) DO UPDATE SET epss = excluded.epss, "
            "percentile = excluded.percentile, score_date = excluded.score_date",
            payload,
        )
        self.connection.commit()
        return len(payload)

    def epss(self, cve_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT * FROM epss WHERE cve = ?", (cve_id,)).fetchone()
        if row is None:
            return None
        return {
            "cve": row["cve"],
            "epss": row["epss"],
            "percentile": row["percentile"],
            "score_date": row["score_date"],
        }

    def put_kev(self, records: Iterable[dict[str, Any]]) -> int:
        rows = [(record["cveID"], _dumps(record)) for record in records]
        self.connection.executemany(
            "INSERT INTO kev (cve, json) VALUES (?, ?) "
            "ON CONFLICT(cve) DO UPDATE SET json = excluded.json",
            rows,
        )
        self.connection.commit()
        return len(rows)

    def kev(self, cve_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT json FROM kev WHERE cve = ?", (cve_id,)).fetchone()
        return None if row is None else json.loads(row["json"])

    def put_feed_meta(
        self, feed: str, path: str, digest: str, file_date: str | None, rows: int
    ) -> None:
        self.connection.execute(
            "INSERT INTO feeds_meta (feed, path, sha256, file_date, rows, loaded_at) "
            "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(feed) DO UPDATE SET path = excluded.path, "
            "sha256 = excluded.sha256, file_date = excluded.file_date, rows = excluded.rows, "
            "loaded_at = excluded.loaded_at",
            (feed, path, digest, file_date, rows, _now()),
        )
        self.connection.commit()

    def feeds_meta(self) -> dict[str, dict[str, Any]]:
        rows = self.connection.execute("SELECT * FROM feeds_meta ORDER BY feed").fetchall()
        return {
            row["feed"]: {
                "path": row["path"],
                "sha256": row["sha256"],
                "file_date": row["file_date"],
                "rows": row["rows"],
                "loaded_at": row["loaded_at"],
            }
            for row in rows
        }
