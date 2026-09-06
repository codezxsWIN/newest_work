"""SQLite persistence with fixed tables and deterministic model serialization."""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from types import TracebackType
from typing import Self, TypeVar

from pydantic import BaseModel, ConfigDict, ValidationError

from vulnassess.errors import ConfigError
from vulnassess.schema import ContextProfile, Enrichment, Finding, Host, Rationale, ScoreBreakdown

_Model = TypeVar("_Model", bound=BaseModel)
_Value = str | int | float | None

_COLUMNS = {
	"runs": ("run_id", "started_at", "config_hash", "feeds_json"),
	"hosts": ("run_id", "ip", "json"),
	"findings": ("id", "run_id", "json", "first_seen", "last_seen"),
	"enrichments": ("finding_id", "cve_id", "json"),
	"context_profiles": ("run_id", "host_ip", "json"),
	"scores": ("run_id", "finding_id", "json", "risk", "band"),
	"rationales": ("run_id", "finding_id", "json"),
	"cve": ("id", "json", "cvss31_base", "cvss40_base"),
	"epss": ("cve", "epss", "percentile", "score_date"),
	"kev": ("cve", "json"),
	"feeds_meta": ("feed", "path", "sha256", "file_date", "rows", "loaded_at"),
}

_SCHEMA = """
BEGIN;
CREATE TABLE runs (
	run_id TEXT PRIMARY KEY, started_at TEXT NOT NULL,
	config_hash TEXT NOT NULL, feeds_json TEXT NOT NULL
);
CREATE TABLE hosts (
	run_id TEXT NOT NULL REFERENCES runs(run_id), ip TEXT NOT NULL, json TEXT NOT NULL,
	PRIMARY KEY (run_id, ip)
);
CREATE TABLE findings (
	id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(run_id), json TEXT NOT NULL,
	first_seen TEXT NOT NULL, last_seen TEXT NOT NULL
);
CREATE TABLE enrichments (
	finding_id TEXT NOT NULL REFERENCES findings(id), cve_id TEXT NOT NULL, json TEXT NOT NULL,
	PRIMARY KEY (finding_id, cve_id)
);
CREATE TABLE context_profiles (
	run_id TEXT NOT NULL REFERENCES runs(run_id), host_ip TEXT NOT NULL, json TEXT NOT NULL,
	PRIMARY KEY (run_id, host_ip),
	FOREIGN KEY (run_id, host_ip) REFERENCES hosts(run_id, ip)
);
CREATE TABLE scores (
	run_id TEXT NOT NULL REFERENCES runs(run_id),
	finding_id TEXT NOT NULL REFERENCES findings(id), json TEXT NOT NULL,
	risk REAL NOT NULL, band TEXT NOT NULL,
	PRIMARY KEY (run_id, finding_id)
);
CREATE TABLE rationales (
	run_id TEXT NOT NULL REFERENCES runs(run_id),
	finding_id TEXT NOT NULL REFERENCES findings(id), json TEXT NOT NULL,
	PRIMARY KEY (run_id, finding_id)
);
CREATE TABLE cve (id TEXT PRIMARY KEY, json TEXT NOT NULL, cvss31_base REAL, cvss40_base REAL);
CREATE TABLE epss (
	cve TEXT PRIMARY KEY, epss REAL NOT NULL, percentile REAL NOT NULL, score_date TEXT NOT NULL
);
CREATE TABLE kev (cve TEXT PRIMARY KEY, json TEXT NOT NULL);
CREATE TABLE feeds_meta (
	feed TEXT PRIMARY KEY, path TEXT NOT NULL, sha256 TEXT NOT NULL,
	file_date TEXT NOT NULL, rows INTEGER NOT NULL, loaded_at TEXT NOT NULL
);
CREATE INDEX hosts_ip ON hosts(ip);
CREATE INDEX findings_run_id ON findings(run_id);
CREATE INDEX enrichments_cve_id ON enrichments(cve_id);
CREATE INDEX context_profiles_host_ip ON context_profiles(host_ip);
CREATE INDEX scores_finding_id ON scores(finding_id);
CREATE INDEX scores_risk ON scores(risk);
CREATE INDEX rationales_finding_id ON rationales(finding_id);
COMMIT;
"""


class Run(BaseModel):
	"""Typed metadata supplied explicitly by the caller, never inferred by the store."""

	model_config = ConfigDict(frozen=True)

	run_id: str
	started_at: datetime
	config_hash: str
	feeds: dict[str, str]


def _json(model: BaseModel) -> str:
	return json.dumps(
		model.model_dump(mode="json"),
		sort_keys=True,
		separators=(",", ":"),
		ensure_ascii=False,
		allow_nan=False,
	)


class Store:
	"""Open an existing database, or explicitly create one with create=True."""

	def __init__(self, path: Path, *, create: bool = False) -> None:
		self.path = path.resolve()
		exists = self.path.is_file()
		if not exists and not create:
			raise ConfigError(f"MISSING: SQLite store {self.path}; create it explicitly first")
		if not self.path.parent.is_dir():
			raise ConfigError(f"MISSING: SQLite store parent directory {self.path.parent}")
		mode = "rwc" if create else "rw"
		connection: sqlite3.Connection | None = None
		try:
			connection = sqlite3.connect(f"{self.path.as_uri()}?mode={mode}", uri=True)
			connection.row_factory = sqlite3.Row
			connection.execute("PRAGMA foreign_keys = ON")
			connection.execute("PRAGMA trusted_schema = OFF")
			if exists:
				self._validate_layout(connection)
			journal = connection.execute("PRAGMA journal_mode = WAL").fetchone()
			if journal is None or journal[0] != "wal":
				raise ConfigError(f"SQLite store {self.path} cannot enable journal_mode=WAL")
			if not exists:
				connection.executescript(_SCHEMA)
		except (sqlite3.Error, OSError) as error:
			if connection is not None:
				connection.close()
			raise ConfigError(f"Invalid or inaccessible SQLite store/schema: {self.path}") from error
		except ConfigError:
			if connection is not None:
				connection.close()
			raise
		self._connection = connection

	def _validate_layout(self, connection: sqlite3.Connection) -> None:
		for table, columns in _COLUMNS.items():
			rows = connection.execute(
				"SELECT name FROM pragma_table_info(?) ORDER BY cid", (table,)
			).fetchall()
			if tuple(row[0] for row in rows) != columns:
				raise ConfigError(f"Invalid SQLite schema for table {table} in {self.path}")

	def __enter__(self) -> Self:
		return self

	def __exit__(
		self,
		error_type: type[BaseException] | None,
		error: BaseException | None,
		traceback: TracebackType | None,
	) -> None:
		self.close()

	def close(self) -> None:
		self._connection.close()

	def _rows(self, sql: str, parameters: tuple[_Value, ...] = ()) -> list[sqlite3.Row]:
		try:
			return self._connection.execute(sql, parameters).fetchall()
		except sqlite3.Error as error:
			raise ConfigError(f"SQLite query failed for store {self.path}") from error

	def _write(self, sql: str, parameters: tuple[_Value, ...]) -> None:
		try:
			with self._connection:
				self._connection.execute(sql, parameters)
		except sqlite3.Error as error:
			raise ConfigError(f"SQLite write failed for store {self.path}") from error

	def _decode(self, model: type[_Model], row: sqlite3.Row) -> _Model:
		try:
			return model.model_validate_json(row["json"])
		except ValidationError as error:
			raise ConfigError(f"Invalid {model.__name__}.json in store {self.path}") from error

	def add_run(self, run: Run) -> None:
		feeds_json = json.dumps(run.feeds, sort_keys=True, separators=(",", ":"))
		self._write(
			"INSERT INTO runs (run_id, started_at, config_hash, feeds_json) VALUES (?, ?, ?, ?) "
			"ON CONFLICT(run_id) DO NOTHING",
			(run.run_id, run.started_at.isoformat(), run.config_hash, feeds_json),
		)
		if self.get_run(run.run_id) != run:
			raise ConfigError(f"Conflicting runs.run_id {run.run_id!r} in store {self.path}")

	def get_run(self, run_id: str) -> Run:
		rows = self._rows("SELECT * FROM runs WHERE run_id = ?", (run_id,))
		if not rows:
			raise ConfigError(f"MISSING: runs.run_id {run_id!r} in store {self.path}")
		row = rows[0]
		try:
			return Run(
				run_id=row["run_id"],
				started_at=row["started_at"],
				config_hash=row["config_hash"],
				feeds=json.loads(row["feeds_json"]),
			)
		except (ValidationError, ValueError, TypeError) as error:
			raise ConfigError(f"Invalid runs metadata for run_id {run_id!r} in {self.path}") from error

	def upsert_host(self, run_id: str, host: Host) -> None:
		self.get_run(run_id)
		self._write(
			"INSERT INTO hosts (run_id, ip, json) VALUES (?, ?, ?) "
			"ON CONFLICT(run_id, ip) DO UPDATE SET json = excluded.json",
			(run_id, host.ip, _json(host)),
		)

	def list_hosts(self, run_id: str) -> list[Host]:
		self.get_run(run_id)
		return [
			self._decode(Host, row)
			for row in self._rows("SELECT json FROM hosts WHERE run_id = ? ORDER BY ip", (run_id,))
		]

	def upsert_finding(self, finding: Finding) -> None:
		self.get_run(finding.provenance.run_id)
		try:
			with self._connection:
				self._connection.execute(
					"INSERT INTO findings (id, run_id, json, first_seen, last_seen) "
					"VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING",
					(
						finding.id,
						finding.provenance.run_id,
						_json(finding),
						finding.first_seen.isoformat(),
						finding.last_seen.isoformat(),
					),
				)
				original = self.get_finding(finding.id)
				updated = original.model_copy(update={"last_seen": finding.last_seen})
				self._connection.execute(
					"UPDATE findings SET json = ?, last_seen = ? WHERE id = ?",
					(_json(updated), updated.last_seen.isoformat(), finding.id),
				)
		except sqlite3.Error as error:
			raise ConfigError(f"SQLite findings write failed for store {self.path}") from error

	def get_finding(self, finding_id: str) -> Finding:
		rows = self._rows("SELECT json FROM findings WHERE id = ?", (finding_id,))
		if not rows:
			raise ConfigError(f"MISSING: findings.id {finding_id!r} in store {self.path}")
		return self._decode(Finding, rows[0])

	def list_findings(self, run_id: str | None = None) -> list[Finding]:
		if run_id is None:
			rows = self._rows("SELECT json FROM findings ORDER BY id")
		else:
			self.get_run(run_id)
			rows = self._rows("SELECT json FROM findings WHERE run_id = ? ORDER BY id", (run_id,))
		return [self._decode(Finding, row) for row in rows]

	def upsert_enrichment(self, enrichment: Enrichment) -> None:
		self.get_finding(enrichment.finding_id)
		self._write(
			"INSERT INTO enrichments (finding_id, cve_id, json) VALUES (?, ?, ?) "
			"ON CONFLICT(finding_id, cve_id) DO UPDATE SET json = excluded.json",
			(enrichment.finding_id, enrichment.cve_id, _json(enrichment)),
		)

	def list_enrichments(self, finding_id: str) -> list[Enrichment]:
		self.get_finding(finding_id)
		return [
			self._decode(Enrichment, row)
			for row in self._rows(
				"SELECT json FROM enrichments WHERE finding_id = ? ORDER BY cve_id", (finding_id,)
			)
		]

	def upsert_context(self, run_id: str, profile: ContextProfile) -> None:
		self.get_run(run_id)
		host_rows = self._rows(
			"SELECT json FROM hosts WHERE run_id = ? AND ip = ?", (run_id, profile.host_ip)
		)
		if not host_rows:
			raise ConfigError(
				f"SQLite write failed for store {self.path}: "
				f"MISSING: hosts.ip {profile.host_ip!r} for run_id {run_id!r}"
			)
		self._decode(Host, host_rows[0])
		self._write(
			"INSERT INTO context_profiles (run_id, host_ip, json) VALUES (?, ?, ?) "
			"ON CONFLICT(run_id, host_ip) DO UPDATE SET json = excluded.json",
			(run_id, profile.host_ip, _json(profile)),
		)

	def get_context(self, run_id: str, host_ip: str) -> ContextProfile:
		rows = self._rows(
			"SELECT json FROM context_profiles WHERE run_id = ? AND host_ip = ?", (run_id, host_ip)
		)
		if not rows:
			raise ConfigError(
				f"MISSING: context_profiles for run_id {run_id!r}, host_ip {host_ip!r} in {self.path}"
			)
		return self._decode(ContextProfile, rows[0])

	def upsert_score(self, run_id: str, score: ScoreBreakdown) -> None:
		self.get_run(run_id)
		self.get_finding(score.finding_id)
		self._write(
			"INSERT INTO scores (run_id, finding_id, json, risk, band) VALUES (?, ?, ?, ?, ?) "
			"ON CONFLICT(run_id, finding_id) DO UPDATE SET "
			"json = excluded.json, risk = excluded.risk, band = excluded.band",
			(run_id, score.finding_id, _json(score), score.risk, score.band),
		)

	def list_scores(self, run_id: str) -> list[ScoreBreakdown]:
		self.get_run(run_id)
		return [
			self._decode(ScoreBreakdown, row)
			for row in self._rows(
				"SELECT json FROM scores WHERE run_id = ? ORDER BY risk DESC, finding_id", (run_id,)
			)
		]

	def upsert_rationale(self, run_id: str, rationale: Rationale) -> None:
		self.get_run(run_id)
		self.get_finding(rationale.finding_id)
		self._write(
			"INSERT INTO rationales (run_id, finding_id, json) VALUES (?, ?, ?) "
			"ON CONFLICT(run_id, finding_id) DO UPDATE SET json = excluded.json",
			(run_id, rationale.finding_id, _json(rationale)),
		)

	def get_rationale(self, run_id: str, finding_id: str) -> Rationale:
		rows = self._rows(
			"SELECT json FROM rationales WHERE run_id = ? AND finding_id = ?", (run_id, finding_id)
		)
		if not rows:
			raise ConfigError(
				f"MISSING: rationales for run_id {run_id!r}, finding_id {finding_id!r} in {self.path}"
			)
		return self._decode(Rationale, rows[0])
