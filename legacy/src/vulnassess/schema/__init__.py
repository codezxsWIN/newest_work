"""Fixed public data contracts for the offline assessment pipeline."""

from datetime import date, datetime
from hashlib import sha256
from typing import Any, Literal, Self, get_args
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Tool = Literal["nmap", "nikto", "zap"]
Role = Literal[
	"database",
	"web_frontend",
	"app_server",
	"domain_controller",
	"mail",
	"file_share",
	"iot_embedded",
	"workstation",
	"network_device",
	"unknown",
]
Band = Literal["Critical", "High", "Medium", "Low"]


class Provenance(BaseModel):
	tool: Tool
	raw_path: str
	record_index: int
	run_id: str


class Service(BaseModel):
	port: int
	protocol: Literal["tcp", "udp"]
	name: str | None
	product: str | None
	version: str | None
	cpe: str | None
	banner: str | None
	tls: bool = False


class Host(BaseModel):
	ip: str
	hostname: str | None
	os_guess: str | None
	services: list[Service]


class Finding(BaseModel):
	model_config = ConfigDict(frozen=True)

	id: str
	host_ip: str
	port: int | None
	protocol: str | None
	url: str | None
	tool: Tool
	tool_native_id: str
	title: str
	description: str
	evidence: str = Field(max_length=2048)
	cve_ids: list[str]
	cwe_ids: list[str]
	reference_urls: list[str]
	native_severity: str | None
	native_confidence: str | None
	first_seen: datetime
	last_seen: datetime
	provenance: Provenance

	@staticmethod
	def fingerprint(
		host_ip: str,
		port: int | None,
		protocol: str | None,
		tool: Tool,
		tool_native_id: str,
		url: str | None,
	) -> str:
		return sha256(
			"|".join(
				[host_ip, str(port or ""), protocol or "", tool, tool_native_id, url or ""]
			).encode()
		).hexdigest()

	@model_validator(mode="after")
	def validate_identity(self) -> Self:
		fingerprint = self.fingerprint(
			self.host_ip, self.port, self.protocol, self.tool, self.tool_native_id, self.url
		)
		if self.id != str(uuid5(NAMESPACE_URL, fingerprint)):
			raise ValueError("Finding.id must be uuid5(NAMESPACE_URL, fingerprint)")
		if self.tool != self.provenance.tool:
			raise ValueError("Finding.provenance.tool must match Finding.tool")
		if self.tool in ("nmap", "nikto") and self.native_severity is not None:
			raise ValueError("Finding.native_severity must be None for nmap and nikto")
		return self


class Feature(BaseModel):
	value: Any
	confidence: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
	source: Literal["rule", "llm", "manual"]
	evidence: str = Field(min_length=1)

	@field_validator("evidence")
	@classmethod
	def nonempty_evidence(cls, value: str) -> str:
		if not value.strip():
			raise ValueError("Feature.evidence must not be empty; use 'none observed' for absence")
		return value


class ContextProfile(BaseModel):
	host_ip: str
	role: Feature
	exposure: Feature
	segment: str | None
	controls: dict[Literal["waf", "auth_required", "tls", "rate_limiting"], Feature]
	manual: dict[str, Feature]

	@model_validator(mode="after")
	def validate_values(self) -> Self:
		if not isinstance(self.role.value, str) or self.role.value not in get_args(Role):
			raise ValueError("ContextProfile.role.value must be a contractual Role")
		if self.exposure.value not in ("internal", "internet_facing"):
			raise ValueError("ContextProfile.exposure.value must be internal or internet_facing")
		for key, feature in self.manual.items():
			if key == "criticality":
				if type(feature.value) is not int or not 1 <= feature.value <= 5:
					raise ValueError("ContextProfile.manual.criticality.value must be 1-5")
			elif key == "environment":
				if feature.value not in ("prod", "test"):
					raise ValueError("ContextProfile.manual.environment.value must be prod or test")
			else:
				raise ValueError(f"ContextProfile.manual.{key} is an unknown key")
		return self


class Enrichment(BaseModel):
	model_config = ConfigDict(frozen=True)

	finding_id: str
	cve_id: str
	match_method: Literal["explicit", "cpe_range"]
	match_confidence: float
	cvss31_vector: str | None
	cvss31_base: float | None
	cvss40_vector: str | None
	cvss40_base: float | None
	epss: float | None
	epss_percentile: float | None
	kev: bool
	kev_date_added: date | None
	feed_dates: dict[str, str]


class ScoreBreakdown(BaseModel):
	model_config = ConfigDict(frozen=True)

	finding_id: str
	cve_id: str | None
	cvss_version_used: Literal["4.0", "3.1"] | None
	base_vector: str | None
	base_score: float | None
	env_vector: str | None
	env_score: float | None
	env_modifications: dict[str, str]
	epss_percentile: float | None
	threat_multiplier: float | None  # None = no EPSS observed; rank on environmental score only
	kev: bool
	native_fallback: str | None
	risk: float
	band: Band
	inputs: dict[str, Any]
	weights_hash: str


class Rationale(BaseModel):
	finding_id: str
	text: str
	source: Literal["llm", "template"]
	model: str | None
	validation: dict[str, Any]
