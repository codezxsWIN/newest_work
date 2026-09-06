"""Validated configuration loading. Files are read locally; nothing is fetched."""

import json
from collections.abc import Iterable
from hashlib import sha256
from ipaddress import AddressValueError, IPv4Network, IPv6Network, ip_address, ip_network
from pathlib import Path
from typing import Any, Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from vulnassess.errors import ConfigError

CONFIG_FILES = ("scope.yaml", "roles.yaml", "weights.yaml", "controls.yaml")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LabTargetTags(_Strict):
    environment: Literal["prod", "test"] | None = None
    criticality: int | None = Field(default=None, ge=1, le=5)
    vantage: Literal["internal", "external"] | None = None


class LabTarget(_Strict):
    name: str
    ip: str
    tags: LabTargetTags = LabTargetTags()


class Canary(_Strict):
    ip: str


class Scope(_Strict):
    """The authorisation fence. A CIDR bounds authorisation; it is not discovery permission."""

    allowed_cidrs: list[str]
    allowed_hosts: list[str] = []
    vantage: Literal["internal", "external"] = "internal"
    lab_targets: list[LabTarget] = []
    canary: Canary | None = None

    @model_validator(mode="after")
    def validate_addresses(self) -> Self:
        networks = _networks(self.allowed_cidrs)
        for host in self.allowed_hosts:
            _parse_address(host, "allowed_hosts")
        for target in self.lab_targets:
            address = _parse_address(target.ip, f"lab_targets.{target.name}.ip")
            if not any(address in network for network in networks):
                raise ValueError(
                    f"lab_targets.{target.name}.ip {target.ip} is outside every allowed CIDR"
                )
        if self.canary is not None:
            canary = _parse_address(self.canary.ip, "canary.ip")
            if any(canary in network for network in networks):
                raise ValueError(f"canary.ip {self.canary.ip} must not be inside an allowed CIDR")
        return self

    def permits(self, target_ip: str) -> bool:
        """Authorise an explicit host or an address inside an allowed CIDR."""
        try:
            address = ip_address(target_ip)
        except ValueError:
            return False
        if self.canary is not None and address == ip_address(self.canary.ip):
            return False
        if any(address == ip_address(host) for host in self.allowed_hosts):
            return True
        return any(address in network for network in _networks(self.allowed_cidrs))


class ControlSignature(_Strict):
    where: Literal["header", "cookie", "body", "status"]
    regex: str
    vendor: str | None = None
    note: str | None = None


class ControlGroup(_Strict):
    signatures: list[ControlSignature]


class ControlSignatures(_Strict):
    waf: ControlGroup
    auth_required: ControlGroup
    rate_limiting: ControlGroup


def _networks(cidrs: Iterable[str]) -> list[IPv4Network | IPv6Network]:
    networks: list[IPv4Network | IPv6Network] = []
    for cidr in cidrs:
        try:
            networks.append(ip_network(cidr, strict=False))
        except (ValueError, AddressValueError) as error:
            raise ValueError(f"allowed_cidrs entry {cidr!r} is not a valid CIDR") from error
    return networks


def _parse_address(value: str, key: str):
    try:
        return ip_address(value)
    except ValueError as error:
        raise ValueError(f"{key} {value!r} is not a valid IP address") from error


def read_yaml(path: Path) -> dict[str, Any]:
    """Read one local YAML mapping, naming the file in every failure."""
    if not path.is_file():
        raise ConfigError(f"MISSING: configuration file {path}")
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise ConfigError(f"Invalid YAML in {path}: {type(error).__name__}") from error
    if payload is None:
        return {}
    if not isinstance(payload, dict):
        raise ConfigError(f"Invalid YAML in {path}: expected a mapping at the top level")
    return payload


def _validate(model: type[BaseModel], payload: dict[str, Any], path: Path) -> Any:
    try:
        return model.model_validate(payload)
    except ValidationError as error:
        first = error.errors()[0]
        key = ".".join(str(part) for part in first["loc"]) or "<root>"
        raise ConfigError(f"Invalid configuration in {path}: key {key}: {first['msg']}") from error


def load_scope(config_dir: Path) -> Scope:
    path = config_dir / "scope.yaml"
    return _validate(Scope, read_yaml(path), path)


def load_controls(config_dir: Path) -> ControlSignatures:
    path = config_dir / "controls.yaml"
    return _validate(ControlSignatures, read_yaml(path), path)


class Settings(BaseModel):
    """Loaded configuration plus the hash that pins it to a run."""

    model_config = ConfigDict(frozen=True)

    config_dir: Path
    scope: Scope
    controls: ControlSignatures
    roles: dict[str, Any]
    weights: dict[str, Any]

    @classmethod
    def load(cls, config_dir: Path = Path("config")) -> "Settings":
        if not config_dir.is_dir():
            raise ConfigError(f"MISSING: configuration directory {config_dir}")
        return cls(
            config_dir=config_dir,
            scope=load_scope(config_dir),
            controls=load_controls(config_dir),
            roles=read_yaml(config_dir / "roles.yaml"),
            weights=read_yaml(config_dir / "weights.yaml"),
        )

    def config_hash(self) -> str:
        """Stable digest of every loaded configuration file."""
        document = {
            "scope": self.scope.model_dump(mode="json"),
            "controls": self.controls.model_dump(mode="json"),
            "roles": self.roles,
            "weights": self.weights,
        }
        payload = json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return sha256(payload.encode("utf-8")).hexdigest()
