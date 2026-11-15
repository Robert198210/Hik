"""Application and device configuration models."""

from __future__ import annotations

import re
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_DEVICE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,31}$")
_CREDENTIAL_REF_RE = re.compile(r"^[a-z0-9_-]{1,64}$")

_RFC1918_NETWORKS: tuple[IPv4Network, ...] = (
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
)


def _subnet_within_rfc1918(network: IPv4Network) -> bool:
    return any(network.subnet_of(parent) for parent in _RFC1918_NETWORKS)


class NetworkConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    subnet: IPv4Network

    @field_validator("subnet")
    @classmethod
    def validate_rfc1918(cls, value: IPv4Network) -> IPv4Network:
        if not _subnet_within_rfc1918(value):
            msg = "subnet must lie within RFC1918 private address space"
            raise ValueError(msg)
        return value


class TimeoutConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    connect: float = Field(default=5.0, ge=0.5, le=120.0)
    read: float = Field(default=20.0, ge=0.5, le=120.0)


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    network: NetworkConfig
    timeouts: TimeoutConfig = Field(default_factory=TimeoutConfig)
    database_path: Path = Path("data/haca.db")
    simulation: bool = False


class DeviceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    role: Literal["nvr", "ptz", "camera"]
    expected_model: str
    host_suffix: int | None = None
    host: IPv4Address | None = None
    scheme: Literal["http", "https"] = "http"
    port: int | None = None
    credential_ref: str
    enabled: bool = True

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not _DEVICE_ID_RE.fullmatch(value):
            msg = "device id must match ^[a-z0-9][a-z0-9_-]{1,31}$"
            raise ValueError(msg)
        return value

    @field_validator("credential_ref")
    @classmethod
    def validate_credential_ref(cls, value: str) -> str:
        if not _CREDENTIAL_REF_RE.fullmatch(value):
            msg = "credential_ref must match ^[a-z0-9_-]{1,64}$"
            raise ValueError(msg)
        return value

    @field_validator("host_suffix")
    @classmethod
    def validate_host_suffix(cls, value: int | None) -> int | None:
        if value is None:
            return value
        if value < 1 or value > 254:
            msg = "host_suffix must be in range 1–254"
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def exactly_one_host_source(self) -> Self:
        has_host = self.host is not None
        has_suffix = self.host_suffix is not None
        if has_host == has_suffix:
            msg = "exactly one of host or host_suffix must be set"
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def default_port(self) -> Self:
        if self.port is not None:
            return self
        default = 443 if self.scheme == "https" else 80
        return self.model_copy(update={"port": default})


class DevicesFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    devices: list[DeviceConfig]


class ResolvedDeviceConfig(BaseModel):
    """Device entry with host and port fully resolved."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    role: Literal["nvr", "ptz", "camera"]
    expected_model: str
    host: IPv4Address
    scheme: Literal["http", "https"]
    port: int
    credential_ref: str
    enabled: bool = True