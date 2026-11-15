"""Collection run models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from haca.collect.extract import DeviceViews
from haca.collect.identify import DeviceIdentity


class EndpointOutcome(StrEnum):
    COLLECTED = "COLLECTED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    ENDPOINT_NOT_FOUND = "ENDPOINT_NOT_FOUND"
    AUTH_DENIED = "AUTH_DENIED"
    TIMEOUT = "TIMEOUT"
    CONNECTION_ERROR = "CONNECTION_ERROR"
    PARSE_ERROR = "PARSE_ERROR"
    BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"
    SKIPPED_CAPABILITY = "SKIPPED_CAPABILITY"
    SKIPPED_DEVICE_OFFLINE = "SKIPPED_DEVICE_OFFLINE"


class RawEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    device_id: str
    endpoint_id: str
    path: str
    outcome: EndpointOutcome
    http_status: int | None
    sub_status_code: str | None
    sha256: str | None
    body: bytes | None
    collected_at: datetime
    elapsed_ms: float


class DeviceCollection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    device_id: str
    role: str
    identity: DeviceIdentity | None
    evidence: dict[str, RawEvidence]
    views: DeviceViews
    missing_fields: tuple[str, ...] = ()
    flattened: dict[str, str] = Field(default_factory=dict)  # noqa: RUF009


class CollectionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_started: datetime
    run_finished: datetime
    simulated: bool
    devices: list[DeviceCollection]


class PlannedRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint_id: str
    params: dict[str, int]