"""Built-in Phase 1 ISAPI endpoint rules (until T2.02 registry YAML)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from haca.security.endpoint_policy import EndpointPolicy, EndpointRule

_PHASE1_DEVICE_INFO = EndpointRule(
    id="system.device_info",
    path_template="/ISAPI/System/deviceInfo",
    method="GET",
    sensitivity="normal",
)


class Phase1EndpointMeta(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    path: str
    method: Literal["GET", "POST"]
    device_roles: tuple[Literal["nvr", "ptz", "camera"], ...]
    verification: Literal["observed_live", "documented", "candidate_unverified"]
    source: str


PHASE1_ENDPOINTS: tuple[Phase1EndpointMeta, ...] = (
    Phase1EndpointMeta(
        id="system.device_info",
        path="/ISAPI/System/deviceInfo",
        method="GET",
        device_roles=("nvr", "ptz", "camera"),
        verification="documented",
        source="Hikvision ISAPI general device information resource",
    ),
)


def build_phase1_policy() -> EndpointPolicy:
    return EndpointPolicy([_PHASE1_DEVICE_INFO])