"""Backward-compatible exports for the ISAPI endpoint registry (T2.01+)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from haca.isapi.registry.loader import RegistryEntry, build_policy, load_registry_entries
from haca.security.endpoint_policy import EndpointPolicy

__all__ = (
    "PHASE1_ENDPOINTS",
    "Phase1EndpointMeta",
    "build_phase1_policy",
    "build_policy",
)


class Phase1EndpointMeta(BaseModel):
    """Legacy metadata tuple shape used in Phase-1 QA tests."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    path: str
    method: Literal["GET", "POST"]
    device_roles: tuple[Literal["nvr", "ptz", "camera"], ...]
    verification: Literal["observed_live", "documented", "candidate_unverified"]
    source: str


def _to_phase1_meta(entry: RegistryEntry) -> Phase1EndpointMeta:
    return Phase1EndpointMeta(
        id=entry.id,
        path=entry.path,
        method=entry.method,
        device_roles=entry.device_roles,
        verification=entry.verification,
        source=entry.source,
    )


PHASE1_ENDPOINTS: tuple[Phase1EndpointMeta, ...] = tuple(
    _to_phase1_meta(e) for e in load_registry_entries()
)


def build_phase1_policy() -> EndpointPolicy:
    return build_policy()