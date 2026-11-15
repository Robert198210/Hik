"""Resolved device models for registry operations."""

from __future__ import annotations

from ipaddress import IPv4Address
from typing import Literal

from pydantic import BaseModel, ConfigDict


class ResolvedDevice(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    role: Literal["nvr", "ptz", "camera"]
    expected_model: str
    host: IPv4Address
    port: int
    scheme: Literal["http", "https"]
    credential_ref: str