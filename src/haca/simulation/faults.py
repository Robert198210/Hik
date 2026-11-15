"""Simulated device fault injection profiles."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class FaultProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    auth_always_fail: bool = False
    connect_error: bool = False
    read_timeout_times: int = 0
    http_status_override: dict[str, int] = Field(default_factory=dict)
    not_support_paths: set[str] = Field(default_factory=set)
    malformed_paths: set[str] = Field(default_factory=set)