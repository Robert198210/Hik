"""Setting Catalog entry models."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

CatalogCategory = Literal[
    "identity",
    "time",
    "network",
    "security",
    "streaming",
    "recording",
    "storage",
    "analytics",
    "linkage",
    "ptz",
    "platform",
]

CatalogScope = Literal["device", "channel", "item"]
CatalogVerification = Literal["candidate_unverified", "observed_live"]
_DeviceRole = Literal["nvr", "ptz", "camera"]


class IsapiSource(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["isapi"]
    endpoint_id: str
    view_path: str


class ManualSource(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["manual"]
    checklist_id: str


CatalogSource = IsapiSource | ManualSource


class CatalogEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    category: CatalogCategory
    title: str
    device_roles: tuple[_DeviceRole, ...]
    scope: CatalogScope
    sources: tuple[CatalogSource, ...]
    verification: CatalogVerification = "candidate_unverified"
    orp_link: str | None = None

    @field_validator("sources")
    @classmethod
    def _non_empty_sources(cls, value: tuple[CatalogSource, ...]) -> tuple[CatalogSource, ...]:
        if not value:
            msg = "catalog entry requires at least one source"
            raise ValueError(msg)
        return value