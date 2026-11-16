"""Canonical audit report model."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from haca.analysis.models import Finding
from haca.catalog.coverage import CoverageEntry, CoverageSummary


class DeviceReportEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    role: str
    expected_model: str
    identity: dict[str, Any] | None
    identification_status: str | None


class AuditMeta(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    haca_version: str
    run_id: str
    started_at: datetime
    finished_at: datetime
    simulated: bool
    scenario: str | None
    orp_hash: str | None
    catalog_version: str
    registry_verification_counts: dict[str, int]


class AuditReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    meta: AuditMeta
    devices: tuple[DeviceReportEntry, ...]
    coverage: CoverageSummary
    coverage_entries: tuple[CoverageEntry, ...]
    coverage_statement: str
    findings: tuple[Finding, ...]
    needs_decision: tuple[dict[str, Any], ...]
    manual_checks: tuple[str, ...]
    ai: ReportAiSection | None = None


class AiRejected(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    device_id: str
    setting_id: str
    reason: str
    rationale: str


class AiCorroboration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str
    note: str


class ReportAiSection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: str
    reason: str | None = None
    summary: str | None = None
    cross_device_notes: tuple[str, ...] = ()
    rejected: tuple[AiRejected, ...] = ()
    corroborations: tuple[AiCorroboration, ...] = ()
    model: str | None = None
    prompt_version: str | None = None
    cached: bool = False
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
