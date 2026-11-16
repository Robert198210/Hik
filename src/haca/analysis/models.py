"""Finding and evidence models for deterministic rules."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator

_EXPLICIT_ORP_SKIP = frozenset({"unspecified", "undecided", "none"})


class Classification(StrEnum):
    CONFIRMED_CONFLICT = "CONFIRMED_CONFLICT"
    POTENTIAL_CONFLICT = "POTENTIAL_CONFLICT"
    OPTIMIZATION = "OPTIMIZATION"
    INFO = "INFO"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class EvidenceTier(StrEnum):
    isapi = "isapi"
    browser = "browser"
    manual = "manual"
    simulation = "simulation"


class FindingSource(StrEnum):
    deterministic = "deterministic"
    ai_validated = "ai_validated"


class EvidenceRef(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    snapshot_id: str
    device_id: str
    endpoint_id: str
    xpath: str
    observed_value: str
    raw_sha256: str | None
    tier: EvidenceTier


class Recommendation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    setting_id: str
    device_id: str
    current_value: str
    recommended_value: str
    rationale: str
    manual_action: str


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    rule_id: str
    category: str
    classification: Classification
    severity: Severity
    basis: Literal["technical", "requirement"]
    devices: tuple[str, ...]
    evidence: tuple[EvidenceRef, ...]
    evidence_tier: EvidenceTier
    orp_refs: tuple[str, ...] = ()
    needs_decision: bool = False
    current_value: str | None = None
    recommended_value: str | None = None
    rationale: str
    source_refs: tuple[str, ...] = ()
    source: FindingSource = FindingSource.deterministic
    simulated_confirmed: bool = False
    rule_error: bool = False
    recommendation: Recommendation | None = None
    subject: str = ""

    @model_validator(mode="after")
    def _validate_finding(self) -> Finding:
        if not self.evidence:
            msg = "finding requires at least one evidence ref"
            raise ValueError(msg)
        if self.needs_decision and self.classification is not Classification.INFO:
            msg = "needs_decision requires INFO classification"
            raise ValueError(msg)
        if self.classification is Classification.CONFIRMED_CONFLICT:
            for ev in self.evidence:
                if ev.tier is EvidenceTier.simulation:
                    msg = "CONFIRMED_CONFLICT cannot use simulation evidence tier"
                    raise ValueError(msg)
            if self.evidence_tier is EvidenceTier.simulation:
                msg = "CONFIRMED_CONFLICT cannot use simulation evidence tier"
                raise ValueError(msg)
            if self.basis == "requirement" and self.orp_refs:
                for ref in self.orp_refs:
                    tail = ref.rsplit(".", 1)[-1].lower()
                    if tail in _EXPLICIT_ORP_SKIP:
                        msg = "CONFIRMED requirement finding references undecided ORP"
                        raise ValueError(msg)
        if self.simulated_confirmed and self.classification is Classification.CONFIRMED_CONFLICT:
            msg = "simulated_confirmed requires non-CONFIRMED classification"
            raise ValueError(msg)
        return self


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.critical: 0,
    Severity.high: 1,
    Severity.medium: 2,
    Severity.low: 3,
    Severity.info: 4,
}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 99),
            f.rule_id,
            ",".join(sorted(f.devices)),
        ),
    )