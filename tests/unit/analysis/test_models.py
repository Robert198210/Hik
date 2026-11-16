from __future__ import annotations

import pytest
from pydantic import ValidationError

from haca.analysis.models import (
    Classification,
    EvidenceRef,
    EvidenceTier,
    Finding,
    Severity,
    sort_findings,
)


def _evidence() -> EvidenceRef:
    return EvidenceRef(
        snapshot_id="run-1",
        device_id="nvr01",
        endpoint_id="storage.hdd",
        xpath="status",
        observed_value="error",
        raw_sha256=None,
        tier=EvidenceTier.isapi,
    )


def test_confirmed_rejects_simulation_tier() -> None:
    with pytest.raises(ValidationError):
        Finding(
            id="x",
            rule_id="R-TEST",
            category="t",
            classification=Classification.CONFIRMED_CONFLICT,
            severity=Severity.high,
            basis="technical",
            devices=("nvr01",),
            evidence=(
                EvidenceRef(
                    snapshot_id="r",
                    device_id="nvr01",
                    endpoint_id="e",
                    xpath="x",
                    observed_value="y",
                    raw_sha256=None,
                    tier=EvidenceTier.simulation,
                ),
            ),
            evidence_tier=EvidenceTier.simulation,
            rationale="test",
        )


def test_needs_decision_requires_info() -> None:
    with pytest.raises(ValidationError):
        Finding(
            id="x",
            rule_id="R-TEST",
            category="t",
            classification=Classification.CONFIRMED_CONFLICT,
            severity=Severity.high,
            basis="requirement",
            devices=("nvr01",),
            evidence=(_evidence(),),
            evidence_tier=EvidenceTier.isapi,
            needs_decision=True,
            rationale="test",
        )


def test_sort_findings() -> None:
    low = Finding(
        id="a",
        rule_id="R-B",
        category="t",
        classification=Classification.INFO,
        severity=Severity.low,
        basis="technical",
        devices=("cam01",),
        evidence=(_evidence(),),
        evidence_tier=EvidenceTier.isapi,
        rationale="low",
    )
    high = Finding(
        id="b",
        rule_id="R-A",
        category="t",
        classification=Classification.CONFIRMED_CONFLICT,
        severity=Severity.high,
        basis="technical",
        devices=("nvr01",),
        evidence=(_evidence(),),
        evidence_tier=EvidenceTier.isapi,
        rationale="high",
    )
    ordered = sort_findings([low, high])
    assert ordered[0].severity is Severity.high