from __future__ import annotations

import re
from datetime import UTC, datetime

from haca.analysis.models import (
    Classification,
    EvidenceRef,
    EvidenceTier,
    Finding,
    Severity,
)
from haca.audit import audit_exit_code
from haca.catalog.coverage import CoverageSummary
from haca.reports.json_report import report_to_json
from haca.reports.markdown import render_markdown
from haca.reports.models import AuditMeta, AuditReport, DeviceReportEntry

_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
_SERIAL = re.compile(r"SYNTH-[A-Z0-9]{6,}")


def _sample_report() -> AuditReport:
    finding = Finding(
        id="R-TEST:nvr01:demo",
        rule_id="R-TEST",
        category="test",
        classification=Classification.INFO,
        severity=Severity.info,
        basis="technical",
        devices=("nvr01",),
        evidence=(
            EvidenceRef(
                snapshot_id="run",
                device_id="nvr01",
                endpoint_id="system.device_info",
                xpath="serialNumber",
                observed_value="SYNTH-ABCDEF123456",
                raw_sha256=None,
                tier=EvidenceTier.simulation,
            ),
        ),
        evidence_tier=EvidenceTier.simulation,
        rationale="demo",
        current_value="SYNTH-ABCDEF123456",
    )
    return AuditReport(
        meta=AuditMeta(
            haca_version="0.1.0.dev0",
            run_id="run-1",
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
            simulated=True,
            scenario="clean",
            orp_hash="abc",
            catalog_version="1",
            registry_verification_counts={"documented": 1},
        ),
        devices=(
            DeviceReportEntry(
                id="nvr01",
                role="nvr",
                expected_model="DS-7616NXI-K2(D)",
                identity={"serial_masked": "****1234", "mac_masked": "**:**:**:**:53:01"},
                identification_status="IDENTIFIED",
            ),
        ),
        coverage=CoverageSummary(
            catalog_version="1",
            per_device={},
            totals={"VERIFIED_ISAPI": 1},
            observed_uncataloged=0,
        ),
        coverage_entries=(),
        coverage_statement=(
            "Verified 1 of 1 settings in HACA catalog v1. "
            "The catalog does not cover every Hikvision setting."
        ),
        findings=(finding,),
        needs_decision=(),
        manual_checks=("manual.dual_vca",),
    )


def test_json_masks_serial() -> None:
    payload = report_to_json(_sample_report())
    assert "ABCDEF123456" not in payload
    assert "****3456" in payload


def test_markdown_simulated_banner() -> None:
    md = render_markdown(_sample_report())
    assert "SIMULATED" in md
    assert "Coverage matrix" in md


def test_audit_exit_codes() -> None:
    sample = _sample_report().findings[0]
    assert audit_exit_code([sample]) == 0
    high = sample.model_copy(
        update={
            "severity": Severity.high,
            "simulated_confirmed": True,
            "classification": Classification.POTENTIAL_CONFLICT,
        }
    )
    assert audit_exit_code([high]) == 3
