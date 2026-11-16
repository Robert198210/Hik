"""Audit orchestration — collect, correlate, rules, report."""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from haca import __version__
from haca.analysis.engine import RuleEngine
from haca.analysis.models import Finding, Severity
from haca.catalog.coverage import (
    CATALOG_VERSION,
    CoverageEntry,
    compute_coverage,
    coverage_summary,
    observed_uncataloged_count,
)
from haca.catalog.loader import load_catalog_entries
from haca.catalog.models import CatalogEntry, ManualSource
from haca.collect.identify import IdentificationResult, identify_devices
from haca.collect.runner import run_simulated_collection
from haca.config.models import AppConfig
from haca.devices.models import ResolvedDevice
from haca.isapi.client import IsapiClient
from haca.isapi.registry.loader import load_registry_entries
from haca.isapi.registry.phase1_endpoints import build_phase1_policy
from haca.reports.models import AuditMeta, AuditReport, DeviceReportEntry
from haca.requirements.loader import requirements_hash
from haca.requirements.models import RequirementsProfile
from haca.security.egress import EgressPolicy
from haca.simulation.defaults import (
    build_simulation_network_for_scenario,
    simulation_credential,
    simulation_registry,
    simulation_timeouts,
)


def registry_verification_counts() -> dict[str, int]:
    return dict(Counter(entry.verification for entry in load_registry_entries()))


class AuditOrchestrator:
    def run_audit(
        self,
        app_config: AppConfig,
        devices: list[ResolvedDevice],
        orp: RequirementsProfile,
        *,
        simulate: bool,
        scenario: str | None,
        manual_attestations: dict[str, dict[str, object]] | None = None,
        db_path: Path | None = None,
        ai: object | None = None,
    ) -> AuditReport:
        del app_config, ai
        started = datetime.now(UTC)
        catalog = load_catalog_entries()
        if simulate:
            if not scenario:
                raise ValueError("scenario is required for simulation")
            collection, coverage = run_simulated_collection(scenario)
            if manual_attestations:
                coverage = compute_coverage(
                    catalog, collection, orp, manual=manual_attestations
                )
            id_results = [
                r
                for r in _identify_simulated(scenario or "clean")
            ]
        else:
            raise NotImplementedError("live audit is not wired in MVP")

        run_id = str(uuid.uuid4())
        engine = RuleEngine()
        findings, _corr = engine.run(
            collection, devices, orp, coverage, run_id=run_id
        )
        finished = datetime.now(UTC)
        summary = coverage_summary(
            coverage,
            catalog,
            observed_uncataloged=observed_uncataloged_count(collection),
        )
        verified = summary.totals.get("VERIFIED_ISAPI", 0) + summary.totals.get(
            "VERIFIED_MANUAL", 0
        )
        total = sum(summary.totals.values())
        statement = (
            f"Verified {verified} of {total} settings in HACA catalog v{summary.catalog_version}. "
            "The catalog does not cover every Hikvision setting."
        )
        needs = _needs_decision_from_findings(findings)
        manual_checks = _manual_checklist_ids(catalog, coverage, manual_attestations)

        if db_path is not None:
            from haca.store.db import open_db
            from haca.store.repositories import (
                save_audit_findings,
                save_collection,
                save_coverage,
            )

            _, session_factory = open_db(db_path)
            with session_factory() as session:
                persisted_id = save_collection(
                    session,
                    collection,
                    orp_hash=requirements_hash(orp),
                    catalog_version=CATALOG_VERSION,
                    scenario=scenario,
                    kind="audit",
                )
                save_coverage(session, persisted_id, coverage)
                save_audit_findings(session, persisted_id, findings)

        device_entries = tuple(
            DeviceReportEntry(
                id=dev.id,
                role=dev.role,
                expected_model=dev.expected_model,
                identity=_identity_payload(id_results, dev.id),
                identification_status=_ident_status(id_results, dev.id),
            )
            for dev in devices
        )

        return AuditReport(
            meta=AuditMeta(
                haca_version=__version__,
                run_id=run_id,
                started_at=started,
                finished_at=finished,
                simulated=simulate,
                scenario=scenario,
                orp_hash=requirements_hash(orp),
                catalog_version=CATALOG_VERSION,
                registry_verification_counts=registry_verification_counts(),
            ),
            devices=device_entries,
            coverage=summary,
            coverage_entries=tuple(coverage),
            coverage_statement=statement,
            findings=tuple(findings),
            needs_decision=tuple(needs),
            manual_checks=manual_checks,
            ai=None,
        )


def audit_exit_code(findings: list[Finding]) -> int:
    if any(f.classification.value == "CONFIRMED_CONFLICT" for f in findings):
        return 3
    if any(f.severity in (Severity.critical, Severity.high) for f in findings):
        return 3
    return 0


def _identify_simulated(scenario: str) -> list[IdentificationResult]:

    network = build_simulation_network_for_scenario(scenario)
    registry = simulation_registry()
    policy = build_phase1_policy()
    credential = simulation_credential()
    pairs = []
    for device in registry.all():
        client = IsapiClient(
            device,
            credential,
            registry,
            policy,
            EgressPolicy({device.host}),
            simulation_timeouts(),
            inner_transport=network.transport(),
        )
        pairs.append((device, client))
    try:
        return identify_devices(pairs, simulated=True)
    finally:
        for _d, client in pairs:
            client.close()


def _identity_payload(results: list[IdentificationResult], device_id: str) -> dict[str, Any] | None:
    for item in results:
        if item.device_id == device_id and item.identity:
            return item.identity.model_dump()
    return None


def _ident_status(results: list[IdentificationResult], device_id: str) -> str | None:
    for item in results:
        if item.device_id == device_id:
            return item.status.value
    return None


def _needs_decision_from_findings(findings: list[Finding]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for finding in findings:
        if not finding.needs_decision:
            continue
        for ref in finding.orp_refs:
            if ref in seen:
                continue
            seen.add(ref)
            out.append({"field": ref, "note": finding.rationale, "finding_id": finding.id})
    return sorted(out, key=lambda row: row["field"])


def _manual_checklist_ids(
    catalog: tuple[CatalogEntry, ...],
    coverage: list[CoverageEntry],
    manual: dict[str, dict[str, object]] | None,
) -> tuple[str, ...]:
    covered_manual = {
        entry.setting_id
        for entry in coverage
        if entry.status == "VERIFIED_MANUAL"
    }
    pending: list[str] = []
    for entry in catalog:
        for src in entry.sources:
            if isinstance(src, ManualSource) and src.checklist_id not in covered_manual:
                pending.append(src.checklist_id)
    return tuple(sorted(set(pending)))
