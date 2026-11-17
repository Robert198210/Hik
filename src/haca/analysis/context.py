"""Rule evaluation context and finding builders."""

from __future__ import annotations

from typing import TYPE_CHECKING

from haca.analysis.correlator import CorrelationResult
from haca.analysis.models import (
    Classification,
    EvidenceRef,
    EvidenceTier,
    Finding,
    FindingSource,
    Recommendation,
    Severity,
)
from haca.analysis.orp_access import OrpAccess
from haca.catalog.coverage import CoverageEntry
from haca.collect.models import CollectionResult, DeviceCollection, EndpointOutcome

if TYPE_CHECKING:
    from haca.requirements.models import RequirementsProfile


class RuleContext:
    def __init__(
        self,
        *,
        result: CollectionResult,
        correlation: CorrelationResult,
        orp: RequirementsProfile,
        coverage: list[CoverageEntry],
        run_id: str,
    ) -> None:
        self.result = result
        self.correlation = correlation
        self.orp = orp
        self.orp_access = OrpAccess(orp)
        self.coverage = coverage
        self.run_id = run_id
        self.simulated = result.simulated
        self._devices: dict[str, DeviceCollection] = {
            d.device_id: d for d in result.devices
        }
        self._tier = EvidenceTier.simulation if result.simulated else EvidenceTier.isapi

    def device(self, device_id: str) -> DeviceCollection | None:
        return self._devices.get(device_id)

    def evidence(
        self,
        device_id: str,
        endpoint_id: str,
        xpath: str,
        value: str,
    ) -> EvidenceRef:
        dev = self._devices[device_id]
        raw = dev.evidence.get(endpoint_id)
        sha = raw.sha256 if raw else None
        return EvidenceRef(
            snapshot_id=self.run_id,
            device_id=device_id,
            endpoint_id=endpoint_id,
            xpath=xpath,
            observed_value=value,
            raw_sha256=sha,
            tier=self._tier,
        )

    def view_accessible(self, device_id: str, view_field: str) -> bool:
        dev = self._devices.get(device_id)
        if dev is None:
            return False
        endpoint = _VIEW_ENDPOINTS.get(view_field)
        if endpoint and endpoint in dev.evidence:
            outcome = dev.evidence[endpoint].outcome
            if outcome is not EndpointOutcome.COLLECTED:
                return False
        views = dev.views
        return getattr(views, view_field, None) is not None

    def build_finding(
        self,
        *,
        rule_id: str,
        title: str,
        category: str,
        basis: str,
        default_severity: Severity,
        devices: tuple[str, ...],
        classification: Classification,
        subject: str,
        rationale: str,
        evidence: list[EvidenceRef],
        orp_refs: tuple[str, ...] = (),
        needs_decision: bool = False,
        current_value: str | None = None,
        recommended_value: str | None = None,
        source_refs: tuple[str, ...] = (),
        recommendation: Recommendation | None = None,
        rule_error: bool = False,
    ) -> Finding:
        device_key = ",".join(sorted(devices))
        finding_id = f"{rule_id}:{device_key}:{subject}"
        sim_confirmed = False
        effective_class = classification
        if self.simulated and classification is Classification.CONFIRMED_CONFLICT:
            effective_class = Classification.POTENTIAL_CONFLICT
            sim_confirmed = True
        return Finding(
            id=finding_id,
            rule_id=rule_id,
            category=category,
            classification=effective_class,
            severity=default_severity,
            basis=basis,  # type: ignore[arg-type]
            devices=devices,
            evidence=tuple(evidence),
            evidence_tier=self._tier,
            orp_refs=orp_refs,
            needs_decision=needs_decision,
            current_value=current_value,
            recommended_value=recommended_value,
            rationale=rationale,
            source_refs=source_refs or ("ADR-011",),
            source=FindingSource.deterministic,
            recommendation=recommendation,
            rule_error=rule_error,
            subject=subject,
            simulated_confirmed=sim_confirmed,
        )


_VIEW_ENDPOINTS: dict[str, str] = {
    "streams": "streaming.channels",
    "time": "system.time",
    "ntp": "system.time.ntp_servers",
    "network": "system.network.interfaces",
    "admin_access": "security.admin_accesses",
    "line_detection": "smart.line_detection",
    "field_detection": "smart.field_detection",
    "region_entrance": "smart.region_entrance",
    "triggers": "event.triggers",
    "tracks": "record.tracks",
    "record_search": "content.record_search",
    "log_search": "content.log_search",
    "hdds": "storage.hdd",
    "proxy_channels": "input_proxy.channels",
    "park_action": "ptz.park_action",
    "patrols": "ptz.patrols",
    "presets": "ptz.presets",
    "platform": "platform.ezviz",
}