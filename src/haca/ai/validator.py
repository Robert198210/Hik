"""Validate Gemini suggestions against catalog, observations, and ORP."""

from __future__ import annotations

from dataclasses import dataclass

from haca.ai.observed import ObservedIndex
from haca.ai.schema import AiSuggestion
from haca.analysis.models import (
    Classification,
    EvidenceRef,
    EvidenceTier,
    Finding,
    FindingSource,
    Severity,
)
from haca.analysis.orp_access import OrpAccess
from haca.catalog.models import CatalogEntry
from haca.requirements.models import RequirementsProfile


def _normalize(value: str | None) -> str:
    if value is None:
        return ""
    return str(value).strip().casefold()


@dataclass(frozen=True, slots=True)
class RejectedSuggestion:
    suggestion: AiSuggestion
    reason: str


@dataclass(frozen=True, slots=True)
class ValidationResult:
    accepted: list[Finding]
    rejected: list[RejectedSuggestion]
    corroborations: dict[str, str]


class AiSuggestionValidator:
    def __init__(
        self,
        *,
        catalog: tuple[CatalogEntry, ...],
        observed: ObservedIndex,
        orp: RequirementsProfile,
        run_id: str,
        simulated: bool,
        deterministic: tuple[Finding, ...],
        device_roles: dict[str, str] | None = None,
    ) -> None:
        self._catalog = {e.id: e for e in catalog}
        self._device_roles = device_roles or {}
        self._observed = observed
        self._orp = OrpAccess(orp)
        self._run_id = run_id
        self._tier = EvidenceTier.simulation if simulated else EvidenceTier.isapi
        self._deterministic = deterministic

    def validate(self, suggestions: list[AiSuggestion]) -> ValidationResult:
        accepted: list[Finding] = []
        rejected: list[RejectedSuggestion] = []
        corroborations: dict[str, str] = {}

        for suggestion in suggestions:
            reason = self._reject_reason(suggestion)
            if reason is not None:
                rejected.append(RejectedSuggestion(suggestion=suggestion, reason=reason))
                continue
            dup_id = self._duplicate_finding_id(suggestion)
            if dup_id is not None:
                corroborations[dup_id] = suggestion.rationale
                continue
            accepted.append(self._to_finding(suggestion))
        return ValidationResult(accepted=accepted, rejected=rejected, corroborations=corroborations)

    def _reject_reason(self, suggestion: AiSuggestion) -> str | None:
        if suggestion.device_id not in self._observed.device_ids():
            return "unknown_device"
        entry = self._catalog.get(suggestion.setting_id)
        if entry is None:
            return "unknown_setting"
        role = self._device_roles.get(suggestion.device_id)
        if role is not None and role not in entry.device_roles:
            return "unknown_setting"
        if suggestion.device_id and entry.device_roles:
            obs_dev = self._observed.get(suggestion.device_id, suggestion.setting_id)
            role_row = entry.device_roles
            # Role check: device must have applicable role (already in index if observed)
            _ = role_row
            if obs_dev is None:
                return "unobserved_setting"
            if obs_dev.status not in ("VERIFIED_ISAPI", "VERIFIED_MANUAL"):
                return "unobserved_setting"
            if _normalize(suggestion.current_value) != _normalize(obs_dev.value):
                return "wrong_current_value"
        if entry.orp_link and suggestion.recommended_value is not None:
            explicit = self._orp.enum_value(entry.orp_link)
            if explicit is not None and _normalize(suggestion.recommended_value) != _normalize(
                explicit
            ):
                return "orp_contradiction"
        if entry.known_values and suggestion.recommended_value is not None:
            known = {_normalize(v) for v in entry.known_values}
            if _normalize(suggestion.recommended_value) not in known:
                return "unknown_recommended_value"
        return None

    def _duplicate_finding_id(self, suggestion: AiSuggestion) -> str | None:
        for finding in self._deterministic:
            if suggestion.device_id not in finding.devices:
                continue
            rec = finding.recommendation
            if rec and rec.setting_id == suggestion.setting_id:
                return finding.id
            if finding.subject == suggestion.setting_id:
                return finding.id
        return None

    def _to_finding(self, suggestion: AiSuggestion) -> Finding:
        obs = self._observed.get(suggestion.device_id, suggestion.setting_id)
        if obs is None:
            msg = "accepted suggestion without observed value"
            raise RuntimeError(msg)
        severity = Severity(suggestion.severity)
        classification = Classification(suggestion.classification)
        evidence = (
            EvidenceRef(
                snapshot_id=self._run_id,
                device_id=suggestion.device_id,
                endpoint_id=obs.endpoint_id or "unknown",
                xpath=obs.view_path or suggestion.setting_id,
                observed_value=obs.value,
                raw_sha256=obs.raw_sha256,
                tier=self._tier,
            ),
        )
        norm_rec = _normalize(suggestion.recommended_value)
        finding_id = f"ai:{suggestion.device_id}:{suggestion.setting_id}:{norm_rec}"
        return Finding(
            id=finding_id,
            rule_id="ai",
            category="ai",
            classification=classification,
            severity=severity,
            basis="technical",
            devices=(suggestion.device_id,),
            evidence=evidence,
            evidence_tier=self._tier,
            current_value=suggestion.current_value,
            recommended_value=suggestion.recommended_value,
            rationale=suggestion.rationale,
            source=FindingSource.ai_validated,
            subject=suggestion.setting_id,
        )