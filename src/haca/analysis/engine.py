"""Rule engine — evaluate all registered rules with simulation safeguards."""

from __future__ import annotations

import logging
from typing import cast

from haca.analysis.context import _VIEW_ENDPOINTS, RuleContext
from haca.analysis.correlator import CorrelationResult, correlate
from haca.analysis.models import Classification, Finding, Severity, sort_findings
from haca.analysis.rules.builtins import all_builtin_rules
from haca.catalog.coverage import CoverageEntry
from haca.collect.models import CollectionResult
from haca.devices.models import ResolvedDevice
from haca.requirements.models import RequirementsProfile

_LOGGER = logging.getLogger("haca.analysis")


class RuleEngine:
    def __init__(self, rules: list[object] | None = None) -> None:
        self._rules = rules or all_builtin_rules()

    def run(
        self,
        result: CollectionResult,
        devices: list[ResolvedDevice],
        orp: RequirementsProfile,
        coverage: list[CoverageEntry],
        *,
        run_id: str,
    ) -> tuple[list[Finding], CorrelationResult]:
        correlation = correlate(result, devices)
        ctx = RuleContext(
            result=result,
            correlation=correlation,
            orp=orp,
            coverage=coverage,
            run_id=run_id,
        )
        findings: list[Finding] = []
        for rule in self._rules:
            findings.extend(_evaluate_rule(rule, ctx))
        finalized = [_finalize_requirement_empty(f, orp) for f in findings]
        return sort_findings(finalized), correlation


def _evaluate_rule(rule: object, ctx: RuleContext) -> list[Finding]:  # noqa: C901
    rule_id = getattr(rule, "id", "unknown")
    requires: tuple[str, ...] = getattr(rule, "requires", ())
    missing_views = _missing_required_views(ctx, requires)
    if missing_views:
        device_id = ctx.result.devices[0].device_id if ctx.result.devices else "unknown"
        return [
            ctx.build_finding(
                rule_id=rule_id,
                title=getattr(rule, "title", rule_id),
                category=getattr(rule, "category", "data"),
                basis=getattr(rule, "basis", "technical"),
                default_severity=cast(
                    Severity, getattr(rule, "default_severity", Severity.info)
                ),
                devices=(device_id,),
                classification=Classification.INSUFFICIENT_DATA,
                subject="missing-views",
                rationale=f"Missing data for rule: {', '.join(missing_views)}",
                evidence=[
                    ctx.evidence(
                        device_id,
                        _VIEW_ENDPOINTS.get(missing_views[0], "unknown"),
                        "view",
                        "missing",
                    )
                ],
            )
        ]
    try:
        raw = rule.evaluate(ctx)  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001
        _LOGGER.exception("Rule %s failed", rule_id)
        device_id = ctx.result.devices[0].device_id if ctx.result.devices else "unknown"
        return [
            ctx.build_finding(
                rule_id=rule_id,
                title=getattr(rule, "title", rule_id),
                category=getattr(rule, "category", "data"),
                basis=getattr(rule, "basis", "technical"),
                default_severity=cast(
                    Severity, getattr(rule, "default_severity", Severity.info)
                ),
                devices=(device_id,),
                classification=Classification.INSUFFICIENT_DATA,
                subject="rule-error",
                rationale=f"Rule evaluation error: {exc}",
                evidence=[ctx.evidence(device_id, "system.device_info", "rule", rule_id)],
                rule_error=True,
            )
        ]
    return list(raw)


def _missing_required_views(ctx: RuleContext, requires: tuple[str, ...]) -> list[str]:
    missing: list[str] = []
    for view_field in requires:
        if not any(ctx.view_accessible(d.device_id, view_field) for d in ctx.result.devices):
            missing.append(view_field)
    return missing


def _finalize_requirement_empty(finding: Finding, orp: RequirementsProfile) -> Finding:
    if (
        finding.basis == "requirement"
        and finding.simulated_confirmed
        and _orp_effectively_empty(orp)
    ):
        return finding.model_copy(update={"simulated_confirmed": False})
    return finding


def _orp_effectively_empty(orp: RequirementsProfile) -> bool:
    if orp.devices:
        return False
    from haca.requirements.models import SystemRequirements

    defaults = SystemRequirements()
    return orp.system.model_dump() == defaults.model_dump()