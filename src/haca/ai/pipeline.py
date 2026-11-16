"""Orchestrate optional AI enrichment after deterministic audit."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy.orm import Session

from haca.ai.client import AiClient
from haca.ai.credentials import load_gemini_api_key
from haca.ai.payload import AiPayload, build_payload
from haca.ai.prompts import PROMPT_VERSION, build_prompt
from haca.ai.schema import AiAnalysis
from haca.ai.usage import (
    estimate_cost,
    load_cached_analysis,
    payload_cache_key,
    payload_sha256,
    record_call,
    store_cache,
    within_token_budget,
)
from haca.ai.validator import AiSuggestionValidator
from haca.analysis.models import Finding, sort_findings
from haca.catalog.coverage import CoverageEntry, CoverageSummary
from haca.catalog.models import CatalogEntry
from haca.collect.models import CollectionResult
from haca.config.models import AiConfig, AppConfig
from haca.devices.models import ResolvedDevice
from haca.reports.models import (
    AiCorroboration,
    AiRejected,
    ReportAiSection,
)
from haca.requirements.models import RequirementsProfile
from haca.security.redaction import redact_text

_LOGGER = logging.getLogger("haca.ai")


@dataclass(frozen=True, slots=True)
class AiEnrichmentResult:
    findings: tuple[Finding, ...]
    ai: ReportAiSection
    payload: AiPayload | None


def _skip_section(status: str, reason: str) -> ReportAiSection:
    return ReportAiSection(status=status, reason=reason)


def enrich_findings(
    *,
    findings: tuple[Finding, ...],
    collection: CollectionResult,
    devices: list[ResolvedDevice],
    orp: RequirementsProfile,
    catalog: tuple[CatalogEntry, ...],
    coverage: list[CoverageEntry],
    coverage_summary: CoverageSummary,
    app_config: AppConfig,
    ai_config: AiConfig | None,
    run_id: str,
    client: AiClient | None,
    session: Session | None,
    force_enable: bool,
) -> AiEnrichmentResult:
    if not force_enable:
        return AiEnrichmentResult(
            findings=findings,
            ai=_skip_section("skipped", "disabled"),
            payload=None,
        )
    if ai_config is None:
        return AiEnrichmentResult(
            findings=findings,
            ai=_skip_section("skipped", "missing_ai_config"),
            payload=None,
        )

    prompt = build_prompt()
    payload = build_payload(
        report=None,
        collection=collection,
        devices=devices,
        orp=orp,
        catalog=catalog,
        coverage=coverage,
        coverage_summary=coverage_summary,
        findings=findings,
        subnet=app_config.network.subnet,
        budget_chars=ai_config.budget_chars,
    )
    if client is None:
        if load_gemini_api_key() is None:
            return AiEnrichmentResult(
                findings=findings,
                ai=_skip_section("skipped", "missing_api_key"),
                payload=payload,
            )
        try:
            from haca.ai.client import GeminiClient

            key = load_gemini_api_key()
            if key is None:
                return AiEnrichmentResult(
                    findings=findings,
                    ai=_skip_section("skipped", "missing_api_key"),
                    payload=payload,
                )
            client = GeminiClient(
                key,
                ai_config.model,
                temperature=ai_config.temperature,
                max_output_tokens=ai_config.max_output_tokens,
            )
        except ImportError:
            return AiEnrichmentResult(
                findings=findings,
                ai=_skip_section("skipped", "sdk_not_installed"),
                payload=payload,
            )

    if not within_token_budget(client, prompt, payload.json_text, ai_config.max_input_tokens):
        return AiEnrichmentResult(
            findings=findings,
            ai=_skip_section("skipped", "budget_exceeded"),
            payload=payload,
        )

    cache_key = payload_cache_key(ai_config.model, payload.json_text)
    cached = False
    analysis: AiAnalysis | None = None
    call_result = None
    status = "ok"
    try:
        if session is not None:
            analysis = load_cached_analysis(session, cache_key)
            if analysis is not None:
                cached = True
        if analysis is None:
            call_result = client.generate(prompt, payload.json_text)
            analysis = call_result.parsed
            if analysis is None:
                status = "error"
                raw_head = redact_text((call_result.raw_text or "")[:300])
                detail = (
                    f"no parsed AiAnalysis; raw_chars={len(call_result.raw_text or '')}; "
                    f"raw_head={raw_head!r}"
                )
                _LOGGER.warning("AI response not parsed: %s", detail)
                return AiEnrichmentResult(
                    findings=findings,
                    ai=ReportAiSection(
                        status="error", reason="invalid_response", detail=detail
                    ),
                    payload=payload,
                )
            if session is not None:
                store_cache(session, cache_key, analysis)
                session.commit()
    except Exception as exc:  # noqa: BLE001
        detail = redact_text(f"{type(exc).__name__}: {str(exc)[:500]}")
        _LOGGER.warning("AI call failed: %s", detail)
        return AiEnrichmentResult(
            findings=findings,
            ai=ReportAiSection(status="error", reason="network_error", detail=detail),
            payload=payload,
        )
    finally:
        if session is not None and (call_result is not None or cached):
            cost = None
            if call_result is not None:
                cost = estimate_cost(
                    ai_config.model,
                    call_result.input_tokens,
                    call_result.output_tokens,
                    ai_config.pricing,
                )
            record_call(
                session,
                run_id=run_id,
                model=ai_config.model,
                prompt_version=PROMPT_VERSION,
                result=call_result,
                payload_hash=payload_sha256(payload.json_text),
                status=status,
                est_cost=cost,
                cached=cached,
            )
            session.commit()

    from haca.ai.observed import ObservedIndex

    observed = ObservedIndex(catalog, collection, coverage)
    device_roles: dict[str, str] = {d.id: str(d.role) for d in devices}
    validation = AiSuggestionValidator(
        catalog=catalog,
        observed=observed,
        orp=orp,
        run_id=run_id,
        simulated=collection.simulated,
        deterministic=findings,
        device_roles=device_roles,
    ).validate(analysis.suggestions)

    merged = list(findings)
    corroboration_rows: list[AiCorroboration] = []
    for finding in merged:
        note = validation.corroborations.get(finding.id)
        if note:
            corroboration_rows.append(AiCorroboration(finding_id=finding.id, note=note))
    merged.extend(validation.accepted)
    merged = sort_findings(merged)

    rejected_rows = tuple(
        AiRejected(
            device_id=item.suggestion.device_id,
            setting_id=item.suggestion.setting_id,
            reason=item.reason,
            rationale=item.suggestion.rationale,
        )
        for item in validation.rejected
    )

    ai_section = ReportAiSection(
        status="cached" if cached else "ok",
        reason=None,
        summary=analysis.summary,
        cross_device_notes=tuple(analysis.cross_device_notes),
        rejected=rejected_rows,
        corroborations=tuple(corroboration_rows),
        model=ai_config.model,
        prompt_version=PROMPT_VERSION,
        cached=cached,
        input_tokens=call_result.input_tokens if call_result else 0,
        output_tokens=call_result.output_tokens if call_result else 0,
        total_tokens=call_result.total_tokens if call_result else 0,
    )
    return AiEnrichmentResult(findings=tuple(merged), ai=ai_section, payload=payload)