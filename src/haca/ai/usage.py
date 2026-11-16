"""Token budget, cache, and usage accounting."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from haca.ai.client import AiCallResult, AiClient
from haca.ai.prompts import PROMPT_VERSION
from haca.ai.schema import AiAnalysis
from haca.config.models import ModelPricing
from haca.store.models import AiCacheRow, AiCallRow

AiRunStatus = Literal["ok", "cached", "skipped", "error"]


def payload_cache_key(model: str, payload_json: str) -> str:
    material = f"{model}\n{PROMPT_VERSION}\n{payload_json}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def payload_sha256(payload_json: str) -> str:
    return hashlib.sha256(payload_json.encode("utf-8")).hexdigest()


def estimate_cost(
    model: str,
    input_tokens: int,
    output_tokens: int,
    pricing: dict[str, ModelPricing],
) -> float | None:
    row = pricing.get(model)
    if row is None:
        return None
    return (input_tokens / 1_000_000.0) * row.input_per_mtok + (
        output_tokens / 1_000_000.0
    ) * row.output_per_mtok


def load_cached_analysis(session: Session, key: str) -> AiAnalysis | None:
    row = session.scalars(select(AiCacheRow).where(AiCacheRow.cache_key == key)).first()
    if row is None:
        return None
    data = json.loads(row.response_json)
    return AiAnalysis.model_validate(data)


def store_cache(session: Session, key: str, analysis: AiAnalysis) -> None:
    session.add(
        AiCacheRow(
            cache_key=key,
            response_json=analysis.model_dump_json(),
            created_at=datetime.now(UTC),
        )
    )


def record_call(
    session: Session,
    *,
    run_id: str,
    model: str,
    prompt_version: str,
    result: AiCallResult | None,
    payload_hash: str,
    status: str,
    est_cost: float | None,
    cached: bool,
) -> None:
    session.add(
        AiCallRow(
            run_id=run_id,
            model=model,
            prompt_version=prompt_version,
            input_tokens=result.input_tokens if result else 0,
            output_tokens=result.output_tokens if result else 0,
            total_tokens=result.total_tokens if result else 0,
            est_cost=est_cost,
            latency_ms=result.latency_ms if result else 0,
            payload_sha256=payload_hash,
            status="cached" if cached else status,
        )
    )


def within_token_budget(client: AiClient, prompt: str, payload_json: str, limit: int) -> bool:
    combined = f"{prompt}\n{payload_json}"
    return client.count_tokens(combined) <= limit