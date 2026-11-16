"""Structured Gemini output models."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

AiClassification = Literal["POTENTIAL_CONFLICT", "OPTIMIZATION", "INFO"]
AiSeverity = Literal["high", "medium", "low", "info"]


class AiSuggestion(BaseModel):
    device_id: str
    setting_id: str
    current_value: str | None
    recommended_value: str | None
    classification: AiClassification
    severity: AiSeverity
    rationale: str
    depends_on: list[str] = Field(default_factory=list)


class AiAnalysis(BaseModel):
    summary: str
    suggestions: list[AiSuggestion] = Field(default_factory=list)
    cross_device_notes: list[str] = Field(default_factory=list)