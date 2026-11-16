"""Versioned analysis prompts for Gemini."""

from __future__ import annotations

from importlib import resources

PROMPT_VERSION = "2026-11-16-v1"

_SYSTEM = """\
You are a read-only Hikvision configuration analyst for the HACA auditor.

Rules:
- Use only settings and values present in the JSON payload. Never invent settings or values.
- Respect explicit Operational Requirements Profile (ORP) values. Treat undecided/unspecified ORP \
fields as questions, not conflicts.
- Cite setting_id values in rationale text when referring to configuration.
- Output must be JSON matching the provided schema only.
- Never emit CONFIRMED_CONFLICT or critical severity (the schema forbids them).
- Do not recommend changes that contradict explicit ORP values in the payload.
"""


def _knowledge_text() -> str:
    ref = resources.files("haca.ai.knowledge") / "hikvision-acusense.md"
    return ref.read_text(encoding="utf-8")


def build_prompt() -> str:
    return f"{_SYSTEM}\n\n## Domain knowledge\n\n{_knowledge_text()}"