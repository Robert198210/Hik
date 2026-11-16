"""Rule protocol and shared helpers."""

from __future__ import annotations

from typing import Literal, Protocol

from haca.analysis.context import RuleContext
from haca.analysis.models import Finding, Severity


class Rule(Protocol):
    id: str
    title: str
    category: str
    basis: Literal["technical", "requirement"]
    default_severity: Severity
    requires: tuple[str, ...]
    requires_orp: tuple[str, ...]

    def evaluate(self, ctx: RuleContext) -> list[Finding]: ...


_WEEKDAYS = (
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
)


def parse_targets(target: str | None) -> set[str]:
    if not target:
        return set()
    return {part.strip().lower() for part in target.split(",") if part.strip()}


def schedule_has_cmr_full_week(
    schedule: tuple[tuple[str, str, str, str, str, bool], ...],
) -> bool:
    covered: dict[str, tuple[str, str]] = {}
    for start_day, start_time, end_day, end_time, mode, record in schedule:
        if not record or mode.upper() != "CMR":
            continue
        if start_time.startswith("00:00") and end_time.startswith("23:59"):
            idx_start = _WEEKDAYS.index(start_day) if start_day in _WEEKDAYS else -1
            idx_end = _WEEKDAYS.index(end_day) if end_day in _WEEKDAYS else -1
            if idx_start >= 0 and idx_end >= idx_start:
                for idx in range(idx_start, idx_end + 1):
                    covered[_WEEKDAYS[idx]] = (mode, "full")
    return len(covered) >= 7


def parse_local_ts(text: str | None) -> float | None:
    if not text:
        return None
    try:
        from datetime import datetime

        cleaned = text.replace("Z", "+00:00")
        if cleaned.endswith("+01:00") or "+" in cleaned[-6:]:
            return datetime.fromisoformat(cleaned).timestamp()
        return datetime.fromisoformat(cleaned).timestamp()
    except ValueError:
        return None