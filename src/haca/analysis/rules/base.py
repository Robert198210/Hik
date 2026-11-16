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


_MINUTES_PER_DAY = 24 * 60
_MINUTES_PER_WEEK = 7 * _MINUTES_PER_DAY


def _clock_minutes(day: str, clock: str) -> int | None:
    """Minutes from Monday 00:00. ``24:00`` on a day is the next midnight."""
    if day not in _WEEKDAYS:
        return None
    parts = clock.split(":")
    if len(parts) < 2:
        return None
    try:
        hour = int(parts[0])
        minute = int(parts[1])
    except ValueError:
        return None
    if hour == 24 and minute == 0:
        return _WEEKDAYS.index(day) * _MINUTES_PER_DAY + _MINUTES_PER_DAY
    if hour > 23 or minute > 59:
        return None
    return _WEEKDAYS.index(day) * _MINUTES_PER_DAY + hour * 60 + minute


def schedule_has_cmr_full_week(
    schedule: tuple[tuple[str, str, str, str, str, bool], ...],
) -> bool:
    """True when CMR recording covers every weekday from midnight to the next midnight.

    Hikvision writes a full day as Monday 00:00 through Tuesday 00:00, or as
    Monday 00:00 through Monday 23:59. A block that ends at the next midnight
    does not include that next day.
    """
    covered: set[str] = set()
    for start_day, start_time, end_day, end_time, mode, record in schedule:
        if not record or mode.upper() != "CMR":
            continue
        start = _clock_minutes(start_day, start_time)
        end = _clock_minutes(end_day, end_time)
        if start is None or end is None:
            continue
        if end <= start:
            end += _MINUTES_PER_WEEK
        for index, day in enumerate(_WEEKDAYS):
            for shift in (0, _MINUTES_PER_WEEK):
                day_start = index * _MINUTES_PER_DAY + shift
                if start <= day_start and end >= day_start + _MINUTES_PER_DAY - 1:
                    covered.add(day)
                    break
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