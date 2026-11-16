from __future__ import annotations

from haca.analysis.rules.base import schedule_has_cmr_full_week

_DAYS = (
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
)


def _next(day: str) -> str:
    return _DAYS[(_DAYS.index(day) + 1) % 7]


def test_midnight_to_next_midnight_cmr_covers_the_week() -> None:
    schedule = tuple(
        (day, "00:00:00", _next(day), "00:00:00", "CMR", True) for day in _DAYS
    )
    assert schedule_has_cmr_full_week(schedule)


def test_same_day_until_2359_still_covers_the_week() -> None:
    schedule = (
        ("Monday", "00:00:00", "Friday", "23:59:59", "CMR", True),
        ("Saturday", "00:00:00", "Sunday", "23:59:59", "CMR", True),
    )
    assert schedule_has_cmr_full_week(schedule)


def test_weekend_motion_is_not_a_full_cmr_week() -> None:
    schedule = (
        ("Monday", "00:00:00", "Friday", "23:59:59", "CMR", True),
        ("Saturday", "00:00:00", "Sunday", "23:59:59", "MOTION", True),
    )
    assert not schedule_has_cmr_full_week(schedule)


def test_one_midnight_block_does_not_cover_the_next_day() -> None:
    schedule = (("Sunday", "00:00:00", "Monday", "00:00:00", "CMR", True),)
    assert not schedule_has_cmr_full_week(schedule)
