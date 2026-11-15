"""Path denylist patterns (method-independent, case-insensitive)."""

from __future__ import annotations

import re

_DENY_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"reboot", re.IGNORECASE),
    re.compile(r"factoryReset", re.IGNORECASE),
    re.compile(r"factoryDefault", re.IGNORECASE),
    re.compile(r"upgrade", re.IGNORECASE),
    re.compile(r"updateFirmware", re.IGNORECASE),
    re.compile(r"firmware", re.IGNORECASE),
    re.compile(r"configurationData", re.IGNORECASE),
    re.compile(
        r"PTZCtrl/.*/(?:continuous|momentary|absolute|relative|"
        r"presets/.+/goto|homeposition|patrols/.+/start|auxcontrols)",
        re.IGNORECASE,
    ),
    re.compile(r"Storage/hdd/.*/format", re.IGNORECASE),
    re.compile(r"format", re.IGNORECASE),
    re.compile(r"Security/users", re.IGNORECASE),
    re.compile(r"activate", re.IGNORECASE),
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"/SDK/", re.IGNORECASE),
    re.compile(r"/PSIA/", re.IGNORECASE),
    re.compile(r"/cgi-bin/", re.IGNORECASE),
)


def is_denied_path(decoded_path: str) -> bool:
    """Return True if *decoded_path* matches any denylist pattern."""
    return any(pattern.search(decoded_path) for pattern in _DENY_PATTERNS)