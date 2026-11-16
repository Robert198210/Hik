"""Mask identifiers in audit report output."""

from __future__ import annotations

import re
from typing import Any

_MAC_COLON = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
_MAC_DASH = re.compile(r"\b(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}\b")
# Synthetic serials only. A broader uppercase pattern also matched rule ids
# (R-STOR-001), ADR citations, model names, and IDENTIFIED.
_SERIAL_LIKE = re.compile(r"\bSYNTH-[A-Z0-9-]{4,}\b")
_RULE_ID = re.compile(r"^R-[A-Z0-9]+-\d{3}$")


def mask_serial(value: str) -> str:
    token = value.strip()
    if len(token) < 4:
        return "****"
    return f"****{token[-4:]}"


def mask_mac(value: str) -> str:
    parts = re.split(r"[:-]", value)
    if len(parts) == 6:
        return f"**:**:**:**:{parts[4]}:{parts[5]}"
    return "**:**:**:**:**:**"


def mask_identifier_field(setting_id: str | None, value: str | None) -> str | None:
    if value is None:
        return None
    low = (setting_id or "").lower()
    if "serial" in low:
        return mask_serial(value)
    if "mac" in low:
        return mask_mac(value)
    if "username" in low:
        return "***"
    return value


def mask_text(value: str) -> str:
    if _RULE_ID.match(value.strip()):
        return value
    def _mac(match: re.Match[str]) -> str:
        return mask_mac(match.group(0))

    def _serial(match: re.Match[str]) -> str:
        return mask_serial(match.group(0))

    text = _MAC_COLON.sub(_mac, value)
    text = _MAC_DASH.sub(_mac, text)
    return _SERIAL_LIKE.sub(_serial, text)


def mask_structure(obj: Any, *, setting_hint: str | None = None) -> Any:
    if isinstance(obj, dict):
        masked: dict[str, Any] = {}
        for key, val in obj.items():
            hint = key if isinstance(val, str) else setting_hint
            masked[key] = mask_structure(val, setting_hint=hint)
        return masked
    if isinstance(obj, list):
        return [mask_structure(item) for item in obj]
    if isinstance(obj, str):
        key_low = (setting_hint or "").lower()
        if "username" in key_low:
            return "***"
        if "serial" in key_low:
            return mask_serial(obj)
        if "mac" in key_low:
            return mask_mac(obj)
        if key_low in ("current_value", "observed_value") and _MAC_COLON.search(obj):
            return mask_text(obj)
        return mask_text(obj)
    return obj
