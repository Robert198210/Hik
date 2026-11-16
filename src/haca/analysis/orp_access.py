"""Read explicit values from the Operational Requirements Profile."""

from __future__ import annotations

from enum import Enum
from typing import Any

from haca.requirements.models import RequirementsProfile


class OrpAccess:
    def __init__(self, profile: RequirementsProfile) -> None:
        self._profile = profile

    def value(self, path: str) -> Any | None:
        explicit = self._raw_value(path)
        if explicit is None:
            return None
        if isinstance(explicit, Enum):
            if explicit.value in ("unspecified", "undecided"):
                return None
            return explicit.value
        return explicit

    def is_explicit(self, path: str) -> bool:
        return self.value(path) is not None

    def enum_value(self, path: str) -> str | None:
        val = self.value(path)
        return str(val) if val is not None else None

    def _raw_value(self, path: str) -> Any | None:
        parts = path.split(".")
        if not parts:
            return None
        if parts[0] == "system":
            if len(parts) != 2:
                return None
            return getattr(self._profile.system, parts[1], None)
        if parts[0] == "devices" and len(parts) == 3:
            dev = self._profile.devices.get(parts[1])
            if dev is None:
                return None
            return getattr(dev, parts[2], None)
        return None

    def raw_enum(self, path: str) -> Enum | None:
        val = self._raw_value(path)
        return val if isinstance(val, Enum) else None