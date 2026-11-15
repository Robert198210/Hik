"""Load and hash Operational Requirements Profile files."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import ValidationError

from haca.config.errors import ConfigError
from haca.config.loader import _load_yaml, _raise_pydantic, _reject_secret_keys
from haca.requirements.models import RequirementsProfile


def load_requirements(path: Path, device_ids: set[str]) -> RequirementsProfile:
    data = _load_yaml(path)
    _reject_secret_keys(path, data)
    try:
        profile = RequirementsProfile.model_validate(data)
    except ValidationError as exc:
        _raise_pydantic(path, "requirements", exc)

    unknown = set(profile.devices.keys()) - device_ids
    if unknown:
        names = ", ".join(sorted(unknown))
        raise ConfigError(
            path,
            "devices",
            f"unknown device id(s) in requirements profile: {names}",
        )
    return profile


def requirements_hash(profile: RequirementsProfile) -> str:
    payload = profile.model_dump(mode="json")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()