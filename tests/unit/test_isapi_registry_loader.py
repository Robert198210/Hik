from __future__ import annotations

import pytest

from haca.isapi.registry.loader import (
    RegistryValidationError,
    build_policy,
    load_registry_entries,
)
from haca.security.errors import PolicyViolation


def test_registry_loads_expected_entry_count() -> None:
    entries = load_registry_entries()
    assert len(entries) == 23
    assert sum(1 for e in entries if e.sensitivity == "denied") == 2


def test_denied_entry_rejected_by_authorize() -> None:
    policy = build_policy()
    with pytest.raises(PolicyViolation):
        policy.authorize("GET", "/ISAPI/System/configurationData", "", None)


def test_deliberate_denylisted_path_fails_lint() -> None:
    import yaml

    good = load_registry_entries()
    rows = [
        {
            "id": "evil.format",
            "path": "/ISAPI/ContentMgmt/Storage/hdd/1/format",
            "method": "GET",
            "device_roles": ["nvr"],
            "verification": "candidate_unverified",
            "source": "test fixture",
        },
        good[0].model_dump(mode="json"),
    ]
    bad_yaml = yaml.safe_dump(rows).encode()
    with pytest.raises(RegistryValidationError, match="denylist"):
        load_registry_entries(yaml_bytes=bad_yaml)


def test_duplicate_id_fails_lint() -> None:
    base = load_registry_entries()
    rows = [base[0].model_dump(), base[0].model_dump()]
    import yaml

    blob = yaml.safe_dump(rows).encode()
    with pytest.raises(RegistryValidationError, match="duplicate"):
        load_registry_entries(yaml_bytes=blob)