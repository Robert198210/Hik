from __future__ import annotations

import pytest
import yaml

from haca.catalog.loader import CatalogValidationError, load_catalog_entries


def test_catalog_loads_minimum_entries() -> None:
    entries = load_catalog_entries()
    assert len(entries) >= 35


def test_unknown_endpoint_reference_fails() -> None:
    entries = load_catalog_entries()
    row = entries[0].model_dump()
    row["sources"] = [
        {"kind": "isapi", "endpoint_id": "missing.endpoint", "view_path": "identity_model"}
    ]
    blob = yaml.safe_dump([row]).encode()
    with pytest.raises(CatalogValidationError, match="unknown endpoint"):
        load_catalog_entries(yaml_bytes=blob)


def test_invalid_view_path_rejected() -> None:
    row = {
        "id": "bad.view",
        "category": "identity",
        "title": "bad",
        "device_roles": ["nvr"],
        "scope": "device",
        "sources": [
            {"kind": "isapi", "endpoint_id": "system.device_info", "view_path": "nope.path"},
        ],
    }
    blob = yaml.safe_dump([row]).encode()
    with pytest.raises(CatalogValidationError, match="invalid view_path"):
        load_catalog_entries(
            yaml_bytes=blob,
            registry_endpoint_ids=frozenset({"system.device_info"}),
        )


def test_manual_source_requires_checklist_id() -> None:
    row = {
        "id": "manual.bad",
        "category": "analytics",
        "title": "bad",
        "device_roles": ["nvr"],
        "scope": "device",
        "sources": [{"kind": "manual", "checklist_id": ""}],
    }
    blob = yaml.safe_dump([row]).encode()
    with pytest.raises(CatalogValidationError):
        load_catalog_entries(yaml_bytes=blob, registry_endpoint_ids=frozenset())