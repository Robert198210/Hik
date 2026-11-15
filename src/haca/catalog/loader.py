"""Load and validate the Setting Catalog from packaged YAML."""

from __future__ import annotations

from importlib import resources
from typing import Any

import yaml
from pydantic import TypeAdapter, ValidationError

from haca.catalog.models import CatalogEntry
from haca.isapi.registry.loader import load_registry_entries

_CATALOG_PACKAGE = "haca.catalog"
_CATALOG_FILE = "settings.yaml"

_CATALOG_ADAPTER: TypeAdapter[CatalogEntry] = TypeAdapter(CatalogEntry)


class CatalogValidationError(ValueError):
    """Raised when catalog YAML fails lint rules."""


def catalog_yaml_bytes() -> bytes:
    ref = resources.files(_CATALOG_PACKAGE) / _CATALOG_FILE
    return ref.read_bytes()


def _parse_raw_entries(raw: Any) -> list[CatalogEntry]:
    if not isinstance(raw, list):
        msg = "settings.yaml root must be a sequence"
        raise CatalogValidationError(msg)

    entries: list[CatalogEntry] = []
    errors: list[str] = []
    for index, item in enumerate(raw):
        try:
            entries.append(_CATALOG_ADAPTER.validate_python(item))
        except ValidationError as exc:
            errors.append(f"item {index}: {exc}")
    if errors:
        raise CatalogValidationError("; ".join(errors))
    return entries


def load_catalog_entries(
    *,
    yaml_bytes: bytes | None = None,
    registry_endpoint_ids: frozenset[str] | None = None,
) -> tuple[CatalogEntry, ...]:
    data = yaml_bytes if yaml_bytes is not None else catalog_yaml_bytes()
    raw = yaml.safe_load(data)
    entries = _parse_raw_entries(raw)

    seen: set[str] = set()
    for entry in entries:
        if entry.id in seen:
            msg = f"duplicate catalog id {entry.id!r}"
            raise CatalogValidationError(msg)
        seen.add(entry.id)

    endpoint_ids = registry_endpoint_ids
    if endpoint_ids is None:
        endpoint_ids = frozenset(e.id for e in load_registry_entries())

    for entry in entries:
        for source in entry.sources:
            if source.kind == "isapi" and source.endpoint_id not in endpoint_ids:
                msg = (
                    f"{entry.id}: isapi source references unknown endpoint "
                    f"{source.endpoint_id!r}"
                )
                raise CatalogValidationError(msg)
            if source.kind == "manual" and not source.checklist_id.strip():
                msg = f"{entry.id}: manual source requires checklist_id"
                raise CatalogValidationError(msg)

    return tuple(entries)