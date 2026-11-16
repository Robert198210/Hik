"""Index of catalog setting values observed during collection."""

from __future__ import annotations

from dataclasses import dataclass

from haca.catalog.coverage import CoverageEntry
from haca.catalog.models import CatalogEntry, IsapiSource
from haca.catalog.view_path import resolve_view_path
from haca.collect.models import CollectionResult


def _stringify(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ",".join(_stringify(v) for v in value)
    return str(value)


@dataclass(frozen=True, slots=True)
class ObservedSetting:
    device_id: str
    setting_id: str
    value: str
    status: str
    endpoint_id: str | None
    view_path: str | None
    raw_sha256: str | None


class ObservedIndex:
    def __init__(
        self,
        catalog: tuple[CatalogEntry, ...],
        collection: CollectionResult,
        coverage: list[CoverageEntry],
    ) -> None:
        self._by_device: dict[str, dict[str, ObservedSetting]] = {}
        status_map = {(c.device_id, c.setting_id): c.status for c in coverage}
        catalog_by_id = {e.id: e for e in catalog}
        for device in collection.devices:
            bucket: dict[str, ObservedSetting] = {}
            for (device_id, sid), status in status_map.items():
                if device_id != device.device_id:
                    continue
                if status not in ("VERIFIED_ISAPI", "VERIFIED_MANUAL"):
                    continue
                entry = catalog_by_id.get(sid)
                if entry is None:
                    continue
                isapi = next((s for s in entry.sources if isinstance(s, IsapiSource)), None)
                if isapi is None:
                    continue
                present, value = resolve_view_path(device.views, isapi.view_path)
                if not present and status != "VERIFIED_MANUAL":
                    continue
                obs_value = _stringify(value)
                ev = device.evidence.get(isapi.endpoint_id)
                bucket[sid] = ObservedSetting(
                    device_id=device_id,
                    setting_id=sid,
                    value=obs_value,
                    status=status,
                    endpoint_id=isapi.endpoint_id,
                    view_path=isapi.view_path,
                    raw_sha256=ev.sha256 if ev else None,
                )
            self._by_device[device.device_id] = bucket

    def get(self, device_id: str, setting_id: str) -> ObservedSetting | None:
        return self._by_device.get(device_id, {}).get(setting_id)

    def device_ids(self) -> frozenset[str]:
        return frozenset(self._by_device.keys())

    def all_verified_isapi(self, device_id: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for sid, row in self._by_device.get(device_id, {}).items():
            if row.status == "VERIFIED_ISAPI":
                out[sid] = row.value
        return out