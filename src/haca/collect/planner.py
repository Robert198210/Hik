"""Collection request planning from the ISAPI registry."""

from __future__ import annotations

from haca.collect.models import PlannedRequest
from haca.devices.models import ResolvedDevice
from haca.isapi.registry.loader import RegistryEntry

_ORDER_ANCHOR = ("system.device_info", "smart.capabilities")


def _params_for(entry: RegistryEntry) -> dict[str, int]:
    params: dict[str, int] = {}
    templates = (entry.path, *entry.variants)
    for template in templates:
        if "{channel}" in template:
            params["channel"] = 1
        if "{id}" in template:
            params["id"] = 101
        if "{track}" in template:
            params["track"] = 1
    return params


def _sort_key(index: int, entry: RegistryEntry) -> tuple[int, int]:
    try:
        anchor = _ORDER_ANCHOR.index(entry.id)
    except ValueError:
        anchor = len(_ORDER_ANCHOR)
    return (anchor, index)


def plan(device: ResolvedDevice, registry: tuple[RegistryEntry, ...]) -> list[PlannedRequest]:
    """Return ordered endpoint reads for one device."""
    applicable = [
        (index, entry)
        for index, entry in enumerate(registry)
        if device.role in entry.device_roles and entry.sensitivity != "denied"
    ]
    applicable.sort(key=lambda row: _sort_key(row[0], row[1]))
    ordered = [entry for _index, entry in applicable]
    return [
        PlannedRequest(endpoint_id=entry.id, params=_params_for(entry)) for entry in ordered
    ]