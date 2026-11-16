"""Map NVR proxy channels to configured camera devices."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from haca.collect.models import CollectionResult, DeviceCollection
from haca.devices.models import ResolvedDevice


class CorrelationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    channel_of: dict[str, int]
    device_by_channel: dict[int, str]
    unknown_channels: tuple[tuple[int, str], ...]
    unattached_devices: tuple[str, ...]


def correlate(
    result: CollectionResult,
    devices: tuple[ResolvedDevice, ...] | list[ResolvedDevice],
) -> CorrelationResult:
    by_ip: dict[str, ResolvedDevice] = {str(d.host): d for d in devices}
    camera_ips = {str(d.host): d.id for d in devices if d.role == "camera"}

    nvr = next((d for d in result.devices if d.device_id.endswith("nvr01") or _is_nvr(d)), None)
    if nvr is None:
        nvr = next((d for d in result.devices if _role(d) == "nvr"), None)

    channel_of: dict[str, int] = {}
    device_by_channel: dict[int, str] = {}
    unknown: list[tuple[int, str]] = []
    attached_cameras: set[str] = set()

    if nvr is not None and nvr.views.proxy_channels:
        for proxy in nvr.views.proxy_channels:
            if proxy.id is None or proxy.ip is None:
                continue
            try:
                ch_id = int(proxy.id)
            except ValueError:
                continue
            dev = by_ip.get(proxy.ip)
            if dev is not None:
                channel_of[dev.id] = ch_id
                device_by_channel[ch_id] = dev.id
                if dev.role == "camera":
                    attached_cameras.add(dev.id)
            else:
                unknown.append((ch_id, proxy.ip))

    unattached = tuple(
        sorted(
            dev_id
            for ip, dev_id in camera_ips.items()
            if dev_id not in attached_cameras
        )
    )

    return CorrelationResult(
        channel_of=channel_of,
        device_by_channel=device_by_channel,
        unknown_channels=tuple(sorted(unknown, key=lambda x: x[0])),
        unattached_devices=unattached,
    )


def _role(collection: DeviceCollection) -> str:
    return collection.role


def _is_nvr(collection: DeviceCollection) -> bool:
    return collection.role == "nvr"