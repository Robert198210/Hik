"""Typed ISAPI extractors (tolerant parsing)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from haca.isapi.xml import XmlDocument


class StreamView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str | None = None
    codec: str | None = None
    width: int | None = None
    height: int | None = None
    fps: float | None = None
    bitrate_mode: str | None = None
    bitrate_kbps: int | None = None
    vbr_cap_kbps: int | None = None
    smart_codec: bool | None = None


class TimeView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    time_mode: str | None = None
    local_time: str | None = None
    time_zone: str | None = None


class NtpView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    servers: tuple[str, ...] = ()


class NetworkView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    addressing_type: str | None = None
    ip: str | None = None
    gateway: str | None = None


class AdminAccessView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    protocols: dict[str, tuple[bool | None, int | None]] = Field(default_factory=dict)


class VcaRuleView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: str | None = None
    engine_enabled: bool | None = None
    items: tuple[dict[str, object], ...] = ()


class TriggerView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_type: str | None = None
    channel: int | None = None
    methods: frozenset[str] = frozenset()


class TrackView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    track_id: str | None = None
    channel: int | None = None
    enable: bool | None = None
    default_mode: str | None = None
    pre_s: int | None = None
    post_s: int | None = None
    schedule: tuple[tuple[str, str, str, str, str, bool], ...] = ()


class HddView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str | None = None
    status: str | None = None
    capacity_mb: int | None = None
    free_mb: int | None = None


class ProxyChannelView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str | None = None
    protocol: str | None = None
    ip: str | None = None
    port: int | None = None
    online: bool | None = None


class ParkActionView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool | None = None
    park_time_s: int | None = None
    action_type: str | None = None
    action_num: int | None = None


class PatrolView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    items: tuple[dict[str, object], ...] = ()


class PresetView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    items: tuple[dict[str, object], ...] = ()


class PlatformView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ezviz_enabled: bool | None = None


class DeviceViews(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    streams: tuple[StreamView, ...] | None = None
    time: TimeView | None = None
    ntp: NtpView | None = None
    network: NetworkView | None = None
    admin_access: AdminAccessView | None = None
    line_detection: VcaRuleView | None = None
    field_detection: VcaRuleView | None = None
    region_entrance: VcaRuleView | None = None
    triggers: tuple[TriggerView, ...] | None = None
    tracks: tuple[TrackView, ...] | None = None
    hdds: tuple[HddView, ...] | None = None
    proxy_channels: tuple[ProxyChannelView, ...] | None = None
    park_action: ParkActionView | None = None
    patrols: PatrolView | None = None
    presets: PresetView | None = None
    platform: PlatformView | None = None
    identity_model: str | None = None
    identity_firmware: str | None = None


def _as_bool(text: str | None) -> bool | None:
    if text is None:
        return None
    low = text.strip().lower()
    if low in ("true", "1", "yes"):
        return True
    if low in ("false", "0", "no"):
        return False
    return None


def _as_int(text: str | None) -> int | None:
    if text is None or not text.strip():
        return None
    try:
        return int(text.strip())
    except ValueError:
        return None


def extract_views(
    endpoint_id: str,
    doc: XmlDocument,
    missing: list[str],
) -> DeviceViews:
    """Return partial ``DeviceViews`` updates for one endpoint."""
    if endpoint_id == "system.device_info" or endpoint_id.startswith("system.device_info"):
        model = doc.text("model")
        fw = doc.text("firmwareVersion")
        if model is None:
            missing.append("model")
        if fw is None:
            missing.append("firmwareVersion")
        return DeviceViews(identity_model=model, identity_firmware=fw)

    if endpoint_id.startswith("system.time") and "ntp" not in endpoint_id:
        mode = doc.text("timeMode")
        if mode is None:
            missing.append("timeMode")
        return DeviceViews(
            time=TimeView(
                time_mode=mode,
                local_time=doc.text("localTime"),
                time_zone=doc.text("timeZone"),
            )
        )

    if endpoint_id.startswith("system.time.ntp"):
        host = doc.text("hostName") or doc.text("NTPServer/hostName")
        servers = (host,) if host else ()
        if not servers:
            missing.append("NTPServer.hostName")
        return DeviceViews(ntp=NtpView(servers=servers))

    if endpoint_id.startswith("system.network"):
        net = NetworkView(
            addressing_type=doc.text("addressingType"),
            ip=doc.text("ipAddress"),
            gateway=doc.text("DefaultGateway/ipAddress") or doc.text("ipAddress"),
        )
        if net.addressing_type is None:
            missing.append("IPAddress.addressingType")
        return DeviceViews(network=net)

    if endpoint_id.startswith("security.admin"):
        protocols: dict[str, tuple[bool | None, int | None]] = {}
        for elem in doc._root.iter():  # noqa: SLF001
            if elem.tag.split("}")[-1] != "AdminAccessProtocol":
                continue
            proto_name = None
            enabled = None
            port = None
            for child in elem:
                tag = child.tag.split("}")[-1]
                if tag == "protocol":
                    proto_name = (child.text or "").strip()
                elif tag == "enabled":
                    enabled = _as_bool(child.text)
                elif tag == "portNo":
                    port = _as_int(child.text)
            if proto_name:
                protocols[proto_name] = (enabled, port)
        if not protocols:
            missing.append("AdminAccessProtocol")
        return DeviceViews(admin_access=AdminAccessView(protocols=protocols))

    if "streaming" in endpoint_id:
        streams: list[StreamView] = []
        for ch in doc._root.iter():  # noqa: SLF001
            if ch.tag.split("}")[-1] != "StreamingChannel":
                continue
            ch_id = doc.text("id") if ch is doc._root else None
            codec = None
            width = height = None
            fps = None
            mode = None
            bitrate = vbr = None
            smart = None
            for child in ch.iter():
                tag = child.tag.split("}")[-1]
                if tag == "id" and child.text:
                    ch_id = child.text.strip()
                elif tag == "videoCodecType":
                    codec = (child.text or "").strip() or None
                elif tag == "videoResolutionWidth":
                    width = _as_int(child.text)
                elif tag == "videoResolutionHeight":
                    height = _as_int(child.text)
                elif tag == "maxFrameRate":
                    raw = _as_int(child.text)
                    fps = (raw / 100.0) if raw is not None else None
                elif tag == "videoQualityControlType":
                    mode = (child.text or "").strip() or None
                elif tag in ("constantBitRate", "bitrate"):
                    bitrate = _as_int(child.text)
                elif tag == "vbrUpperCap":
                    vbr = _as_int(child.text)
                elif tag == "enabled" and smart is None:
                    smart = _as_bool(child.text)
            streams.append(
                StreamView(
                    id=ch_id,
                    codec=codec,
                    width=width,
                    height=height,
                    fps=fps,
                    bitrate_mode=mode,
                    bitrate_kbps=bitrate,
                    vbr_cap_kbps=vbr,
                    smart_codec=smart,
                )
            )
        return DeviceViews(streams=tuple(streams) if streams else None)

    if endpoint_id.startswith("smart.line"):
        enabled = _as_bool(doc.text("enabled"))
        if enabled is None:
            missing.append("LineDetection.enabled")
        return DeviceViews(
            line_detection=VcaRuleView(kind="line", engine_enabled=enabled, items=())
        )

    if endpoint_id.startswith("smart.field"):
        enabled = _as_bool(doc.text("enabled"))
        if enabled is None:
            missing.append("FieldDetection.enabled")
        return DeviceViews(
            field_detection=VcaRuleView(kind="field", engine_enabled=enabled, items=())
        )

    if endpoint_id.startswith("smart.region"):
        enabled = _as_bool(doc.text("enabled"))
        if enabled is None:
            missing.append("RegionEntrance.enabled")
        return DeviceViews(
            region_entrance=VcaRuleView(kind="region_entrance", engine_enabled=enabled, items=())
        )

    if endpoint_id.startswith("event.trigger"):
        triggers: list[TriggerView] = []
        for elem in doc._root.iter():  # noqa: SLF001
            if elem.tag.split("}")[-1] != "EventTrigger":
                continue
            event_type = channel = None
            methods: set[str] = set()
            for child in elem.iter():
                tag = child.tag.split("}")[-1]
                if tag == "eventType":
                    event_type = (child.text or "").strip() or None
                elif tag == "channelID":
                    channel = _as_int(child.text)
                elif tag == "notificationMethod":
                    val = (child.text or "").strip()
                    if val:
                        methods.add(val)
            triggers.append(
                TriggerView(event_type=event_type, channel=channel, methods=frozenset(methods))
            )
        return DeviceViews(triggers=tuple(triggers) if triggers else ())

    if endpoint_id.startswith("record.track"):
        return DeviceViews(tracks=())

    if endpoint_id.startswith("storage.hdd"):
        hdds: list[HddView] = []
        for elem in doc._root.iter():  # noqa: SLF001
            if elem.tag.split("}")[-1] != "hdd":
                continue
            hid = status = cap = free = None
            for child in elem:
                tag = child.tag.split("}")[-1]
                if tag == "id":
                    hid = (child.text or "").strip()
                elif tag == "status":
                    status = (child.text or "").strip()
                elif tag == "capacity":
                    cap = _as_int(child.text)
                elif tag == "freeSpace":
                    free = _as_int(child.text)
            hdds.append(HddView(id=hid, status=status, capacity_mb=cap, free_mb=free))
        return DeviceViews(hdds=tuple(hdds) if hdds else ())

    if endpoint_id.startswith("input_proxy.channels"):
        channels: list[ProxyChannelView] = []
        for elem in doc._root.iter():  # noqa: SLF001
            if elem.tag.split("}")[-1] != "InputProxyChannel":
                continue
            cid = proto = ip = None
            port = None
            for child in elem:
                tag = child.tag.split("}")[-1]
                if tag == "id":
                    cid = (child.text or "").strip()
                elif tag == "proxyProtocol":
                    proto = (child.text or "").strip()
                elif tag == "ipAddress":
                    ip = (child.text or "").strip()
                elif tag == "portNo":
                    port = _as_int(child.text)
            channels.append(
                ProxyChannelView(id=cid, protocol=proto, ip=ip, port=port, online=None)
            )
        return DeviceViews(proxy_channels=tuple(channels) if channels else ())

    if endpoint_id.startswith("input_proxy.channels_status"):
        return DeviceViews()

    if endpoint_id.startswith("ptz.park"):
        view = ParkActionView(
            enabled=_as_bool(doc.text("enabled")),
            park_time_s=_as_int(doc.text("parkTime")),
            action_type=doc.text("Action/ActionType") or doc.text("ActionType"),
            action_num=_as_int(doc.text("Action/ActionNum")),
        )
        return DeviceViews(park_action=view)

    if endpoint_id.startswith("ptz.patrol"):
        return DeviceViews(patrols=PatrolView(items=()))

    if endpoint_id.startswith("ptz.preset"):
        return DeviceViews(presets=PresetView(items=()))

    if endpoint_id.startswith("platform.ezviz"):
        enabled = _as_bool(doc.text("enabled"))
        if enabled is None:
            missing.append("EZVIZ.enabled")
        return DeviceViews(platform=PlatformView(ezviz_enabled=enabled))

    return DeviceViews()


def merge_views(base: DeviceViews, patch: DeviceViews) -> DeviceViews:
    data = base.model_dump()
    for key, value in patch.model_dump().items():
        if value is None:
            continue
        if isinstance(value, (list, tuple)) and len(value) == 0:
            continue
        if isinstance(value, dict) and not value:
            continue
        data[key] = value
    return DeviceViews.model_validate(data)