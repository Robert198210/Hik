"""Typed ISAPI extractors (tolerant parsing)."""

from __future__ import annotations

from xml.etree.ElementTree import Element

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
    resolution: str | None = None


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


class ProtocolAccessView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool | None = None
    port: int | None = None


class AdminAccessView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    protocols: dict[str, ProtocolAccessView] = Field(default_factory=dict)


class VcaItemView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str | None = None
    enabled: bool | None = None
    detection_target: str | None = None
    coordinate_count: int | None = None


class VcaRuleView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: str | None = None
    engine_enabled: bool | None = None
    items: tuple[VcaItemView, ...] = ()


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
    schedule_coverage: str | None = None
    pre_post_seconds: str | None = None


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


class LogEventView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    meta_id: str | None = None
    para_type: str | None = None
    started_at: str | None = None


class LogSearchView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    num_matches: int | None = None
    events: tuple[LogEventView, ...] = ()


class RecordSegmentView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    track_id: str | None = None
    start_time: str | None = None
    end_time: str | None = None
    record_type: str | None = None


class RecordSearchView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    num_matches: int | None = None
    segments: tuple[RecordSegmentView, ...] = ()


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
    log_search: LogSearchView | None = None
    record_search: RecordSearchView | None = None
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
        servers: list[str] = []
        for elem in doc._root.iter():  # noqa: SLF001
            if elem.tag.split("}")[-1] != "NTPServer":
                continue
            host = None
            for child in elem:
                if child.tag.split("}")[-1] == "hostName" and child.text:
                    host = child.text.strip()
            if host:
                servers.append(host)
        if not servers:
            missing.append("NTPServer.hostName")
        return DeviceViews(ntp=NtpView(servers=tuple(servers)))

    if endpoint_id.startswith("system.network"):
        addressing = ip = gateway = None
        for elem in doc._root.iter():  # noqa: SLF001
            local = elem.tag.split("}")[-1]
            if local == "addressingType" and elem.text:
                addressing = elem.text.strip()
            elif local == "ipAddress" and elem.text and ip is None:
                ip = elem.text.strip()
            elif local == "DefaultGateway":
                for child in elem:
                    if child.tag.split("}")[-1] == "ipAddress" and child.text:
                        gateway = child.text.strip()
        net = NetworkView(addressing_type=addressing, ip=ip, gateway=gateway)
        if net.addressing_type is None:
            missing.append("IPAddress.addressingType")
        return DeviceViews(network=net)

    if endpoint_id.startswith("security.admin"):
        protocols: dict[str, ProtocolAccessView] = {}
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
                protocols[proto_name] = ProtocolAccessView(enabled=enabled, port=port)
        if not protocols:
            missing.append("AdminAccessProtocol")
        return DeviceViews(admin_access=AdminAccessView(protocols=protocols))

    if "streaming" in endpoint_id:
        streams: list[StreamView] = []
        for ch in doc._root.iter():  # noqa: SLF001
            if ch.tag.split("}")[-1] != "StreamingChannel":
                continue
            ch_id = None
            video_elem = None
            for child in ch:
                tag = child.tag.split("}")[-1]
                if tag == "id" and child.text:
                    ch_id = child.text.strip()
                elif tag == "Video":
                    video_elem = child
            codec = None
            width = height = None
            fps = None
            mode = None
            bitrate = vbr = None
            smart = None
            if video_elem is not None:
                for child in video_elem.iter():
                    tag = child.tag.split("}")[-1]
                    if tag == "videoCodecType":
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
                    elif tag == "enabled" and child is not video_elem:
                        smart = _as_bool(child.text)
            resolution = f"{width}x{height}" if width and height else None
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
                    resolution=resolution,
                )
            )
        return DeviceViews(streams=tuple(streams) if streams else ())

    if endpoint_id.startswith("smart.line"):
        enabled = _as_bool(doc.text("enabled"))
        if enabled is None:
            missing.append("LineDetection.enabled")
        items = _parse_line_items(doc)
        return DeviceViews(
            line_detection=VcaRuleView(kind="line", engine_enabled=enabled, items=items)
        )

    if endpoint_id.startswith("smart.field"):
        enabled = _as_bool(doc.text("enabled"))
        if enabled is None:
            missing.append("FieldDetection.enabled")
        items = _parse_field_items(doc)
        return DeviceViews(
            field_detection=VcaRuleView(kind="field", engine_enabled=enabled, items=items)
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
                elif tag in ("channelID", "videoInputChannelID", "dynVideoInputChannelID"):
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
        tracks = _parse_tracks(doc)
        return DeviceViews(tracks=tracks)

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

    if endpoint_id.startswith("input_proxy.channels_status"):
        channels: list[ProxyChannelView] = []
        for elem in doc._root.iter():  # noqa: SLF001
            if elem.tag.split("}")[-1] != "InputProxyChannelStatus":
                continue
            cid = online = None
            for child in elem:
                tag = child.tag.split("}")[-1]
                if tag == "id":
                    cid = (child.text or "").strip()
                elif tag == "online":
                    online = _as_bool(child.text)
            if cid:
                channels.append(ProxyChannelView(id=cid, online=online))
        return DeviceViews(proxy_channels=tuple(channels) if channels else ())

    if endpoint_id.startswith("input_proxy.channels"):
        channels = []
        for elem in doc._root.iter():  # noqa: SLF001
            if elem.tag.split("}")[-1] != "InputProxyChannel":
                continue
            cid = proto = ip = None
            port = None
            for child in elem.iter():
                tag = child.tag.split("}")[-1]
                if tag == "id" and child.text and cid is None:
                    cid = child.text.strip()
                elif tag == "proxyProtocol" and child.text:
                    proto = child.text.strip()
                elif tag == "ipAddress" and child.text and ip is None:
                    ip = child.text.strip()
                elif tag == "managePortNo" or tag == "portNo" and port is None:
                    port = _as_int(child.text)
            channels.append(
                ProxyChannelView(id=cid, protocol=proto, ip=ip, port=port, online=None)
            )
        return DeviceViews(proxy_channels=tuple(channels) if channels else ())

    if endpoint_id.startswith("ptz.park"):
        view = ParkActionView(
            enabled=_as_bool(doc.text("enabled")),
            park_time_s=_as_int(doc.text("parkTime")),
            action_type=doc.text("Action/ActionType") or doc.text("ActionType"),
            action_num=_as_int(doc.text("Action/ActionNum")),
        )
        return DeviceViews(park_action=view)

    if endpoint_id.startswith("ptz.patrol"):
        patrol_items = _parse_named_items(doc, "PTZPatrol")
        return DeviceViews(patrols=PatrolView(items=patrol_items))

    if endpoint_id.startswith("ptz.preset"):
        preset_items = _parse_named_items(doc, "PTZPreset")
        return DeviceViews(presets=PresetView(items=preset_items))

    if endpoint_id.startswith("platform.ezviz"):
        enabled = _as_bool(doc.text("enabled"))
        if enabled is None:
            missing.append("EZVIZ.enabled")
        return DeviceViews(platform=PlatformView(ezviz_enabled=enabled))

    if endpoint_id == "content.log_search":
        return DeviceViews(log_search=_parse_log_search(doc, missing))

    if endpoint_id == "content.record_search":
        return DeviceViews(record_search=_parse_record_search(doc, missing))

    return DeviceViews()


def _parse_line_items(doc: XmlDocument) -> tuple[VcaItemView, ...]:
    items: list[VcaItemView] = []
    for elem in doc._root.iter():  # noqa: SLF001
        if elem.tag.split("}")[-1] != "LineItem":
            continue
        item_id = enabled = target = None
        coord_count = 0
        for child in elem.iter():
            tag = child.tag.split("}")[-1]
            if tag == "id" and child.text:
                item_id = child.text.strip()
            elif tag == "enabled":
                enabled = _as_bool(child.text)
            elif tag == "detectionTarget":
                target = (child.text or "").strip() or None
            elif tag == "Coordinates":
                coord_count += 1
        items.append(
            VcaItemView(
                id=item_id,
                enabled=enabled,
                detection_target=target,
                coordinate_count=coord_count or None,
            )
        )
    return tuple(items)


def _parse_field_items(doc: XmlDocument) -> tuple[VcaItemView, ...]:
    items: list[VcaItemView] = []
    for elem in doc._root.iter():  # noqa: SLF001
        if elem.tag.split("}")[-1] != "FieldDetectionRegion":
            continue
        item_id = enabled = target = None
        coord_count = 0
        for child in elem.iter():
            tag = child.tag.split("}")[-1]
            if tag == "id" and child.text:
                item_id = child.text.strip()
            elif tag == "enabled":
                enabled = _as_bool(child.text)
            elif tag == "detectionTarget":
                target = (child.text or "").strip() or None
            elif tag == "RegionCoordinates":
                coord_count += 1
        items.append(
            VcaItemView(
                id=item_id,
                enabled=enabled,
                detection_target=target,
                coordinate_count=coord_count or None,
            )
        )
    return tuple(items)


def _parse_tracks(doc: XmlDocument) -> tuple[TrackView, ...]:
    tracks: list[TrackView] = []
    for elem in doc._root.iter():  # noqa: SLF001
        if elem.tag.split("}")[-1] != "Track":
            continue
        track_id = channel = default_mode = None
        enable = pre = post = None
        schedule: list[tuple[str, str, str, str, str, bool]] = []
        for child in elem:
            tag = child.tag.split("}")[-1]
            if tag == "id" and child.text:
                track_id = child.text.strip()
            elif tag == "Channel" and child.text:
                channel = _as_int(child.text)
            elif tag == "Enable":
                enable = _as_bool(child.text)
            elif tag == "DefaultRecordingMode":
                default_mode = (child.text or "").strip() or None
            elif tag == "PreRecordTimeSeconds":
                pre = _as_int(child.text)
            elif tag == "PostRecordTimeSeconds":
                post = _as_int(child.text)
        for action in elem.iter():
            if action.tag.split("}")[-1] != "ScheduleAction":
                continue
            start_day = end_day = start_time = end_time = None
            mode = "CMR"
            record = True
            for child in action.iter():
                tag = child.tag.split("}")[-1]
                if tag == "DayOfWeek" and child.text:
                    if start_day is None:
                        start_day = child.text.strip()
                    else:
                        end_day = child.text.strip()
                elif tag == "TimeOfDay" and child.text:
                    if start_time is None:
                        start_time = child.text.strip()
                    else:
                        end_time = child.text.strip()
                elif tag == "ActionRecordingMode" and child.text:
                    mode = child.text.strip()
                elif tag == "Record":
                    record = _as_bool(child.text) or False
            if start_day and start_time and end_day and end_time:
                schedule.append((start_day, start_time, end_day, end_time, mode, record))
        coverage = "weekday+weekend" if len(schedule) >= 2 else ("configured" if schedule else None)
        pre_post = f"{pre}/{post}" if pre is not None and post is not None else None
        tracks.append(
            TrackView(
                track_id=track_id,
                channel=channel,
                enable=enable,
                default_mode=default_mode,
                pre_s=pre,
                post_s=post,
                schedule=tuple(schedule),
                schedule_coverage=coverage,
                pre_post_seconds=pre_post,
            )
        )
    return tuple(tracks)


def _local(tag: str) -> str:
    return tag.split("}")[-1]


def _first_text(elem: Element, name: str) -> str | None:
    for child in elem.iter():
        if _local(child.tag) == name and child.text and child.text.strip():
            return child.text.strip()
    return None


def _parse_log_search(doc: XmlDocument, missing: list[str]) -> LogSearchView:
    raw_count = _first_text(doc._root, "numOfMatches")  # noqa: SLF001
    if raw_count is None:
        missing.append("numOfMatches")
    events: list[LogEventView] = []
    for elem in doc._root.iter():  # noqa: SLF001
        if _local(elem.tag) != "searchMatchItem":
            continue
        events.append(
            LogEventView(
                meta_id=_first_text(elem, "metaId"),
                para_type=_first_text(elem, "paraType"),
                started_at=_first_text(elem, "StartDateTime"),
            )
        )
    return LogSearchView(num_matches=_as_int(raw_count), events=tuple(events))


def _parse_record_search(doc: XmlDocument, missing: list[str]) -> RecordSearchView:
    raw_count = _first_text(doc._root, "numOfMatches")  # noqa: SLF001
    if raw_count is None:
        missing.append("numOfMatches")
    segments: list[RecordSegmentView] = []
    for elem in doc._root.iter():  # noqa: SLF001
        if _local(elem.tag) != "searchMatchItem":
            continue
        record_type = _first_text(elem, "metadataDescriptor")
        segments.append(
            RecordSegmentView(
                track_id=_first_text(elem, "trackID"),
                start_time=_first_text(elem, "startTime"),
                end_time=_first_text(elem, "endTime"),
                record_type=record_type,
            )
        )
    return RecordSearchView(num_matches=_as_int(raw_count), segments=tuple(segments))


def _parse_named_items(doc: XmlDocument, local_name: str) -> tuple[dict[str, object], ...]:
    rows: list[dict[str, object]] = []
    for elem in doc._root.iter():  # noqa: SLF001
        if elem.tag.split("}")[-1] != local_name:
            continue
        row: dict[str, object] = {}
        for child in elem:
            tag = child.tag.split("}")[-1]
            if child.text and child.text.strip():
                row[tag] = child.text.strip()
        if row:
            rows.append(row)
    return tuple(rows)


def _merge_proxy_channels(
    left: tuple[ProxyChannelView, ...] | None,
    right: tuple[ProxyChannelView, ...] | None,
) -> tuple[ProxyChannelView, ...]:
    by_id: dict[str, ProxyChannelView] = {}
    for item in left or ():
        if item.id:
            by_id[item.id] = item
    for item in right or ():
        if item.id is None:
            continue
        existing = by_id.get(item.id)
        if existing is None:
            by_id[item.id] = item
            continue
        by_id[item.id] = ProxyChannelView(
            id=item.id,
            protocol=item.protocol or existing.protocol,
            ip=item.ip or existing.ip,
            port=item.port if item.port is not None else existing.port,
            online=item.online if item.online is not None else existing.online,
        )
    return tuple(by_id[k] for k in sorted(by_id))


def _proxy_tuple(raw: object) -> tuple[ProxyChannelView, ...]:
    if not raw:
        return ()
    items = list(raw) if isinstance(raw, (list, tuple)) else []
    out: list[ProxyChannelView] = []
    for item in items:
        if isinstance(item, ProxyChannelView):
            out.append(item)
        else:
            out.append(ProxyChannelView.model_validate(item))
    return tuple(out)


def merge_views(base: DeviceViews, patch: DeviceViews) -> DeviceViews:
    data = base.model_dump()
    patch_data = patch.model_dump()
    for key, value in patch_data.items():
        if value is None:
            continue
        if key == "proxy_channels":
            existing = _proxy_tuple(data.get("proxy_channels"))
            incoming = _proxy_tuple(value)
            data[key] = _merge_proxy_channels(existing, incoming)
            continue
        if key == "admin_access" and data.get("admin_access") and value:
            merged = dict(data["admin_access"]["protocols"])
            merged.update(value["protocols"])
            data[key] = {"protocols": merged}
            continue
        data[key] = value
    return DeviceViews.model_validate(data)