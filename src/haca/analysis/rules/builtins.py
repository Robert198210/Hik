"""Built-in deterministic audit rules (MVP)."""

from __future__ import annotations

from haca.analysis.context import RuleContext
from haca.analysis.models import Classification, Finding, Severity
from haca.analysis.rules.base import parse_local_ts, parse_targets, schedule_has_cmr_full_week
from haca.collect.extract import DeviceViews, ProxyChannelView, TriggerView


class RInv001:
    id = "R-INV-001"
    title = "NVR channel inventory mismatch"
    category = "inventory"
    basis = "technical"
    default_severity = Severity.medium
    requires = ("proxy_channels",)
    requires_orp: tuple[str, ...] = ()

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        nvr = next((d for d in ctx.result.devices if d.role == "nvr"), None)
        if nvr is None:
            return findings
        for ch_id, ip in ctx.correlation.unknown_channels:
            findings.append(
                ctx.build_finding(
                    rule_id=self.id,
                    title=self.title,
                    category=self.category,
                    basis=self.basis,
                    default_severity=self.default_severity,
                    devices=(nvr.device_id,),
                    classification=Classification.POTENTIAL_CONFLICT,
                    subject=f"unknown-{ch_id}",
                    rationale=f"NVR proxy channel {ch_id} points to unknown IP {ip}",
                    evidence=[
                        ctx.evidence(nvr.device_id, "input_proxy.channels", "ipAddress", ip)
                    ],
                    current_value=ip,
                )
            )
        for dev_id in ctx.correlation.unattached_devices:
            findings.append(
                ctx.build_finding(
                    rule_id=self.id,
                    title=self.title,
                    category=self.category,
                    basis=self.basis,
                    default_severity=self.default_severity,
                    devices=(dev_id,),
                    classification=Classification.POTENTIAL_CONFLICT,
                    subject=f"unattached-{dev_id}",
                    rationale=f"Configured camera {dev_id} has no NVR input proxy channel",
                    evidence=[ctx.evidence(dev_id, "system.device_info", "model", dev_id)],
                    current_value="not_on_nvr",
                    recommended_value="linked_in_nvr",
                )
            )
        return findings


class RConn001:
    id = "R-CONN-001"
    title = "NVR proxy channel offline"
    category = "linkage"
    basis = "technical"
    default_severity = Severity.high
    requires = ("proxy_channels",)
    requires_orp: tuple[str, ...] = ()

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        nvr = next((d for d in ctx.result.devices if d.role == "nvr"), None)
        if nvr is None or not nvr.views.proxy_channels:
            return findings
        channels = _merge_proxy(nvr.views)
        for proxy in channels:
            if proxy.online is False:
                findings.append(
                    ctx.build_finding(
                        rule_id=self.id,
                        title=self.title,
                        category=self.category,
                        basis=self.basis,
                        default_severity=self.default_severity,
                        devices=(nvr.device_id,),
                        classification=Classification.CONFIRMED_CONFLICT,
                        subject=f"offline-{proxy.id}",
                        rationale=f"Input proxy channel {proxy.id} is offline",
                        evidence=[
                            ctx.evidence(
                                nvr.device_id,
                                "input_proxy.channels_status",
                                "online",
                                "false",
                            )
                        ],
                        current_value="offline",
                        recommended_value="online",
                    )
                )
        return findings


class RStor001:
    id = "R-STOR-001"
    title = "HDD status not healthy"
    category = "storage"
    basis = "technical"
    default_severity = Severity.critical
    requires = ("hdds",)
    requires_orp: tuple[str, ...] = ()

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        nvr = next((d for d in ctx.result.devices if d.role == "nvr"), None)
        if nvr is None or not nvr.views.hdds:
            return findings
        for hdd in nvr.views.hdds:
            if hdd.status and hdd.status.lower() != "ok":
                findings.append(
                    ctx.build_finding(
                        rule_id=self.id,
                        title=self.title,
                        category=self.category,
                        basis=self.basis,
                        default_severity=self.default_severity,
                        devices=(nvr.device_id,),
                        classification=Classification.CONFIRMED_CONFLICT,
                        subject=f"hdd-{hdd.id}",
                        rationale=f"HDD {hdd.id} status is {hdd.status}",
                        evidence=[
                            ctx.evidence(
                                nvr.device_id, "storage.hdd", "status", hdd.status
                            )
                        ],
                        current_value=hdd.status,
                        recommended_value="ok",
                    )
                )
        return findings


class RStor002:
    id = "R-STOR-002"
    title = "Estimated retention below requirement"
    category = "storage"
    basis = "requirement"
    default_severity = Severity.high
    requires = ("hdds", "streams", "tracks")
    requires_orp = ("system.min_retention_days",)

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        nvr = next((d for d in ctx.result.devices if d.role == "nvr"), None)
        if nvr is None:
            return findings
        hdds = nvr.views.hdds or ()
        total_cap = sum(h.capacity_mb or 0 for h in hdds)
        if total_cap <= 0 or any(h.capacity_mb is None for h in hdds if hdds):
            if not hdds:
                return findings
            findings.append(
                ctx.build_finding(
                    rule_id=self.id,
                    title=self.title,
                    category=self.category,
                    basis=self.basis,
                    default_severity=Severity.info,
                    devices=(nvr.device_id,),
                    classification=Classification.INSUFFICIENT_DATA,
                    subject="retention-capacity-missing",
                    rationale="HDD capacity not available for retention estimate",
                    evidence=[
                        ctx.evidence(nvr.device_id, "storage.hdd", "capacity", "missing")
                    ],
                )
            )
            return findings

        daily_kbps = 0
        missing_bitrate = False
        for dev in ctx.result.devices:
            if not dev.views.streams:
                continue
            for stream in dev.views.streams:
                if stream.id and stream.id.endswith("01"):
                    kbps = stream.bitrate_kbps or stream.vbr_cap_kbps
                    if kbps is None:
                        missing_bitrate = True
                    else:
                        daily_kbps += kbps
        if missing_bitrate or daily_kbps <= 0:
            findings.append(
                ctx.build_finding(
                    rule_id=self.id,
                    title=self.title,
                    category=self.category,
                    basis=self.basis,
                    default_severity=Severity.info,
                    devices=(nvr.device_id,),
                    classification=Classification.INSUFFICIENT_DATA,
                    subject="retention-bitrate-missing",
                    rationale="Main stream bitrate missing for retention estimate",
                    evidence=[
                        ctx.evidence(
                            nvr.device_id, "record.tracks", "tracks", "bitrate_missing"
                        )
                    ],
                )
            )
            return findings

        daily_mb = daily_kbps * 86400 / 8 / 1024
        est_days = total_cap / daily_mb if daily_mb > 0 else 0.0
        min_days = ctx.orp_access.value("system.min_retention_days")
        if min_days is None:
            return findings

        if est_days < float(min_days):
            findings.append(
                ctx.build_finding(
                    rule_id=self.id,
                    title=self.title,
                    category=self.category,
                    basis=self.basis,
                    default_severity=self.default_severity,
                    devices=(nvr.device_id,),
                    classification=Classification.CONFIRMED_CONFLICT,
                    subject="retention-below-min",
                    rationale=(
                        f"Estimated retention {est_days:.1f}d is below required {min_days}d"
                    ),
                    evidence=[
                        ctx.evidence(
                            nvr.device_id,
                            "storage.hdd",
                            "estimate_days",
                            f"{est_days:.2f}",
                        )
                    ],
                    orp_refs=("system.min_retention_days",),
                    current_value=f"{est_days:.1f}",
                    recommended_value=str(min_days),
                )
            )
        return findings


class RRec001:
    id = "R-REC-001"
    title = "Recording schedule vs ORP mode"
    category = "recording"
    basis = "requirement"
    default_severity = Severity.high
    requires = ("tracks",)
    requires_orp = ("system.recording_mode",)

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        mode = ctx.orp_access.enum_value("system.recording_mode")
        if mode is None:
            return []
        findings: list[Finding] = []
        nvr = next((d for d in ctx.result.devices if d.role == "nvr"), None)
        if nvr is None or not nvr.views.tracks:
            return findings
        for track in nvr.views.tracks:
            if mode == "continuous_24_7":
                if not schedule_has_cmr_full_week(track.schedule):
                    findings.append(
                        ctx.build_finding(
                            rule_id=self.id,
                            title=self.title,
                            category=self.category,
                            basis=self.basis,
                            default_severity=self.default_severity,
                            devices=(nvr.device_id,),
                            classification=Classification.CONFIRMED_CONFLICT,
                            subject=f"track-{track.track_id}-cmr",
                            rationale="continuous_24_7 requires CMR covering all 7 days",
                            evidence=[
                                ctx.evidence(
                                    nvr.device_id,
                                    "record.tracks",
                                    "schedule",
                                    str(track.schedule),
                                )
                            ],
                            orp_refs=("system.recording_mode",),
                            current_value="partial_or_motion",
                            recommended_value="CMR_24_7",
                        )
                    )
            elif mode == "event_only" and schedule_has_cmr_full_week(track.schedule):
                findings.append(
                    ctx.build_finding(
                        rule_id=self.id,
                        title=self.title,
                        category=self.category,
                        basis=self.basis,
                        default_severity=Severity.low,
                        devices=(nvr.device_id,),
                        classification=Classification.OPTIMIZATION,
                        subject=f"track-{track.track_id}-storage",
                        rationale="event_only ORP but schedule is CMR 24/7 (storage waste)",
                        evidence=[
                            ctx.evidence(
                                nvr.device_id,
                                "record.tracks",
                                "schedule",
                                "CMR_full_week",
                            )
                        ],
                        orp_refs=("system.recording_mode",),
                    )
                )
        return findings


class RRec002:
    id = "R-REC-002"
    title = "Track disabled with schedule present"
    category = "recording"
    basis = "technical"
    default_severity = Severity.info
    requires = ("tracks",)
    requires_orp: tuple[str, ...] = ()

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        nvr = next((d for d in ctx.result.devices if d.role == "nvr"), None)
        if nvr is None or not nvr.views.tracks:
            return findings
        for track in nvr.views.tracks:
            if track.enable is False and track.schedule:
                findings.append(
                    ctx.build_finding(
                        rule_id=self.id,
                        title=self.title,
                        category=self.category,
                        basis=self.basis,
                        default_severity=self.default_severity,
                        devices=(nvr.device_id,),
                        classification=Classification.INSUFFICIENT_DATA,
                        subject=f"track-{track.track_id}-disabled",
                        rationale=(
                            "Track disabled but schedule exists; "
                            "verify playback markers manually"
                        ),
                        evidence=[
                            ctx.evidence(
                                nvr.device_id, "record.tracks", "Enable", "false"
                            )
                        ],
                        source_refs=("manual.playback_markers",),
                    )
                )
        return findings


class RProto001:
    id = "R-PROTO-001"
    title = "Camera protocol vs ORP"
    category = "linkage"
    basis = "requirement"
    default_severity = Severity.high
    requires = ("proxy_channels",)
    requires_orp: tuple[str, ...] = ()

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        nvr = next((d for d in ctx.result.devices if d.role == "nvr"), None)
        if nvr is None:
            return findings
        proxies = {p.ip: p for p in _merge_proxy(nvr.views) if p.ip}
        for dev in ctx.result.devices:
            if dev.role not in ("camera", "ptz"):
                continue
            host = None
            if dev.views.network and dev.views.network.ip:
                host = dev.views.network.ip
            if host is None:
                for key, val in dev.flattened.items():
                    if key.endswith(":ipAddress") and val:
                        host = val
                        break
            proxy = proxies.get(host) if host else None
            if proxy is None or proxy.protocol is None:
                continue
            proto_path = f"devices.{dev.device_id}.camera_protocol"
            orp_proto = ctx.orp_access.enum_value(proto_path)
            observed = proxy.protocol.upper()
            if orp_proto == "hikvision" and observed == "ONVIF":
                findings.append(
                    ctx.build_finding(
                        rule_id=self.id,
                        title=self.title,
                        category=self.category,
                        basis=self.basis,
                        default_severity=self.default_severity,
                        devices=(nvr.device_id, dev.device_id),
                        classification=Classification.CONFIRMED_CONFLICT,
                        subject=f"proto-{dev.device_id}",
                        rationale="ORP requires Hikvision protocol but NVR proxy uses ONVIF",
                        evidence=[
                            ctx.evidence(
                                nvr.device_id,
                                "input_proxy.channels",
                                "proxyProtocol",
                                observed,
                            )
                        ],
                        orp_refs=(proto_path,),
                        current_value=observed,
                        recommended_value="HIKVISION",
                    )
                )
            elif orp_proto == "onvif_allowed" and observed == "ONVIF":
                timeline = ctx.orp_access.value("system.timeline_markers_required")
                if timeline is True:
                    findings.append(
                        ctx.build_finding(
                            rule_id=self.id,
                            title=self.title,
                            category=self.category,
                            basis=self.basis,
                            default_severity=Severity.medium,
                            devices=(nvr.device_id, dev.device_id),
                            classification=Classification.POTENTIAL_CONFLICT,
                            subject=f"proto-onvif-{dev.device_id}",
                            rationale="ONVIF with timeline markers required may lose metadata",
                            evidence=[
                                ctx.evidence(
                                    nvr.device_id,
                                    "input_proxy.channels",
                                    "proxyProtocol",
                                    observed,
                                )
                            ],
                            orp_refs=(proto_path, "system.timeline_markers_required"),
                            current_value=observed,
                        )
                    )
            elif orp_proto is None and observed == "ONVIF":
                findings.append(
                    ctx.build_finding(
                        rule_id=self.id,
                        title=self.title,
                        category=self.category,
                        basis=self.basis,
                        default_severity=Severity.info,
                        devices=(nvr.device_id, dev.device_id),
                        classification=Classification.INFO,
                        subject=f"proto-undecided-{dev.device_id}",
                        rationale="ONVIF in use but camera_protocol is unspecified in ORP",
                        evidence=[
                            ctx.evidence(
                                nvr.device_id,
                                "input_proxy.channels",
                                "proxyProtocol",
                                observed,
                            )
                        ],
                        needs_decision=True,
                        orp_refs=(proto_path,),
                        current_value=observed,
                    )
                )
        return findings


class RVca001:
    id = "R-VCA-001"
    title = "Required VCA events enabled"
    category = "analytics"
    basis = "requirement"
    default_severity = Severity.high
    requires = ("line_detection",)
    requires_orp: tuple[str, ...] = ()

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for dev in ctx.result.devices:
            dev_req = ctx.orp.devices.get(dev.device_id)
            if dev_req is None or not dev_req.required_events:
                continue
            req = {e.lower().replace("-", "_") for e in dev_req.required_events}
            rule = dev.views.line_detection
            if rule is None:
                continue
            if "line_crossing" in req or "linedetection" in req:
                enabled_items = [i for i in rule.items if i.enabled]
                if rule.engine_enabled and not enabled_items:
                    findings.append(
                        ctx.build_finding(
                            rule_id=self.id,
                            title=self.title,
                            category=self.category,
                            basis=self.basis,
                            default_severity=self.default_severity,
                            devices=(dev.device_id,),
                            classification=Classification.CONFIRMED_CONFLICT,
                            subject="line-crossing-missing",
                            rationale="Line crossing required but no enabled line rules",
                            evidence=[
                                ctx.evidence(
                                    dev.device_id,
                                    "smart.line_detection",
                                    "enabled",
                                    "engine_only",
                                )
                            ],
                            orp_refs=(
                                f"devices.{dev.device_id}.required_events",
                            ),
                        )
                    )
                elif not rule.engine_enabled:
                    findings.append(
                        ctx.build_finding(
                            rule_id=self.id,
                            title=self.title,
                            category=self.category,
                            basis=self.basis,
                            default_severity=self.default_severity,
                            devices=(dev.device_id,),
                            classification=Classification.CONFIRMED_CONFLICT,
                            subject="line-engine-off",
                            rationale="Line crossing required but engine disabled",
                            evidence=[
                                ctx.evidence(
                                    dev.device_id,
                                    "smart.line_detection",
                                    "enabled",
                                    "false",
                                )
                            ],
                            orp_refs=(
                                f"devices.{dev.device_id}.required_events",
                            ),
                        )
                    )
        return findings


class RVca002:
    id = "R-VCA-002"
    title = "VCA rule without detection target"
    category = "analytics"
    basis = "technical"
    default_severity = Severity.medium
    requires = ("line_detection", "field_detection")
    requires_orp: tuple[str, ...] = ()

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for dev in ctx.result.devices:
            for rule, endpoint in (
                (dev.views.line_detection, "smart.line_detection"),
                (dev.views.field_detection, "smart.field_detection"),
            ):
                if rule is None:
                    continue
                for item in rule.items:
                    if item.enabled and not parse_targets(item.detection_target):
                        findings.append(
                            ctx.build_finding(
                                rule_id=self.id,
                                title=self.title,
                                category=self.category,
                                basis=self.basis,
                                default_severity=self.default_severity,
                                devices=(dev.device_id,),
                                classification=Classification.POTENTIAL_CONFLICT,
                                subject=f"empty-target-{item.id}",
                                rationale="Enabled VCA item has empty detection target",
                                evidence=[
                                    ctx.evidence(
                                        dev.device_id,
                                        endpoint,
                                        "detectionTarget",
                                        "",
                                    )
                                ],
                                current_value="",
                                recommended_value="human,vehicle",
                            )
                        )
        return findings


class RVca003:
    id = "R-VCA-003"
    title = "VCA geometry incomplete"
    category = "analytics"
    basis = "technical"
    default_severity = Severity.medium
    requires = ("line_detection", "field_detection")
    requires_orp: tuple[str, ...] = ()

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for dev in ctx.result.devices:
            if dev.views.line_detection:
                for item in dev.views.line_detection.items:
                    if item.enabled and (item.coordinate_count or 0) < 2:
                        findings.append(
                            ctx.build_finding(
                                rule_id=self.id,
                                title=self.title,
                                category=self.category,
                                basis=self.basis,
                                default_severity=self.default_severity,
                                devices=(dev.device_id,),
                                classification=Classification.CONFIRMED_CONFLICT,
                                subject=f"line-coords-{item.id}",
                                rationale="Enabled line rule has fewer than 2 coordinates",
                                evidence=[
                                    ctx.evidence(
                                        dev.device_id,
                                        "smart.line_detection",
                                        "coordinate_count",
                                        str(item.coordinate_count or 0),
                                    )
                                ],
                            )
                        )
            if dev.views.field_detection:
                for item in dev.views.field_detection.items:
                    count = item.coordinate_count or 0
                    if item.enabled and count == 0:
                        findings.append(
                            ctx.build_finding(
                                rule_id=self.id,
                                title=self.title,
                                category=self.category,
                                basis=self.basis,
                                default_severity=self.default_severity,
                                devices=(dev.device_id,),
                                classification=Classification.CONFIRMED_CONFLICT,
                                subject=f"field-coords-{item.id}",
                                rationale="Enabled field region has fewer than 3 coordinates",
                                evidence=[
                                    ctx.evidence(
                                        dev.device_id,
                                        "smart.field_detection",
                                        "coordinate_count",
                                        str(item.coordinate_count or 0),
                                    )
                                ],
                            )
                        )
        return findings


class RVca004:
    id = "R-VCA-004"
    title = "VCA targets vs ORP event_targets"
    category = "analytics"
    basis = "requirement"
    default_severity = Severity.medium
    requires = ("line_detection", "field_detection")
    requires_orp: tuple[str, ...] = ()

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for dev in ctx.result.devices:
            targets_path = f"devices.{dev.device_id}.event_targets"
            required = ctx.orp_access.value(targets_path)
            if not required:
                continue
            required_set = {str(t).lower() for t in required}
            for rule, endpoint in (
                (dev.views.line_detection, "smart.line_detection"),
                (dev.views.field_detection, "smart.field_detection"),
            ):
                if rule is None:
                    continue
                for item in rule.items:
                    if not item.enabled:
                        continue
                    have = parse_targets(item.detection_target)
                    if not required_set.issubset(have):
                        findings.append(
                            ctx.build_finding(
                                rule_id=self.id,
                                title=self.title,
                                category=self.category,
                                basis=self.basis,
                                default_severity=self.default_severity,
                                devices=(dev.device_id,),
                                classification=Classification.CONFIRMED_CONFLICT,
                                subject=f"targets-{item.id}",
                                rationale="Enabled VCA item missing required event targets",
                                evidence=[
                                    ctx.evidence(
                                        dev.device_id,
                                        endpoint,
                                        "detectionTarget",
                                        item.detection_target or "",
                                    )
                                ],
                                orp_refs=(targets_path,),
                                current_value=item.detection_target or "",
                                recommended_value=",".join(sorted(required_set)),
                            )
                        )
        return findings


class RLink001:
    id = "R-LINK-001"
    title = "NVR notification center for camera analytics"
    category = "linkage"
    basis = "requirement"
    default_severity = Severity.medium
    requires = ("triggers", "line_detection")
    requires_orp: tuple[str, ...] = ()

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        nvr = next((d for d in ctx.result.devices if d.role == "nvr"), None)
        if nvr is None or not nvr.views.triggers:
            return findings
        triggers_by_ch: dict[int, list[TriggerView]] = {}
        for trig in nvr.views.triggers:
            if trig.channel is not None:
                triggers_by_ch.setdefault(trig.channel, []).append(trig)

        for dev in ctx.result.devices:
            notify_path = f"devices.{dev.device_id}.notify_center_required"
            notify = ctx.orp_access.value(notify_path)
            if notify is None:
                if dev.views.line_detection and dev.views.line_detection.engine_enabled:
                    ch = ctx.correlation.channel_of.get(dev.device_id)
                    if ch is None:
                        continue
                    linked = _find_event(triggers_by_ch.get(ch, []), "linedetection")
                    if linked is not None and "center" not in linked.methods:
                        findings.append(
                            ctx.build_finding(
                                rule_id=self.id,
                                title=self.title,
                                category=self.category,
                                basis=self.basis,
                                default_severity=Severity.info,
                                devices=(nvr.device_id, dev.device_id),
                                classification=Classification.INFO,
                                subject=f"center-undecided-{dev.device_id}",
                                rationale=(
                                    "notify_center_required unset; "
                                    "linedetection trigger lacks center"
                                ),
                                evidence=[
                                    ctx.evidence(
                                        nvr.device_id,
                                        "event.triggers",
                                        "notificationMethod",
                                        str(sorted(linked.methods)),
                                    )
                                ],
                                needs_decision=True,
                                orp_refs=(notify_path,),
                            )
                        )
                continue
            if notify is not True:
                continue
            if not dev.views.line_detection or not dev.views.line_detection.engine_enabled:
                continue
            ch = ctx.correlation.channel_of.get(dev.device_id)
            if ch is None:
                continue
            linked = _find_event(triggers_by_ch.get(ch, []), "linedetection")
            if linked is None or "center" not in linked.methods:
                findings.append(
                    ctx.build_finding(
                        rule_id=self.id,
                        title=self.title,
                        category=self.category,
                        basis=self.basis,
                        default_severity=self.default_severity,
                        devices=(nvr.device_id, dev.device_id),
                        classification=Classification.CONFIRMED_CONFLICT,
                        subject=f"no-center-{dev.device_id}",
                        rationale=(
                            "ORP requires notify center on linedetection "
                            "but trigger lacks center"
                        ),
                        evidence=[
                            ctx.evidence(
                                nvr.device_id,
                                "event.triggers",
                                "notificationMethod",
                                str(sorted(linked.methods)) if linked else "missing",
                            )
                        ],
                        orp_refs=(notify_path,),
                        recommended_value="center",
                    )
                )
        return findings


class RTime001:
    id = "R-TIME-001"
    title = "Time source and clock alignment"
    category = "time"
    basis = "requirement"
    default_severity = Severity.medium
    requires = ("time",)
    requires_orp = ("system.time_source",)

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        if ctx.orp_access.enum_value("system.time_source") == "ntp":
            for dev in ctx.result.devices:
                mode = dev.views.time.time_mode if dev.views.time else None
                if mode and mode.upper() != "NTP":
                    findings.append(
                        ctx.build_finding(
                            rule_id=self.id,
                            title=self.title,
                            category=self.category,
                            basis="requirement",
                            default_severity=self.default_severity,
                            devices=(dev.device_id,),
                            classification=Classification.CONFIRMED_CONFLICT,
                            subject=f"time-mode-{dev.device_id}",
                            rationale="ORP requires NTP but device timeMode is not NTP",
                            evidence=[
                                ctx.evidence(
                                    dev.device_id, "system.time", "timeMode", mode
                                )
                            ],
                            orp_refs=("system.time_source",),
                            current_value=mode,
                            recommended_value="NTP",
                        )
                    )

        if ctx.orp_access.enum_value("system.time_source") == "nvr_sync":
            nvr_dev = next((d for d in ctx.result.devices if d.role == "nvr"), None)
            nvr_mode = (
                nvr_dev.views.time.time_mode
                if nvr_dev and nvr_dev.views.time and nvr_dev.views.time.time_mode
                else None
            )
            if nvr_dev is not None and nvr_mode:
                for dev in ctx.result.devices:
                    if dev.device_id == nvr_dev.device_id:
                        continue
                    mode = dev.views.time.time_mode if dev.views.time else None
                    if mode and mode.upper() != nvr_mode.upper():
                        findings.append(
                            ctx.build_finding(
                                rule_id=self.id,
                                title=self.title,
                                category=self.category,
                                basis="requirement",
                                default_severity=self.default_severity,
                                devices=(dev.device_id,),
                                classification=Classification.CONFIRMED_CONFLICT,
                                subject=f"time-mode-{dev.device_id}",
                                rationale=(
                                    "ORP time source is NVR sync but device "
                                    f"timeMode {mode} differs from NVR {nvr_mode}"
                                ),
                                evidence=[
                                    ctx.evidence(
                                        dev.device_id, "system.time", "timeMode", mode
                                    )
                                ],
                                orp_refs=("system.time_source",),
                                current_value=mode,
                                recommended_value=nvr_mode,
                            )
                        )

        nvr = next((d for d in ctx.result.devices if d.role == "nvr"), None)
        ref_ts = None
        ref_at = None
        if nvr and nvr.views.time:
            ref_ts = parse_local_ts(nvr.views.time.local_time)
            ref_ev = nvr.evidence.get("system.time")
            ref_at = ref_ev.collected_at.timestamp() if ref_ev else None
        if ref_ts is None or ref_at is None:
            return findings
        for dev in ctx.result.devices:
            if dev.device_id == nvr.device_id if nvr else False:
                continue
            if not dev.views.time or not dev.views.time.local_time:
                findings.append(
                    ctx.build_finding(
                        rule_id=self.id,
                        title=self.title,
                        category=self.category,
                        basis="technical",
                        default_severity=Severity.low,
                        devices=(dev.device_id,),
                        classification=Classification.INSUFFICIENT_DATA,
                        subject=f"time-missing-{dev.device_id}",
                        rationale="Local time missing for drift comparison",
                        evidence=[
                            ctx.evidence(dev.device_id, "system.time", "localTime", "")
                        ],
                    )
                )
                continue
            dev_ts = parse_local_ts(dev.views.time.local_time)
            ev = dev.evidence.get("system.time")
            if dev_ts is None or ev is None:
                findings.append(
                    ctx.build_finding(
                        rule_id=self.id,
                        title=self.title,
                        category=self.category,
                        basis="technical",
                        default_severity=Severity.low,
                        devices=(dev.device_id,),
                        classification=Classification.INSUFFICIENT_DATA,
                        subject=f"time-unparseable-{dev.device_id}",
                        rationale="Unparseable local time",
                        evidence=[
                            ctx.evidence(
                                dev.device_id,
                                "system.time",
                                "localTime",
                                dev.views.time.local_time,
                            )
                        ],
                    )
                )
                continue
            collected_at = ev.collected_at.timestamp()
            drift = abs((dev_ts - collected_at) - (ref_ts - ref_at))
            if drift > 30:
                findings.append(
                    ctx.build_finding(
                        rule_id=self.id,
                        title=self.title,
                        category=self.category,
                        basis="technical",
                        default_severity=Severity.low,
                        devices=(dev.device_id,),
                        classification=Classification.POTENTIAL_CONFLICT,
                        subject=f"time-drift-{dev.device_id}",
                        rationale=f"Clock drift vs NVR exceeds 30s ({drift:.0f}s)",
                        evidence=[
                            ctx.evidence(
                                dev.device_id,
                                "system.time",
                                "localTime",
                                dev.views.time.local_time,
                            )
                        ],
                        current_value=f"{drift:.0f}s",
                    )
                )
        return findings


class RSec001:
    id = "R-SEC-001"
    title = "HTTPS requirement"
    category = "security"
    basis = "requirement"
    default_severity = Severity.medium
    requires = ("admin_access",)
    requires_orp = ("system.https_required",)

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        https_req = ctx.orp_access.enum_value("system.https_required")
        findings: list[Finding] = []
        for dev in ctx.result.devices:
            access = dev.views.admin_access
            if access is None:
                continue
            https = access.protocols.get("HTTPS")
            http = access.protocols.get("HTTP")
            https_on = https.enabled if https else None
            http_on = http.enabled if http else None
            if https_req == "required" and https_on is False:
                findings.append(
                    ctx.build_finding(
                        rule_id=self.id,
                        title=self.title,
                        category=self.category,
                        basis=self.basis,
                        default_severity=self.default_severity,
                        devices=(dev.device_id,),
                        classification=Classification.CONFIRMED_CONFLICT,
                        subject="https-off",
                        rationale="ORP requires HTTPS but HTTPS is disabled",
                        evidence=[
                            ctx.evidence(
                                dev.device_id,
                                "security.admin_accesses",
                                "HTTPS.enabled",
                                "false",
                            )
                        ],
                        orp_refs=("system.https_required",),
                        current_value="disabled",
                        recommended_value="enabled",
                    )
                )
            elif https_req is None and http_on and https_on is False:
                findings.append(
                    ctx.build_finding(
                        rule_id=self.id,
                        title=self.title,
                        category=self.category,
                        basis=self.basis,
                        default_severity=Severity.info,
                        devices=(dev.device_id,),
                        classification=Classification.INFO,
                        subject="https-undecided",
                        rationale="HTTP enabled and HTTPS disabled; https_required unspecified",
                        evidence=[
                            ctx.evidence(
                                dev.device_id,
                                "security.admin_accesses",
                                "HTTPS.enabled",
                                "false",
                            )
                        ],
                        needs_decision=True,
                        orp_refs=("system.https_required",),
                    )
                )
        return findings


class RHikc001:
    id = "R-HIKC-001"
    title = "Hik-Connect / EZVIZ vs ORP"
    category = "platform"
    basis = "requirement"
    default_severity = Severity.high
    requires = ("platform",)
    requires_orp = ("system.hik_connect",)

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        policy = ctx.orp_access.enum_value("system.hik_connect")
        findings: list[Finding] = []
        for dev in ctx.result.devices:
            plat = dev.views.platform
            if plat is None or plat.ezviz_enabled is None:
                continue
            enabled = plat.ezviz_enabled
            if policy == "forbidden" and enabled:
                findings.append(
                    ctx.build_finding(
                        rule_id=self.id,
                        title=self.title,
                        category=self.category,
                        basis=self.basis,
                        default_severity=self.default_severity,
                        devices=(dev.device_id,),
                        classification=Classification.CONFIRMED_CONFLICT,
                        subject="hikc-forbidden",
                        rationale="ORP forbids Hik-Connect but EZVIZ is enabled",
                        evidence=[
                            ctx.evidence(
                                dev.device_id, "platform.ezviz", "enabled", "true"
                            )
                        ],
                        orp_refs=("system.hik_connect",),
                        current_value="enabled",
                        recommended_value="disabled",
                    )
                )
            elif policy == "required" and not enabled:
                findings.append(
                    ctx.build_finding(
                        rule_id=self.id,
                        title=self.title,
                        category=self.category,
                        basis=self.basis,
                        default_severity=Severity.medium,
                        devices=(dev.device_id,),
                        classification=Classification.CONFIRMED_CONFLICT,
                        subject="hikc-required",
                        rationale="ORP requires Hik-Connect but EZVIZ is disabled",
                        evidence=[
                            ctx.evidence(
                                dev.device_id, "platform.ezviz", "enabled", "false"
                            )
                        ],
                        orp_refs=("system.hik_connect",),
                        current_value="disabled",
                        recommended_value="enabled",
                    )
                )
            elif policy is None and dev.device_id == "nvr01":
                findings.append(
                    ctx.build_finding(
                        rule_id=self.id,
                        title=self.title,
                        category=self.category,
                        basis=self.basis,
                        default_severity=Severity.info,
                        devices=(dev.device_id,),
                        classification=Classification.INFO,
                        subject="hikc-undecided",
                        rationale="Hik-Connect policy undecided in ORP",
                        evidence=[
                            ctx.evidence(
                                dev.device_id,
                                "platform.ezviz",
                                "enabled",
                                str(enabled).lower(),
                            )
                        ],
                        needs_decision=True,
                        orp_refs=("system.hik_connect",),
                        current_value=str(enabled).lower(),
                    )
                )
                return findings
        return findings


class RPtz001:
    id = "R-PTZ-001"
    title = "PTZ mode vs park action"
    category = "ptz"
    basis = "requirement"
    default_severity = Severity.low
    requires = ("park_action",)
    requires_orp: tuple[str, ...] = ()

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for dev in ctx.result.devices:
            if dev.role != "ptz":
                continue
            mode_path = f"devices.{dev.device_id}.ptz_mode"
            mode = ctx.orp_access.enum_value(mode_path)
            park = dev.views.park_action
            if mode is None:
                findings.append(
                    ctx.build_finding(
                        rule_id=self.id,
                        title=self.title,
                        category=self.category,
                        basis=self.basis,
                        default_severity=Severity.info,
                        devices=(dev.device_id,),
                        classification=Classification.INFO,
                        subject="ptz-mode-undecided",
                        rationale="PTZ mode undecided in ORP",
                        evidence=[
                            ctx.evidence(
                                dev.device_id,
                                "ptz.park_action",
                                "enabled",
                                str(park.enabled) if park else "unknown",
                            )
                        ],
                        needs_decision=True,
                        orp_refs=(mode_path,),
                    )
                )
                continue
            if (
                mode == "static_home_preset"
                and park
                and (not park.enabled or (park.action_type or "").lower() != "preset")
            ):
                findings.append(
                        ctx.build_finding(
                            rule_id=self.id,
                            title=self.title,
                            category=self.category,
                            basis=self.basis,
                            default_severity=self.default_severity,
                            devices=(dev.device_id,),
                            classification=Classification.CONFIRMED_CONFLICT,
                            subject="park-preset",
                            rationale="static_home_preset requires park action preset enabled",
                            evidence=[
                                ctx.evidence(
                                    dev.device_id,
                                    "ptz.park_action",
                                    "ActionType",
                                    park.action_type or "",
                                )
                            ],
                            orp_refs=(mode_path,),
                            current_value=park.action_type or "disabled",
                            recommended_value="preset",
                        )
                    )
        return findings


class RPtz002:
    id = "R-PTZ-002"
    title = "Patrol with fixed VCA rules"
    category = "ptz"
    basis = "technical"
    default_severity = Severity.medium
    requires = ("patrols", "line_detection")
    requires_orp: tuple[str, ...] = ()

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for dev in ctx.result.devices:
            if dev.role != "ptz":
                continue
            mode_path = f"devices.{dev.device_id}.ptz_mode"
            mode = ctx.orp_access.enum_value(mode_path)
            patrols = dev.views.patrols
            if not patrols or not patrols.items:
                continue
            has_patrol = any(row.get("enabled") == "true" for row in patrols.items)
            if not has_patrol:
                continue
            line = dev.views.line_detection
            field = dev.views.field_detection
            enabled_items = False
            if line:
                enabled_items = any(i.enabled for i in line.items)
            if field:
                enabled_items = enabled_items or any(i.enabled for i in field.items)
            engine_only = bool(
                line and line.engine_enabled and not any(i.enabled for i in line.items)
            )
            if mode is None:
                if not engine_only:
                    continue
            elif mode == "patrol" or not enabled_items and not engine_only:
                continue
            if enabled_items or engine_only:
                findings.append(
                    ctx.build_finding(
                        rule_id=self.id,
                        title=self.title,
                        category=self.category,
                        basis=self.basis,
                        default_severity=self.default_severity,
                        devices=(dev.device_id,),
                        classification=Classification.POTENTIAL_CONFLICT,
                        subject="patrol-vca",
                        rationale="Patrol enabled while VCA rules assume a fixed view",
                        evidence=[
                            ctx.evidence(
                                dev.device_id, "ptz.patrols", "enabled", "true"
                            )
                        ],
                        source_refs=(
                            "HACA knowledge: VCA rules drawn for a fixed PTZ view",
                        ),
                    )
                )
        return findings


def _merge_proxy(views: DeviceViews) -> tuple[ProxyChannelView, ...]:

    by_id: dict[str, ProxyChannelView] = {}
    for item in views.proxy_channels or ():
        if item.id:
            by_id[item.id] = item
    return tuple(by_id[k] for k in sorted(by_id))


def _find_event(
    triggers: list[TriggerView], event_type: str
) -> TriggerView | None:
    want = event_type.lower()
    for trig in triggers:
        if trig.event_type and trig.event_type.lower() == want:
            return trig
    return None


def all_builtin_rules() -> list[object]:
    return [
        RInv001(),
        RConn001(),
        RStor001(),
        RStor002(),
        RRec001(),
        RRec002(),
        RProto001(),
        RVca001(),
        RVca002(),
        RVca003(),
        RVca004(),
        RLink001(),
        RTime001(),
        RSec001(),
        RHikc001(),
        RPtz001(),
        RPtz002(),
    ]