"""Operational Requirements Profile (ORP) models."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class RecordingMode(StrEnum):
    continuous_24_7 = "continuous_24_7"
    event_only = "event_only"
    continuous_plus_event = "continuous_plus_event"
    unspecified = "unspecified"


class AnalyticsLocation(StrEnum):
    camera = "camera"
    nvr = "nvr"
    unspecified = "unspecified"


class RemoteAccess(StrEnum):
    lan_only = "lan_only"
    lan_vpn_only = "lan_vpn_only"
    cloud_p2p = "cloud_p2p"
    unspecified = "unspecified"


class Tristate(StrEnum):
    required = "required"
    forbidden = "forbidden"
    undecided = "undecided"


class TimeSource(StrEnum):
    nvr_sync = "nvr_sync"
    ntp = "ntp"
    unspecified = "unspecified"


class HttpsRequired(StrEnum):
    required = "required"
    forbidden = "forbidden"
    unspecified = "unspecified"


class CameraProtocol(StrEnum):
    hikvision = "hikvision"
    onvif_allowed = "onvif_allowed"
    unspecified = "unspecified"


class PtzMode(StrEnum):
    static_home_preset = "static_home_preset"
    patrol = "patrol"
    auto_tracking = "auto_tracking"
    manual = "manual"
    undecided = "undecided"


class SystemRequirements(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    recording_mode: RecordingMode = RecordingMode.unspecified
    min_retention_days: int | None = None
    analytics_location: AnalyticsLocation = AnalyticsLocation.unspecified
    timeline_markers_required: bool | None = None
    remote_access: RemoteAccess = RemoteAccess.unspecified
    hik_connect: Tristate = Tristate.undecided
    time_source: TimeSource = TimeSource.unspecified
    https_required: HttpsRequired = HttpsRequired.unspecified


class DeviceRequirements(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    camera_protocol: CameraProtocol = CameraProtocol.unspecified
    ptz_mode: PtzMode = PtzMode.undecided
    auto_tracking: Tristate = Tristate.undecided
    required_events: tuple[str, ...] = ()
    event_targets: tuple[str, ...] = ()
    notify_center_required: bool | None = None


class RequirementsProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    profile_version: int = 1
    system: SystemRequirements = Field(default_factory=SystemRequirements)
    devices: dict[str, DeviceRequirements] = Field(default_factory=dict)