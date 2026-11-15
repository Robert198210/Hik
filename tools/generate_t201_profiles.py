#!/usr/bin/env python3
"""One-shot generator for T2.01 scenario profiles (synthetic data only)."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import yaml

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from haca.isapi.registry.loader import (  # noqa: E402
    entries_for_role,
    load_registry_entries,
    render_endpoint_path,
)

_NS = 'xmlns="http://www.hikvision.com/ver20/XMLSchema"'
PROFILES = _REPO / "src/haca/simulation/profiles"
SHARED_NOT_SUPPORT = (
    "../../shared/edge-cases/response_status_not_support.xml"
)
SHARED_NOT_FOUND = "../../shared/edge-cases/response_status_url_not_found.xml"

DEVICES: dict[str, str] = {"nvr01": "nvr", "ptz01": "ptz", "cam01": "camera"}


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _provenance() -> str:
    return (
        "origin: synthetic\n"
        "synthetic_profiles: true\n"
        "real_device_validated: false\n"
        "notes: T2.01 scenario fixture; ADR-017 synthetic values only.\n"
    )


def device_info_xml(device_id: str) -> str:
    meta = {
        "nvr01": (
            "SYNTHETIC NVR01",
            "DS-7616NXI-K2(D)",
            "NVR",
            "V4.99.000",
            "00:00:5E:00:53:00",
        ),
        "ptz01": (
            "SYNTHETIC PTZ01",
            "DS-2DE4425IWG1-E",
            "IPDome",
            "V5.99.000",
            "00:00:5E:00:53:01",
        ),
        "cam01": (
            "SYNTHETIC CAM01",
            "DS-2CD2087G3-LI2UY/SL",
            "IPCamera",
            "V5.99.000",
            "00:00:5E:00:53:02",
        ),
    }
    name, model, dtype, fw, mac = meta[device_id]
    serial = f"SYNTH-{device_id.upper()}-0001"
    uid = {
        "nvr01": "00000000-0000-0000-0000-000000000000",
        "ptz01": "00000000-0000-0000-0000-000000000001",
        "cam01": "00000000-0000-0000-0000-000000000002",
    }[device_id]
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<DeviceInfo version="2.0" {_NS}>
  <deviceName>{name}</deviceName>
  <deviceID>{uid}</deviceID>
  <model>{model}</model>
  <serialNumber>{serial}</serialNumber>
  <macAddress>{mac}</macAddress>
  <firmwareVersion>{fw}</firmwareVersion>
  <firmwareReleasedDate>build 991231</firmwareReleasedDate>
  <deviceType>{dtype}</deviceType>
  <manufacturer>hikvision</manufacturer>
</DeviceInfo>
"""


def time_xml(mode: str) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<Time {_NS}>
  <timeMode>{mode}</timeMode>
  <localTime>2026-11-15T12:00:00+01:00</localTime>
  <timeZone>CST-1:00:00</timeZone>
</Time>
"""


def ntp_xml() -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<NTPServerList {_NS}>
  <NTPServer>
    <id>1</id>
    <addressingFormatType>hostname</addressingFormatType>
    <hostName>pool.ntp.synthetic.local</hostName>
    <portNo>123</portNo>
    <synchronizeInterval>60</synchronizeInterval>
  </NTPServer>
</NTPServerList>
"""


def network_xml(ip: str) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<NetworkInterfaceList {_NS}>
  <NetworkInterface>
    <id>1</id>
    <IPAddress>
      <ipVersion>v4</ipVersion>
      <addressingType>static</addressingType>
      <ipAddress>{ip}</ipAddress>
      <subnetMask>192.168.250.0</subnetMask>
      <DefaultGateway>
        <ipAddress>192.168.250.1</ipAddress>
      </DefaultGateway>
    </IPAddress>
  </NetworkInterface>
</NetworkInterfaceList>
"""


def admin_access_xml(http_on: bool, https_on: bool) -> str:
    def row(proto: str, enabled: bool, port: int) -> str:
        return f"""  <AdminAccessProtocol>
    <id>{port}</id>
    <enabled>{"true" if enabled else "false"}</enabled>
    <protocol>{proto}</protocol>
    <portNo>{port}</portNo>
  </AdminAccessProtocol>"""

    rows = [
        row("HTTP", http_on, 80),
        row("HTTPS", https_on, 443),
        row("RTSP", True, 554),
        row("DEV_MANAGE", True, 8000),
    ]
    body = "\n".join(rows)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<AdminAccessProtocolList {_NS}>
{body}
</AdminAccessProtocolList>
"""


def streaming_xml() -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<StreamingChannelList {_NS}>
  <StreamingChannel>
    <id>101</id>
    <channelName>Main</channelName>
    <enabled>true</enabled>
    <Video>
      <videoCodecType>H.265</videoCodecType>
      <videoResolutionWidth>2560</videoResolutionWidth>
      <videoResolutionHeight>1440</videoResolutionHeight>
      <videoQualityControlType>CBR</videoQualityControlType>
      <constantBitRate>4096</constantBitRate>
      <maxFrameRate>2500</maxFrameRate>
      <GovLength>50</GovLength>
      <SmartCodec>
        <enabled>true</enabled>
      </SmartCodec>
    </Video>
  </StreamingChannel>
</StreamingChannelList>
"""


def smart_cap_xml(region: bool) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<SmartCap {_NS}>
  <isSupportLineDetection>true</isSupportLineDetection>
  <isSupportFieldDetection>true</isSupportFieldDetection>
  <isSupportRegionEntrance>{"true" if region else "false"}</isSupportRegionEntrance>
</SmartCap>
"""


def line_detection_xml(enabled: bool, items_enabled: bool) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<LineDetection {_NS}>
  <id>1</id>
  <enabled>{"true" if enabled else "false"}</enabled>
  <LineItemList>
    <LineItem>
      <id>1</id>
      <enabled>{"true" if items_enabled else "false"}</enabled>
      <sensitivityLevel>50</sensitivityLevel>
      <directionSensitivity>any</directionSensitivity>
      <detectionTarget>human,vehicle</detectionTarget>
      <CoordinatesList>
        <Coordinates><positionX>10</positionX><positionY>10</positionY></Coordinates>
        <Coordinates><positionX>90</positionX><positionY>90</positionY></Coordinates>
      </CoordinatesList>
    </LineItem>
  </LineItemList>
</LineDetection>
"""


def field_detection_xml(empty_target: bool, no_coords: bool) -> str:
    target = "" if empty_target else "human,vehicle"
    coords = (
        ""
        if no_coords
        else """      <RegionCoordinatesList>
        <RegionCoordinates><positionX>5</positionX><positionY>5</positionY></RegionCoordinates>
      </RegionCoordinatesList>"""
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<FieldDetection {_NS}>
  <id>1</id>
  <enabled>true</enabled>
  <FieldDetectionRegionList>
    <FieldDetectionRegion>
      <id>1</id>
      <enabled>true</enabled>
      <sensitivityLevel>50</sensitivityLevel>
      <timeThreshold>5</timeThreshold>
      <detectionTarget>{target}</detectionTarget>
{coords}
    </FieldDetectionRegion>
  </FieldDetectionRegionList>
</FieldDetection>
"""


def region_entrance_xml() -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<RegionEntrance {_NS}>
  <id>1</id>
  <enabled>true</enabled>
  <RegionEntranceRegionList>
    <RegionEntranceRegion>
      <id>1</id>
      <enabled>true</enabled>
      <sensitivityLevel>50</sensitivityLevel>
      <detectionTarget>human,vehicle</detectionTarget>
      <RegionCoordinatesList>
        <RegionCoordinates><positionX>1</positionX><positionY>1</positionY></RegionCoordinates>
      </RegionCoordinatesList>
    </RegionEntranceRegion>
  </RegionEntranceRegionList>
</RegionEntrance>
"""


def triggers_xml(with_center: bool, protocol_onvif: bool) -> str:
    methods = ["record"]
    if with_center:
        methods.append("center")
    method_xml = "\n".join(
        f"""      <EventTriggerNotification>
        <id>{i + 1}</id>
        <notificationMethod>{m}</notificationMethod>
        <videoInputID>1</videoInputID>
      </EventTriggerNotification>"""
        for i, m in enumerate(methods)
    )
    extra = ""
    if protocol_onvif:
        extra = """
  <EventTrigger>
    <id>2</id>
    <eventType>VMD</eventType>
    <videoInputChannelID>1</videoInputChannelID>
    <EventTriggerNotificationList>
      <EventTriggerNotification>
        <id>1</id>
        <notificationMethod>record</notificationMethod>
        <videoInputID>1</videoInputID>
      </EventTriggerNotification>
    </EventTriggerNotificationList>
  </EventTrigger>"""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<EventTriggerList {_NS}>
  <EventTrigger>
    <id>1</id>
    <eventType>linedetection</eventType>
    <videoInputChannelID>1</videoInputChannelID>
    <EventTriggerNotificationList>
{method_xml}
    </EventTriggerNotificationList>
  </EventTrigger>{extra}
</EventTriggerList>
"""


def tracks_xml(weekend_motion: bool) -> str:
    mode_week = "CMR" if not weekend_motion else "MOTION"
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<TrackList {_NS}>
  <Track>
    <id>101</id>
    <Channel>1</Channel>
    <Enable>true</Enable>
    <DefaultRecordingMode>CMR</DefaultRecordingMode>
    <PreRecordTimeSeconds>5</PreRecordTimeSeconds>
    <PostRecordTimeSeconds>5</PostRecordTimeSeconds>
    <TrackSchedule>
      <ScheduleBlockList>
        <ScheduleBlock>
          <id>1</id>
          <ScheduleAction>
            <id>1</id>
            <ScheduleActionStartTime><DayOfWeek>Monday</DayOfWeek><TimeOfDay>00:00:00</TimeOfDay></ScheduleActionStartTime>
            <ScheduleActionEndTime><DayOfWeek>Friday</DayOfWeek><TimeOfDay>23:59:59</TimeOfDay></ScheduleActionEndTime>
            <Actions><Record>true</Record><ActionRecordingMode>CMR</ActionRecordingMode></Actions>
          </ScheduleAction>
          <ScheduleAction>
            <id>2</id>
            <ScheduleActionStartTime><DayOfWeek>Saturday</DayOfWeek><TimeOfDay>00:00:00</TimeOfDay></ScheduleActionStartTime>
            <ScheduleActionEndTime><DayOfWeek>Sunday</DayOfWeek><TimeOfDay>23:59:59</TimeOfDay></ScheduleActionEndTime>
            <Actions><Record>true</Record><ActionRecordingMode>{mode_week}</ActionRecordingMode></Actions>
          </ScheduleAction>
        </ScheduleBlock>
      </ScheduleBlockList>
    </TrackSchedule>
  </Track>
</TrackList>
"""


def hdd_xml(status: str) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<hddList {_NS}>
  <hdd>
    <id>1</id>
    <hddName>SYNTH-HDD1</hddName>
    <hddType>SATA</hddType>
    <status>{status}</status>
    <capacity>8000000</capacity>
    <freeSpace>4000000</freeSpace>
    <property>RW</property>
  </hdd>
</hddList>
"""


def input_proxy_xml(onvif_ch1: bool, orphan_ch2: bool) -> str:
    proto1 = "ONVIF" if onvif_ch1 else "HIKVISION"
    ch2 = ""
    if orphan_ch2:
        ch2 = """
  <InputProxyChannel>
    <id>2</id>
    <name>orphan-camera</name>
    <sourceInputPortDescriptor>
      <proxyProtocol>HIKVISION</proxyProtocol>
      <addressingFormatType>ipAddress</addressingFormatType>
      <ipAddress>192.168.250.250</ipAddress>
      <managePortNo>8000</managePortNo>
      <srcInputPort>2</srcInputPort>
      <userName>synthetic</userName>
      <streamType>auto</streamType>
    </sourceInputPortDescriptor>
  </InputProxyChannel>"""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<InputProxyChannelList {_NS}>
  <InputProxyChannel>
    <id>1</id>
    <name>cam01-channel</name>
    <sourceInputPortDescriptor>
      <proxyProtocol>{proto1}</proxyProtocol>
      <addressingFormatType>ipAddress</addressingFormatType>
      <ipAddress>192.168.250.202</ipAddress>
      <managePortNo>8000</managePortNo>
      <srcInputPort>1</srcInputPort>
      <userName>synthetic</userName>
      <streamType>auto</streamType>
    </sourceInputPortDescriptor>
  </InputProxyChannel>{ch2}
</InputProxyChannelList>
"""


def input_proxy_status_xml(offline_ch2: bool) -> str:
    ch2 = ""
    if offline_ch2:
        ch2 = """
  <InputProxyChannelStatus>
    <id>2</id>
    <sourceInputPortDescriptor>
      <ipAddress>192.168.250.250</ipAddress>
    </sourceInputPortDescriptor>
    <online>false</online>
  </InputProxyChannelStatus>"""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<InputProxyChannelStatusList {_NS}>
  <InputProxyChannelStatus>
    <id>1</id>
    <sourceInputPortDescriptor>
      <ipAddress>192.168.250.202</ipAddress>
    </sourceInputPortDescriptor>
    <online>true</online>
  </InputProxyChannelStatus>{ch2}
</InputProxyChannelStatusList>
"""


def park_action_xml() -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<ParkAction {_NS}>
  <enabled>true</enabled>
  <Parktime>300</Parktime>
  <Action>
    <ActionType>preset</ActionType>
    <ActionNum>1</ActionNum>
  </Action>
</ParkAction>
"""


def patrols_xml() -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<PTZPatrolList {_NS}>
  <PTZPatrol>
    <id>1</id>
    <enabled>true</enabled>
    <patrolName>default-patrol</patrolName>
  </PTZPatrol>
</PTZPatrolList>
"""


def presets_xml() -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<PTZPresetList {_NS}>
  <PTZPreset>
    <id>1</id>
    <enabled>true</enabled>
    <presetName>home</presetName>
  </PTZPreset>
</PTZPresetList>
"""


def ezviz_xml(enabled: bool) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<EZVIZ {_NS}>
  <enabled>{"true" if enabled else "false"}</enabled>
</EZVIZ>
"""


FILE_BUILDERS: dict[str, str] = {}


def scenario_params(scenario: str) -> dict[str, object]:
    if scenario == "scenario-clean":
        return {
            "time_mode": "NTP",
            "http": True,
            "https": True,
            "region_cap": True,
            "line_enabled": True,
            "line_items": True,
            "field_empty_target": False,
            "field_no_coords": False,
            "triggers_center": True,
            "tracks_weekend_motion": False,
            "hdd_status": "ok",
            "onvif_ch1": False,
            "orphan_ch2": False,
            "offline_ch2": False,
            "ezviz_enabled": True,
            "park_404": False,
            "ezviz_not_support": False,
        }
    if scenario == "scenario-conflicts":
        return {
            "time_mode_by_device": {"ptz01": "manual"},
            "http": True,
            "https": True,
            "region_cap": True,
            "line_enabled": True,
            "line_items": False,
            "field_empty_target": True,
            "field_no_coords": True,
            "triggers_center": False,
            "tracks_weekend_motion": True,
            "hdd_status": "error",
            "onvif_ch1": True,
            "orphan_ch2": True,
            "offline_ch2": True,
            "ezviz_enabled": True,
            "park_404": False,
            "ezviz_not_support": False,
        }
    if scenario == "scenario-unsupported":
        return {
            "time_mode": "NTP",
            "http": True,
            "https": True,
            "region_cap": False,
            "line_enabled": True,
            "line_items": True,
            "field_empty_target": False,
            "field_no_coords": False,
            "triggers_center": True,
            "tracks_weekend_motion": False,
            "hdd_status": "ok",
            "onvif_ch1": False,
            "orphan_ch2": False,
            "offline_ch2": False,
            "ezviz_enabled": True,
            "park_404": True,
            "ezviz_not_support_ptz": True,
        }
    raise ValueError(scenario)


def build_files(device_id: str, scenario: str, params: dict[str, object]) -> dict[str, str]:
    ips = {
        "nvr01": "192.168.250.200",
        "ptz01": "192.168.250.201",
        "cam01": "192.168.250.202",
    }
    ip = ips[device_id]
    time_mode = str(params.get("time_mode", "NTP"))
    if "time_mode_by_device" in params:
        time_mode = str(params["time_mode_by_device"].get(device_id, time_mode))  # type: ignore[union-attr]

    files = {
        "device_info.xml": device_info_xml(device_id),
        "time.xml": time_xml(time_mode),
        "ntp_servers.xml": ntp_xml(),
        "network_interfaces.xml": network_xml(ip),
        "admin_accesses.xml": admin_access_xml(bool(params["http"]), bool(params["https"])),
        "streaming_channels.xml": streaming_xml(),
        "event_triggers.xml": triggers_xml(
            bool(params["triggers_center"]),
            bool(params.get("onvif_ch1") and device_id == "nvr01"),
        ),
        "platform_ezviz.xml": ezviz_xml(bool(params["ezviz_enabled"])),
    }

    if device_id in {"ptz01", "cam01"}:
        files["smart_capabilities.xml"] = smart_cap_xml(bool(params["region_cap"]))
        files["line_detection.xml"] = line_detection_xml(
            bool(params["line_enabled"]),
            bool(params["line_items"]),
        )
        files["field_detection.xml"] = field_detection_xml(
            bool(params["field_empty_target"]),
            bool(params["field_no_coords"]),
        )
        files["region_entrance.xml"] = region_entrance_xml()

    if device_id == "ptz01":
        files["ptz_patrols.xml"] = patrols_xml()
        files["ptz_presets.xml"] = presets_xml()
        if not bool(params["park_404"]):
            files["ptz_park_action.xml"] = park_action_xml()

    if device_id == "nvr01":
        files["record_tracks.xml"] = tracks_xml(bool(params["tracks_weekend_motion"]))
        files["storage_hdd.xml"] = hdd_xml(str(params["hdd_status"]))
        files["input_proxy_channels.xml"] = input_proxy_xml(
            bool(params["onvif_ch1"]),
            bool(params["orphan_ch2"]),
        )
        files["input_proxy_status.xml"] = input_proxy_status_xml(bool(params["offline_ch2"]))

    return files


ENDPOINT_FILES: dict[str, str] = {
    "system.device_info": "device_info.xml",
    "system.time": "time.xml",
    "system.time.ntp_servers": "ntp_servers.xml",
    "system.network.interfaces": "network_interfaces.xml",
    "security.admin_accesses": "admin_accesses.xml",
    "streaming.channels": "streaming_channels.xml",
    "smart.capabilities": "smart_capabilities.xml",
    "smart.line_detection": "line_detection.xml",
    "smart.field_detection": "field_detection.xml",
    "smart.region_entrance": "region_entrance.xml",
    "event.triggers": "event_triggers.xml",
    "ptz.park_action": "ptz_park_action.xml",
    "ptz.patrols": "ptz_patrols.xml",
    "ptz.presets": "ptz_presets.xml",
    "record.tracks": "record_tracks.xml",
    "storage.hdd": "storage_hdd.xml",
    "input_proxy.channels": "input_proxy_channels.xml",
    "input_proxy.channels_status": "input_proxy_status.xml",
    "platform.ezviz": "platform_ezviz.xml",
}


def build_index(
    device_id: str,
    role: str,
    scenario: str,
    entries: tuple,
    params: dict[str, object],
) -> dict[str, dict[str, object]]:
    paths: dict[str, dict[str, object]] = {}
    for entry in entries_for_role(entries, role):  # type: ignore[arg-type]
        if entry.sensitivity == "denied":
            continue
        path = render_endpoint_path(entry)
        file_name = ENDPOINT_FILES.get(entry.id)
        if file_name is None:
            continue

        if entry.id == "ptz.park_action" and bool(params.get("park_404")):
            paths[path] = {"file": SHARED_NOT_FOUND, "status": 404}
            continue

        if (
            entry.id == "platform.ezviz"
            and device_id == "ptz01"
            and bool(params.get("ezviz_not_support_ptz"))
        ):
            paths[path] = {"file": SHARED_NOT_SUPPORT, "status": 200}
            continue

        if entry.id == "smart.region_entrance" and scenario == "scenario-conflicts":
            # Variant-only firmware: primary path returns RequestUrlNotFound.
            paths[path] = {"file": SHARED_NOT_FOUND, "status": 404}
            for variant in entry.variants:
                vpath = variant.replace("{channel}", "1")
                paths[vpath] = {"file": file_name, "status": 200}
            continue

        paths[path] = {"file": file_name, "status": 200}

    return paths


def main() -> None:
    registry = load_registry_entries()
    for scenario in ("scenario-clean", "scenario-conflicts", "scenario-unsupported"):
        params = scenario_params(scenario)
        for device_id, role in DEVICES.items():
            dest = PROFILES / device_id / scenario
            if dest.is_dir():
                shutil.rmtree(dest)
            dest.mkdir(parents=True, exist_ok=True)
            _write(dest / "provenance.yaml", _provenance())
            xml_map = build_files(device_id, scenario, params)
            for name, content in xml_map.items():
                _write(dest / name, content)
            index = {"paths": build_index(device_id, role, scenario, registry, params)}
            _write(dest / "index.yaml", yaml.safe_dump(index, sort_keys=False))


if __name__ == "__main__":
    main()