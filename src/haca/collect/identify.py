"""Read-only device identification via ``system.device_info``."""

from __future__ import annotations

import logging
import re
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from haca.devices.models import ResolvedDevice
from haca.isapi.client import IsapiClient
from haca.isapi.errors import (
    AuthError,
    DeviceConnectionError,
    DeviceReportedError,
    DeviceTimeout,
    EndpointNotFound,
    IsapiError,
    NotSupportedError,
    XmlParseError,
)
from haca.security.errors import PolicyViolation

_LOGGER = logging.getLogger("haca.collect")

_FIRMWARE_RE = re.compile(r"^V(\d+)\.(\d+)\.(\d+)")


class IdentificationStatus(StrEnum):
    IDENTIFIED = "IDENTIFIED"
    MODEL_MISMATCH = "MODEL_MISMATCH"
    AUTH_FAILED = "AUTH_FAILED"
    UNREACHABLE = "UNREACHABLE"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    ENDPOINT_NOT_FOUND = "ENDPOINT_NOT_FOUND"
    POLICY_BLOCKED = "POLICY_BLOCKED"
    ERROR = "ERROR"


class DeviceIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    device_id: str
    model: str
    device_type: str
    firmware_version: str
    firmware_major: int | None
    firmware_minor: int | None
    firmware_patch: int | None
    firmware_build: str | None
    serial_masked: str
    mac_masked: str


class IdentificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    device_id: str
    status: IdentificationStatus
    identity: DeviceIdentity | None
    message: str
    simulated: bool


def mask_serial(serial: str) -> str:
    text = serial.strip()
    if len(text) < 4:
        return "****"
    return f"****{text[-4:]}"


def mask_mac(mac: str) -> str:
    parts = mac.strip().split(":")
    if len(parts) != 6:
        return "**:**:**:**:**:**"
    return f"**:**:**:**:{parts[4]}:{parts[5]}"


def parse_firmware(raw: str) -> tuple[str, int | None, int | None, int | None]:
    text = raw.strip()
    match = _FIRMWARE_RE.match(text)
    if match is None:
        return text, None, None, None
    major, minor, patch = (int(match.group(i)) for i in range(1, 4))
    return text, major, minor, patch


def identify(
    client: IsapiClient,
    device: ResolvedDevice,
    *,
    simulated: bool = False,
) -> IdentificationResult:
    try:
        response = client.read("system.device_info")
    except PolicyViolation as exc:
        _LOGGER.warning(
            "identification policy blocked for %s: %s",
            device.id,
            exc.reason_code,
        )
        return IdentificationResult(
            device_id=device.id,
            status=IdentificationStatus.POLICY_BLOCKED,
            identity=None,
            message=str(exc),
            simulated=simulated,
        )
    except AuthError as exc:
        return _error_result(device.id, IdentificationStatus.AUTH_FAILED, exc, simulated)
    except DeviceConnectionError as exc:
        return _error_result(device.id, IdentificationStatus.UNREACHABLE, exc, simulated)
    except DeviceTimeout as exc:
        return _error_result(device.id, IdentificationStatus.UNREACHABLE, exc, simulated)
    except NotSupportedError as exc:
        return _error_result(device.id, IdentificationStatus.NOT_SUPPORTED, exc, simulated)
    except EndpointNotFound as exc:
        return _error_result(device.id, IdentificationStatus.ENDPOINT_NOT_FOUND, exc, simulated)
    except (XmlParseError, DeviceReportedError, IsapiError) as exc:
        return _error_result(device.id, IdentificationStatus.ERROR, exc, simulated)
    except Exception as exc:  # noqa: BLE001
        return _error_result(device.id, IdentificationStatus.ERROR, exc, simulated)

    document = response.document
    if document is None:
        return IdentificationResult(
            device_id=device.id,
            status=IdentificationStatus.ERROR,
            identity=None,
            message="empty deviceInfo response",
            simulated=simulated,
        )

    model = (document.text("model") or "").strip()
    device_type = (document.text("deviceType") or "").strip()
    firmware_raw = document.text("firmwareVersion") or ""
    build = document.text("firmwareReleasedDate")
    serial = document.text("serialNumber") or ""
    mac = document.text("macAddress") or ""

    firmware_version, major, minor, patch = parse_firmware(firmware_raw)

    identity = DeviceIdentity(
        device_id=device.id,
        model=model,
        device_type=device_type,
        firmware_version=firmware_version,
        firmware_major=major,
        firmware_minor=minor,
        firmware_patch=patch,
        firmware_build=build,
        serial_masked=mask_serial(serial),
        mac_masked=mask_mac(mac),
    )

    if model != device.expected_model.strip():
        return IdentificationResult(
            device_id=device.id,
            status=IdentificationStatus.MODEL_MISMATCH,
            identity=identity,
            message=f"reported model {model!r} != expected {device.expected_model!r}",
            simulated=simulated,
        )

    return IdentificationResult(
        device_id=device.id,
        status=IdentificationStatus.IDENTIFIED,
        identity=identity,
        message="ok",
        simulated=simulated,
    )


def identify_devices(
    clients: list[tuple[ResolvedDevice, IsapiClient]],
    *,
    simulated: bool = False,
) -> list[IdentificationResult]:
    results: list[IdentificationResult] = []
    for device, client in clients:
        results.append(identify(client, device, simulated=simulated))
    return results


def _error_result(
    device_id: str,
    status: IdentificationStatus,
    exc: Exception,
    simulated: bool,
) -> IdentificationResult:
    message = getattr(exc, "message", None) or str(exc)
    return IdentificationResult(
        device_id=device_id,
        status=status,
        identity=None,
        message=message,
        simulated=simulated,
    )