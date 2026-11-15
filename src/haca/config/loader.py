"""Load and validate YAML configuration files."""

from __future__ import annotations

from ipaddress import IPv4Address
from pathlib import Path
from typing import Any, NoReturn

import yaml
from pydantic import ValidationError

from haca.config.errors import ConfigError
from haca.config.models import (
    AppConfig,
    DeviceConfig,
    DevicesFile,
    NetworkConfig,
    ResolvedDeviceConfig,
)


def _load_yaml(path: Path) -> Any:
    if not path.is_file():
        raise ConfigError(path, "", "configuration file not found")
    text = path.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        if mark is not None:
            message = f"invalid YAML at line {mark.line + 1}, column {mark.column + 1}"
        else:
            message = "invalid YAML syntax"
        raise ConfigError(path, "", message) from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(path, "", "root must be a mapping")
    return data


def _raise_pydantic(path: Path, field: str, exc: ValidationError) -> NoReturn:
    errors = exc.errors()
    first = errors[0] if errors else {"loc": (), "msg": str(exc)}
    loc = first.get("loc", ())
    subfield = ".".join(str(part) for part in loc) if loc else field
    message = str(first.get("msg", "validation error"))
    if any(ConfigError.secret_field_name(str(part)) for part in loc):
        message = "invalid or disallowed field"
    raise ConfigError(path, subfield or field, message) from exc


def _reject_secret_keys(path: Path, data: dict[str, Any], prefix: str = "") -> None:
    for key, value in data.items():
        field = f"{prefix}.{key}" if prefix else key
        if ConfigError.secret_field_name(key):
            raise ConfigError(
                path,
                field,
                "secret-like keys are not allowed in configuration files",
            )
        if isinstance(value, dict):
            _reject_secret_keys(path, value, field)


def load_app_config(path: Path) -> AppConfig:
    data = _load_yaml(path)
    _reject_secret_keys(path, data)
    try:
        return AppConfig.model_validate(data)
    except ValidationError as exc:
        _raise_pydantic(path, "", exc)


def _host_from_suffix(network: NetworkConfig, suffix: int) -> IPv4Address:
    if suffix < 1 or suffix > 254:
        raise ValueError("host_suffix must be in range 1–254")
    base = int(network.subnet.network_address)
    host_int = base + suffix
    host = IPv4Address(host_int)
    if host not in network.subnet:
        msg = f"resolved host {host} is outside configured subnet {network.subnet}"
        raise ValueError(msg)
    return host


def _resolve_device(device: DeviceConfig, network: NetworkConfig) -> ResolvedDeviceConfig:
    if device.host is not None:
        host = device.host
        if host not in network.subnet:
            msg = f"host {host} is outside configured subnet {network.subnet}"
            raise ValueError(msg)
    elif device.host_suffix is not None:
        host = _host_from_suffix(network, device.host_suffix)
    else:
        msg = "exactly one of host or host_suffix must be set"
        raise ValueError(msg)
    port = device.port if device.port is not None else (
        443 if device.scheme == "https" else 80
    )
    return ResolvedDeviceConfig(
        id=device.id,
        role=device.role,
        expected_model=device.expected_model,
        host=host,
        scheme=device.scheme,
        port=port,
        credential_ref=device.credential_ref,
        enabled=device.enabled,
    )


def load_devices(path: Path, network: NetworkConfig) -> list[ResolvedDeviceConfig]:
    data = _load_yaml(path)
    _reject_secret_keys(path, data)
    try:
        devices_file = DevicesFile.model_validate(data)
    except ValidationError as exc:
        _raise_pydantic(path, "devices", exc)

    seen: set[str] = set()
    resolved: list[ResolvedDeviceConfig] = []
    for index, device in enumerate(devices_file.devices):
        if device.id in seen:
            raise ConfigError(path, f"devices[{index}].id", "duplicate device id")
        seen.add(device.id)
        try:
            resolved.append(_resolve_device(device, network))
        except ValueError as exc:
            raise ConfigError(path, f"devices[{index}]", str(exc)) from exc
    return resolved