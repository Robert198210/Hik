"""In-memory registry of configured devices."""

from __future__ import annotations

from ipaddress import IPv4Address

from haca.config.models import AppConfig, ResolvedDeviceConfig
from haca.devices.models import ResolvedDevice
from haca.devices.network_policy import NetworkPolicy


class UnknownDevice(KeyError):
    """Raised when a device id is not present in the registry."""


class DuplicateDeviceEndpointError(ValueError):
    """Raised when two devices share the same host and port."""


def _parse_ipv4_literal(host: str) -> IPv4Address | None:
    if ":" in host:
        return None
    if not host or host.endswith("."):
        return None
    parts = host.split(".")
    if len(parts) != 4:
        return None
    for part in parts:
        if not part.isdecimal():
            return None
        if len(part) > 1 and part[0] == "0":
            return None
        value = int(part, 10)
        if value > 255:
            return None
    try:
        return IPv4Address(host)
    except ValueError:
        return None


class DeviceRegistry:
    def __init__(self, devices: list[ResolvedDevice], policy: NetworkPolicy) -> None:
        self._policy = policy
        self._by_id: dict[str, ResolvedDevice] = {}
        self._endpoint_index: dict[tuple[IPv4Address, int, str], ResolvedDevice] = {}

        for device in devices:
            policy.check_host(device.host)
            endpoint = (device.host, device.port, device.scheme)
            if endpoint in self._endpoint_index:
                msg = (
                    f"duplicate endpoint {device.scheme}://{device.host}:{device.port} "
                    f"for devices {self._endpoint_index[endpoint].id!r} and {device.id!r}"
                )
                raise DuplicateDeviceEndpointError(msg)
            self._by_id[device.id] = device
            self._endpoint_index[endpoint] = device

        self._devices = tuple(devices)

    @classmethod
    def from_config(
        cls,
        app: AppConfig,
        devices: list[ResolvedDeviceConfig],
    ) -> DeviceRegistry:
        policy = NetworkPolicy(subnet=app.network.subnet, simulation=app.simulation)
        resolved = [
            ResolvedDevice(
                id=device.id,
                role=device.role,
                expected_model=device.expected_model,
                host=device.host,
                port=device.port,
                scheme=device.scheme,
                credential_ref=device.credential_ref,
            )
            for device in devices
        ]
        return cls(resolved, policy)

    def get(self, device_id: str) -> ResolvedDevice:
        try:
            return self._by_id[device_id]
        except KeyError as exc:
            raise UnknownDevice(device_id) from exc

    def match(self, host: str, port: int, scheme: str) -> ResolvedDevice | None:
        address = _parse_ipv4_literal(host)
        if address is None:
            return None
        return self._endpoint_index.get((address, port, scheme))

    def all(self) -> tuple[ResolvedDevice, ...]:
        return self._devices