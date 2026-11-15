from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network
from typing import Literal

import pytest

from haca.devices.models import ResolvedDevice
from haca.devices.network_policy import NetworkPolicy
from haca.devices.registry import DeviceRegistry, DuplicateDeviceEndpointError, UnknownDevice

SUBNET = IPv4Network("192.168.250.0/24")


def _device(
    device_id: str,
    host: str,
    *,
    port: int = 80,
    scheme: Literal["http", "https"] = "http",
) -> ResolvedDevice:
    return ResolvedDevice(
        id=device_id,
        role="nvr",
        expected_model="SYNTH-NVR",
        host=IPv4Address(host),
        port=port,
        scheme=scheme,
        credential_ref=device_id,
    )


def test_match_returns_device_for_exact_endpoint() -> None:
    policy = NetworkPolicy(SUBNET, simulation=False)
    ptz = _device("ptz01", "192.168.250.201")
    registry = DeviceRegistry([ptz], policy)
    assert registry.match("192.168.250.201", 80, "http") == ptz


@pytest.mark.parametrize(
    ("host", "port", "scheme"),
    [
        ("nvr.local", 80, "http"),
        ("192.168.250.201", 8080, "http"),
        ("192.168.250.201", 80, "https"),
        ("192.168.250.0200", 80, "http"),
        ("2001:db8::1", 80, "http"),
    ],
)
def test_match_returns_none_for_non_matches(host: str, port: int, scheme: str) -> None:
    policy = NetworkPolicy(SUBNET, simulation=False)
    registry = DeviceRegistry([_device("nvr01", "192.168.250.200")], policy)
    assert registry.match(host, port, scheme) is None


def test_duplicate_host_port_raises() -> None:
    policy = NetworkPolicy(SUBNET, simulation=False)
    first = _device("nvr01", "192.168.250.200")
    second = _device("nvr02", "192.168.250.200")
    with pytest.raises(DuplicateDeviceEndpointError):
        DeviceRegistry([first, second], policy)


def test_get_unknown_raises() -> None:
    policy = NetworkPolicy(SUBNET, simulation=False)
    registry = DeviceRegistry([_device("nvr01", "192.168.250.200")], policy)
    with pytest.raises(UnknownDevice):
        registry.get("missing")


def test_all_returns_tuple() -> None:
    policy = NetworkPolicy(SUBNET, simulation=False)
    devices = [_device("nvr01", "192.168.250.200"), _device("ptz01", "192.168.250.201")]
    registry = DeviceRegistry(devices, policy)
    assert registry.all() == tuple(devices)