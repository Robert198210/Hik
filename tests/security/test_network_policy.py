from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network

import pytest

from haca.devices.network_policy import NetworkPolicy, NetworkPolicyViolation

SUBNET = IPv4Network("192.168.250.0/24")


@pytest.mark.security
@pytest.mark.parametrize(
    "address",
    [
        IPv4Address("8.8.8.8"),
        IPv4Address("192.168.1.10"),
        IPv4Address("127.0.0.1"),
        IPv4Address("169.254.1.1"),
        IPv4Address("192.168.250.0"),
        IPv4Address("192.168.250.255"),
    ],
)
def test_rejects_disallowed_addresses_without_simulation(address: IPv4Address) -> None:
    policy = NetworkPolicy(SUBNET, simulation=False)
    with pytest.raises(NetworkPolicyViolation):
        policy.check_host(address)


@pytest.mark.security
def test_allows_loopback_in_simulation() -> None:
    policy = NetworkPolicy(SUBNET, simulation=True)
    policy.check_host(IPv4Address("127.0.0.1"))


@pytest.mark.security
def test_allows_host_inside_subnet() -> None:
    policy = NetworkPolicy(SUBNET, simulation=False)
    policy.check_host(IPv4Address("192.168.250.201"))