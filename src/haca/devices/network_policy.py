"""Network egress policy for device endpoints."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network

_RFC1918: tuple[IPv4Network, ...] = (
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
)

_LINK_LOCAL = IPv4Network("169.254.0.0/16")
_MULTICAST = IPv4Network("224.0.0.0/4")
_LOOPBACK = IPv4Network("127.0.0.0/8")
_GLOBAL_BROADCAST = IPv4Address("255.255.255.255")


class NetworkPolicyViolation(Exception):
    """Raised when a target host violates the configured network policy."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class NetworkPolicy:
    """Restricts device communication to RFC1918 hosts within the configured subnet."""

    def __init__(self, subnet: IPv4Network, simulation: bool) -> None:
        self._subnet = subnet
        self._simulation = simulation

    @property
    def subnet(self) -> IPv4Network:
        return self._subnet

    @property
    def simulation(self) -> bool:
        return self._simulation

    def check_host(self, ip: IPv4Address) -> None:
        if ip in _LINK_LOCAL:
            raise NetworkPolicyViolation("link-local addresses are not allowed")

        if ip in _MULTICAST or ip == _GLOBAL_BROADCAST:
            raise NetworkPolicyViolation("multicast/broadcast addresses are not allowed")

        if ip in _LOOPBACK:
            if not self._simulation:
                raise NetworkPolicyViolation("loopback is only allowed in simulation mode")
            return

        if not self._in_rfc1918(ip):
            raise NetworkPolicyViolation(f"address {ip} is not in RFC1918 space")

        if ip == self._subnet.network_address:
            raise NetworkPolicyViolation("network address is not a valid host target")

        if ip == self._subnet.broadcast_address:
            raise NetworkPolicyViolation("subnet broadcast is not a valid host target")

        if ip not in self._subnet:
            msg = f"address {ip} is outside configured subnet {self._subnet}"
            raise NetworkPolicyViolation(msg)

    @staticmethod
    def _in_rfc1918(ip: IPv4Address) -> bool:
        return any(ip in network for network in _RFC1918)