"""Outbound connection egress policy."""

from __future__ import annotations

from ipaddress import IPv4Address

import httpx

from haca.security.errors import PolicyViolation

_GEMINI_HOST = "generativelanguage.googleapis.com"


def _parse_ipv4_host(host: str) -> IPv4Address | None:
    if not host or ":" in host:
        return None
    try:
        return IPv4Address(host)
    except ValueError:
        return None


class EgressPolicy:
    def __init__(self, device_hosts: set[IPv4Address], allow_gemini: bool = False) -> None:
        self._device_hosts = device_hosts
        self._allow_gemini = allow_gemini

    def check(self, url: httpx.URL) -> None:
        host = url.host or ""
        scheme = url.scheme
        port = url.port
        if port is None:
            port = 443 if scheme == "https" else 80

        if host == _GEMINI_HOST and scheme == "https" and port == 443 and self._allow_gemini:
            return

        address = _parse_ipv4_host(host)
        if address is not None and address in self._device_hosts:
            return

        raise PolicyViolation("egress_denied", f"egress to {scheme}://{host}:{port} denied")