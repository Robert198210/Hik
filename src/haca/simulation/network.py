"""Simulated LAN of Hikvision devices."""

from __future__ import annotations

import httpx

from haca.simulation.device import SimulatedDevice

_SIM_USERNAME = "synthetic"
_SIM_PASSWORD = "synthetic-pass"


class SimulatedNetwork:
    def __init__(self, devices: dict[tuple[str, int], SimulatedDevice]) -> None:
        self._devices = devices
        self.request_log: list[tuple[str, str, str]] = []

    @property
    def username(self) -> str:
        return _SIM_USERNAME

    @property
    def password(self) -> str:
        return _SIM_PASSWORD

    def transport(self) -> httpx.MockTransport:
        """Return an ``httpx.MockTransport`` routing requests by host and port."""

        def handler(request: httpx.Request) -> httpx.Response:
            host = request.url.host or ""
            port = request.url.port
            if port is None:
                port = 443 if request.url.scheme == "https" else 80
            device = self._devices.get((host, port))
            if device is None:
                msg = f"no simulated device at {host}:{port}"
                raise httpx.ConnectError(msg)
            raw_path = request.url.raw_path.split(b"?", 1)[0].decode("ascii")
            self.request_log.append((device.device_id, request.method, raw_path))
            return device.handle(request)

        return httpx.MockTransport(handler)