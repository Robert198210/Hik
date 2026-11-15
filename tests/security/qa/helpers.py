# ruff: noqa: S105, S106, S107
"""Shared builders for QA adversarial tests (synthetic data only, no real network)."""

from __future__ import annotations

from collections.abc import Callable
from ipaddress import IPv4Address, IPv4Network

import httpx
from pydantic import SecretStr

from haca.config.models import TimeoutConfig
from haca.devices.models import ResolvedDevice
from haca.devices.network_policy import NetworkPolicy
from haca.devices.registry import DeviceRegistry
from haca.isapi.client import IsapiClient
from haca.isapi.registry.phase1_endpoints import build_phase1_policy
from haca.security.credentials import Credential
from haca.security.egress import EgressPolicy
from haca.security.endpoint_policy import EndpointPolicy, EndpointRule
from haca.security.transport_guard import ReadOnlyTransport

SUBNET = IPv4Network("192.168.250.0/24")
DEVICE_HOST = "192.168.250.200"
DEVICE_INFO_URL = f"http://{DEVICE_HOST}/ISAPI/System/deviceInfo"

Handler = Callable[[httpx.Request], httpx.Response]


def make_device(
    device_id: str = "nvr01",
    host: str = DEVICE_HOST,
    port: int = 80,
    scheme: str = "http",
) -> ResolvedDevice:
    return ResolvedDevice(
        id=device_id,
        role="nvr",
        expected_model="SYNTH-NVR",
        host=IPv4Address(host),
        port=port,
        scheme=scheme,  # type: ignore[arg-type]
        credential_ref=device_id,
    )


def make_registry(device: ResolvedDevice | None = None) -> DeviceRegistry:
    device = device or make_device()
    return DeviceRegistry([device], NetworkPolicy(SUBNET, simulation=False))


class CountingTransport(httpx.BaseTransport):
    """Inner transport that counts calls and records (method, url)."""

    def __init__(self, handler: Handler | None = None) -> None:
        self.calls: list[tuple[str, str]] = []
        self._handler = handler or (lambda _r: httpx.Response(200, content=b"<ok/>"))

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.calls.append((request.method, str(request.url)))
        return self._handler(request)


def make_guard(
    inner: httpx.BaseTransport,
    policy: EndpointPolicy | None = None,
    *,
    allow_gemini: bool = False,
) -> ReadOnlyTransport:
    registry = make_registry()
    hosts = {d.host for d in registry.all()}
    return ReadOnlyTransport(
        inner,
        registry,
        policy or build_phase1_policy(),
        EgressPolicy(hosts, allow_gemini=allow_gemini),
    )


def permissive_policy(raw_path: str) -> EndpointPolicy:
    """A deliberately permissive rule that allowlists exactly *raw_path* (denylist must win)."""
    rule = EndpointRule(
        id="qa.permissive",
        path_template=raw_path,
        method="GET",
        sensitivity="normal",
    )
    return EndpointPolicy([rule])


def make_client(
    inner: httpx.BaseTransport,
    *,
    password: str = "synthetic-pass",
    username: str = "synthetic",
    policy: EndpointPolicy | None = None,
    sleeps: list[float] | None = None,
) -> IsapiClient:
    device = make_device()
    registry = make_registry(device)
    sleeps_list = sleeps if sleeps is not None else []
    return IsapiClient(
        device,
        Credential(username=username, password=SecretStr(password)),
        registry,
        policy or build_phase1_policy(),
        EgressPolicy({device.host}),
        TimeoutConfig(),
        inner_transport=inner,
        sleep=sleeps_list.append,
    )


DEVICE_INFO_BODY = b"""<?xml version="1.0" encoding="UTF-8"?>
<DeviceInfo version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
  <deviceName>SYNTHETIC NVR01</deviceName>
  <model>SYNTH-NVR</model>
  <serialNumber>SYNTH-NVR01-0001</serialNumber>
  <macAddress>00:00:5E:00:53:00</macAddress>
  <firmwareVersion>V4.99.000</firmwareVersion>
  <deviceType>NVR</deviceType>
</DeviceInfo>"""
