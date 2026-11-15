from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network

import httpx
import pytest

from haca.devices.models import ResolvedDevice
from haca.devices.network_policy import NetworkPolicy
from haca.devices.registry import DeviceRegistry
from haca.security.egress import EgressPolicy
from haca.security.endpoint_policy import EndpointPolicy, EndpointRule
from haca.security.errors import PolicyViolation
from haca.security.transport_guard import ReadOnlyTransport

_SUBNET = IPv4Network("192.168.250.0/24")


def _registry() -> DeviceRegistry:
    policy = NetworkPolicy(_SUBNET, simulation=False)
    device = ResolvedDevice(
        id="nvr01",
        role="nvr",
        expected_model="SYNTH-NVR",
        host=IPv4Address("192.168.250.200"),
        port=80,
        scheme="http",
        credential_ref="nvr01",
    )
    return DeviceRegistry([device], policy)


def _endpoint_policy() -> EndpointPolicy:
    return EndpointPolicy(
        [
            EndpointRule(
                id="system.device_info",
                path_template="/ISAPI/System/deviceInfo",
                method="GET",
                sensitivity="normal",
            )
        ]
    )


def _egress(registry: DeviceRegistry) -> EgressPolicy:
    hosts = {device.host for device in registry.all()}
    return EgressPolicy(hosts)


class CountingTransport(httpx.BaseTransport):
    def __init__(self, responses: list[httpx.Response] | None = None) -> None:
        self.count = 0
        self._responses = list(responses or [httpx.Response(200)])
        self._index = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.count += 1
        if self._index < len(self._responses):
            response = self._responses[self._index]
            self._index += 1
            return response
        return httpx.Response(200)

    def close(self) -> None:
        pass


@pytest.mark.security
@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("http://192.168.250.201/ISAPI/System/deviceInfo", "egress_denied"),
        ("http://192.168.250.200:8080/ISAPI/System/deviceInfo", "unknown_device"),
        ("https://192.168.250.200/ISAPI/System/deviceInfo", "unknown_device"),
        ("http://nvr.local/ISAPI/System/deviceInfo", "egress_denied"),
        ("http://8.8.8.8/ISAPI/System/deviceInfo", "egress_denied"),
    ],
)
def test_transport_rejects_before_inner(url: str, reason: str) -> None:
    registry = _registry()
    inner = CountingTransport()
    transport = ReadOnlyTransport(inner, registry, _endpoint_policy(), _egress(registry))
    request = httpx.Request("GET", url)
    with pytest.raises(PolicyViolation) as exc_info:
        transport.handle_request(request)
    assert exc_info.value.reason_code == reason
    assert inner.count == 0


@pytest.mark.security
def test_upgrade_header_rejected() -> None:
    registry = _registry()
    inner = CountingTransport()
    transport = ReadOnlyTransport(inner, registry, _endpoint_policy(), _egress(registry))
    request = httpx.Request(
        "GET",
        "http://192.168.250.200/ISAPI/System/deviceInfo",
        headers={"Upgrade": "websocket"},
    )
    with pytest.raises(PolicyViolation) as exc_info:
        transport.handle_request(request)
    assert exc_info.value.reason_code == "upgrade_denied"
    assert inner.count == 0


@pytest.mark.security
def test_cookie_header_allowed_to_reach_inner() -> None:
    registry = _registry()
    inner = CountingTransport()
    transport = ReadOnlyTransport(inner, registry, _endpoint_policy(), _egress(registry))
    request = httpx.Request(
        "GET",
        "http://192.168.250.200/ISAPI/System/deviceInfo",
        headers={"Cookie": "session=synthetic"},
    )
    transport.handle_request(request)
    assert inner.count == 1


@pytest.mark.security
def test_digest_retry_invokes_guard_twice() -> None:
    registry = _registry()
    challenge = httpx.Response(
        401,
        headers={
            "WWW-Authenticate": (
                'Digest realm="SYNTH", nonce="abc", qop="auth", opaque="x"'
            ),
        },
    )
    success = httpx.Response(200, content=b"<DeviceInfo/>")
    inner = CountingTransport([challenge, success])
    transport = ReadOnlyTransport(inner, registry, _endpoint_policy(), _egress(registry))
    client = httpx.Client(
        transport=transport,
        auth=httpx.DigestAuth("synthetic_user", "synthetic_pass"),
    )
    response = client.get("http://192.168.250.200/ISAPI/System/deviceInfo")
    assert response.status_code == 200
    assert inner.count == 2
    client.close()


@pytest.mark.security
def test_allowed_request_delegates_to_inner() -> None:
    registry = _registry()
    inner = CountingTransport()
    transport = ReadOnlyTransport(inner, registry, _endpoint_policy(), _egress(registry))
    request = httpx.Request("GET", "http://192.168.250.200/ISAPI/System/deviceInfo")
    response = transport.handle_request(request)
    assert response.status_code == 200
    assert inner.count == 1


@pytest.mark.security
def test_query_string_checked_separately_from_path() -> None:
    registry = _registry()
    policy = EndpointPolicy(
        [
            EndpointRule(
                id="system.device_info",
                path_template="/ISAPI/System/deviceInfo",
                method="GET",
                sensitivity="normal",
                allowed_query=frozenset({"format"}),
            )
        ]
    )
    inner = CountingTransport()
    transport = ReadOnlyTransport(inner, registry, policy, _egress(registry))
    ok = httpx.Request("GET", "http://192.168.250.200/ISAPI/System/deviceInfo?format=json")
    assert transport.handle_request(ok).status_code == 200
    bad = httpx.Request("GET", "http://192.168.250.200/ISAPI/System/deviceInfo?cmd=reboot")
    with pytest.raises(PolicyViolation) as exc_info:
        transport.handle_request(bad)
    assert exc_info.value.reason_code == "query_not_allowed"
    assert inner.count == 1