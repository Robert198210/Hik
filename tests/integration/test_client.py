from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network

import httpx
import pytest
from pydantic import SecretStr

from haca.config.models import TimeoutConfig
from haca.devices.models import ResolvedDevice
from haca.devices.network_policy import NetworkPolicy
from haca.devices.registry import DeviceRegistry
from haca.isapi.client import IsapiClient
from haca.isapi.errors import (
    AuthError,
    DeviceConnectionError,
    EndpointNotFound,
    NotSupportedError,
    UnexpectedStatus,
    XmlParseError,
)
from haca.isapi.registry.phase1_endpoints import build_phase1_policy
from haca.security.credentials import Credential
from haca.security.egress import EgressPolicy
from haca.security.endpoint_policy import EndpointPolicy, EndpointRule
from haca.security.errors import PolicyViolation

_SUBNET = IPv4Network("192.168.250.0/24")


def _device() -> ResolvedDevice:
    return ResolvedDevice(
        id="nvr01",
        role="nvr",
        expected_model="SYNTH-NVR",
        host=IPv4Address("192.168.250.200"),
        port=80,
        scheme="http",
        credential_ref="nvr01",
    )


def _registry(device: ResolvedDevice) -> DeviceRegistry:
    return DeviceRegistry([device], NetworkPolicy(_SUBNET, simulation=False))


def _client(
    handler: httpx.MockTransport,
    *,
    policy: EndpointPolicy | None = None,
) -> IsapiClient:
    device = _device()
    registry = _registry(device)
    policy = policy or build_phase1_policy()
    egress = EgressPolicy({device.host})
    cred = Credential(username="admin", password=SecretStr("synthetic_pass"))
    return IsapiClient(
        device,
        cred,
        registry,
        policy,
        egress,
        TimeoutConfig(),
        inner_transport=handler,
        sleep=lambda _secs: None,
    )


_DEVICE_INFO = b"""<?xml version="1.0"?>
<DeviceInfo xmlns="http://www.hikvision.com/ver20/XMLSchema">
    <model>SYNTH-NVR</model>
</DeviceInfo>"""


@pytest.mark.simulation
def test_read_device_info_parses_model() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=_DEVICE_INFO)

    with _client(httpx.MockTransport(handler)) as client:
        response = client.read("system.device_info")
    assert response.document is not None
    assert response.document.text("model") == "SYNTH-NVR"


@pytest.mark.simulation
def test_response_status_not_support_maps_to_error() -> None:
    body = b"""<ResponseStatus><subStatusCode>notSupport</subStatusCode></ResponseStatus>"""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body)

    with _client(httpx.MockTransport(handler)) as client, pytest.raises(NotSupportedError):
        client.read("system.device_info")


@pytest.mark.simulation
def test_401_with_response_status_body_is_auth_error() -> None:
    body = b"""<ResponseStatus><statusCode>4</statusCode>
<subStatusCode>badAuthorization</subStatusCode></ResponseStatus>"""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, content=body)

    with _client(httpx.MockTransport(handler)) as client, pytest.raises(AuthError):
        client.read("system.device_info")


@pytest.mark.simulation
def test_403_with_not_support_body_is_not_supported() -> None:
    body = b"""<ResponseStatus><subStatusCode>notSupport</subStatusCode></ResponseStatus>"""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, content=body)

    with _client(httpx.MockTransport(handler)) as client, pytest.raises(NotSupportedError):
        client.read("system.device_info")


@pytest.mark.simulation
def test_response_status_url_not_found() -> None:
    body = b"""<ResponseStatus><subStatusCode>RequestUrlNotFound</subStatusCode></ResponseStatus>"""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, content=body)

    with _client(httpx.MockTransport(handler)) as client, pytest.raises(EndpointNotFound):
        client.read("system.device_info")


class _CountingTransport(httpx.BaseTransport):
    def __init__(self, responses: list[httpx.Response]) -> None:
        self.count = 0
        self._responses = responses

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.count += 1
        return self._responses[min(self.count - 1, len(self._responses) - 1)]

    def close(self) -> None:
        pass


@pytest.mark.simulation
def test_digest_challenge_then_success() -> None:
    challenge = httpx.Response(
        401,
        headers={
            "WWW-Authenticate": 'Digest realm="SYNTH", nonce="n", qop="auth", opaque="o"',
        },
    )
    success = httpx.Response(200, content=_DEVICE_INFO)
    inner = _CountingTransport([challenge, success])
    with _client(inner) as client:
        response = client.read("system.device_info")
    assert response.http_status == 200
    assert inner.count == 2


@pytest.mark.simulation
def test_invalid_digest_credentials_raise_auth_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            headers={
                "WWW-Authenticate": 'Digest realm="SYNTH", nonce="n", qop="auth", opaque="o"',
            },
        )

    with _client(httpx.MockTransport(handler)) as client, pytest.raises(AuthError):
        client.read("system.device_info")


@pytest.mark.simulation
def test_redirect_not_followed() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(302, headers={"Location": "http://8.8.8.8/"})

    with (
        _client(httpx.MockTransport(handler)) as client,
        pytest.raises(UnexpectedStatus) as exc_info,
    ):
        client.read("system.device_info")
    assert exc_info.value.http_status == 302
    assert len(calls) == 1


@pytest.mark.simulation
def test_read_timeout_retries_then_succeeds() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            raise httpx.ReadTimeout("read timeout")
        return httpx.Response(200, content=_DEVICE_INFO)

    sleeps: list[float] = []

    device = _device()
    registry = _registry(device)
    cred = Credential(username="admin", password=SecretStr("synthetic_pass"))
    client = IsapiClient(
        device,
        cred,
        registry,
        build_phase1_policy(),
        EgressPolicy({device.host}),
        TimeoutConfig(),
        inner_transport=httpx.MockTransport(handler),
        sleep=sleeps.append,
    )
    with client:
        response = client.read("system.device_info")
    assert response.http_status == 200
    assert sleeps == [0.5, 1.0]


@pytest.mark.simulation
def test_connect_error_exhausted_raises_device_connection_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    with _client(httpx.MockTransport(handler)) as client, pytest.raises(DeviceConnectionError):
        client.read("system.device_info")


@pytest.mark.simulation
def test_http_500_is_unexpected_without_retry() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(500)

    with _client(httpx.MockTransport(handler)) as client, pytest.raises(UnexpectedStatus):
        client.read("system.device_info")
    assert calls["n"] == 1


@pytest.mark.simulation
def test_xxe_body_raises_xml_parse_error() -> None:
    body = b'<?xml version="1.0"?><!DOCTYPE a [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><a>&xxe;</a>'

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body)

    with _client(httpx.MockTransport(handler)) as client, pytest.raises(XmlParseError):
        client.read("system.device_info")


@pytest.mark.simulation
def test_unknown_endpoint_and_denied_raise_before_transport() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, content=_DEVICE_INFO)

    denied = EndpointPolicy(
        [
            EndpointRule(
                id="denied.endpoint",
                path_template="/ISAPI/System/deviceInfo",
                method="GET",
                sensitivity="denied",
            )
        ]
    )
    with (
        _client(httpx.MockTransport(handler), policy=denied) as client,
        pytest.raises(PolicyViolation),
    ):
        client.read("denied.endpoint")
    with _client(httpx.MockTransport(handler)) as client, pytest.raises(PolicyViolation):
        client.read("unknown.id")
    assert calls == []