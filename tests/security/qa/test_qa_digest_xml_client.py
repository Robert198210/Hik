# ruff: noqa: S104, S105, S106, S107, S324, E501
"""T1.09 QA: Digest flows, XML hostility, client error taxonomy, simulator Digest server."""

from __future__ import annotations

import hashlib

import httpx
import pytest

from haca.isapi.errors import (
    AuthError,
    DeviceConnectionError,
    DeviceTimeout,
    IsapiError,
    UnexpectedStatus,
    XmlParseError,
)
from haca.isapi.xml import parse_xml
from haca.simulation.device import SimulatedDevice
from haca.simulation.profile_loader import simulation_profiles_root

from .helpers import DEVICE_INFO_BODY, DEVICE_INFO_URL, CountingTransport, make_client

pytestmark = pytest.mark.security


def _md5(value: str) -> str:
    return hashlib.md5(value.encode(), usedforsecurity=False).hexdigest()


# ---------------------------------------------------------------------------
# Digest (client side, scripted device)
# ---------------------------------------------------------------------------


def _digest_device(user: str, password: str, *, qop: str | None, nonce: str = "n0nce"):
    """Scripted device: challenges, then verifies RFC 2069 / 7616 digests."""
    state = {"calls": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        state["calls"] += 1
        auth = request.headers.get("Authorization")
        challenge = f'Digest realm="QA", nonce="{nonce}"' + (f', qop="{qop}"' if qop else "")
        if auth is None:
            return httpx.Response(401, headers={"WWW-Authenticate": challenge})
        params = dict(
            part.strip().split("=", 1) for part in auth[len("Digest ") :].split(",") if "=" in part
        )
        params = {k: v.strip('"') for k, v in params.items()}
        ha1 = _md5(f"{user}:QA:{password}")
        ha2 = _md5(f"GET:{params.get('uri', '')}")
        if "qop" in params:
            expected = _md5(
                f"{ha1}:{nonce}:{params['nc']}:{params['cnonce']}:{params['qop']}:{ha2}"
            )
        else:
            expected = _md5(f"{ha1}:{nonce}:{ha2}")
        if params.get("response") == expected and params.get("username") == user:
            return httpx.Response(200, content=DEVICE_INFO_BODY)
        return httpx.Response(401, headers={"WWW-Authenticate": challenge})

    return handler, state


@pytest.mark.parametrize("qop", ["auth", None])
def test_digest_success_with_and_without_qop(qop: str | None) -> None:
    handler, state = _digest_device("synthetic", "synthetic-pass", qop=qop)
    inner = CountingTransport(handler)
    with make_client(inner) as client:
        response = client.read("system.device_info")
    assert response.document is not None
    assert state["calls"] == 2


@pytest.mark.parametrize("qop", ["auth", None])
def test_digest_wrong_password_exactly_two_calls(qop: str | None) -> None:
    handler, state = _digest_device("synthetic", "synthetic-pass", qop=qop)
    inner = CountingTransport(handler)
    with make_client(inner, password="wrong") as client, pytest.raises(AuthError):
        client.read("system.device_info")
    assert state["calls"] == 2


def test_digest_stale_nonce_repeated_401_is_auth_error_without_loop() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(
            401,
            headers={
                "WWW-Authenticate": 'Digest realm="QA", nonce="fresh", qop="auth", stale=true'
            },
        )

    with make_client(CountingTransport(handler)) as client, pytest.raises(AuthError):
        client.read("system.device_info")
    assert calls["n"] == 2


def test_digest_401_without_challenge_header_is_auth_error() -> None:
    inner = CountingTransport(lambda _r: httpx.Response(401))
    with make_client(inner) as client, pytest.raises(AuthError):
        client.read("system.device_info")
    assert len(inner.calls) == 1


def test_basic_challenge_is_never_answered_with_basic_credentials() -> None:
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("Authorization"))
        return httpx.Response(401, headers={"WWW-Authenticate": 'Basic realm="QA"'})

    with make_client(CountingTransport(handler)) as client, pytest.raises(AuthError):
        client.read("system.device_info")
    assert all(a is None for a in seen)  # no downgrade to Basic


@pytest.mark.xfail(
    strict=True,
    reason="DEF-T1.05-1: non-taxonomy httpx/builtin exceptions leak out of IsapiClient.read",
)
@pytest.mark.parametrize(
    "scenario",
    ["read_error", "remote_protocol", "write_error", "digest_no_nonce", "digest_unknown_algo"],
)
def test_all_transport_level_failures_map_to_isapi_error(scenario: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if scenario == "read_error":
            raise httpx.ReadError("boom")
        if scenario == "remote_protocol":
            raise httpx.RemoteProtocolError("boom")
        if scenario == "write_error":
            raise httpx.WriteError("boom")
        if scenario == "digest_no_nonce":
            return httpx.Response(401, headers={"WWW-Authenticate": 'Digest realm="x"'})
        return httpx.Response(
            401,
            headers={"WWW-Authenticate": 'Digest realm="x", nonce="n", algorithm=FOO'},
        )

    with make_client(CountingTransport(handler)) as client, pytest.raises(IsapiError):
        client.read("system.device_info")


def test_timeouts_and_connection_errors_use_taxonomy() -> None:
    sleeps: list[float] = []
    with (
        pytest.raises(DeviceTimeout),
        make_client(
            CountingTransport(lambda _r: (_ for _ in ()).throw(httpx.ReadTimeout("t"))),
            sleeps=sleeps,
        ) as client,
    ):
        client.read("system.device_info")
    assert sleeps == [0.5, 1.0]
    sleeps2: list[float] = []
    with (
        pytest.raises(DeviceConnectionError),
        make_client(
            CountingTransport(lambda _r: (_ for _ in ()).throw(httpx.ConnectError("c"))),
            sleeps=sleeps2,
        ) as client,
    ):
        client.read("system.device_info")
    assert sleeps2 == [0.5, 1.0]


@pytest.mark.parametrize("status", [400, 404 + 1, 418, 500, 501, 507])
def test_unexpected_http_statuses_do_not_retry(status: int) -> None:
    inner = CountingTransport(lambda _r: httpx.Response(status))
    with make_client(inner) as client, pytest.raises(IsapiError):
        client.read("system.device_info")
    assert len(inner.calls) == 1


@pytest.mark.parametrize("status", [502, 503, 504])
def test_gateway_statuses_retry_then_unexpected(status: int) -> None:
    sleeps: list[float] = []
    inner = CountingTransport(lambda _r: httpx.Response(status))
    with make_client(inner, sleeps=sleeps) as client, pytest.raises(UnexpectedStatus):
        client.read("system.device_info")
    assert len(inner.calls) == 3
    assert sleeps == [0.5, 1.0]


@pytest.mark.parametrize("status", [401, 403, 404, 405])
def test_auth_and_not_found_statuses_never_retry(status: int) -> None:
    inner = CountingTransport(lambda _r: httpx.Response(status))
    with make_client(inner) as client, pytest.raises(IsapiError):
        client.read("system.device_info")
    assert len(inner.calls) == 1


# ---------------------------------------------------------------------------
# Simulator Digest server (RFC 7616 subset)
# ---------------------------------------------------------------------------


def _sim() -> SimulatedDevice:
    return SimulatedDevice(
        "nvr01",
        simulation_profiles_root() / "nvr01" / "synthetic-default",
        username="synthetic",
        password="synthetic-pass",
    )


def _digest_header(
    user: str,
    password: str,
    nonce: str,
    *,
    qop: str | None = "auth",
    uri: str = "/ISAPI/System/deviceInfo",
    nc: str = "00000001",
    cnonce: str = "abc",
) -> str:
    ha1 = _md5(f"{user}:HACA-SIMULATED:{password}")
    ha2 = _md5(f"GET:{uri}")
    if qop:
        resp = _md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
        extra = f', qop={qop}, nc={nc}, cnonce="{cnonce}"'
    else:
        resp = _md5(f"{ha1}:{nonce}:{ha2}")
        extra = ""
    return (
        f'Digest username="{user}", realm="HACA-SIMULATED", nonce="{nonce}", '
        f'uri="{uri}", response="{resp}"{extra}'
    )


def _nonce_of(response: httpx.Response) -> str:
    header = response.headers["WWW-Authenticate"]
    return header.split('nonce="', 1)[1].split('"', 1)[0]


def _get(dev: SimulatedDevice, auth: str | None) -> httpx.Response:
    headers = {"Authorization": auth} if auth else {}
    return dev.handle(httpx.Request("GET", DEVICE_INFO_URL, headers=headers))


def test_simulator_challenge_shape_and_valid_auth() -> None:
    dev = _sim()
    challenge = _get(dev, None)
    assert challenge.status_code == 401
    header = challenge.headers["WWW-Authenticate"]
    assert 'realm="HACA-SIMULATED"' in header and 'qop="auth"' in header
    assert "algorithm=MD5" in header
    nonce = _nonce_of(challenge)
    assert _get(dev, _digest_header("synthetic", "synthetic-pass", nonce)).status_code == 200


def test_simulator_rejects_wrong_password_user_realm_and_unknown_nonce() -> None:
    dev = _sim()
    nonce = _nonce_of(_get(dev, None))
    assert _get(dev, _digest_header("synthetic", "wrong", nonce)).status_code == 401
    nonce = _nonce_of(_get(dev, None))
    assert _get(dev, _digest_header("other", "synthetic-pass", nonce)).status_code == 401
    assert (
        _get(dev, _digest_header("synthetic", "synthetic-pass", "deadbeefunknown")).status_code
        == 401
    )
    assert _get(dev, 'Digest username="synthetic"').status_code == 401
    assert _get(dev, "Digest").status_code == 401
    assert _get(dev, "Basic c3ludGhldGljOnN5bnRoZXRpYy1wYXNz").status_code == 401


def test_simulator_per_device_nonces_are_distinct() -> None:
    a, b = _sim(), _sim()
    assert _nonce_of(_get(a, None)) != _nonce_of(_get(b, None))
    nonce_a = _nonce_of(_get(a, None))
    assert _get(b, _digest_header("synthetic", "synthetic-pass", nonce_a)).status_code == 401


@pytest.mark.xfail(
    strict=True,
    reason="DEF-T1.07-1: rotated-out (stale) nonces stay valid; spec requires 401 for stale nonce",
)
def test_simulator_rejects_stale_nonce_after_rotation() -> None:
    dev = _sim()
    old_nonce = _nonce_of(_get(dev, None))
    rotated = _get(dev, _digest_header("synthetic", "wrong", old_nonce))  # forces rotation
    assert _nonce_of(rotated) != old_nonce
    assert _get(dev, _digest_header("synthetic", "synthetic-pass", old_nonce)).status_code == 401


def test_simulator_non_get_is_405_even_when_authenticated() -> None:
    dev = _sim()
    nonce = _nonce_of(_get(dev, None))
    auth = _digest_header("synthetic", "synthetic-pass", nonce)
    for method in ("PUT", "DELETE", "POST", "PATCH", "OPTIONS", "HEAD"):
        response = dev.handle(
            httpx.Request(method, DEVICE_INFO_URL, headers={"Authorization": auth})
        )
        assert response.status_code == 405


# ---------------------------------------------------------------------------
# XML hostility
# ---------------------------------------------------------------------------

_NS = 'xmlns="http://www.hikvision.com/ver20/XMLSchema"'


@pytest.mark.parametrize(
    "body",
    [
        b'<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/passwd">]><d>&x;</d>',
        b'<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x SYSTEM "http://192.168.250.1/x">]><d>&x;</d>',
        b'<?xml version="1.0"?><!DOCTYPE d SYSTEM "http://192.168.250.1/evil.dtd"><d/>',
        b'<?xml version="1.0"?><!DOCTYPE d [<!ENTITY % p SYSTEM "file:///etc/hostname"> %p;]><d/>',
        b'<?xml version="1.0"?><!DOCTYPE d [<!ENTITY a "x"><!ENTITY b "&a;&a;">]><d>&b;</d>',
        b'<?xml version="1.0"?><!DOCTYPE d [<!ELEMENT d ANY>]><d/>',
        b"<!DOCTYPE d><d/>",
        b'<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x "&#60;d/&#62;">]><d>&x;</d>',
    ],
)
def test_xxe_and_dtd_payloads_rejected_without_leaking_file_content(body: bytes) -> None:
    with pytest.raises(XmlParseError) as exc:
        parse_xml(body)
    assert "root:" not in str(exc.value)


def test_billion_laughs_and_quadratic_blowup_rejected_quickly() -> None:
    lol = ["<!ENTITY lol0 'SYNTH'>"]
    for i in range(1, 10):
        ref = f"&lol{i - 1};"
        lol.append(f"<!ENTITY lol{i} '{ref * 10}'>")
    body = f"<?xml version='1.0'?><!DOCTYPE l [{''.join(lol)}]><l>&lol9;</l>".encode()
    with pytest.raises(XmlParseError):
        parse_xml(body)
    quad = "<!ENTITY a '" + "x" * 5000 + "'>"
    body = f"<!DOCTYPE q [{quad}]><q>{'&a;' * 5000}</q>".encode()
    with pytest.raises(XmlParseError):
        parse_xml(body)


@pytest.mark.parametrize(
    "body",
    [
        f"<DeviceInfo {_NS}><model>M</model></DeviceInfo>".encode(),
        b"<DeviceInfo><model>M</model></DeviceInfo>",
        b'<DeviceInfo xmlns="urn:totally:wrong"><model>M</model></DeviceInfo>',
        b'<h:DeviceInfo xmlns:h="http://www.isapi.org/ver20/XMLSchema"><h:model>M</h:model></h:DeviceInfo>',
        b'<DeviceInfo xmlns="http://www.isapi.org/ver20/XMLSchema" version="1.0"><model>M</model></DeviceInfo>',
        b'<DeviceInfo xmlns="http://www.hikvision.com/ver20/XMLSchema"><x:model xmlns:x="urn:a">M</x:model></DeviceInfo>',
        b"\xef\xbb\xbf<DeviceInfo><model>M</model></DeviceInfo>",
        b"  \n\t\xef\xbb\xbf".strip() + b"<DeviceInfo><model>M</model></DeviceInfo>\n\n",
    ],
)
def test_namespace_and_bom_variants_are_namespace_agnostic(body: bytes) -> None:
    assert parse_xml(body).text("model") == "M"


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"   ",
        b"\xef\xbb\xbf",
        b"<a>",
        b"<a></b>",
        b"not xml",
        b"<a>\x00</a>",
        b"<a>\x01</a>",
        b"<?xml version='1.0' encoding='UTF-16'?><a/>",
        b"<a b='1' b='2'/>",
        b"<a xmlns:p=''><p:b/></a>",
        b"<a/><b/>",
    ],
)
def test_malformed_inputs_raise_only_xml_parse_error(body: bytes) -> None:
    with pytest.raises(XmlParseError):
        parse_xml(body)


@pytest.mark.parametrize(
    "body",
    [
        b"\xef\xbb\xbf\xef\xbb\xbf<a/>",
        b"\xff\xfe<\x00a\x00/\x00>\x00",
        b"\xfe\xff\x00<\x00a\x00/\x00>",
    ],
)
def test_unusual_but_wellformed_encodings_parse_to_plain_document(body: bytes) -> None:
    assert parse_xml(body).root_tag == "a"


@pytest.mark.xfail(
    strict=True,
    reason="DEF-T1.05-3: LookupError for unknown XML encoding escapes parse_xml",
)
def test_unknown_declared_encoding_raises_xml_parse_error() -> None:
    with pytest.raises(XmlParseError):
        parse_xml(b"<?xml version='1.0' encoding='bogus'?><a/>")


def test_size_limit_boundaries() -> None:
    pad = 5_000_000
    base = b"<a>"
    tail = b"</a>"
    ok = base + b"x" * (pad - len(base) - len(tail)) + tail
    assert len(ok) == pad
    assert parse_xml(ok).root_tag == "a"
    with pytest.raises(XmlParseError):
        parse_xml(ok + b" ")
    with pytest.raises(XmlParseError):
        parse_xml(b"<a/>", max_bytes=3)


def test_deep_nesting_is_handled_without_leaking_other_exceptions() -> None:
    depth = 50_000
    body = b"<a>" * depth + b"</a>" * depth
    try:
        doc = parse_xml(body)
    except XmlParseError:
        return
    assert doc.root_tag == "a"
    assert doc.text("a/a/a") is None


def test_error_message_is_bounded() -> None:
    with pytest.raises(XmlParseError) as exc:
        parse_xml(b"<a>" + b"Z" * 10_000)
    assert len(exc.value.message) < 200
    assert "Z" * 200 not in exc.value.message


def test_oversized_response_through_client_is_xml_parse_error() -> None:
    body = b"<DeviceInfo>" + b"x" * 5_000_000 + b"</DeviceInfo>"
    inner = CountingTransport(
        lambda _r: httpx.Response(200, content=body, headers={"Content-Type": "application/xml"})
    )
    with make_client(inner) as client, pytest.raises(XmlParseError):
        client.read("system.device_info")


def test_xxe_via_client_even_with_wrong_content_type() -> None:
    body = b'<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/passwd">]><d>&x;</d>'
    for ctype in ("application/xml", "text/xml", "text/html", "text/plain"):
        inner = CountingTransport(
            lambda _r, c=ctype: httpx.Response(200, content=body, headers={"Content-Type": c})
        )
        with make_client(inner) as client, pytest.raises(XmlParseError):
            client.read("system.device_info")


@pytest.mark.xfail(
    strict=True,
    reason="DEF-T1.05-2: XmlParseError raised by IsapiClient carries empty device_id/endpoint_id",
)
def test_xml_parse_error_from_client_is_attributed_to_device_and_endpoint() -> None:
    inner = CountingTransport(
        lambda _r: httpx.Response(
            200, content=b"<DeviceInfo><oops>", headers={"Content-Type": "application/xml"}
        )
    )
    with make_client(inner) as client, pytest.raises(XmlParseError) as exc:
        client.read("system.device_info")
    assert exc.value.device_id == "nvr01"
    assert exc.value.endpoint_id == "system.device_info"


def test_response_status_bodies_map_correctly_for_200_403_404() -> None:
    from haca.isapi.errors import DeviceReportedError, EndpointNotFound, NotSupportedError

    def status_body(sub: str, code: int = 4) -> bytes:
        return (
            f"<ResponseStatus {_NS}><requestURL>/x</requestURL><statusCode>{code}</statusCode>"
            f"<statusString>s</statusString><subStatusCode>{sub}</subStatusCode></ResponseStatus>"
        ).encode()

    cases = [
        (200, "notSupport", NotSupportedError),
        (403, "notSupport", NotSupportedError),
        (200, "RequestUrlNotFound", EndpointNotFound),
        (404, "RequestUrlNotFound", EndpointNotFound),
        (404, "urlNotFound", EndpointNotFound),
        (404, "", DeviceReportedError),
        (403, "", DeviceReportedError),
        (401, "notSupport", AuthError),
    ]
    for http_status, sub, expected in cases:
        body = status_body(sub)
        inner = CountingTransport(
            lambda _r, s=http_status, b=body: httpx.Response(
                s, content=b, headers={"Content-Type": "application/xml"}
            )
        )
        with make_client(inner) as client, pytest.raises(expected):
            client.read("system.device_info")
    for http_status, expected in ((403, AuthError), (404, EndpointNotFound)):
        inner = CountingTransport(lambda _r, s=http_status: httpx.Response(s))
        with make_client(inner) as client, pytest.raises(expected):
            client.read("system.device_info")
