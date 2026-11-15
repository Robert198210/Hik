# ruff: noqa: S104, S105, S106, S107, S324, E501
"""T1.09 QA: methods, denylist variants, hosts, redirects (ADR-001 read-only enforcement)."""

from __future__ import annotations

import httpx
import pytest

from haca.devices.network_policy import NetworkPolicy
from haca.devices.registry import DeviceRegistry
from haca.security.endpoint_policy import EndpointPolicy, EndpointRule
from haca.security.errors import PolicyViolation
from haca.simulation.defaults import build_simulation_network, simulation_registry

from .helpers import (
    DEVICE_HOST,
    DEVICE_INFO_BODY,
    DEVICE_INFO_URL,
    SUBNET,
    CountingTransport,
    make_client,
    make_guard,
    make_registry,
    permissive_policy,
)

pytestmark = pytest.mark.security

# ---------------------------------------------------------------------------
# 1. Methods
# ---------------------------------------------------------------------------

_BAD_METHODS = [
    "PUT",
    "DELETE",
    "PATCH",
    "HEAD",
    "OPTIONS",
    "POST",
    "TRACE",
    "CONNECT",
    "PROPFIND",
    "MKCOL",
    "COPY",
    "MOVE",
    "SEARCH",
    "REBOOT",
]


@pytest.mark.parametrize("method", _BAD_METHODS)
def test_read_only_transport_blocks_non_get_before_inner(method: str) -> None:
    inner = CountingTransport()
    guard = make_guard(inner)
    request = httpx.Request(method, DEVICE_INFO_URL, content=b"<x/>")
    with pytest.raises(PolicyViolation) as exc:
        guard.handle_request(request)
    assert exc.value.reason_code == "method_not_allowed"
    assert inner.calls == []


@pytest.mark.parametrize("method", _BAD_METHODS)
def test_isapi_client_underlying_httpx_client_blocks_non_get(method: str) -> None:
    """Even if a caller reaches the internal httpx.Client, the transport chain refuses."""
    inner = CountingTransport()
    with make_client(inner) as client, pytest.raises(PolicyViolation):
        client._client.request(method, DEVICE_INFO_URL, content=b"<x/>")  # noqa: SLF001
    assert inner.calls == []


def test_isapi_client_public_surface_is_read_only() -> None:
    from haca.isapi.client import IsapiClient

    public = sorted(n for n in dir(IsapiClient) if not n.startswith("_"))
    assert public == ["close", "read"]


def test_read_only_transport_streaming_body_post_fails_closed() -> None:
    inner = CountingTransport()
    guard = make_guard(inner)

    def gen() -> object:
        yield b"<x/>"

    request = httpx.Request("POST", DEVICE_INFO_URL, content=gen())  # type: ignore[arg-type]
    with pytest.raises(Exception):  # noqa: B017, PT011 - any refusal is fine; must not reach inner
        guard.handle_request(request)
    assert inner.calls == []


def test_read_does_not_accept_extra_params_or_unknown_ids() -> None:
    inner = CountingTransport()
    with make_client(inner) as client:
        with pytest.raises(PolicyViolation):
            client.read("system.device_info", channel=1)
        for bad in ("", "system.reboot", "SYSTEM.DEVICE_INFO", "system.device_info ", "../x"):
            with pytest.raises(PolicyViolation):
                client.read(bad)
    assert inner.calls == []


@pytest.mark.xfail(
    strict=True, reason="DEF-T1.04-2: authorize() normalises method with str.upper()"
)
def test_policy_rejects_non_ascii_or_lowercase_method_spellings() -> None:
    policy = EndpointPolicy(
        [
            EndpointRule(
                id="qa.post",
                path_template="/ISAPI/Log/search",
                method="POST",
                read_post=True,
                sensitivity="normal",
                post_root_elements=frozenset({"Search"}),
            )
        ]
    )
    for method in ("POſT", "post", "Post"):  # 'ſ' (U+017F) upper-cases to 'S'
        with pytest.raises(PolicyViolation):
            policy.authorize(method, "/ISAPI/Log/search", "", b"<Search/>")


# ---------------------------------------------------------------------------
# 2. Denylist variants (permissive rule that allowlists the exact raw path)
# ---------------------------------------------------------------------------

_DENY_BASES = [
    "/ISAPI/System/reboot",
    "/ISAPI/System/factoryReset",
    "/ISAPI/System/factoryDefault",
    "/ISAPI/System/upgrade",
    "/ISAPI/System/updateFirmware",
    "/ISAPI/System/firmware",
    "/ISAPI/System/configurationData",
    "/ISAPI/PTZCtrl/channels/1/continuous",
    "/ISAPI/PTZCtrl/channels/1/momentary",
    "/ISAPI/PTZCtrl/channels/1/absolute",
    "/ISAPI/PTZCtrl/channels/1/relative",
    "/ISAPI/PTZCtrl/channels/1/presets/1/goto",
    "/ISAPI/PTZCtrl/channels/1/homeposition",
    "/ISAPI/PTZCtrl/channels/1/patrols/1/start",
    "/ISAPI/PTZCtrl/channels/1/auxcontrols/1",
    "/ISAPI/ContentMgmt/Storage/hdd/1/format",
    "/ISAPI/ContentMgmt/Storage/format",
    "/ISAPI/Security/users",
    "/ISAPI/Security/users/1",
    "/ISAPI/System/activate",
    "/ISAPI/System/password",
    "/SDK/x",
    "/PSIA/x",
    "/cgi-bin/x",
]


def _encode_last_segment(path: str) -> str:
    head, _, tail = path.rpartition("/")
    return head + "/" + "".join(f"%{ord(c):02X}" for c in tail)


def _encode_first_letter_last_segment(path: str) -> str:
    head, _, tail = path.rpartition("/")
    return head + "/" + f"%{ord(tail[0]):02x}" + tail[1:]


_TRANSFORMS = {
    "identity": lambda p: p,
    "upper": str.upper,
    "lower": str.lower,
    "swapcase": str.swapcase,
    "encode_last_segment_upper_hex": _encode_last_segment,
    "encode_first_letter_lower_hex": _encode_first_letter_last_segment,
    "semicolon_param": lambda p: p + ";jsessionid=1",
}

_DENY_CASES = [
    pytest.param(name, base, id=f"{name}:{base}") for name in _TRANSFORMS for base in _DENY_BASES
]


@pytest.mark.parametrize(("transform", "base"), _DENY_CASES)
def test_denylist_variants_rejected_even_with_permissive_rule(transform: str, base: str) -> None:
    raw = _TRANSFORMS[transform](base)
    if not raw.isascii() or raw.startswith("%"):
        pytest.skip("not representable")
    policy = permissive_policy(raw)
    with pytest.raises(PolicyViolation) as exc:
        policy.authorize("GET", raw, "", None)
    assert exc.value.reason_code in {"denylist_match", "path_hygiene"}


@pytest.mark.parametrize(("transform", "base"), _DENY_CASES)
def test_denylist_variants_never_reach_inner_through_phase1_policy(
    transform: str, base: str
) -> None:
    raw = _TRANSFORMS[transform](base)
    inner = CountingTransport()
    guard = make_guard(inner)
    try:
        request = httpx.Request("GET", f"http://{DEVICE_HOST}{raw}")
    except httpx.InvalidURL:
        return
    with pytest.raises(PolicyViolation):
        guard.handle_request(request)
    assert inner.calls == []


_TRAVERSAL_RAW = [
    "/ISAPI/System/deviceInfo/../reboot",
    "/ISAPI/System/%2e%2e/reboot",
    "/ISAPI/System/%2E%2E/reboot",
    "/ISAPI/System/..%2freboot",
    "/ISAPI/System/..%2Freboot",
    "/ISAPI/System/..%5creboot",
    "/ISAPI/System/deviceInfo%2f..%2freboot",
    "/ISAPI/System/deviceInfo%00/reboot",
    "/ISAPI/System/deviceInfo%00",
    "/ISAPI/System\\reboot",
    "/ISAPI/System/./reboot",
    "/ISAPI//System/reboot",
    "/ISAPI/System/deviceInfo/..",
    "/ISAPI/System/deviceInfo/.",
    "/ISAPI/System/%252e%252e/reboot",
    "/ISAPI/System/%252Freboot",
    "/ISAPI/System/%c0%ae%c0%ae/reboot",
    "/ISAPI/System/%c0%af",
    "/ISAPI/System/%ff",
    "/ISAPI/System/\uff52eboot",
    "/ISAPI/System/reb\u00f6ot",
    "/ISAPI/System/%u002e%u002e/reboot",
    "/ISAPI/System/deviceInfo%20",
    "/ISAPI/System/deviceInfo%09",
    "/ISAPI/System/device%49nfo",
    "/ISAPI/System/deviceinfo",
    "/isapi/system/deviceInfo",
    "/ISAPI/System/deviceInfo/",
    "ISAPI/System/deviceInfo",
    "",
    "/",
    "*",
]


@pytest.mark.parametrize("raw", _TRAVERSAL_RAW)
def test_traversal_and_encoding_variants_rejected_by_policy(raw: str) -> None:
    policy = EndpointPolicy(
        [
            EndpointRule(
                id="d", path_template="/ISAPI/System/deviceInfo", method="GET", sensitivity="normal"
            )
        ]
    )
    with pytest.raises(PolicyViolation):
        policy.authorize("GET", raw, "", None)


@pytest.mark.parametrize("query", ["reboot=1", "%72eboot=1", "a=1&b=2", "format", "x;y=1", "='"])
def test_unknown_query_keys_rejected(query: str) -> None:
    inner = CountingTransport()
    guard = make_guard(inner)
    request = httpx.Request("GET", f"{DEVICE_INFO_URL}?{query}")
    with pytest.raises(PolicyViolation):
        guard.handle_request(request)
    assert inner.calls == []


def test_fragment_is_not_part_of_policy_decision() -> None:
    inner = CountingTransport()
    guard = make_guard(inner)
    # fragments are stripped by httpx and never sent; request must still be the same safe path
    request = httpx.Request("GET", f"{DEVICE_INFO_URL}#/../reboot")
    guard.handle_request(request)
    assert inner.calls
    assert b"reboot" not in request.url.raw_path


@pytest.mark.xfail(
    strict=True,
    reason="DEF-T1.04-1: denylist '.*' does not cross %0a/%0d and hygiene does not reject control chars",
)
@pytest.mark.parametrize(
    "raw",
    [
        "/ISAPI/PTZCtrl/channels/1%0a/continuous",
        "/ISAPI/PTZCtrl/channels/1%0d%0a/presets/1/goto",
    ],
)
def test_control_characters_in_path_do_not_bypass_structured_denylist(raw: str) -> None:
    policy = permissive_policy(raw)
    with pytest.raises(PolicyViolation):
        policy.authorize("GET", raw, "", None)


# ---------------------------------------------------------------------------
# 3. Hosts / egress through ReadOnlyTransport
# ---------------------------------------------------------------------------

_BAD_URLS = [
    "http://8.8.8.8/ISAPI/System/deviceInfo",
    "http://1.1.1.1/ISAPI/System/deviceInfo",
    "http://192.168.1.10/ISAPI/System/deviceInfo",
    "http://10.0.0.5/ISAPI/System/deviceInfo",
    "http://172.16.0.5/ISAPI/System/deviceInfo",
    "http://169.254.169.254/ISAPI/System/deviceInfo",
    "http://127.0.0.1/ISAPI/System/deviceInfo",
    "http://localhost/ISAPI/System/deviceInfo",
    "http://nvr.local/ISAPI/System/deviceInfo",
    "http://example.com/ISAPI/System/deviceInfo",
    "http://[::1]/ISAPI/System/deviceInfo",
    "http://[::ffff:192.168.250.200]/ISAPI/System/deviceInfo",
    "http://[fe80::1]/ISAPI/System/deviceInfo",
    f"http://{DEVICE_HOST}:8080/ISAPI/System/deviceInfo",
    f"http://{DEVICE_HOST}:443/ISAPI/System/deviceInfo",
    f"https://{DEVICE_HOST}/ISAPI/System/deviceInfo",
    f"https://{DEVICE_HOST}:80/ISAPI/System/deviceInfo",
    f"ftp://{DEVICE_HOST}/ISAPI/System/deviceInfo",
    f"ws://{DEVICE_HOST}/ISAPI/System/deviceInfo",
    f"http://{DEVICE_HOST}./ISAPI/System/deviceInfo",
    "http://192.168.250.0200/ISAPI/System/deviceInfo",
    "http://3232299208/ISAPI/System/deviceInfo",
    "http://0xC0A8FAC8/ISAPI/System/deviceInfo",
    "http://0300.0250.0372.0310/ISAPI/System/deviceInfo",
    "http://192.168.250.201/ISAPI/System/deviceInfo",
    f"http://{DEVICE_HOST}@8.8.8.8/ISAPI/System/deviceInfo",
    "http://user:pw@8.8.8.8:80/ISAPI/System/deviceInfo",
    f"http://8.8.8.8#@{DEVICE_HOST}/ISAPI/System/deviceInfo",
    "https://generativelanguage.googleapis.com/ISAPI/System/deviceInfo",
]


@pytest.mark.parametrize("url", _BAD_URLS)
@pytest.mark.parametrize("allow_gemini", [False, True])
def test_bad_targets_rejected_before_inner(url: str, allow_gemini: bool) -> None:
    inner = CountingTransport()
    guard = make_guard(inner, allow_gemini=allow_gemini)
    try:
        request = httpx.Request("GET", url)
    except (httpx.InvalidURL, httpx.UnsupportedProtocol):
        return  # refused at URL construction: also acceptable
    with pytest.raises(PolicyViolation):
        guard.handle_request(request)
    assert inner.calls == []


def test_positive_control_exact_device_url_reaches_inner() -> None:
    inner = CountingTransport()
    guard = make_guard(inner)
    guard.handle_request(httpx.Request("GET", DEVICE_INFO_URL))
    assert len(inner.calls) == 1


def test_default_port_forms_are_equivalent_and_allowed() -> None:
    inner = CountingTransport()
    guard = make_guard(inner)
    guard.handle_request(httpx.Request("GET", f"http://{DEVICE_HOST}:80/ISAPI/System/deviceInfo"))
    assert len(inner.calls) == 1


@pytest.mark.parametrize(
    "host",
    [
        "nvr.local",
        "localhost",
        "",
        " 192.168.250.200",
        "192.168.250.200 ",
        "192.168.250.200\n",
        "192.168.250.200.",
        "192.168.250.0200",
        "192.168.250.0x10",
        "0xC0A8FAC8",
        "3232299208",
        "192.168.250",
        "192.168.250.200.1",
        "\uff11\uff19\uff12.168.250.200",
        "::ffff:192.168.250.200",
        "[::1]",
        "2001:db8::1",
        "192.168.250.256",
        "192.168.250.-1",
        "192.168.250.+1",
    ],
)
def test_registry_match_is_strict_ipv4_literal(host: str) -> None:
    registry = make_registry()
    assert registry.match(host, 80, "http") is None


@pytest.mark.parametrize(
    ("port", "scheme"),
    [
        (0, "http"),
        (-1, "http"),
        (81, "http"),
        (65616, "http"),
        (80, "HTTP"),
        (80, "https"),
        (80, ""),
    ],
)
def test_registry_match_rejects_port_scheme_variants(port: int, scheme: str) -> None:
    assert make_registry().match(DEVICE_HOST, port, scheme) is None


def test_simulation_registry_only_matches_synthetic_hosts() -> None:
    registry = simulation_registry()
    assert registry.match("127.0.0.1", 80, "http") is None
    assert registry.match("192.168.250.200", 80, "http") is not None
    assert registry.match("192.168.250.203", 80, "http") is None


def test_non_simulation_registry_rejects_loopback_device() -> None:
    from ipaddress import IPv4Address

    from haca.devices.models import ResolvedDevice
    from haca.devices.network_policy import NetworkPolicyViolation

    device = ResolvedDevice(
        id="lo01",
        role="nvr",
        expected_model="X",
        host=IPv4Address("127.0.0.1"),
        port=80,
        scheme="http",
        credential_ref="lo01",
    )
    with pytest.raises(NetworkPolicyViolation):
        DeviceRegistry([device], NetworkPolicy(SUBNET, simulation=False))


# ---------------------------------------------------------------------------
# 4. Redirects and statuses via IsapiClient
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize(
    "location",
    [
        "http://8.8.8.8/",
        f"http://{DEVICE_HOST}/ISAPI/System/reboot",
        "/ISAPI/System/reboot",
        "http://192.168.250.201/ISAPI/System/deviceInfo",
    ],
)
def test_redirects_never_followed(status: int, location: str) -> None:
    from haca.isapi.errors import UnexpectedStatus

    inner = CountingTransport(lambda _r: httpx.Response(status, headers={"Location": location}))
    with make_client(inner) as client, pytest.raises(UnexpectedStatus) as exc:
        client.read("system.device_info")
    assert exc.value.http_status == status
    assert len(inner.calls) == 1


def test_simulator_request_log_only_get_even_after_rejections() -> None:
    network = build_simulation_network()
    registry = simulation_registry()
    device = registry.get("nvr01")
    from pydantic import SecretStr

    from haca.config.models import TimeoutConfig
    from haca.isapi.client import IsapiClient
    from haca.isapi.errors import AuthError
    from haca.isapi.registry.phase1_endpoints import build_phase1_policy
    from haca.security.credentials import Credential
    from haca.security.egress import EgressPolicy

    client = IsapiClient(
        device,
        Credential(username="synthetic", password=SecretStr("nope")),
        registry,
        build_phase1_policy(),
        EgressPolicy({device.host}),
        TimeoutConfig(),
        inner_transport=network.transport(),
        sleep=lambda _s: None,
    )
    with client:
        with pytest.raises(AuthError):
            client.read("system.device_info")
        with pytest.raises(PolicyViolation):
            client._client.request("PUT", DEVICE_INFO_URL.replace(DEVICE_HOST, "192.168.250.200"))  # noqa: SLF001
    assert network.request_log
    assert {m for _d, m, _p in network.request_log} == {"GET"}


def test_cookie_header_not_logged_by_guard(caplog: pytest.LogCaptureFixture) -> None:
    inner = CountingTransport(lambda _r: httpx.Response(200, content=DEVICE_INFO_BODY))
    guard = make_guard(inner)
    caplog.set_level("DEBUG")
    request = httpx.Request("GET", DEVICE_INFO_URL, headers={"Cookie": "SESSION=QA-COOKIE-CANARY"})
    guard.handle_request(request)
    with pytest.raises(PolicyViolation):
        guard.handle_request(
            httpx.Request("PUT", DEVICE_INFO_URL, headers={"Cookie": "SESSION=QA-COOKIE-CANARY"})
        )
    assert "QA-COOKIE-CANARY" not in caplog.text
    assert make_registry() is not None
