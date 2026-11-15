from __future__ import annotations

import pytest

from haca.security.endpoint_policy import EndpointPolicy, EndpointRule
from haca.security.errors import PolicyViolation

_DEVICE_INFO = EndpointRule(
    id="system.device_info",
    path_template="/ISAPI/System/deviceInfo",
    method="GET",
    sensitivity="normal",
)

_GET_RULE = _DEVICE_INFO

_LOG_SEARCH = EndpointRule(
    id="content.log_search",
    path_template="/ISAPI/ContentMgmt/logSearch",
    method="POST",
    read_post=True,
    sensitivity="normal",
    post_root_elements=frozenset({"CMSearchDescription"}),
)


def _policy_with_allow_all_denylist_paths() -> EndpointPolicy:
    """Rules that would allow denylisted paths if the denylist did not override."""
    rules = [
        EndpointRule(
            id=f"allow.{idx}",
            path_template=path,
            method="GET",
            sensitivity="normal",
        )
        for idx, path in enumerate(
            [
                "/ISAPI/System/reboot",
                "/ISAPI/System/factoryReset",
                "/ISAPI/System/updateFirmware",
                "/ISAPI/System/configurationData",
                "/ISAPI/PTZCtrl/channels/1/continuous",
                "/ISAPI/PTZCtrl/channels/1/presets/1/goto",
                "/ISAPI/ContentMgmt/Storage/hdd/1/format",
                "/ISAPI/Security/users",
                "/ISAPI/System/activate",
                "/SDK/x",
                "/PSIA/x",
                "/cgi-bin/x",
            ]
        )
    ]
    return EndpointPolicy(rules)


@pytest.mark.security
@pytest.mark.parametrize(
    "method",
    ["PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "POST"],
)
def test_get_rule_rejects_non_get_methods(method: str) -> None:
    policy = EndpointPolicy([_GET_RULE])
    with pytest.raises(PolicyViolation) as exc_info:
        policy.authorize(method, "/ISAPI/System/deviceInfo", "", None)
    assert exc_info.value.reason_code == "method_not_allowed"


@pytest.mark.security
@pytest.mark.parametrize(
    "path",
    [
        "/ISAPI/System/reboot",
        "/ISAPI/System/factoryReset",
        "/ISAPI/System/updateFirmware",
        "/ISAPI/System/configurationData",
        "/ISAPI/PTZCtrl/channels/1/continuous",
        "/ISAPI/PTZCtrl/channels/1/presets/1/goto",
        "/ISAPI/ContentMgmt/Storage/hdd/1/format",
        "/ISAPI/Security/users",
        "/ISAPI/System/activate",
        "/SDK/x",
        "/PSIA/x",
        "/cgi-bin/x",
    ],
)
def test_denylist_overrides_allowlist(path: str) -> None:
    policy = _policy_with_allow_all_denylist_paths()
    with pytest.raises(PolicyViolation) as exc_info:
        policy.authorize("GET", path, "", None)
    assert exc_info.value.reason_code == "denylist_match"


@pytest.mark.security
@pytest.mark.parametrize(
    "path",
    [
        "/ISAPI/System/shutdown",
        "/ISAPI/System/configurationData/restore",
        "/ISAPI/ContentMgmt/record/control/manual/start/tracks/101",
        "/ISAPI/System/IO/outputs/1/trigger",
        "/ISAPI/PTZCtrl/channels/1/patrols/1/stop",
        "/ISAPI/PTZCtrl/channels/1/zoom",
        "/ISAPI/PTZCtrl/channels/1/focus",
        "/ISAPI/PTZCtrl/channels/1/position3D",
        "/ISAPI/PTZCtrl/channels/1/park",
    ],
)
def test_denylist_hardening_patterns(path: str) -> None:
    rule = EndpointRule(id="allow.any", path_template=path, method="GET", sensitivity="normal")
    with pytest.raises(PolicyViolation) as exc_info:
        EndpointPolicy([rule]).authorize("GET", path, "", None)
    assert exc_info.value.reason_code == "denylist_match"


@pytest.mark.security
@pytest.mark.parametrize(
    "path",
    [
        "/ISAPI/PTZCtrl/channels/1/presets",
        "/ISAPI/PTZCtrl/channels/1/patrols",
        "/ISAPI/PTZCtrl/channels/1/parkAction",
        "/ISAPI/Event/triggers",
        "/ISAPI/ContentMgmt/record/tracks",
        "/ISAPI/ContentMgmt/Storage/hdd",
        "/ISAPI/Smart/LineDetection/1",
        "/ISAPI/Security/adminAccesses",
    ],
)
def test_planned_read_paths_not_denied(path: str) -> None:
    rule = EndpointRule(id="allow.read", path_template=path, method="GET", sensitivity="normal")
    assert EndpointPolicy([rule]).authorize("GET", path, "", None).id == "allow.read"


@pytest.mark.security
@pytest.mark.parametrize(
    ("path", "query"),
    [
        ("/ISAPI/System/%2e%2e/reboot", ""),
        ("/ISAPI//System/reboot", ""),
        ("/ISAPI/System/REBOOT", ""),
        ("/ISAPI/System/deviceInfo/../reboot", ""),
        ("%252e", ""),
        ("/ISAPI/System/deviceInfo", "unknown=1"),
    ],
)
def test_bypass_attempts_rejected(path: str, query: str) -> None:
    policy = EndpointPolicy([_GET_RULE])
    with pytest.raises(PolicyViolation):
        policy.authorize("GET", path, query, None)


@pytest.mark.security
def test_non_ascii_path_rejected() -> None:
    policy = EndpointPolicy([_GET_RULE])
    with pytest.raises(PolicyViolation) as exc_info:
        policy.authorize("GET", "/ISAPI/System/deviceInf\u00e9", "", None)
    assert exc_info.value.reason_code == "path_hygiene"


@pytest.mark.security
def test_render_substitutes_channel_placeholder() -> None:
    rule = EndpointRule(
        id="streaming.channel",
        path_template="/ISAPI/Streaming/channels/{channel}",
        method="GET",
        sensitivity="normal",
    )
    policy = EndpointPolicy([rule])
    assert policy.render("streaming.channel", channel=1) == "/ISAPI/Streaming/channels/1"


@pytest.mark.security
def test_render_rejects_missing_params() -> None:
    rule = EndpointRule(
        id="streaming.channel",
        path_template="/ISAPI/Streaming/channels/{channel}",
        method="GET",
        sensitivity="normal",
    )
    policy = EndpointPolicy([rule])
    with pytest.raises(PolicyViolation):
        policy.render("streaming.channel")


@pytest.mark.security
def test_post_requires_allowed_root_element() -> None:
    policy = EndpointPolicy([_LOG_SEARCH])
    body = b'<?xml version="1.0"?><OtherRoot/>'
    with pytest.raises(PolicyViolation) as exc_info:
        policy.authorize(
            "POST",
            "/ISAPI/ContentMgmt/logSearch",
            "",
            body,
        )
    assert exc_info.value.reason_code == "invalid_post_body"


@pytest.mark.security
def test_post_accepts_valid_root_element() -> None:
    policy = EndpointPolicy([_LOG_SEARCH])
    body = b'<?xml version="1.0"?><CMSearchDescription/>'
    rule = policy.authorize("POST", "/ISAPI/ContentMgmt/logSearch", "", body)
    assert rule.id == "content.log_search"


@pytest.mark.security
def test_rule_for_unknown_endpoint_id() -> None:
    policy = EndpointPolicy([_GET_RULE])
    with pytest.raises(PolicyViolation) as exc_info:
        policy.rule_for("missing.endpoint")
    assert exc_info.value.reason_code == "not_allowlisted"


@pytest.mark.security
@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"channel": -1}, "invalid_params"),
        ({"channel": 100000}, "invalid_params"),
        ({"channel": 1, "extra": 2}, "invalid_params"),
    ],
)
def test_render_rejects_invalid_params(kwargs: dict[str, int], reason: str) -> None:
    rule = EndpointRule(
        id="streaming.channel",
        path_template="/ISAPI/Streaming/channels/{channel}",
        method="GET",
        sensitivity="normal",
    )
    policy = EndpointPolicy([rule])
    with pytest.raises(PolicyViolation) as exc_info:
        policy.render("streaming.channel", **kwargs)
    assert exc_info.value.reason_code == reason


@pytest.mark.security
def test_render_rejects_unsubstituted_duplicate_placeholders() -> None:
    rule = EndpointRule(
        id="dup.channel",
        path_template="/ISAPI/Streaming/channels/{channel}/tracks/{channel}",
        method="GET",
        sensitivity="normal",
    )
    policy = EndpointPolicy([rule])
    with pytest.raises(PolicyViolation) as exc_info:
        policy.render("dup.channel", channel=1)
    assert exc_info.value.reason_code == "invalid_params"


@pytest.mark.security
@pytest.mark.parametrize("path", ["/ISAPI/System\\reboot", "/ISAPI/System/%2fadmin"])
def test_path_hygiene_illegal_and_encoded_chars(path: str) -> None:
    policy = EndpointPolicy([_GET_RULE])
    with pytest.raises(PolicyViolation) as exc_info:
        policy.authorize("GET", path, "", None)
    assert exc_info.value.reason_code == "path_hygiene"


@pytest.mark.security
def test_post_requires_non_empty_body() -> None:
    policy = EndpointPolicy([_LOG_SEARCH])
    with pytest.raises(PolicyViolation) as exc_info:
        policy.authorize("POST", "/ISAPI/ContentMgmt/logSearch", "", b"   ")
    assert exc_info.value.reason_code == "invalid_post_body"


@pytest.mark.security
def test_post_rejects_malformed_xml() -> None:
    policy = EndpointPolicy([_LOG_SEARCH])
    with pytest.raises(PolicyViolation) as exc_info:
        policy.authorize("POST", "/ISAPI/ContentMgmt/logSearch", "", b"not-xml")
    assert exc_info.value.reason_code == "invalid_post_body"


@pytest.mark.security
def test_get_not_allowed_on_post_only_rule() -> None:
    policy = EndpointPolicy([_LOG_SEARCH])
    with pytest.raises(PolicyViolation) as exc_info:
        policy.authorize("GET", "/ISAPI/ContentMgmt/logSearch", "", None)
    assert exc_info.value.reason_code == "method_not_allowed"


@pytest.mark.security
def test_not_allowlisted_path() -> None:
    policy = EndpointPolicy([_GET_RULE])
    with pytest.raises(PolicyViolation) as exc_info:
        policy.authorize("GET", "/ISAPI/System/missing", "", None)
    assert exc_info.value.reason_code == "not_allowlisted"


@pytest.mark.security
def test_allowed_query_keys_pass() -> None:
    rule = EndpointRule(
        id="with.query",
        path_template="/ISAPI/System/deviceInfo",
        method="GET",
        sensitivity="normal",
        allowed_query=frozenset({"format"}),
    )
    policy = EndpointPolicy([rule])
    matched = policy.authorize("GET", "/ISAPI/System/deviceInfo", "format=xml", None)
    assert matched.id == "with.query"


@pytest.mark.security
def test_denied_sensitivity_endpoint() -> None:
    rule = EndpointRule(
        id="denied.snap",
        path_template="/ISAPI/Streaming/channels/1/picture",
        method="GET",
        sensitivity="denied",
    )
    policy = EndpointPolicy([rule])
    with pytest.raises(PolicyViolation) as exc_info:
        policy.authorize("GET", "/ISAPI/Streaming/channels/1/picture", "", None)
    assert exc_info.value.reason_code == "denied_endpoint"