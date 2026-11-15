from __future__ import annotations

from haca.isapi.response_status import parse_response_status
from haca.isapi.xml import parse_xml


def test_parse_response_status_fields() -> None:
    body = b"""<?xml version="1.0"?>
<ResponseStatus version="2.0">
    <requestURL>/ISAPI/System/deviceInfo</requestURL>
    <statusCode>4</statusCode>
    <statusString>Invalid Operation</statusString>
    <subStatusCode>notSupport</subStatusCode>
    <description>not supported</description>
</ResponseStatus>"""
    doc = parse_xml(body)
    status = parse_response_status(doc)
    assert status is not None
    assert status.request_url == "/ISAPI/System/deviceInfo"
    assert status.status_code == 4
    assert status.status_string == "Invalid Operation"
    assert status.sub_status_code == "notSupport"
    assert status.description == "not supported"
    assert not status.is_success


def test_is_success_by_status_code_or_substatus() -> None:
    ok_code = parse_response_status(
        parse_xml(b"<ResponseStatus><statusCode>1</statusCode></ResponseStatus>")
    )
    assert ok_code is not None and ok_code.is_success
    ok_sub = parse_response_status(
        parse_xml(b"<ResponseStatus><subStatusCode>ok</subStatusCode></ResponseStatus>")
    )
    assert ok_sub is not None and ok_sub.is_success


def test_non_response_status_returns_none() -> None:
    doc = parse_xml(b"<DeviceInfo><model>x</model></DeviceInfo>")
    assert parse_response_status(doc) is None