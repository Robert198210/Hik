from __future__ import annotations

import pytest

from haca.isapi.errors import XmlParseError
from haca.isapi.xml import parse_xml

_DEVICE_INFO_HI = b"""<?xml version="1.0" encoding="UTF-8"?>
<DeviceInfo version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
    <model>SYNTH-NVR</model>
</DeviceInfo>
"""

_DEVICE_INFO_ISAPI = _DEVICE_INFO_HI.replace(
    b"http://www.hikvision.com/ver20/XMLSchema",
    b"http://www.isapi.org/ver20/XMLSchema",
)

_DEVICE_INFO_NO_NS = b"""<?xml version="1.0" encoding="UTF-8"?>
<DeviceInfo version="1.0">
    <model>SYNTH-CAM</model>
</DeviceInfo>
"""


@pytest.mark.parametrize(
    "body",
    [_DEVICE_INFO_HI, _DEVICE_INFO_ISAPI, _DEVICE_INFO_NO_NS],
)
def test_parse_device_info_namespaces(body: bytes) -> None:
    doc = parse_xml(body)
    assert doc.text("model") in {"SYNTH-NVR", "SYNTH-CAM"}


def test_strips_bom_and_whitespace() -> None:
    body = b"\xef\xbb\xbf\n  " + _DEVICE_INFO_NO_NS + b"  "
    doc = parse_xml(body)
    assert doc.text("model") == "SYNTH-CAM"


def test_xxe_rejected() -> None:
    body = b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><a>&xxe;</a>'
    with pytest.raises(XmlParseError):
        parse_xml(body)


def test_billion_laughs_rejected() -> None:
    body = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>"""
    with pytest.raises(XmlParseError):
        parse_xml(body)


def test_oversized_body_rejected() -> None:
    body = b"<root>" + b"x" * (5_000_000 + 1) + b"</root>"
    with pytest.raises(XmlParseError):
        parse_xml(body)