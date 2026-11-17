"""Fixed read-only CMSearchDescription bodies for log and recording search."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Literal, cast
from xml.etree.ElementTree import Element, tostring

from defusedxml.ElementTree import ParseError, fromstring  # type: ignore[import-untyped]

_WINDOW = timedelta(hours=24)
_NS = "http://www.isapi.org/ver20/XMLSchema"
_DROP_LOCALS = frozenset(
    {"username", "ipaddress", "ipv6address", "macaddress", "playbackuri"}
)


LogVariant = Literal["std", "plain_time", "hikvision"]


def read_post_body(
    endpoint_id: str,
    now: datetime | None = None,
    *,
    variant: LogVariant = "std",
) -> bytes:
    """Return the only POST body HACA may send for this endpoint."""
    moment = now or datetime.now(UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    moment = moment.astimezone(UTC).replace(microsecond=0)
    start = moment - _WINDOW
    if endpoint_id == "content.log_search":
        return _description(
            search_id="{00000000-0000-0000-0000-000000000001}",
            start=start,
            end=moment,
            extra=_log_extra(variant),
            with_zone=variant == "std",
        )
    if endpoint_id == "content.record_search":
        return _description(
            search_id="{00000000-0000-0000-0000-000000000002}",
            start=start,
            end=moment,
            extra=_record_extra(),
        )
    msg = f"no read-only POST body for {endpoint_id!r}"
    raise ValueError(msg)


def redact_search_identifiers(body: bytes) -> bytes:
    """Drop account and address fields before a search result is stored."""
    try:
        root = fromstring(
            body,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except (ParseError, ValueError, TypeError):
        return body
    for parent in root.iter():
        for child in list(parent):
            local = child.tag.split("}")[-1].lower()
            if local in _DROP_LOCALS:
                parent.remove(child)
    return cast(bytes, tostring(root, encoding="utf-8", xml_declaration=True))


def _description(
    *,
    search_id: str,
    start: datetime,
    end: datetime,
    extra: list[Element],
    with_zone: bool = True,
) -> bytes:
    root = Element("CMSearchDescription", {"version": "1.0", "xmlns": _NS})
    _text(root, "searchID", search_id)
    span_list = Element("timeSpanList")
    span = Element("timeSpan")
    _text(span, "startTime", _stamp(start, with_zone=with_zone))
    _text(span, "endTime", _stamp(end, with_zone=with_zone))
    span_list.append(span)
    root.append(span_list)
    for node in extra:
        root.append(node)
    return cast(bytes, tostring(root, encoding="utf-8", xml_declaration=True))


def _log_extra(variant: LogVariant) -> list[Element]:
    meta = Element("metaId")
    meta.text = "log.hikvision.com" if variant == "hikvision" else "log.std-cgi.com"
    limit = Element("maxResults")
    limit.text = "100"
    if variant != "std":
        return [meta, limit]
    position = Element("searchResultPosition")
    position.text = "0"
    return [meta, position, limit]


def _record_extra() -> list[Element]:
    tracks = Element("trackList")
    for track_id in ("101", "201"):
        _text(tracks, "trackID", track_id)
    kinds = Element("contentTypeList")
    _text(kinds, "contentType", "video")
    position = Element("searchResultPosition")
    position.text = "0"
    limit = Element("maxResults")
    limit.text = "40"
    return [tracks, kinds, position, limit]


def _text(parent: Element, tag: str, value: str) -> None:
    node = Element(tag)
    node.text = value
    parent.append(node)


def _stamp(moment: datetime, *, with_zone: bool = True) -> str:
    text = moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S")
    return f"{text}Z" if with_zone else text
