"""Resolve Setting Catalog ``view_path`` values against ``DeviceViews``."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from haca.collect.extract import AdminAccessView, DeviceViews

_SEGMENT_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(?:\[([^\]]+)\])?$")

_VIEW_ROOTS = frozenset(
    {
        "identity_model",
        "identity_firmware",
        "time",
        "ntp",
        "network",
        "admin_access",
        "streams",
        "tracks",
        "hdds",
        "triggers",
        "proxy_channels",
        "line_detection",
        "field_detection",
        "region_entrance",
        "park_action",
        "patrols",
        "presets",
        "platform",
        "log_search",
        "record_search",
    }
)

_LIST_TERMINAL_FIELDS = frozenset({"items", "servers", "schedule", "methods"})


class ViewPathSyntaxError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ViewSegment:
    name: str
    key: str | None = None


def parse_view_path(path: str) -> tuple[ViewSegment, ...]:
    if not path.strip():
        raise ViewPathSyntaxError("empty view_path")
    segments: list[ViewSegment] = []
    for piece in path.split("."):
        match = _SEGMENT_RE.fullmatch(piece)
        if match is None:
            raise ViewPathSyntaxError(f"invalid segment {piece!r} in {path!r}")
        segments.append(ViewSegment(match.group(1), match.group(2)))
    return tuple(segments)


def validate_view_path_syntax(path: str) -> None:
    segments = parse_view_path(path)
    if len(segments) == 1 and segments[0].key is None:
        if segments[0].name not in {"identity_model", "identity_firmware"}:
            raise ViewPathSyntaxError(f"unknown root {segments[0].name!r}")
        return
    if segments[0].name not in _VIEW_ROOTS:
        raise ViewPathSyntaxError(f"unknown root {segments[0].name!r}")
    if segments[0].name == "admin_access" and (
        len(segments) != 4 or segments[1].name != "protocols"
    ):
        raise ViewPathSyntaxError("expected admin_access.protocols.PROTO.FIELD")


class _MissingView(ValueError):
    pass


def _match_item(item: Any, key: str) -> bool:
    for attr in ("id", "track_id", "event_type"):
        val = getattr(item, attr, None)
        if val is not None and str(val).lower() == key.lower():
            return True
    return False


def _pick_from_collection(collection: Any, seg: ViewSegment) -> Any:
    if not isinstance(collection, (list, tuple)):
        raise _MissingView
    if seg.key == "*":
        return list(collection)
    for item in collection:
        if _match_item(item, seg.key or ""):
            return item
    raise _MissingView


def _resolve(views: DeviceViews, segments: tuple[ViewSegment, ...], index: int) -> Any:
    if index >= len(segments):
        return views
    seg = segments[index]

    if index == 0:
        if seg.name in {"identity_model", "identity_firmware"}:
            return getattr(views, seg.name, None)
        parent = getattr(views, seg.name, None)
        if parent is None:
            raise _MissingView
        if seg.key:
            return _resolve(_pick_from_collection(parent, seg), segments, index + 1)
        return _resolve(parent, segments, index + 1)

    if isinstance(views, AdminAccessView) and seg.name == "protocols":
        proto = views.protocols.get(segments[index + 1].name)
        if proto is None:
            raise _MissingView
        field = segments[index + 2].name
        if field == "enabled":
            return proto.enabled
        if field == "port":
            return proto.port
        raise ViewPathSyntaxError(f"unknown protocol field {field!r}")

    if seg.key:
        collection = getattr(views, seg.name, None)
        picked = _pick_from_collection(collection, seg)
        return _resolve(picked, segments, index + 1)

    value = getattr(views, seg.name, None)
    if index == len(segments) - 1:
        return value
    if value is None:
        raise _MissingView
    return _resolve(value, segments, index + 1)


def resolve_view_path(views: DeviceViews, path: str) -> tuple[bool, object]:
    validate_view_path_syntax(path)
    segments = parse_view_path(path)
    try:
        value = _resolve(views, segments, 0)
    except _MissingView:
        return False, None
    return _is_present(value, segments[-1]), value


def _is_present(value: object, terminal: ViewSegment) -> bool:
    if value is None:
        return False
    if terminal.name in _LIST_TERMINAL_FIELDS and isinstance(value, (list, tuple, frozenset)):
        return True
    if isinstance(value, (list, tuple)) and value == ():
        return True
    if isinstance(value, (bool, int, float)):
        return True
    if isinstance(value, str):
        return value != ""
    return True