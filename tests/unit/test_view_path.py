from __future__ import annotations

import pytest

from haca.catalog.view_path import ViewPathSyntaxError, resolve_view_path, validate_view_path_syntax
from haca.collect.extract import (
    AdminAccessView,
    DeviceViews,
    ProtocolAccessView,
    StreamView,
    TriggerView,
    VcaItemView,
    VcaRuleView,
)


def test_validate_unknown_root() -> None:
    with pytest.raises(ViewPathSyntaxError):
        validate_view_path_syntax("missing.leaf")


def test_resolve_admin_protocol() -> None:
    views = DeviceViews(
        admin_access=AdminAccessView(
            protocols={"HTTP": ProtocolAccessView(enabled=True, port=80)},
        )
    )
    ok, value = resolve_view_path(views, "admin_access.protocols.HTTP.enabled")
    assert ok and value is True


def test_resolve_stream_by_id() -> None:
    views = DeviceViews(
        streams=(StreamView(id="101", codec="H.265", resolution="2560x1440"),)
    )
    ok, value = resolve_view_path(views, "streams[101].codec")
    assert ok and value == "H.265"


def test_resolve_line_items_present_when_empty() -> None:
    views = DeviceViews(line_detection=VcaRuleView(engine_enabled=True, items=()))
    ok, value = resolve_view_path(views, "line_detection.items")
    assert ok and value == ()


def test_resolve_line_item_field() -> None:
    views = DeviceViews(
        line_detection=VcaRuleView(
            items=(VcaItemView(id="1", detection_target="human,vehicle"),)
        )
    )
    ok, value = resolve_view_path(views, "line_detection.items[1].detection_target")
    assert ok and value == "human,vehicle"


def test_resolve_trigger_methods() -> None:
    views = DeviceViews(
        triggers=(TriggerView(event_type="linedetection", methods=frozenset({"center"})),)
    )
    ok, value = resolve_view_path(views, "triggers[linedetection].methods")
    assert ok and value == frozenset({"center"})