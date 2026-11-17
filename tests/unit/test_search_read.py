from __future__ import annotations

from datetime import UTC, datetime

from defusedxml.ElementTree import fromstring  # type: ignore[import-untyped]

from haca.collect.extract import extract_views
from haca.isapi.search_body import read_post_body, redact_search_identifiers
from haca.isapi.xml import parse_xml
from haca.security.endpoint_policy import EndpointPolicy, EndpointRule


def _root(body: bytes) -> str:
    element = fromstring(body, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    tag = element.tag
    return tag.split("}")[-1] if "}" in tag else tag


def test_log_search_body_is_a_fixed_last_day_query() -> None:
    now = datetime(2026, 11, 17, 9, 0, tzinfo=UTC)
    body = read_post_body("content.log_search", now=now)
    text = body.decode()
    assert _root(body) == "CMSearchDescription"
    assert "log.std-cgi.com" in text
    assert "2026-11-16T09:00:00Z" in text
    assert "2026-11-17T09:00:00Z" in text
    assert "maxResults" in text


def test_record_search_body_asks_for_both_channel_one_tracks() -> None:
    now = datetime(2026, 11, 17, 9, 0, tzinfo=UTC)
    body = read_post_body("content.record_search", now=now)
    text = body.decode()
    assert "<trackID>101</trackID>" in text
    assert "<trackID>201</trackID>" in text
    assert "<contentType>video</contentType>" in text


def test_policy_accepts_the_generated_search_body() -> None:
    policy = EndpointPolicy(
        [
            EndpointRule(
                id="content.log_search",
                path_template="/ISAPI/ContentMgmt/logSearch",
                method="POST",
                read_post=True,
                post_root_elements=frozenset({"CMSearchDescription"}),
                sensitivity="normal",
            )
        ]
    )
    body = read_post_body("content.log_search")
    rule = policy.authorize("POST", "/ISAPI/ContentMgmt/logSearch", "", body)
    assert rule.id == "content.log_search"


def test_redaction_drops_account_and_address_fields() -> None:
    raw = b"""<?xml version="1.0"?>
    <CMSearchResult>
      <userName>synthetic</userName>
      <ipAddress>192.168.250.50</ipAddress>
      <playbackURI>rtsp://192.168.250.200/Streaming/tracks/101/</playbackURI>
      <paraType>lineDetectionStart</paraType>
    </CMSearchResult>"""
    cleaned = redact_search_identifiers(raw).decode()
    assert "synthetic" not in cleaned
    assert "192.168.250.50" not in cleaned
    assert "playbackURI" not in cleaned
    assert "lineDetectionStart" in cleaned


def test_extract_log_and_record_search() -> None:
    log_doc = parse_xml(
        b"""<?xml version="1.0"?>
        <CMSearchResult>
          <numOfMatches>1</numOfMatches>
          <searchMatchItem>
            <metaId>log.std-cgi.com/Alarm</metaId>
            <paraType>lineDetectionStart</paraType>
            <StartDateTime>2026-11-16T12:00:00Z</StartDateTime>
          </searchMatchItem>
        </CMSearchResult>"""
    )
    record_doc = parse_xml(
        b"""<?xml version="1.0"?>
        <CMSearchResult>
          <numOfMatches>1</numOfMatches>
          <searchMatchItem>
            <trackID>101</trackID>
            <startTime>2026-11-16T12:00:00Z</startTime>
            <endTime>2026-11-16T12:05:00Z</endTime>
            <metadataDescriptor>recordType.meta.hikvision.com/timing</metadataDescriptor>
          </searchMatchItem>
        </CMSearchResult>"""
    )
    missing: list[str] = []
    log_view = extract_views("content.log_search", log_doc, missing).log_search
    record_view = extract_views("content.record_search", record_doc, missing).record_search
    assert log_view is not None and log_view.num_matches == 1
    assert log_view.events[0].para_type == "lineDetectionStart"
    assert record_view is not None and record_view.segments[0].track_id == "101"
    assert record_view.segments[0].record_type is not None
    assert record_view.segments[0].record_type.endswith("/timing")
