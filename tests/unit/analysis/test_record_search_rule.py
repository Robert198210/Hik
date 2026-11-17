from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import IPv4Address

from haca.analysis.context import RuleContext
from haca.analysis.correlator import correlate
from haca.analysis.models import Classification
from haca.analysis.rules.builtins import RRec002
from haca.collect.extract import (
    DeviceViews,
    RecordSearchView,
    RecordSegmentView,
    TrackView,
)
from haca.collect.models import (
    CollectionResult,
    DeviceCollection,
    EndpointOutcome,
    RawEvidence,
)
from haca.devices.models import ResolvedDevice
from haca.requirements.models import RequirementsProfile

_NOW = datetime(2026, 11, 17, 9, 0, tzinfo=UTC)
_SCHEDULE = (("Monday", "00:00:00", "Monday", "23:59:59", "CMR", True),)


def _evidence(endpoint_id: str) -> RawEvidence:
    return RawEvidence(
        device_id="nvr01",
        endpoint_id=endpoint_id,
        path="/ISAPI/Synthetic/missing",
        outcome=EndpointOutcome.COLLECTED,
        http_status=200,
        sub_status_code=None,
        sha256="abc",
        body=b"<ok/>",
        collected_at=_NOW,
        elapsed_ms=1.0,
    )


def _findings(
    *,
    enabled: bool,
    search: RecordSearchView | None,
) -> list:
    views = DeviceViews(
        tracks=(
            TrackView(
                track_id="101",
                enable=enabled,
                schedule=_SCHEDULE,
            ),
        ),
        record_search=search,
    )
    evidence = {"record.tracks": _evidence("record.tracks")}
    if search is not None:
        evidence["content.record_search"] = _evidence("content.record_search")
    result = CollectionResult(
        run_started=_NOW,
        run_finished=_NOW,
        simulated=False,
        devices=[
            DeviceCollection(
                device_id="nvr01",
                role="nvr",
                identity=None,
                evidence=evidence,
                views=views,
            )
        ],
    )
    devices = [
        ResolvedDevice(
            id="nvr01",
            role="nvr",
            expected_model="SYNTH",
            host=IPv4Address("192.168.250.200"),
            port=80,
            scheme="http",
            credential_ref="nvr01",
        )
    ]
    ctx = RuleContext(
        result=result,
        correlation=correlate(result, devices),
        orp=RequirementsProfile(),
        coverage=[],
        run_id="test-run",
    )
    return RRec002().evaluate(ctx)


def test_disabled_track_without_search_stays_insufficient() -> None:
    findings = _findings(enabled=False, search=None)
    assert len(findings) == 1
    assert findings[0].classification is Classification.INSUFFICIENT_DATA


def test_disabled_track_with_segments_reports_the_count() -> None:
    findings = _findings(
        enabled=False,
        search=RecordSearchView(
            num_matches=1,
            segments=(
                RecordSegmentView(track_id="101", record_type="timing"),
            ),
        ),
    )
    assert findings[0].classification is Classification.INFO
    assert findings[0].current_value == "1"
    assert "Human/vehicle timeline markers" in findings[0].rationale


def test_disabled_track_with_empty_search_reports_no_video() -> None:
    findings = _findings(
        enabled=False,
        search=RecordSearchView(num_matches=0, segments=()),
    )
    assert findings[0].classification is Classification.INFO
    assert "no video segments" in findings[0].rationale


def test_enabled_track_is_silent() -> None:
    assert _findings(enabled=True, search=RecordSearchView(num_matches=0, segments=())) == []
