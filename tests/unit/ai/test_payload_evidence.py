from __future__ import annotations

import json
from pathlib import Path

from haca.ai.payload import build_payload
from haca.ai.prompts import build_prompt
from haca.analysis.models import Classification, EvidenceRef, EvidenceTier, Finding, Severity
from haca.catalog.coverage import compute_coverage, coverage_summary, observed_uncataloged_count
from haca.catalog.loader import load_catalog_entries
from haca.collect.runner import run_simulated_collection
from haca.config.loader import load_app_config
from haca.requirements.loader import load_requirements
from haca.simulation.defaults import default_resolved_devices


def _payload(findings: tuple[Finding, ...] = ()):
    collection, coverage = run_simulated_collection("clean")
    catalog = load_catalog_entries()
    devices = list(default_resolved_devices())
    orp = load_requirements(
        Path("config/requirements.example.yaml"),
        {device.id for device in devices},
    )
    coverage = compute_coverage(catalog, collection, orp)
    summary = coverage_summary(
        coverage,
        catalog,
        observed_uncataloged=observed_uncataloged_count(collection),
    )
    app = load_app_config(Path("config/haca.example.yaml"))
    return build_payload(
        report=None,
        collection=collection,
        devices=devices,
        orp=orp,
        catalog=catalog,
        coverage=coverage,
        coverage_summary=summary,
        findings=findings,
        subnet=app.network.subnet,
        budget_chars=200_000,
    )


def test_payload_sends_log_kinds_tracks_and_manual_gaps() -> None:
    parsed = json.loads(_payload().json_text)
    nvr_logs = next(row for row in parsed["evidence"]["logs"] if row["device_id"] == "nvr01")
    assert nvr_logs["num_matches"] == 1
    assert nvr_logs["kinds"][0]["para_type"] == "lineDetectionStart"
    assert nvr_logs["kinds"][0]["meta_id"] == "log.std-cgi.com/Alarm"
    recordings = next(
        row for row in parsed["evidence"]["recordings"] if row["device_id"] == "nvr01"
    )
    tracks = {row["track_id"]: row for row in recordings["tracks"]}
    assert tracks["101"]["segments"] == 1
    assert tracks["201"]["segments"] == 1
    assert tracks["101"]["types"] == ["timing"]
    dual = next(
        row
        for row in parsed["evidence"]["gaps"]
        if row["device_id"] == "ptz01" and row["setting_id"] == "manual.dual_vca"
    )
    assert dual["status"] == "MANUAL_CHECK"
    assert dual["reason"] == "manual_check"
    assert "playbackURI" not in json.dumps(parsed)


def test_finding_rationale_is_sent_with_addresses_masked() -> None:
    finding = Finding(
        id="f1",
        rule_id="R-VCA-001",
        category="analytics",
        classification=Classification.INFO,
        severity=Severity.info,
        basis="technical",
        devices=("ptz01",),
        evidence=(
            EvidenceRef(
                snapshot_id="run-1",
                device_id="ptz01",
                endpoint_id="smart.line_detection",
                xpath="enabled",
                observed_value="false",
                raw_sha256=None,
                tier=EvidenceTier.isapi,
            ),
        ),
        evidence_tier=EvidenceTier.isapi,
        current_value="false",
        recommended_value="true",
        rationale="Line engine is off at 192.168.250.201",
    )
    parsed = json.loads(_payload((finding,)).json_text)
    row = parsed["deterministic_findings"][0]
    assert row["rationale"].startswith("Line engine is off at <subnet>.")
    assert "192.168.250.201" not in row["rationale"]


def test_prompt_forbids_filling_gaps_from_memory() -> None:
    prompt = build_prompt()
    assert "evidence.gaps" in prompt
    assert "Do not fill it from memory" in prompt
    assert "log.hikvision.com" in prompt
    assert "Save Camera VCA Data" in prompt
    assert "debug log" in prompt
