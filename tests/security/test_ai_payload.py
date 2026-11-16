from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from haca.ai.payload import build_payload
from haca.catalog.coverage import compute_coverage, coverage_summary, observed_uncataloged_count
from haca.catalog.loader import load_catalog_entries
from haca.collect.runner import run_simulated_collection
from haca.config.loader import load_app_config
from haca.requirements.loader import load_requirements
from haca.simulation.defaults import default_resolved_devices


@pytest.mark.security
def test_conflicts_payload_has_no_identifier_leaks() -> None:
    collection, coverage = run_simulated_collection("conflicts")
    catalog = load_catalog_entries()
    devices = list(default_resolved_devices())
    device_ids = {d.id for d in devices}
    orp = load_requirements(Path("config/requirements.example.yaml"), device_ids)
    coverage = compute_coverage(catalog, collection, orp)
    summary = coverage_summary(
        coverage,
        catalog,
        observed_uncataloged=observed_uncataloged_count(collection),
    )
    app = load_app_config(Path("config/haca.example.yaml"))
    payload = build_payload(
        report=None,
        collection=collection,
        devices=devices,
        orp=orp,
        catalog=catalog,
        coverage=coverage,
        coverage_summary=summary,
        findings=(),
        subnet=app.network.subnet,
        budget_chars=app.ai.budget_chars if app.ai else 200_000,
    )
    text = payload.json_text
    assert "SYNTH-" not in text
    assert not re.search(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b", text)
    assert "deviceID" not in text
    assert "userName" not in text
    assert "<?xml" not in text
    parsed = json.loads(text)
    blob = json.dumps(parsed)
    assert re.search(r"192\.168\.250\.\d+", blob) is None
    assert "<subnet>." in blob