from __future__ import annotations

import pytest

from haca.catalog.loader import load_catalog_entries
from haca.catalog.models import IsapiSource
from haca.collect.runner import run_simulated_collection


@pytest.mark.simulation
def test_scenario_clean_isapi_coverage_verified() -> None:
    catalog = load_catalog_entries()
    result, coverage = run_simulated_collection("clean")
    by_key = {(e.device_id, e.setting_id): e for e in coverage}

    for entry in catalog:
        for device in result.devices:
            if device.role not in entry.device_roles:
                continue
            row = by_key[(device.device_id, entry.id)]
            isapi_sources = [s for s in entry.sources if isinstance(s, IsapiSource)]
            manual_only = not isapi_sources and any(s.kind == "manual" for s in entry.sources)
            if manual_only:
                assert row.status == "NOT_IMPLEMENTED_IN_HACA", (device.device_id, entry.id, row)
                continue
            if not isapi_sources:
                continue
            assert row.status == "VERIFIED_ISAPI", (device.device_id, entry.id, row)
            assert row.evidence_tier == "simulation"