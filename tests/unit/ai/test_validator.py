from __future__ import annotations

from pathlib import Path

from haca.ai.observed import ObservedIndex
from haca.ai.schema import AiSuggestion
from haca.ai.validator import AiSuggestionValidator
from haca.analysis.models import (
    Classification,
    FindingSource,
)
from haca.catalog.coverage import compute_coverage
from haca.catalog.loader import load_catalog_entries
from haca.collect.runner import run_simulated_collection
from haca.requirements.loader import load_requirements
from haca.simulation.defaults import default_resolved_devices

_REPO = Path(__file__).resolve().parents[3]


def _suggestion(**overrides: object) -> AiSuggestion:
    base = {
        "device_id": "ptz01",
        "setting_id": "security.http_enabled",
        "current_value": "true",
        "recommended_value": "false",
        "classification": "OPTIMIZATION",
        "severity": "low",
        "rationale": "Disable plain HTTP.",
        "depends_on": [],
    }
    base.update(overrides)
    return AiSuggestion.model_validate(base)


def test_accepts_valid_suggestion() -> None:
    collection, coverage = run_simulated_collection("clean")
    catalog = load_catalog_entries()
    device_ids = {d.id for d in default_resolved_devices()}
    orp = load_requirements(_REPO / "config" / "requirements.example.yaml", device_ids)
    coverage = compute_coverage(catalog, collection, orp)
    observed = ObservedIndex(catalog, collection, coverage)
    validator = AiSuggestionValidator(
        catalog=catalog,
        observed=observed,
        orp=orp,
        run_id="run-1",
        simulated=True,
        deterministic=(),
        device_roles={d.id: d.role for d in default_resolved_devices()},
    )
    result = validator.validate([_suggestion()])
    assert len(result.accepted) == 1
    assert result.accepted[0].source is FindingSource.ai_validated
    assert result.accepted[0].classification is not Classification.CONFIRMED_CONFLICT


def test_rejects_hallucinated_setting() -> None:
    collection, coverage = run_simulated_collection("clean")
    catalog = load_catalog_entries()
    device_ids = {d.id for d in default_resolved_devices()}
    orp = load_requirements(_REPO / "config" / "requirements.example.yaml", device_ids)
    coverage = compute_coverage(catalog, collection, orp)
    observed = ObservedIndex(catalog, collection, coverage)
    validator = AiSuggestionValidator(
        catalog=catalog,
        observed=observed,
        orp=orp,
        run_id="run-1",
        simulated=True,
        deterministic=(),
        device_roles={d.id: d.role for d in default_resolved_devices()},
    )
    result = validator.validate(
        [
            _suggestion(setting_id="bogus.setting", current_value="x"),
            _suggestion(device_id="nope", current_value="true"),
            _suggestion(current_value="not-observed"),
        ]
    )
    reasons = {item.reason for item in result.rejected}
    assert "unknown_setting" in reasons
    assert "unknown_device" in reasons
    assert "wrong_current_value" in reasons