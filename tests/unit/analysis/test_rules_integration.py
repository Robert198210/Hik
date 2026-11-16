from __future__ import annotations

from pathlib import Path

from haca.analysis.engine import RuleEngine
from haca.analysis.models import Classification
from haca.collect.runner import run_simulated_collection
from haca.requirements.loader import load_requirements
from haca.requirements.models import RequirementsProfile, SystemRequirements
from haca.simulation.defaults import default_resolved_devices

_REPO = Path(__file__).resolve().parents[3]
_SEED_ORP = _REPO / "config" / "requirements.example.yaml"


def _run(scenario: str, orp_path: Path | None = None) -> list:
    devices = list(default_resolved_devices())
    device_ids = {d.id for d in devices}
    orp = (
        load_requirements(orp_path or _SEED_ORP, device_ids)
        if orp_path or _SEED_ORP
        else RequirementsProfile()
    )
    result, coverage = run_simulated_collection(scenario)
    findings, _corr = RuleEngine().run(
        result, devices, orp, coverage, run_id="test-run"
    )
    return findings


def test_scenario_clean_only_expected_info() -> None:
    findings = _run("clean")
    assert not any(
        f.classification
        in (Classification.CONFIRMED_CONFLICT, Classification.POTENTIAL_CONFLICT)
        and not f.simulated_confirmed
        for f in findings
    )
    assert not any(f.simulated_confirmed for f in findings)
    info = [f for f in findings if f.classification is Classification.INFO]
    rule_ids = {f.rule_id for f in info}
    assert rule_ids <= {"R-HIKC-001", "R-PTZ-001"}
    assert any(f.orp_refs == ("system.hik_connect",) for f in info)
    assert any("ptz_mode" in ".".join(f.orp_refs) for f in info)


def test_scenario_conflicts_detects_planted_rules() -> None:
    findings = _run("conflicts")
    rule_ids = {f.rule_id for f in findings if f.simulated_confirmed or f.classification in (
        Classification.CONFIRMED_CONFLICT,
        Classification.POTENTIAL_CONFLICT,
        Classification.INFO,
    )}
    expected = {
        "R-INV-001",
        "R-CONN-001",
        "R-STOR-001",
        "R-REC-001",
        "R-PROTO-001",
        "R-VCA-001",
        "R-VCA-002",
        "R-VCA-003",
        "R-LINK-001",
        "R-PTZ-002",
        "R-TIME-001",
    }
    assert expected <= rule_ids
    assert all(
        f.classification is not Classification.CONFIRMED_CONFLICT for f in findings
    )
    assert any(f.simulated_confirmed for f in findings)


def test_empty_orp_no_simulated_confirmed_on_requirement_rules() -> None:
    devices = list(default_resolved_devices())
    empty = RequirementsProfile(system=SystemRequirements(), devices={})
    result, coverage = run_simulated_collection("conflicts")
    findings, _ = RuleEngine().run(result, devices, empty, coverage, run_id="empty")
    for f in findings:
        if f.basis == "requirement":
            assert not f.simulated_confirmed


def test_missing_tracks_insufficient_data() -> None:
    devices = list(default_resolved_devices())
    orp = load_requirements(_SEED_ORP, {d.id for d in devices})
    result, coverage = run_simulated_collection("clean")
    # drop tracks from nvr views
    patched_devices = []
    for dev in result.devices:
        if dev.device_id == "nvr01":
            views = dev.views.model_copy(update={"tracks": None})
            patched_devices.append(dev.model_copy(update={"views": views}))
        else:
            patched_devices.append(dev)
    patched = result.model_copy(update={"devices": patched_devices})
    findings, _ = RuleEngine().run(patched, devices, orp, coverage, run_id="x")
    assert any(
        f.rule_id == "R-REC-001" and f.classification is Classification.INSUFFICIENT_DATA
        for f in findings
    )