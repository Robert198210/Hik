from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from haca.cli import main
from haca.collect.identify import IdentificationResult
from haca.simulation.defaults import build_simulation_network
from haca.simulation.faults import FaultProfile

REPO_ROOT = Path(__file__).resolve().parents[2]


def _run_haca(*args: str) -> subprocess.CompletedProcess[str]:
    cmd = ["uv", "run", "haca", *args]
    env = {
        **dict(__import__("os").environ),
        "UV_CACHE_DIR": "/var/fpwork/ambrosew/.xdg/cache/uv",
        "PATH": f"/var/fpwork/ambrosew/.xdg/local/bin:{__import__('os').environ.get('PATH', '')}",
    }
    env.pop("UV_INDEX", None)
    return subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


@pytest.mark.simulation
def test_cli_identify_simulate_success() -> None:
    proc = _run_haca("identify", "--simulate")
    assert proc.returncode == 0
    assert "SIMULATED — synthetic fixtures, no real device contacted" in proc.stdout
    for device_id in ("nvr01", "ptz01", "cam01"):
        assert device_id in proc.stdout
        assert "IDENTIFIED" in proc.stdout


@pytest.mark.simulation
def test_cli_identify_json_masks_secrets(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["identify", "--simulate", "--json"])
    assert exc.value.code == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload) == 3
    for entry in payload:
        IdentificationResult.model_validate(entry)
        assert entry["simulated"] is True
        if entry["identity"] is not None:
            assert "SYNTH-" not in json.dumps(entry)
            assert "00:00:5E" not in json.dumps(entry)


@pytest.mark.simulation
def test_cli_identify_model_mismatch_exit_code(monkeypatch) -> None:
    profile = REPO_ROOT / "tests/simulation_profiles/ptz01/model-mismatch"

    def _network(**kwargs: object) -> object:
        return build_simulation_network(profile_dirs={"ptz01": profile})

    monkeypatch.setattr("haca.cli.build_simulation_network", _network)
    with pytest.raises(SystemExit) as exc:
        main(["identify", "--simulate"])
    assert exc.value.code == 2


@pytest.mark.simulation
def test_cli_identify_unreachable_partial_success(monkeypatch) -> None:
    def _network(**kwargs: object) -> object:
        return build_simulation_network(faults={"ptz01": FaultProfile(connect_error=True)})

    monkeypatch.setattr("haca.cli.build_simulation_network", _network)
    with pytest.raises(SystemExit) as exc:
        main(["identify", "--simulate"])
    assert exc.value.code == 2


@pytest.mark.simulation
def test_cli_requirements_validate_lists_undecided() -> None:
    proc = _run_haca(
        "requirements",
        "validate",
        "--file",
        "config/requirements.example.yaml",
    )
    assert proc.returncode == 0
    assert "needs_decision: system.hik_connect" in proc.stdout
    assert "needs_decision: ptz01.ptz_mode" in proc.stdout