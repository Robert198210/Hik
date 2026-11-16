from __future__ import annotations

from pathlib import Path

import pytest

from haca.config.errors import ConfigError
from haca.requirements.loader import load_requirements, requirements_hash
from haca.requirements.models import (
    DeviceRequirements,
    RecordingMode,
    RequirementsProfile,
    SystemRequirements,
    TimeSource,
    Tristate,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = REPO_ROOT / "config"
DEVICE_IDS = {"nvr01", "ptz01", "cam01"}


def test_example_requirements_load() -> None:
    profile = load_requirements(CONFIG_DIR / "requirements.example.yaml", DEVICE_IDS)
    assert profile.system.recording_mode == RecordingMode.continuous_24_7
    assert profile.devices["ptz01"].auto_tracking == Tristate.forbidden
    assert profile.system.time_source == TimeSource.nvr_sync


def test_laptop_requirements_use_ntp() -> None:
    profile = load_requirements(REPO_ROOT / "requirements.laptop.yaml", DEVICE_IDS)
    assert profile.system.time_source == TimeSource.ntp
    assert profile.system.recording_mode == RecordingMode.continuous_24_7


def test_empty_profile_defaults(tmp_path: Path) -> None:
    path = tmp_path / "requirements.yaml"
    path.write_text("profile_version: 1\n", encoding="utf-8")
    profile = load_requirements(path, set())
    assert profile.system.recording_mode.value == "unspecified"
    assert profile.system.hik_connect == Tristate.undecided
    assert profile.devices == {}


def test_unknown_device_key_rejected(tmp_path: Path) -> None:
    path = tmp_path / "requirements.yaml"
    path.write_text(
        "profile_version: 1\n"
        "devices:\n"
        "  unknown_cam:\n"
        "    camera_protocol: unspecified\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_requirements(path, DEVICE_IDS)


def test_unknown_enum_value_rejected(tmp_path: Path) -> None:
    path = tmp_path / "requirements.yaml"
    path.write_text(
        "profile_version: 1\n"
        "system:\n"
        "  recording_mode: not_a_valid_mode\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_requirements(path, set())


def test_requirements_hash_stable_across_key_order() -> None:
    profile_a = RequirementsProfile(
        system=SystemRequirements(recording_mode=RecordingMode.event_only),
        devices={
            "ptz01": DeviceRequirements(auto_tracking=Tristate.required),
        },
    )
    profile_b = RequirementsProfile(
        devices={
            "ptz01": DeviceRequirements(auto_tracking=Tristate.required),
        },
        system=SystemRequirements(recording_mode=RecordingMode.event_only),
    )
    assert requirements_hash(profile_a) == requirements_hash(profile_b)


def test_requirements_hash_changes_when_value_changes() -> None:
    base = RequirementsProfile()
    changed = RequirementsProfile(
        system=SystemRequirements(recording_mode=RecordingMode.continuous_24_7),
    )
    assert requirements_hash(base) != requirements_hash(changed)