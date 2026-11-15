from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

import pytest
import yaml

from haca.config.errors import ConfigError
from haca.config.loader import load_app_config, load_devices
from haca.config.models import NetworkConfig

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = REPO_ROOT / "config"


def _network() -> NetworkConfig:
    return NetworkConfig(subnet=IPv4Network("192.168.250.0/24"))


def test_example_files_load() -> None:
    app = load_app_config(CONFIG_DIR / "haca.example.yaml")
    assert app.network.subnet == IPv4Network("192.168.250.0/24")
    devices = load_devices(CONFIG_DIR / "devices.example.yaml", app.network)
    ids = {d.id for d in devices}
    assert ids == {"nvr01", "ptz01", "cam01"}


def test_ptz01_resolves_to_expected_host() -> None:
    devices = load_devices(CONFIG_DIR / "devices.example.yaml", _network())
    ptz = next(d for d in devices if d.id == "ptz01")
    assert ptz.host == IPv4Address("192.168.250.201")


def test_rejects_public_subnet(tmp_path: Path) -> None:
    path = tmp_path / "haca.yaml"
    path.write_text("network:\n  subnet: 8.8.8.0/24\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_app_config(path)


@pytest.mark.parametrize("suffix", [0, 255])
def test_rejects_invalid_suffix(tmp_path: Path, suffix: int) -> None:
    path = tmp_path / "devices.yaml"
    path.write_text(
        yaml.dump(
            {
                "devices": [
                    {
                        "id": "nvr01",
                        "role": "nvr",
                        "expected_model": "SYNTH-NVR",
                        "host_suffix": suffix,
                        "credential_ref": "nvr01",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_devices(path, _network())


def test_rejects_both_host_and_suffix(tmp_path: Path) -> None:
    path = tmp_path / "devices.yaml"
    path.write_text(
        "devices:\n"
        "  - id: nvr01\n"
        "    role: nvr\n"
        "    expected_model: SYNTH-NVR\n"
        "    host_suffix: 200\n"
        "    host: 192.168.250.200\n"
        "    credential_ref: nvr01\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_devices(path, _network())


def test_rejects_password_key(tmp_path: Path) -> None:
    path = tmp_path / "devices.yaml"
    path.write_text(
        "devices:\n"
        "  - id: nvr01\n"
        "    role: nvr\n"
        "    expected_model: SYNTH-NVR\n"
        "    host_suffix: 200\n"
        "    credential_ref: nvr01\n"
        "    password: secret-value\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError) as exc:
        load_devices(path, _network())
    assert "secret-value" not in str(exc.value)


def test_rejects_duplicate_id(tmp_path: Path) -> None:
    path = tmp_path / "devices.yaml"
    path.write_text(
        "devices:\n"
        "  - id: nvr01\n"
        "    role: nvr\n"
        "    expected_model: SYNTH-NVR\n"
        "    host_suffix: 200\n"
        "    credential_ref: nvr01\n"
        "  - id: nvr01\n"
        "    role: camera\n"
        "    expected_model: SYNTH-CAM\n"
        "    host_suffix: 201\n"
        "    credential_ref: cam01\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_devices(path, _network())


def test_rejects_bad_device_id(tmp_path: Path) -> None:
    path = tmp_path / "devices.yaml"
    path.write_text(
        "devices:\n"
        "  - id: Bad_ID\n"
        "    role: nvr\n"
        "    expected_model: SYNTH-NVR\n"
        "    host_suffix: 200\n"
        "    credential_ref: nvr01\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_devices(path, _network())


def test_rejects_host_outside_subnet(tmp_path: Path) -> None:
    path = tmp_path / "devices.yaml"
    path.write_text(
        "devices:\n"
        "  - id: cam01\n"
        "    role: camera\n"
        "    expected_model: SYNTH-CAM\n"
        "    host: 192.168.1.10\n"
        "    credential_ref: cam01\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_devices(path, _network())


def test_default_ports(tmp_path: Path) -> None:
    path = tmp_path / "devices.yaml"
    path.write_text(
        "devices:\n"
        "  - id: nvr01\n"
        "    role: nvr\n"
        "    expected_model: SYNTH-NVR\n"
        "    host_suffix: 200\n"
        "    scheme: https\n"
        "    credential_ref: nvr01\n",
        encoding="utf-8",
    )
    devices = load_devices(path, _network())
    assert devices[0].port == 443