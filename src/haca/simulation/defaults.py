"""Built-in simulated network defaults for ``haca identify --simulate``."""

from __future__ import annotations

from importlib.resources.abc import Traversable
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from pydantic import SecretStr

from haca.config.models import AppConfig, NetworkConfig, TimeoutConfig
from haca.devices.models import ResolvedDevice
from haca.devices.network_policy import NetworkPolicy
from haca.devices.registry import DeviceRegistry
from haca.security.credentials import Credential
from haca.security.redaction import register_secret
from haca.simulation.device import SimulatedDevice
from haca.simulation.faults import FaultProfile
from haca.simulation.network import SimulatedNetwork
from haca.simulation.profile_loader import simulation_profiles_root

_SIMULATION_SUBNET = IPv4Network("192.168.250.0/24")

_DEVICE_TABLE: tuple[tuple[str, str, int, str], ...] = (
    ("nvr01", "nvr", 200, "DS-7616NXI-K2(D)"),
    ("ptz01", "ptz", 201, "DS-2DE4425IWG1-E"),
    ("cam01", "camera", 202, "DS-2CD2087G3-LI2UY/SL"),
)


def simulation_app_config() -> AppConfig:
    return AppConfig(
        network=NetworkConfig(subnet=_SIMULATION_SUBNET),
        simulation=True,
    )


def default_resolved_devices() -> tuple[ResolvedDevice, ...]:
    devices: list[ResolvedDevice] = []
    base = int(_SIMULATION_SUBNET.network_address)
    for device_id, role, suffix, expected_model in _DEVICE_TABLE:
        devices.append(
            ResolvedDevice(
                id=device_id,
                role=role,  # type: ignore[arg-type]
                expected_model=expected_model,
                host=IPv4Address(base + suffix),
                port=80,
                scheme="http",
                credential_ref=device_id,
            )
        )
    return tuple(devices)


def simulation_registry() -> DeviceRegistry:
    return DeviceRegistry(
        list(default_resolved_devices()),
        NetworkPolicy(_SIMULATION_SUBNET, simulation=True),
    )


def simulation_timeouts() -> TimeoutConfig:
    return TimeoutConfig()


def simulation_credential() -> Credential:
    network = build_simulation_network()
    register_secret(network.password)
    return Credential(username=network.username, password=SecretStr(network.password))


def _default_profile_dir(device_id: str, profile_name: str = "synthetic-default") -> Traversable:
    return simulation_profiles_root() / device_id / profile_name


def build_simulation_network(
    *,
    faults: dict[str, FaultProfile] | None = None,
    profile_dirs: dict[str, Path | Traversable] | None = None,
) -> SimulatedNetwork:
    faults = faults or {}
    profile_dirs = profile_dirs or {}
    sim_devices: dict[tuple[str, int], SimulatedDevice] = {}
    cred_user = "synthetic"
    cred_pass = "synthetic-pass"
    for device in default_resolved_devices():
        profile_dir = profile_dirs.get(device.id, _default_profile_dir(device.id))
        sim_devices[(str(device.host), device.port)] = SimulatedDevice(
            device.id,
            profile_dir,
            cred_user,
            cred_pass,
            faults.get(device.id),
        )
    return SimulatedNetwork(sim_devices)