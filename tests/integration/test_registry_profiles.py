from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network

import httpx
import pytest
from pydantic import SecretStr

from haca.config.models import TimeoutConfig
from haca.devices.models import ResolvedDevice
from haca.devices.network_policy import NetworkPolicy
from haca.devices.registry import DeviceRegistry
from haca.isapi.client import IsapiClient
from haca.isapi.errors import EndpointNotFound, NotSupportedError
from haca.isapi.registry.loader import (
    build_policy,
    entries_for_role,
    load_registry_entries,
    render_endpoint_path,
)
from haca.security.credentials import Credential
from haca.security.egress import EgressPolicy
from haca.security.errors import PolicyViolation
from haca.simulation.device import SimulatedDevice
from haca.simulation.network import SimulatedNetwork
from haca.simulation.profile_loader import simulation_profiles_root

_SUBNET = IPv4Network("192.168.250.0/24")
_REGISTRY = load_registry_entries()
_POLICY = build_policy(_REGISTRY)

_DEVICES = [
    ("nvr01", "nvr", 200),
    ("ptz01", "ptz", 201),
    ("cam01", "camera", 202),
]


def _resolved(device_id: str, role: str, suffix: int) -> ResolvedDevice:
    return ResolvedDevice(
        id=device_id,
        role=role,  # type: ignore[arg-type]
        expected_model="SYNTH",
        host=IPv4Address(int(_SUBNET.network_address) + suffix),
        port=80,
        scheme="http",
        credential_ref=device_id,
    )


def _network(scenario: str) -> tuple[SimulatedNetwork, DeviceRegistry]:
    profiles = simulation_profiles_root()
    sim_devices: dict[tuple[str, int], SimulatedDevice] = {}
    resolved: list[ResolvedDevice] = []
    for device_id, role, suffix in _DEVICES:
        dev = _resolved(device_id, role, suffix)
        resolved.append(dev)
        profile_dir = profiles / device_id / scenario
        sim_devices[(str(dev.host), dev.port)] = SimulatedDevice(
            device_id,
            profile_dir,
            "synthetic",
            "synthetic-pass",
        )
    return SimulatedNetwork(sim_devices), DeviceRegistry(
        resolved, NetworkPolicy(_SUBNET, simulation=True)
    )


def _client(
    device: ResolvedDevice,
    registry: DeviceRegistry,
    transport: httpx.BaseTransport,
) -> IsapiClient:
    cred = Credential(username="synthetic", password=SecretStr("synthetic-pass"))
    return IsapiClient(
        device,
        cred,
        registry,
        _POLICY,
        EgressPolicy({device.host}),
        TimeoutConfig(),
        inner_transport=transport,
        sleep=lambda _s: None,
    )


@pytest.mark.simulation
@pytest.mark.parametrize("device_id,role,suffix", _DEVICES)
def test_scenario_clean_read_all_applicable_endpoints(
    device_id: str, role: str, suffix: int
) -> None:
    network, registry = _network("scenario-clean")
    device = _resolved(device_id, role, suffix)
    applicable = [
        e for e in entries_for_role(_REGISTRY, role) if e.sensitivity != "denied"  # type: ignore[arg-type]
    ]
    with _client(device, registry, network.transport()) as client:
        for entry in applicable:
            params: dict[str, int] = {}
            if "{channel}" in entry.path:
                params["channel"] = 1
            if "{id}" in entry.path:
                params["id"] = 101
            response = client.read(entry.id, **params)
            assert response.http_status == 200
            assert response.document is not None


@pytest.mark.simulation
def test_scenario_unsupported_ptz_park_action_not_found() -> None:
    network, registry = _network("scenario-unsupported")
    device = _resolved("ptz01", "ptz", 201)
    with (
        _client(device, registry, network.transport()) as client,
        pytest.raises(EndpointNotFound),
    ):
        client.read("ptz.park_action", channel=1)


@pytest.mark.simulation
def test_scenario_unsupported_ptz_ezviz_not_support() -> None:
    network, registry = _network("scenario-unsupported")
    device = _resolved("ptz01", "ptz", 201)
    with (
        _client(device, registry, network.transport()) as client,
        pytest.raises(NotSupportedError),
    ):
        client.read("platform.ezviz")


@pytest.mark.simulation
def test_conflicts_primary_region_entrance_path_404() -> None:
    network, registry = _network("scenario-conflicts")
    device = _resolved("cam01", "camera", 202)
    entry = next(e for e in _REGISTRY if e.id == "smart.region_entrance")
    primary = render_endpoint_path(entry)
    with (
        _client(device, registry, network.transport()) as client,
        pytest.raises(EndpointNotFound),
    ):
        client.read("smart.region_entrance", channel=1)
    assert primary == "/ISAPI/Smart/regionEntrance/1"


@pytest.mark.simulation
def test_denied_picture_blocked_before_transport() -> None:
    network, registry = _network("scenario-clean")
    device = _resolved("nvr01", "nvr", 200)
    with (
        _client(device, registry, network.transport()) as client,
        pytest.raises(PolicyViolation),
    ):
        client.read("streaming.picture", id=101)