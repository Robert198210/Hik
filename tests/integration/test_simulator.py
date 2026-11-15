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
from haca.isapi.errors import (
    AuthError,
    DeviceConnectionError,
    DeviceTimeout,
    EndpointNotFound,
    NotSupportedError,
    XmlParseError,
)
from haca.isapi.registry.phase1_endpoints import build_phase1_policy
from haca.security.credentials import Credential
from haca.security.egress import EgressPolicy
from haca.security.endpoint_policy import EndpointPolicy, EndpointRule
from haca.simulation.device import SimulatedDevice
from haca.simulation.faults import FaultProfile
from haca.simulation.network import SimulatedNetwork
from haca.simulation.profile_loader import simulation_profiles_root

_SUBNET = IPv4Network("192.168.250.0/24")
_DEVICE_INFO_PATH = "/ISAPI/System/deviceInfo"
_UNKNOWN_PATH = "/ISAPI/Synthetic/missing"


def _resolved(
    device_id: str,
    role: str,
    host_suffix: int,
    expected_model: str,
) -> ResolvedDevice:
    host = IPv4Address(int(_SUBNET.network_address) + host_suffix)
    return ResolvedDevice(
        id=device_id,
        role=role,  # type: ignore[arg-type]
        expected_model=expected_model,
        host=host,
        port=80,
        scheme="http",
        credential_ref=device_id,
    )


def _build_phase1_network(
    faults: dict[str, FaultProfile] | None = None,
) -> tuple[SimulatedNetwork, DeviceRegistry]:
    faults = faults or {}
    profiles = simulation_profiles_root()
    devices_cfg = [
        ("nvr01", "nvr", 200, "DS-7616NXI-K2(D)"),
        ("ptz01", "ptz", 201, "DS-2DE4425IWG1-E"),
        ("cam01", "camera", 202, "DS-2CD2087G3-LI2UY/SL"),
    ]
    sim_devices: dict[tuple[str, int], SimulatedDevice] = {}
    resolved: list[ResolvedDevice] = []
    for device_id, role, suffix, model in devices_cfg:
        dev = _resolved(device_id, role, suffix, model)
        resolved.append(dev)
        profile_dir = profiles / device_id / "synthetic-default"
        sim_devices[(str(dev.host), dev.port)] = SimulatedDevice(
            device_id,
            profile_dir,
            username="synthetic",
            password="synthetic-pass",
            faults=faults.get(device_id),
        )
    network = SimulatedNetwork(sim_devices)
    registry = DeviceRegistry(resolved, NetworkPolicy(_SUBNET, simulation=True))
    return network, registry


def _client_for(
    device: ResolvedDevice,
    registry: DeviceRegistry,
    transport: httpx.BaseTransport,
    *,
    password: str = "synthetic-pass",
    policy: EndpointPolicy | None = None,
) -> IsapiClient:
    policy = policy or build_phase1_policy()
    cred = Credential(username="synthetic", password=SecretStr(password))
    return IsapiClient(
        device,
        cred,
        registry,
        policy,
        EgressPolicy({device.host}),
        TimeoutConfig(),
        inner_transport=transport,
        sleep=lambda _secs: None,
    )


def _policy_with_unknown_path() -> EndpointPolicy:
    base = build_phase1_policy().rule_for("system.device_info")
    unknown = EndpointRule(
        id="test.unknown_path",
        path_template=_UNKNOWN_PATH,
        method="GET",
        sensitivity="normal",
    )
    return EndpointPolicy([base, unknown])


@pytest.mark.simulation
@pytest.mark.parametrize("device_id", ["nvr01", "ptz01", "cam01"])
def test_isapi_client_reads_device_info_with_digest(device_id: str) -> None:
    network, registry = _build_phase1_network()
    device = registry.get(device_id)
    with _client_for(device, registry, network.transport()) as client:
        response = client.read("system.device_info")
    assert response.http_status == 200
    assert response.document is not None
    assert response.document.text("model") is not None
    assert all(method == "GET" for _dev, method, _path in network.request_log)


@pytest.mark.simulation
def test_wrong_password_raises_auth_error() -> None:
    network, registry = _build_phase1_network()
    device = registry.get("nvr01")
    with (
        _client_for(device, registry, network.transport(), password="wrong-pass") as client,
        pytest.raises(AuthError),
    ):
        client.read("system.device_info")


@pytest.mark.simulation
def test_connect_error_maps_to_device_connection_error() -> None:
    network, registry = _build_phase1_network(
        {"nvr01": FaultProfile(connect_error=True)},
    )
    device = registry.get("nvr01")
    with (
        _client_for(device, registry, network.transport()) as client,
        pytest.raises(DeviceConnectionError),
    ):
        client.read("system.device_info")


@pytest.mark.simulation
def test_read_timeout_fault_maps_to_device_timeout() -> None:
    network, registry = _build_phase1_network(
        {"ptz01": FaultProfile(read_timeout_times=3)},
    )
    device = registry.get("ptz01")
    with _client_for(device, registry, network.transport()) as client, pytest.raises(DeviceTimeout):
        client.read("system.device_info")


@pytest.mark.simulation
def test_not_support_path_maps_to_not_supported_error() -> None:
    network, registry = _build_phase1_network(
        {"cam01": FaultProfile(not_support_paths={_DEVICE_INFO_PATH})},
    )
    device = registry.get("cam01")
    with (
        _client_for(device, registry, network.transport()) as client,
        pytest.raises(NotSupportedError),
    ):
        client.read("system.device_info")


@pytest.mark.simulation
def test_unknown_path_maps_to_endpoint_not_found() -> None:
    network, registry = _build_phase1_network()
    device = registry.get("nvr01")
    policy = _policy_with_unknown_path()
    with (
        _client_for(device, registry, network.transport(), policy=policy) as client,
        pytest.raises(EndpointNotFound),
    ):
        client.read("test.unknown_path")


@pytest.mark.simulation
def test_malformed_path_maps_to_xml_parse_error() -> None:
    network, registry = _build_phase1_network(
        {"nvr01": FaultProfile(malformed_paths={_DEVICE_INFO_PATH})},
    )
    device = registry.get("nvr01")
    with _client_for(device, registry, network.transport()) as client, pytest.raises(XmlParseError):
        client.read("system.device_info")


@pytest.mark.simulation
def test_request_log_records_only_get_for_client_reads() -> None:
    network, registry = _build_phase1_network()
    device = registry.get("cam01")
    with _client_for(device, registry, network.transport()) as client:
        client.read("system.device_info")
    methods = {method for _dev, method, _path in network.request_log}
    assert methods == {"GET"}


@pytest.mark.simulation
def test_simulator_returns_405_for_non_get_without_guard() -> None:
    network, registry = _build_phase1_network()
    device = registry.get("nvr01")
    transport = network.transport()
    request = httpx.Request(
        "PUT",
        f"http://{device.host}:{device.port}{_DEVICE_INFO_PATH}",
    )
    response = transport.handle_request(request)
    assert response.status_code == 405