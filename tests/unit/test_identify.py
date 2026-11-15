from __future__ import annotations

from ipaddress import IPv4Address

from pydantic import SecretStr

from haca.collect.identify import (
    DeviceIdentity,
    IdentificationStatus,
    identify,
    mask_mac,
    mask_serial,
    parse_firmware,
)
from haca.config.models import TimeoutConfig
from haca.devices.models import ResolvedDevice
from haca.isapi.client import IsapiClient
from haca.isapi.registry.phase1_endpoints import build_phase1_policy
from haca.security.credentials import Credential
from haca.security.egress import EgressPolicy
from haca.simulation.defaults import build_simulation_network, simulation_registry


def test_mask_serial_and_mac() -> None:
    assert mask_serial("SYNTH-NVR01-0001") == "****0001"
    assert mask_mac("00:00:5E:00:53:01") == "**:**:**:**:53:01"


def test_parse_firmware_matches_and_unknown() -> None:
    raw, major, minor, patch = parse_firmware("V4.99.000")
    assert raw == "V4.99.000"
    assert (major, minor, patch) == (4, 99, 0)
    odd, m, mi, p = parse_firmware("build-only")
    assert odd == "build-only"
    assert (m, mi, p) == (None, None, None)


def test_identify_success_from_simulator() -> None:
    device = ResolvedDevice(
        id="nvr01",
        role="nvr",
        expected_model="DS-7616NXI-K2(D)",
        host=IPv4Address("192.168.250.200"),
        port=80,
        scheme="http",
        credential_ref="nvr01",
    )
    registry = simulation_registry()
    network = build_simulation_network()
    with IsapiClient(
        device,
        Credential(username="synthetic", password=SecretStr("synthetic-pass")),
        registry,
        build_phase1_policy(),
        EgressPolicy({device.host}),
        TimeoutConfig(),
        inner_transport=network.transport(),
    ) as client:
        result = identify(client, device, simulated=True)
    assert result.status == IdentificationStatus.IDENTIFIED
    assert result.identity is not None
    assert isinstance(result.identity, DeviceIdentity)
    assert result.identity.serial_masked == "****0001"
    assert "SYNTH" not in result.identity.serial_masked


def test_identify_model_mismatch() -> None:
    from pathlib import Path

    repo = Path(__file__).resolve().parents[2]
    profile = repo / "tests/simulation_profiles/ptz01/model-mismatch"
    device = ResolvedDevice(
        id="ptz01",
        role="ptz",
        expected_model="DS-2DE4425IWG1-E",
        host=IPv4Address("192.168.250.201"),
        port=80,
        scheme="http",
        credential_ref="ptz01",
    )
    registry = simulation_registry()
    network = build_simulation_network(profile_dirs={"ptz01": profile})
    with IsapiClient(
        device,
        Credential(username="synthetic", password=SecretStr("synthetic-pass")),
        registry,
        build_phase1_policy(),
        EgressPolicy({device.host}),
        TimeoutConfig(),
        inner_transport=network.transport(),
    ) as client:
        result = identify(client, device, simulated=True)
    assert result.status == IdentificationStatus.MODEL_MISMATCH
    assert result.identity is not None
    assert result.identity.model == "DS-2DE4425IW-DE"