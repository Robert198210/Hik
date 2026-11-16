from __future__ import annotations

import os
import subprocess
import sys
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

from haca.collect.engine import CollectionEngine
from haca.config.models import TimeoutConfig
from haca.devices.models import ResolvedDevice
from haca.devices.network_policy import NetworkPolicy, NetworkPolicyViolation
from haca.isapi.registry.loader import build_collection_policy, load_registry_entries
from haca.security.credentials import Credential, DictCredentialStore
from haca.security.egress import EgressPolicy

_REPO = Path(__file__).resolve().parents[2]


def _ip(a: int, b: int, c: int, d: int) -> IPv4Address:
    return IPv4Address((a << 24) + (b << 16) + (c << 8) + d)


def _lan_device() -> ResolvedDevice:
    return ResolvedDevice(
        id="nvr01",
        role="nvr",
        expected_model="DS-7616NXI-K2(D)",
        host=_ip(192, 168, 1, 200),
        port=80,
        scheme="http",
        credential_ref="nvr01",
    )


def _engine(policy: NetworkPolicy | None) -> CollectionEngine:
    registry = load_registry_entries()
    device = _lan_device()
    cred = Credential(username="admin", password=SecretStr("not-used"))
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(
            401,
            headers={
                "WWW-Authenticate": 'Digest realm="test", nonce="abc", qop="auth", algorithm=MD5'
            },
        )
    )
    return CollectionEngine(
        registry,
        build_collection_policy(registry),
        EgressPolicy({device.host}),
        DictCredentialStore({device.id: cred}),
        TimeoutConfig(),
        lambda _device: transport,
        network_policy=policy,
    )


def test_default_engine_rejects_lan_outside_simulation_subnet() -> None:
    with pytest.raises(NetworkPolicyViolation):
        _engine(None).collect([_lan_device()], simulated=False)


def test_live_policy_collects_lan_device_without_leaving_the_process() -> None:
    policy = NetworkPolicy(IPv4Network((_ip(192, 168, 1, 0), 24)), simulation=False)
    result = _engine(policy).collect([_lan_device()], simulated=False)
    assert result.simulated is False
    device = result.devices[0]
    assert device.identification_status == "AUTH_FAILED"
    assert device.evidence["system.device_info"].outcome.value == "AUTH_DENIED"


def test_basename_overwrites_stable_report_names(tmp_path: Path) -> None:
    proc = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "haca",
            "audit",
            "--simulate",
            "--scenario",
            "clean",
            "--format",
            "json,md,html",
            "--out",
            str(tmp_path),
            "--basename",
            "raport",
        ],
        cwd=_REPO,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert (tmp_path / "raport.json").is_file()
    assert (tmp_path / "raport.md").is_file()
    assert (tmp_path / "raport.html").is_file()
    assert list(tmp_path.glob("haca-audit-*")) == []


def test_live_audit_cli_stops_when_credentials_are_missing() -> None:
    env = {key: value for key, value in os.environ.items() if not key.startswith("HACA_CRED_")}
    proc = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "haca",
            "audit",
            "--config",
            "haca.laptop.yaml",
            "--devices",
            "devices.laptop.yaml",
        ],
        cwd=_REPO,
        env=env,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1
    assert "not wired" not in proc.stderr
    assert "credentials not found" in proc.stderr
