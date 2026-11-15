from __future__ import annotations

import logging
from ipaddress import IPv4Address, IPv4Network

import httpx
import pytest
from pydantic import SecretStr

from haca.devices.models import ResolvedDevice
from haca.devices.network_policy import NetworkPolicy
from haca.devices.registry import DeviceRegistry
from haca.security.credentials import (
    Credential,
    CredentialNotFound,
    EnvCredentialStore,
    KeyringCredentialStore,
)
from haca.security.egress import EgressPolicy
from haca.security.endpoint_policy import EndpointPolicy, EndpointRule
from haca.security.errors import PolicyViolation
from haca.security.redaction import install_redaction, redact_text
from haca.security.transport_guard import ReadOnlyTransport

_CANARY = "CANARY-PW-7f3a"


@pytest.mark.security
def test_credential_str_and_repr_hide_password() -> None:
    cred = Credential(username="admin", password=SecretStr(_CANARY))
    assert _CANARY not in str(cred)
    assert _CANARY not in repr(cred)


@pytest.mark.security
def test_env_store_loads_and_registers_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HACA_CRED_NVR01_USERNAME", "admin")
    monkeypatch.setenv("HACA_CRED_NVR01_PASSWORD", _CANARY)
    store = EnvCredentialStore()
    cred = store.get("nvr01")
    assert cred.username == "admin"
    assert cred.password.get_secret_value() == _CANARY
    assert _CANARY not in redact_text(f"password={_CANARY}")


@pytest.mark.security
def test_env_store_missing_raises() -> None:
    store = EnvCredentialStore()
    with pytest.raises(CredentialNotFound):
        store.get("missing-ref")


@pytest.mark.security
def test_keyring_store_missing_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    import keyring

    def _missing(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(keyring, "get_password", _missing)
    store = KeyringCredentialStore()
    with pytest.raises(CredentialNotFound):
        store.get("nvr01")


@pytest.mark.security
def test_canary_password_not_in_logs_or_policy_detail(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    install_redaction()
    monkeypatch.setenv("HACA_CRED_NVR01_USERNAME", "admin")
    monkeypatch.setenv("HACA_CRED_NVR01_PASSWORD", _CANARY)
    store = EnvCredentialStore()
    store.get("nvr01")

    subnet = IPv4Network("192.168.250.0/24")
    policy_np = NetworkPolicy(subnet, simulation=False)
    device = ResolvedDevice(
        id="nvr01",
        role="nvr",
        expected_model="SYNTH-NVR",
        host=IPv4Address("192.168.250.200"),
        port=80,
        scheme="http",
        credential_ref="nvr01",
    )
    registry = DeviceRegistry([device], policy_np)
    endpoint_policy = EndpointPolicy(
        [
            EndpointRule(
                id="system.device_info",
                path_template="/ISAPI/System/deviceInfo",
                method="GET",
                sensitivity="normal",
            )
        ]
    )
    egress = EgressPolicy({device.host})

    class NoopTransport(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            return httpx.Response(200)

        def close(self) -> None:
            pass

    transport = ReadOnlyTransport(
        NoopTransport(),
        registry,
        endpoint_policy,
        egress,
    )
    client = httpx.Client(
        transport=transport,
        auth=httpx.DigestAuth("admin", _CANARY),
        trust_env=False,
    )
    caplog.set_level(logging.DEBUG)
    with pytest.raises(PolicyViolation) as exc_info:
        client.get("http://192.168.250.200/ISAPI/System/reboot")
    client.close()

    assert _CANARY not in caplog.text
    assert _CANARY not in exc_info.value.detail