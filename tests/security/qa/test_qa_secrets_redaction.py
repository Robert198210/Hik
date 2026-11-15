# ruff: noqa: S104, S105, S106, S107, S324, E501
"""T1.09 QA: canary password, redaction filter hostility, credential handling."""

from __future__ import annotations

import io
import json
import logging
import traceback
from collections.abc import Iterator

import pytest
from pydantic import SecretStr

from haca.cli import main
from haca.collect.identify import identify
from haca.config.models import TimeoutConfig
from haca.isapi.client import IsapiClient
from haca.isapi.errors import AuthError
from haca.isapi.registry.phase1_endpoints import build_phase1_policy
from haca.security import redaction
from haca.security.credentials import Credential, CredentialNotFound, EnvCredentialStore
from haca.security.egress import EgressPolicy
from haca.security.errors import PolicyViolation
from haca.security.redaction import SecretRedactor, redact_text, register_secret
from haca.simulation.defaults import build_simulation_network, simulation_registry

from .helpers import DEVICE_INFO_URL, CountingTransport, make_client

pytestmark = pytest.mark.security

CANARY = "QA-CANARY-PW-5e1d9c"


@pytest.fixture
def canary_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HACA_CRED_NVR01_USERNAME", "synthetic")
    monkeypatch.setenv("HACA_CRED_NVR01_PASSWORD", CANARY)


def _all_text(exc: BaseException) -> str:
    chain: list[str] = []
    cur: BaseException | None = exc
    while cur is not None:
        chain.append(str(cur))
        chain.append(repr(cur))
        chain.append(getattr(cur, "detail", "") or "")
        cur = cur.__cause__ or cur.__context__
    chain.append("".join(traceback.format_exception(exc)))
    return "\n".join(chain)


def test_canary_not_in_logs_exceptions_or_reprs_for_failed_auth(
    canary_env: None, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    for name in ("httpx", "httpcore", "haca", "haca.security", "haca.collect"):
        logging.getLogger(name).setLevel(logging.DEBUG)

    cred = EnvCredentialStore().get("nvr01")
    assert cred.password.get_secret_value() == CANARY
    network = build_simulation_network()
    registry = simulation_registry()
    device = registry.get("nvr01")
    client = IsapiClient(
        device,
        cred,
        registry,
        build_phase1_policy(),
        EgressPolicy({device.host}),
        TimeoutConfig(),
        inner_transport=network.transport(),
        sleep=lambda _s: None,
    )
    blobs: list[str] = []
    with client:
        with pytest.raises(AuthError) as auth_exc:
            client.read("system.device_info")
        blobs.append(_all_text(auth_exc.value))
        with pytest.raises(PolicyViolation) as pv_exc:
            client._client.request("PUT", f"http://{device.host}/ISAPI/System/reboot")  # noqa: SLF001
        blobs.append(_all_text(pv_exc.value))
        with pytest.raises(PolicyViolation) as pv2:
            client.read("nope")
        blobs.append(_all_text(pv2.value))
        result = identify(client, device)
        blobs.append(result.model_dump_json())
        blobs.append(repr(client))
        blobs.append(repr(client._client))  # noqa: SLF001
    blobs += [str(cred), repr(cred), cred.model_dump_json(), repr(cred.password), caplog.text]
    for blob in blobs:
        assert CANARY not in blob


def test_canary_not_in_identify_result_for_each_failure_mode(canary_env: None) -> None:
    cred = EnvCredentialStore().get("nvr01")
    registry = simulation_registry()
    device = registry.get("nvr01")
    from haca.simulation.faults import FaultProfile

    for fault in (
        FaultProfile(auth_always_fail=True),
        FaultProfile(connect_error=True),
        FaultProfile(read_timeout_times=3),
        FaultProfile(malformed_paths={"/ISAPI/System/deviceInfo"}),
        FaultProfile(http_status_override={"/ISAPI/System/deviceInfo": 500}),
    ):
        network = build_simulation_network(faults={"nvr01": fault})
        with IsapiClient(
            device,
            cred,
            registry,
            build_phase1_policy(),
            EgressPolicy({device.host}),
            TimeoutConfig(),
            inner_transport=network.transport(),
            sleep=lambda _s: None,
        ) as client:
            result = identify(client, device)
        assert CANARY not in result.model_dump_json()


def test_cli_simulate_output_never_contains_credentials(
    canary_env: None, capsys: pytest.CaptureFixture[str]
) -> None:
    for argv in (["identify", "--simulate"], ["identify", "--simulate", "--json"]):
        with pytest.raises(SystemExit) as exc:
            main(argv)
        assert exc.value.code == 0
        out = capsys.readouterr()
        for text in (out.out, out.err):
            assert CANARY not in text
            assert "synthetic-pass" not in text


def test_cli_live_path_with_partial_credentials_does_not_echo_canary(
    canary_env: None,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ptz01/cam01 credentials intentionally absent: failure happens before any request is made.
    for ref in ("PTZ01", "CAM01"):
        monkeypatch.delenv(f"HACA_CRED_{ref}_USERNAME", raising=False)
        monkeypatch.delenv(f"HACA_CRED_{ref}_PASSWORD", raising=False)
    with pytest.raises(BaseException) as exc:  # noqa: B017, PT011
        main(["identify"])
    out = capsys.readouterr()
    assert CANARY not in out.out + out.err
    assert CANARY not in _all_text(exc.value)


def test_cli_live_path_missing_credentials_exits_cleanly_with_code_1(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for ref in ("NVR01", "PTZ01", "CAM01"):
        monkeypatch.delenv(f"HACA_CRED_{ref}_USERNAME", raising=False)
        monkeypatch.delenv(f"HACA_CRED_{ref}_PASSWORD", raising=False)
    with pytest.raises(SystemExit) as exc:
        main(["identify"])
    assert exc.value.code == 1
    assert "Traceback" not in capsys.readouterr().err


def test_env_store_missing_username_or_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HACA_CRED_ONLYU_USERNAME", "u")
    monkeypatch.delenv("HACA_CRED_ONLYU_PASSWORD", raising=False)
    with pytest.raises(CredentialNotFound):
        EnvCredentialStore().get("onlyu")
    monkeypatch.setenv("HACA_CRED_ONLYP_PASSWORD", "p")
    monkeypatch.delenv("HACA_CRED_ONLYP_USERNAME", raising=False)
    with pytest.raises(CredentialNotFound):
        EnvCredentialStore().get("onlyp")


def test_credential_model_is_frozen_and_forbids_extra() -> None:
    cred = Credential(username="u", password=SecretStr("p"))
    with pytest.raises(Exception):  # noqa: B017, PT011
        cred.username = "x"  # type: ignore[misc]
    with pytest.raises(Exception):  # noqa: B017, PT011
        Credential(username="u", password=SecretStr("p"), token="t")  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# Redaction filter
# ---------------------------------------------------------------------------


def _logger_with_stream(name: str) -> tuple[logging.Logger, io.StringIO]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.addFilter(SecretRedactor())
    logger = logging.getLogger(name)
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    return logger, stream


def test_redact_text_known_patterns_and_registered_values() -> None:
    register_secret("QA-REG-SECRET-A")
    register_secret("QA-REG")  # shorter overlapping secret must not break longer masking
    register_secret("")
    out = redact_text(
        "Authorization: Digest username=a, response=abc\n"
        "x QA-REG-SECRET-A y QA-REG z password=hunter2 token: tkn apikey=k secret=s "
        "AIza" + "A" * 35
    )
    for leaked in ("QA-REG-SECRET-A", "QA-REG", "hunter2", "tkn", "AIzaAAAA", "abc"):
        assert leaked not in out
    assert redact_text("") == ""


def test_secret_redactor_masks_message_and_args() -> None:
    register_secret("QA-ARG-SECRET-1")
    logger, stream = _logger_with_stream("qa.redact.basic")
    logger.warning("login failed password=%s for %s", "QA-ARG-SECRET-1", "QA-ARG-SECRET-1")
    logger.warning("QA-ARG-SECRET-1 in msg")
    assert "QA-ARG-SECRET-1" not in stream.getvalue()


@pytest.mark.parametrize(
    ("text", "leak"),
    [
        ('Digest username="a", response="QALEAKRESP1", nc=1', "QALEAKRESP1"),
        ('Digest username="a", cnonce="QALEAKCNONCE1", nc=1', "QALEAKCNONCE1"),
        ('{"password": "QALEAKJSON1"}', "QALEAKJSON1"),
        ('password: "QALEAKPART1 QALEAKPART2"', "QALEAKPART2"),
        ("password='QALEAKPART3 QALEAKPART4'", "QALEAKPART4"),
    ],
)
def test_unregistered_secret_shapes_are_masked(text: str, leak: str) -> None:
    assert leak not in redact_text(text)


def test_secret_redactor_preserves_mapping_style_args() -> None:
    logger, stream = _logger_with_stream("qa.redact.mapping")
    logger.warning("value=%(a)s", {"a": 1})
    assert "value=1" in stream.getvalue()


@pytest.mark.parametrize("channel", ["object_arg", "exc_info"])
def test_registered_secret_not_leaked_via_exception_objects(channel: str) -> None:
    register_secret("QA-EXC-SECRET-9")
    logger, stream = _logger_with_stream(f"qa.redact.{channel}")
    err = ValueError("connection to QA-EXC-SECRET-9 failed")
    if channel == "object_arg":
        logger.warning("failed: %s", err)
    else:
        try:
            raise err
        except ValueError:
            logger.exception("failed")
    assert "QA-EXC-SECRET-9" not in stream.getvalue()


@pytest.fixture
def fresh_root_logging(monkeypatch: pytest.MonkeyPatch) -> Iterator[logging.Logger]:
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_filters = list(root.filters)
    monkeypatch.setattr(redaction, "_REDACTION_INSTALLED", False)
    try:
        yield root
    finally:
        root.handlers = saved_handlers
        root.filters = saved_filters


def test_install_redaction_covers_existing_handlers(fresh_root_logging: logging.Logger) -> None:
    root = fresh_root_logging
    handler = logging.StreamHandler(io.StringIO())
    root.addHandler(handler)
    redaction.install_redaction()
    assert any(isinstance(f, SecretRedactor) for f in handler.filters)
    n_root = sum(isinstance(f, SecretRedactor) for f in root.filters)
    redaction.install_redaction()
    assert sum(isinstance(f, SecretRedactor) for f in root.filters) == n_root
    assert sum(isinstance(f, SecretRedactor) for f in handler.filters) == 1


def test_install_redaction_covers_handlers_added_later(fresh_root_logging: logging.Logger) -> None:
    root = fresh_root_logging
    redaction.install_redaction()
    late = logging.StreamHandler(io.StringIO())
    root.addHandler(late)
    redaction.install_redaction()
    assert any(isinstance(f, SecretRedactor) for f in late.filters)


def test_policy_violation_detail_never_contains_credentials_or_headers() -> None:
    import httpx

    from .helpers import make_guard

    inner = CountingTransport()
    guard = make_guard(inner)
    request = httpx.Request(
        "PUT",
        DEVICE_INFO_URL,
        headers={"Authorization": f"Digest response={CANARY}", "Cookie": f"s={CANARY}"},
        content=CANARY.encode(),
    )
    with pytest.raises(PolicyViolation) as exc:
        guard.handle_request(request)
    assert CANARY not in _all_text(exc.value)


def test_client_with_canary_does_not_serialise_password(canary_env: None) -> None:
    cred = EnvCredentialStore().get("nvr01")
    with make_client(CountingTransport(), password=CANARY):
        pass
    payload = json.dumps({"cred": str(cred), "repr": repr(cred)})
    assert CANARY not in payload
