# ruff: noqa: S104, S105, S106, S107, S324, E501
"""T1.09 QA: config/ORP hostility, network policy edges, identify and CLI behaviour."""

from __future__ import annotations

import json
import textwrap
from ipaddress import IPv4Address, IPv4Network, IPv6Address
from pathlib import Path

import httpx
import pytest

from haca.cli import _print_identify_table, main
from haca.collect.identify import (
    DeviceIdentity,
    IdentificationResult,
    IdentificationStatus,
    identify,
    identify_devices,
    parse_firmware,
)
from haca.config.errors import ConfigError
from haca.config.loader import load_app_config, load_devices
from haca.config.models import NetworkConfig
from haca.devices.network_policy import NetworkPolicy, NetworkPolicyViolation
from haca.isapi.client import IsapiClient
from haca.isapi.registry.phase1_endpoints import build_phase1_policy
from haca.requirements.loader import load_requirements, requirements_hash
from haca.security.egress import EgressPolicy
from haca.simulation.defaults import (
    build_simulation_network,
    simulation_credential,
    simulation_registry,
    simulation_timeouts,
)
from haca.simulation.faults import FaultProfile

from .helpers import CountingTransport, make_client, make_device

pytestmark = pytest.mark.security

_NET = NetworkConfig(subnet=IPv4Network("192.168.250.0/24"))


def _write(path: Path, text: str) -> Path:
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "subnet",
    [
        "8.8.8.0/24",
        "0.0.0.0/0",
        "10.0.0.0/7",
        "192.168.0.0/15",
        "172.16.0.0/11",
        "172.32.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "224.0.0.0/4",
        "192.168.250.5/24",
        "fd00::/8",
        "not-a-subnet",
        "",
    ],
)
def test_app_config_rejects_non_rfc1918_or_malformed_subnets(tmp_path: Path, subnet: str) -> None:
    path = _write(tmp_path / "a.yaml", f"network:\n  subnet: '{subnet}'\n")
    with pytest.raises(ConfigError):
        load_app_config(path)


@pytest.mark.parametrize(
    "subnet", ["10.1.2.0/24", "172.16.0.0/12", "192.168.0.0/16", "192.168.250.0/24"]
)
def test_app_config_accepts_rfc1918_subnets(tmp_path: Path, subnet: str) -> None:
    path = _write(tmp_path / "a.yaml", f"network:\n  subnet: '{subnet}'\n")
    assert str(load_app_config(path).network.subnet) == subnet


@pytest.mark.parametrize("field", ["connect", "read"])
@pytest.mark.parametrize("value", ["0.4", "0", "-1", "121", ".inf", ".nan", "'x'", "null"])
def test_timeouts_out_of_range_rejected(tmp_path: Path, field: str, value: str) -> None:
    path = _write(
        tmp_path / "a.yaml",
        f"network:\n  subnet: 192.168.250.0/24\ntimeouts:\n  {field}: {value}\n",
    )
    with pytest.raises(ConfigError):
        load_app_config(path)


@pytest.mark.parametrize(
    "content",
    [
        "",
        "- a\n- b\n",
        "just a string\n",
        "network: 5\n",
        "network: {subnet: 192.168.250.0/24, extra: 1}\n",
    ],
)
def test_app_config_structural_garbage(tmp_path: Path, content: str) -> None:
    with pytest.raises(ConfigError):
        load_app_config(_write(tmp_path / "a.yaml", content))


def test_app_config_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_app_config(tmp_path / "nope.yaml")


def test_yaml_python_object_tags_are_not_executed(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "a.yaml",
        "network: !!python/object/apply:builtins.len [[1]]\n",
    )
    with pytest.raises(ConfigError):
        load_app_config(path)


_DEV = """\
devices:
  - id: {id}
    role: nvr
    expected_model: X
    {hostline}
    credential_ref: {ref}
"""


@pytest.mark.parametrize(
    "device_id", ["a", "NVR01", "nvr01\n", "-nvr", "nvr 01", "x" * 33, "", "nvr.01"]
)
def test_device_id_regex_rejections(tmp_path: Path, device_id: str) -> None:
    text = _DEV.format(id=json.dumps(device_id), hostline="host_suffix: 10", ref="nvr01")
    with pytest.raises(ConfigError):
        load_devices(_write(tmp_path / "d.yaml", text), _NET)


@pytest.mark.parametrize("ref", ["NVR01", "nvr01\n", "nvr 01", "a" * 65, "", "nvr:01", "../x"])
def test_credential_ref_regex_rejections(tmp_path: Path, ref: str) -> None:
    text = _DEV.format(id="nvr01", hostline="host_suffix: 10", ref=json.dumps(ref))
    with pytest.raises(ConfigError):
        load_devices(_write(tmp_path / "d.yaml", text), _NET)


@pytest.mark.parametrize(
    "hostline",
    [
        "host_suffix: 0",
        "host_suffix: 255",
        "host_suffix: -1",
        "host_suffix: 256",
        "host: 192.168.251.5",
        "host: 8.8.8.8",
        "host: '192.168.250.0200'",
        "host: nvr.local",
        "host: '::1'",
        "scheme: ftp\n    host_suffix: 5",
    ],
)
def test_device_host_rejections(tmp_path: Path, hostline: str) -> None:
    text = _DEV.format(id="nvr01", hostline=hostline, ref="nvr01")
    with pytest.raises(ConfigError):
        load_devices(_write(tmp_path / "d.yaml", text), _NET)


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "Password",
        "PASSWD",
        "api-key",
        "api_key",
        "token",
        "secret",
        "username",
        "user",
        "private_key",
        "credential",
        "my_password_x",
    ],
)
def test_secret_like_keys_rejected_everywhere_without_echo(tmp_path: Path, key: str) -> None:
    marker = "QA-SECRET-VALUE-77"
    placements = {
        "top": f"{key}: {marker}\nnetwork:\n  subnet: 192.168.250.0/24\n",
        "nested": f"network:\n  subnet: 192.168.250.0/24\n  {key}: {marker}\n",
    }
    for text in placements.values():
        with pytest.raises(ConfigError) as exc:
            load_app_config(_write(tmp_path / "a.yaml", text))
        assert marker not in str(exc.value)
    dev = (
        _DEV.format(id="nvr01", hostline="host_suffix: 10", ref="nvr01") + f"    {key}: {marker}\n"
    )
    with pytest.raises(ConfigError) as exc2:
        load_devices(_write(tmp_path / "d.yaml", dev), _NET)
    assert marker not in str(exc2.value)


@pytest.mark.xfail(
    strict=True,
    reason="DEF-T1.02-2: YAML syntax errors echo the raw source line (may contain secret values)",
)
def test_yaml_syntax_error_does_not_echo_source_line(tmp_path: Path) -> None:
    marker = "QA-SECRET-VALUE-88"
    path = _write(
        tmp_path / "a.yaml",
        f"network:\n  subnet: 192.168.250.0/24\npassword: [{marker}\n",
    )
    with pytest.raises(ConfigError) as exc:
        load_app_config(path)
    assert marker not in str(exc.value)


@pytest.mark.xfail(
    strict=True,
    reason="DEF-T1.02-1: DeviceConfig.port has no range validation (0, negative, >65535 accepted)",
)
@pytest.mark.parametrize("port", [0, -5, 65536, 70000])
def test_device_port_range_validated(tmp_path: Path, port: int) -> None:
    text = _DEV.format(id="nvr01", hostline="host_suffix: 10", ref="nvr01") + f"    port: {port}\n"
    with pytest.raises(ConfigError):
        load_devices(_write(tmp_path / "d.yaml", text), _NET)


def test_disabled_duplicate_suffix_and_unique_ids(tmp_path: Path) -> None:
    text = """\
    devices:
      - {id: aa1, role: nvr, expected_model: X, host_suffix: 10, credential_ref: aa1}
      - {id: aa1, role: ptz, expected_model: X, host_suffix: 11, credential_ref: aa1}
    """
    with pytest.raises(ConfigError):
        load_devices(_write(tmp_path / "d.yaml", text), _NET)


# ---------------------------------------------------------------------------
# ORP
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "profile_version: 1\nunknown_top: 1\n",
        "profile_version: 1\nsystem:\n  recording_mode: bogus\n",
        "profile_version: 1\nsystem:\n  hik_connect: maybe\n",
        "profile_version: 1\ndevices:\n  ghost99:\n    ptz_mode: undecided\n",
        "profile_version: 1\nsystem:\n  unknown_field: x\n",
        "profile_version: 1\nsystem: 5\n",
        "profile_version: 1\nsystem:\n  password: x\n",
        "profile_version: 1\ndevices:\n  nvr01:\n    unknown_field: 1\n",
    ],
)
def test_requirements_rejections(tmp_path: Path, content: str) -> None:
    with pytest.raises(ConfigError):
        load_requirements(_write(tmp_path / "r.yaml", content), {"nvr01", "ptz01", "cam01"})


def test_requirements_hash_changes_for_every_example_value(tmp_path: Path) -> None:
    base = Path(__file__).resolve().parents[3] / "config" / "requirements.example.yaml"
    ids = {"nvr01", "ptz01", "cam01"}
    h0 = requirements_hash(load_requirements(base, ids))
    variant = _write(
        tmp_path / "r.yaml",
        base.read_text(encoding="utf-8").replace("hik_connect: undecided", "hik_connect: required"),
    )
    assert requirements_hash(load_requirements(variant, ids)) != h0
    assert len(h0) == 64


# ---------------------------------------------------------------------------
# NetworkPolicy edges
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ip",
    [
        "0.0.0.0",
        "255.255.255.255",
        "100.64.0.1",
        "172.15.255.255",
        "172.32.0.1",
        "192.167.250.1",
        "192.169.250.1",
        "11.0.0.1",
        "10.0.0.1",
        "224.0.0.1",
        "239.255.255.255",
        "169.254.0.1",
        "192.168.250.0",
        "192.168.250.255",
        "192.168.1.1",
        "8.8.8.8",
    ],
)
@pytest.mark.parametrize("simulation", [False, True])
def test_network_policy_rejects(ip: str, simulation: bool) -> None:
    policy = NetworkPolicy(IPv4Network("192.168.250.0/24"), simulation=simulation)
    with pytest.raises(NetworkPolicyViolation):
        policy.check_host(IPv4Address(ip))


@pytest.mark.parametrize("ip", ["::1", "::ffff:192.168.250.200", "fe80::1", "fd00::1", "::"])
@pytest.mark.parametrize("simulation", [False, True])
def test_network_policy_rejects_ipv6_always(ip: str, simulation: bool) -> None:
    policy = NetworkPolicy(IPv4Network("192.168.250.0/24"), simulation=simulation)
    with pytest.raises(NetworkPolicyViolation):
        policy.check_host(IPv6Address(ip))  # type: ignore[arg-type]


def test_network_policy_loopback_only_in_simulation() -> None:
    subnet = IPv4Network("192.168.250.0/24")
    NetworkPolicy(subnet, simulation=True).check_host(IPv4Address("127.0.0.1"))
    with pytest.raises(NetworkPolicyViolation):
        NetworkPolicy(subnet, simulation=False).check_host(IPv4Address("127.0.0.1"))


def test_network_policy_wider_subnet_edges() -> None:
    policy = NetworkPolicy(IPv4Network("192.168.250.0/23"), simulation=False)
    policy.check_host(IPv4Address("192.168.250.255"))
    policy.check_host(IPv4Address("192.168.251.1"))
    for bad in ("192.168.250.0", "192.168.251.255", "192.168.252.1"):
        with pytest.raises(NetworkPolicyViolation):
            policy.check_host(IPv4Address(bad))


# ---------------------------------------------------------------------------
# Identify
# ---------------------------------------------------------------------------


def _identify_with_body(body: bytes, content_type: str = "application/xml") -> IdentificationResult:
    inner = CountingTransport(
        lambda _r: httpx.Response(200, content=body, headers={"Content-Type": content_type})
    )
    device = make_device()
    with make_client(inner) as client:
        return identify(client, device)


def _info(model: str, extra: str = "") -> bytes:
    return (
        f"<DeviceInfo><model>{model}</model><deviceType>NVR</deviceType>"
        f"<firmwareVersion>V4.99.000</firmwareVersion>"
        f"<serialNumber>SYNTH-QA-0001</serialNumber>"
        f"<macAddress>00:00:5E:00:53:09</macAddress>{extra}</DeviceInfo>"
    ).encode()


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        ("SYNTH-NVR", IdentificationStatus.IDENTIFIED),
        ("  SYNTH-NVR\n", IdentificationStatus.IDENTIFIED),
        ("synth-nvr", IdentificationStatus.MODEL_MISMATCH),
        ("SYNTH-NVR(D)", IdentificationStatus.MODEL_MISMATCH),
        ("SYNTH-NV", IdentificationStatus.MODEL_MISMATCH),
        ("SYNTH-NVR2", IdentificationStatus.MODEL_MISMATCH),
        ("", IdentificationStatus.MODEL_MISMATCH),
    ],
)
def test_identify_model_comparison_is_exact_after_strip(
    model: str, expected: IdentificationStatus
) -> None:
    assert _identify_with_body(_info(model)).status == expected


def test_identify_identified_result_masks_serial_and_mac() -> None:
    result = _identify_with_body(_info("SYNTH-NVR"))
    dumped = result.model_dump_json()
    assert result.identity is not None
    assert "SYNTH-QA-0001" not in dumped and "00:00:5E:00:53:09" not in dumped
    assert result.identity.serial_masked == "****0001"
    assert result.identity.mac_masked == "**:**:**:**:53:09"


@pytest.mark.parametrize(
    ("raw", "parts"),
    [
        ("V4.99.000", (4, 99, 0)),
        ("V5.7.12 build 240101", (5, 7, 12)),
        ("v4.99.000", (None, None, None)),
        ("V4.99", (None, None, None)),
        ("", (None, None, None)),
        ("garbage", (None, None, None)),
        ("V4.99.000x", (4, 99, 0)),
        ("  V1.2.3  ", (1, 2, 3)),
    ],
)
def test_parse_firmware_variants(raw: str, parts: tuple[int | None, ...]) -> None:
    text, major, minor, patch = parse_firmware(raw)
    assert (major, minor, patch) == parts
    assert text == raw.strip()


@pytest.mark.parametrize(
    "body",
    [b"", b"OK", b"<html><body>login</body></html>", b"<ResponseStatus/>", b"<DeviceInfo/>"],
)
def test_identify_odd_but_nonfatal_bodies_never_raise(body: bytes) -> None:
    result = _identify_with_body(body, "text/html")
    assert result.status in {
        IdentificationStatus.ERROR,
        IdentificationStatus.MODEL_MISMATCH,
        IdentificationStatus.IDENTIFIED,
        IdentificationStatus.NOT_SUPPORTED,
        IdentificationStatus.ENDPOINT_NOT_FOUND,
    }


@pytest.mark.xfail(
    strict=True,
    reason="DEF-T1.08-1: XmlParseError preview (80 chars of body) leaks unmasked serial/MAC into result.message",
)
def test_identify_error_message_never_contains_unmasked_serial_or_mac() -> None:
    body = (
        b"<DeviceInfo><serialNumber>SYNTH-LEAK-0001</serialNumber>"
        b"<macAddress>00:00:5E:00:53:09</macAddress><broken>"
    )
    result = _identify_with_body(body)
    assert result.status == IdentificationStatus.ERROR
    dumped = result.model_dump_json()
    assert "SYNTH-LEAK-0001" not in dumped
    assert "00:00:5E:00:53:09" not in dumped


def test_identify_fault_matrix_and_isolation() -> None:
    registry = simulation_registry()
    path = "/ISAPI/System/deviceInfo"
    cases = {
        "auth": (FaultProfile(auth_always_fail=True), IdentificationStatus.AUTH_FAILED),
        "connect": (FaultProfile(connect_error=True), IdentificationStatus.UNREACHABLE),
        "timeout": (FaultProfile(read_timeout_times=3), IdentificationStatus.UNREACHABLE),
        "not_support": (FaultProfile(not_support_paths={path}), IdentificationStatus.NOT_SUPPORTED),
        "malformed": (FaultProfile(malformed_paths={path}), IdentificationStatus.ERROR),
        "http500": (FaultProfile(http_status_override={path: 500}), IdentificationStatus.ERROR),
        "http404": (
            FaultProfile(http_status_override={path: 404}),
            IdentificationStatus.ENDPOINT_NOT_FOUND,
        ),
    }
    for name, (fault, expected) in cases.items():
        network = build_simulation_network(faults={"ptz01": fault})
        pairs = []
        for device in registry.all():
            pairs.append(
                (
                    device,
                    IsapiClient(
                        device,
                        simulation_credential(),
                        registry,
                        build_phase1_policy(),
                        EgressPolicy({device.host}),
                        simulation_timeouts(),
                        inner_transport=network.transport(),
                        sleep=lambda _s: None,
                    ),
                )
            )
        try:
            results = {r.device_id: r.status for r in identify_devices(pairs, simulated=True)}
        finally:
            for _d, c in pairs:
                c.close()
        assert results["ptz01"] == expected, name
        assert results["nvr01"] == IdentificationStatus.IDENTIFIED, name
        assert results["cam01"] == IdentificationStatus.IDENTIFIED, name
        assert {m for _d, m, _p in network.request_log} == {"GET"}


def test_identify_unexpected_exception_does_not_abort_other_devices() -> None:
    class Boom:
        def read(self, _endpoint: str) -> object:
            raise RuntimeError("boom")

    registry = simulation_registry()
    network = build_simulation_network()
    nvr = registry.get("nvr01")
    good = IsapiClient(
        nvr,
        simulation_credential(),
        registry,
        build_phase1_policy(),
        EgressPolicy({nvr.host}),
        simulation_timeouts(),
        inner_transport=network.transport(),
        sleep=lambda _s: None,
    )
    with good:
        results = identify_devices(
            [(registry.get("ptz01"), Boom()), (nvr, good)],  # type: ignore[list-item]
            simulated=True,
        )
    assert [r.status for r in results] == [
        IdentificationStatus.ERROR,
        IdentificationStatus.IDENTIFIED,
    ]


def test_identify_policy_violation_maps_to_policy_blocked_and_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from haca.security.endpoint_policy import EndpointPolicy, EndpointRule

    denied = EndpointPolicy(
        [
            EndpointRule(
                id="system.device_info",
                path_template="/ISAPI/System/deviceInfo",
                method="GET",
                sensitivity="denied",
            )
        ]
    )
    inner = CountingTransport()
    caplog.set_level("WARNING")
    with make_client(inner, policy=denied) as client:
        result = identify(client, make_device())
    assert result.status == IdentificationStatus.POLICY_BLOCKED
    assert inner.calls == []
    assert any("policy blocked" in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_simulate_json_stdout_is_pure_json_and_banner_on_stderr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["identify", "--simulate", "--json"])
    assert exc.value.code == 0
    out = capsys.readouterr()
    payload = json.loads(out.out)
    assert [e["device_id"] for e in payload] == ["nvr01", "ptz01", "cam01"]
    assert all(e["status"] == "IDENTIFIED" and e["simulated"] is True for e in payload)
    assert "SIMULATED" in out.err
    for forbidden in ("SYNTH-NVR01-0001", "SYNTH-PTZ01-0001", "SYNTH-CAM01-0001", "00:00:5E:00:53"):
        assert forbidden not in out.out


def test_cli_simulate_table_has_banner_and_masked_serials(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["identify", "--simulate"])
    assert exc.value.code == 0
    text = capsys.readouterr().out
    assert text.splitlines()[0] == "SIMULATED — synthetic fixtures, no real device contacted"
    assert "****0001" in text and "SYNTH-" not in text


def test_cli_identify_missing_config_exits_1(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["identify", "--config", "/nonexistent/qa-haca.yaml"])
    assert exc.value.code == 1
    assert "not found" in capsys.readouterr().err


def test_cli_no_subcommand_prints_help_exit_0(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 0
    assert "usage" in capsys.readouterr().out.lower()


def test_cli_requirements_validate_error_paths(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    marker = "QA-SECRET-VALUE-99"
    bad_key = _write(tmp_path / "k.yaml", f"profile_version: 1\nsystem:\n  password: {marker}\n")
    bad_dev = _write(tmp_path / "d.yaml", "profile_version: 1\ndevices:\n  ghost99: {}\n")
    for target in (bad_key, bad_dev, tmp_path / "missing.yaml"):
        with pytest.raises(SystemExit) as exc:
            main(["requirements", "validate", "--file", str(target)])
        assert exc.value.code == 1
        err = capsys.readouterr().err
        assert marker not in err


def test_cli_requirements_validate_empty_profile_lists_every_field(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    empty = _write(tmp_path / "e.yaml", "profile_version: 1\n")
    with pytest.raises(SystemExit) as exc:
        main(["requirements", "validate", "--file", str(empty)])
    assert exc.value.code == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines[0]) == 64
    assert any(line.startswith("needs_decision: system.hik_connect") for line in lines)


def test_cli_requirements_example_lists_required_decisions(
    capsys: pytest.CaptureFixture[str],
) -> None:
    example = Path(__file__).resolve().parents[3] / "config" / "requirements.example.yaml"
    with pytest.raises(SystemExit) as exc:
        main(["requirements", "validate", "--file", str(example)])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "needs_decision: system.hik_connect" in out
    assert "needs_decision: ptz01.ptz_mode" in out


@pytest.mark.xfail(
    strict=True,
    reason="DEF-T1.08-3: device-supplied strings (model/firmware) printed raw in table output (ANSI/control chars)",
)
def test_table_output_neutralises_control_characters_from_device(
    capsys: pytest.CaptureFixture[str],
) -> None:
    identity = DeviceIdentity(
        device_id="nvr01",
        model="X\x1b[2J\x1b]0;pwned\x07",
        device_type="NVR",
        firmware_version="V4\r\n99",
        firmware_major=None,
        firmware_minor=None,
        firmware_patch=None,
        firmware_build=None,
        serial_masked="****0001",
        mac_masked="**:**:**:**:53:01",
    )
    result = IdentificationResult(
        device_id="nvr01",
        status=IdentificationStatus.IDENTIFIED,
        identity=identity,
        message="ok",
        simulated=True,
    )
    _print_identify_table([result])
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out and "\r" not in out
