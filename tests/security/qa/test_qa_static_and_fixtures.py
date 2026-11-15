# ruff: noqa: S104, S105, S106, S107, S324, E501
"""T1.09 QA: fabricated-data greps, ADR-001/ADR-017 static checks, scanner evasion, fixtures."""

from __future__ import annotations

import ast
import importlib.metadata
import re
import sys
import textwrap
import tomllib
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
SRC = REPO / "src" / "haca"
QA_DIR = Path(__file__).resolve().parent

if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tools.scan_fixture_secrets import scan  # noqa: E402

pytestmark = pytest.mark.security

_PRIVATE_DIR = "skrypty" + "/" + "Hikvision"  # built by concatenation: this file must not match
_SYNTH_NET = IPv4Network("192.168.250.0/24")


def _text_files(*roots: Path, suffixes: tuple[str, ...]) -> list[Path]:
    files: list[Path] = []
    for root in roots:
        if root.is_file():
            files.append(root)
            continue
        for path in root.rglob("*"):
            if (
                path.is_file()
                and path.suffix in suffixes
                and "__pycache__" not in path.parts
                and ".venv" not in path.parts
            ):
                files.append(path)
    return files


def _code_roots() -> list[Path]:
    return [SRC, REPO / "tools", REPO / "config", REPO / "tests", REPO / "pyproject.toml"]


# ---------------------------------------------------------------------------
# ADR-017: no reference to / derivation from the private capture directory
# ---------------------------------------------------------------------------


def test_no_code_test_config_or_fixture_references_private_hikvision_dir() -> None:
    offenders = []
    for path in _text_files(
        *_code_roots(), suffixes=(".py", ".yaml", ".yml", ".xml", ".toml", ".json", ".txt", ".md")
    ):
        if path.resolve() == Path(__file__).resolve():
            continue
        if _PRIVATE_DIR in path.read_text(encoding="utf-8", errors="replace"):
            offenders.append(str(path.relative_to(REPO)))
    assert offenders == []


def test_no_har_pcap_or_capture_files_in_repo() -> None:
    bad = [
        p
        for p in REPO.rglob("*")
        if p.is_file()
        and p.suffix.lower() in {".har", ".pcap", ".pcapng", ".pem", ".key"}
        and ".venv" not in p.parts
        and ".git" not in p.parts
    ]
    assert bad == []


# ---------------------------------------------------------------------------
# Fabricated data greps (src, tools, config, tests incl. .py)
# ---------------------------------------------------------------------------

_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SYNTH_MAC = re.compile(r"00:00:5E:00:53:[0-9A-F]{2}", re.IGNORECASE)
# Documented non-device addresses that tests use as *negative* examples.
_NEGATIVE_IPS = {
    "8.8.8.8",
    "8.8.8.0",
    "1.1.1.1",
    "192.168.1.10",
    "127.0.0.1",
    "127.0.0.0",
    "169.254.1.1",
    "169.254.0.0",
    "169.254.0.1",
    "169.254.169.254",
    "10.0.0.0",
    "10.0.0.1",
    "10.0.0.5",
    "10.1.2.0",
    "172.16.0.0",
    "172.16.0.5",
    "192.168.0.0",
    "224.0.0.0",
    "255.255.255.255",
    "0.0.0.0",
}


def test_all_macs_in_repo_are_synthetic_or_documented_negative_samples() -> None:
    allowed_negative = {"AA:BB:CC:DD:EE:FF"}
    for path in _text_files(*_code_roots(), suffixes=(".py", ".yaml", ".xml", ".toml")):
        if path.resolve() == Path(__file__).resolve():
            continue
        for mac in _MAC_RE.findall(path.read_text(encoding="utf-8", errors="replace")):
            assert _SYNTH_MAC.fullmatch(mac) or mac.upper() in allowed_negative, (path, mac)


def test_all_ipv4_literals_in_repo_are_synthetic_or_documented_negative_samples() -> None:
    for path in _text_files(*_code_roots(), suffixes=(".py", ".yaml", ".xml", ".toml")):
        if path.resolve() == Path(__file__).resolve() or path.parent == QA_DIR:
            continue
        for literal in _IP_RE.findall(path.read_text(encoding="utf-8", errors="replace")):
            try:
                ip = IPv4Address(literal)
            except ValueError:
                continue  # version strings such as 0.1.0.0
            in_ok = ip in _SYNTH_NET or literal in _NEGATIVE_IPS
            assert in_ok or path.name == "pyproject.toml", (str(path.relative_to(REPO)), literal)


def test_all_serials_and_uuids_in_xml_fixtures_are_synthetic() -> None:
    serial = re.compile(r"<serialNumber>([^<]*)</serialNumber>")
    uuid = re.compile(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    )
    xmls = _text_files(SRC / "simulation", REPO / "tests", suffixes=(".xml",))
    assert xmls
    for path in xmls:
        text = path.read_text(encoding="utf-8")
        for value in serial.findall(text):
            assert re.fullmatch(r"SYNTH-[A-Z0-9]+-\d{4}|SYNTH-XXE-PLACEHOLDER", value), (
                path,
                value,
            )
        for value in uuid.findall(text):
            assert re.fullmatch(r"00000000-0000-0000-0000-0000000000[0-9a-f]{2}", value), (
                path,
                value,
            )


def test_fixture_deviceinfo_elements_are_limited_to_documented_set() -> None:
    """No XML element outside the T1.06 spec list may appear in DeviceInfo fixtures."""
    allowed = {
        "DeviceInfo",
        "deviceName",
        "deviceID",
        "model",
        "serialNumber",
        "macAddress",
        "firmwareVersion",
        "firmwareReleasedDate",
        "deviceType",
        "manufacturer",
    }
    tag = re.compile(r"<([A-Za-z][A-Za-z0-9]*)[\s>/]")
    for path in _text_files(
        SRC / "simulation" / "profiles", REPO / "tests" / "simulation_profiles", suffixes=(".xml",)
    ):
        text = path.read_text(encoding="utf-8")
        if "<DeviceInfo" not in text:
            continue
        assert set(tag.findall(text)) <= allowed | {"ResponseStatus"}, path


def test_fixture_values_match_task_spec() -> None:
    expected = {
        "nvr01": ("DS-7616NXI-K2(D)", "NVR", "V4.99.000"),
        "ptz01": ("DS-2DE4425IWG1-E", "IPDome", "V5.99.000"),
        "cam01": ("DS-2CD2087G3-LI2UY/SL", "IPCamera", "V5.99.000"),
    }
    for device_id, (model, dtype, fw) in expected.items():
        text = (
            SRC / "simulation" / "profiles" / device_id / "synthetic-default" / "device_info.xml"
        ).read_text()
        assert f"<model>{model}</model>" in text
        assert f"<deviceType>{dtype}</deviceType>" in text
        assert f"<firmwareVersion>{fw}</firmwareVersion>" in text
        assert f"<deviceName>SYNTHETIC {device_id.upper()}</deviceName>" in text
        assert "<manufacturer>hikvision</manufacturer>" in text
    ns2 = (SRC / "simulation/profiles/nvr01/synthetic-ns-isapi-org/device_info.xml").read_text()
    assert 'xmlns="http://www.isapi.org/ver20/XMLSchema"' in ns2 and 'version="2.0"' in ns2


def _expanded_registry_paths() -> set[str]:
    from haca.isapi.registry.loader import all_registry_paths, load_registry_entries

    templates = all_registry_paths(load_registry_entries())
    expanded = set(templates)
    for template in templates:
        if "{" in template:
            expanded.add(
                template.replace("{channel}", "1")
                .replace("{id}", "1")
                .replace("{track}", "1")
            )
    return expanded


def test_isapi_paths_in_src_are_registry_or_denylist_only() -> None:
    registry_paths = _expanded_registry_paths()
    path_re = re.compile(r"""["'`>](/(?:ISAPI|SDK|PSIA|cgi-bin)/[^"'`<\s]*)""")
    allowed_synthetic = {"/ISAPI/Synthetic/unavailable", "/ISAPI/Synthetic/missing"}
    for path in _text_files(SRC, suffixes=(".py", ".yaml", ".xml")):
        rel = path.relative_to(SRC).as_posix()
        text = path.read_text(encoding="utf-8")
        for found in path_re.findall(text):
            if rel == "security/denylist.py":
                continue
            assert found in registry_paths or found in allowed_synthetic, (rel, found)
    for path in _text_files(SRC, suffixes=(".py",)):
        rel = path.relative_to(SRC).as_posix()
        if rel in {"security/denylist.py", "isapi/registry/loader.py"}:
            continue
        assert not re.search(r"[\"']/(?:ISAPI|SDK|PSIA|cgi-bin)/", path.read_text()), rel


def test_phase1_registry_entry_has_source_and_verification() -> None:
    from haca.isapi.registry.phase1_endpoints import PHASE1_ENDPOINTS

    assert len(PHASE1_ENDPOINTS) >= 1
    for entry in PHASE1_ENDPOINTS:
        assert entry.source.strip()
        assert entry.verification in {
            "observed_live",
            "documented",
            "candidate_unverified",
        }
    device_info = next(e for e in PHASE1_ENDPOINTS if e.id == "system.device_info")
    assert device_info.method == "GET"
    assert set(device_info.device_roles) == {"nvr", "ptz", "camera"}


# ---------------------------------------------------------------------------
# ADR-001: no write-capable HTTP verbs anywhere in src (AST scan)
# ---------------------------------------------------------------------------

_WRITE_ATTRS = {"put", "post", "delete", "patch", "head", "options", "send", "stream"}


def test_src_has_no_write_capable_http_calls() -> None:
    offenders: list[str] = []
    request_callers: list[str] = []
    for path in _text_files(SRC, suffixes=(".py",)):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        rel = path.relative_to(SRC).as_posix()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in _WRITE_ATTRS and not (
                    isinstance(node.func.value, ast.Name) and node.func.value.id in {"os", "sys"}
                ):
                    offenders.append(f"{rel}:{node.lineno}:{node.func.attr}")
                if node.func.attr == "request":
                    request_callers.append(rel)
            if (
                isinstance(node, ast.Constant)
                and node.value in {"PUT", "DELETE", "PATCH"}
                and rel != "security/endpoint_policy.py"
            ):
                offenders.append(f"{rel}:{node.lineno}:literal {node.value}")
    assert offenders == []
    assert set(request_callers) == {"isapi/client.py"}


def test_runtime_has_no_forbidden_ai_or_cloud_dependency_imports() -> None:
    forbidden = re.compile(r"^\s*(?:import|from)\s+(anthropic|openai|cursor\w*|claude\w*)\b", re.M)
    for path in _text_files(SRC, REPO / "tools", suffixes=(".py",)):
        assert not forbidden.search(path.read_text(encoding="utf-8")), path


def test_lockfile_and_environment_have_no_forbidden_packages() -> None:
    bad = re.compile(r"^(anthropic|openai|cursor.*|claude.*)$", re.IGNORECASE)
    lock = tomllib.loads((REPO / "uv.lock").read_text(encoding="utf-8"))
    names = [p["name"] for p in lock["package"]]
    assert not [n for n in names if bad.match(n)]
    installed = {d.metadata["Name"] for d in importlib.metadata.distributions()}
    assert not [n for n in installed if bad.match(n)]


def test_pyproject_matches_t101_spec() -> None:
    data = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    project = data["project"]
    assert project["name"] == "haca" and project["version"] == "0.1.0.dev0"
    assert project["requires-python"] == ">=3.12,<3.13"
    assert {re.split(r"[<>=]", d)[0] for d in project["dependencies"]} == {
        "httpx",
        "defusedxml",
        "pydantic",
        "sqlalchemy",
        "pyyaml",
        "keyring",
    }
    assert set(project["optional-dependencies"]) == {"ai", "web", "browser"}
    assert project["scripts"]["haca"] == "haca.cli:main"
    assert data["build-system"]["build-backend"] == "hatchling.build"
    pytest_cfg = data["tool"]["pytest"]["ini_options"]
    assert pytest_cfg["addopts"] == "-m 'not live'"
    assert {m.split(":")[0] for m in pytest_cfg["markers"]} == {"security", "simulation", "live"}
    ruff = data["tool"]["ruff"]
    assert ruff["line-length"] == 100 and ruff["lint"]["select"] == [
        "E",
        "F",
        "I",
        "B",
        "UP",
        "S",
        "SIM",
    ]
    assert data["tool"]["mypy"]["disallow_untyped_defs"] is True
    for pkg in (
        "config",
        "requirements",
        "devices",
        "security",
        "isapi",
        "simulation",
        "catalog",
        "collect",
        "store",
        "analysis",
        "reports",
    ):
        assert (SRC / pkg / "__init__.py").is_file(), pkg


# ---------------------------------------------------------------------------
# Scanner evasion attempts
# ---------------------------------------------------------------------------


def _scan_profile(
    tmp_path: Path, files: dict[str, str], provenance: str = "origin: synthetic\n"
) -> set[str]:
    profile = tmp_path / "simulation" / "profiles" / "d1" / "p1"
    profile.mkdir(parents=True)
    (profile / "provenance.yaml").write_text(provenance, encoding="utf-8")
    for name, content in files.items():
        (profile / name).write_text(textwrap.dedent(content), encoding="utf-8")
    return {f.rule for f in scan([tmp_path])}


@pytest.mark.parametrize(
    ("name", "content", "rule"),
    [
        ("a.xml", "<D><macAddress>44:19:B6:11:22:33</macAddress></D>", "mac_address"),
        ("a.xml", "<D><macAddress>aa:bb:cc:dd:ee:ff</macAddress></D>", "mac_address"),
        ("a.yaml", "mac: 44:19:b6:11:22:33\n", "mac_address"),
        ("a.json", '{"ip": "93.184.216.34"}', "ipv4"),
        ("a.yml", "ip: 192.168.1.64\n", "ipv4"),
        ("a.xml", "<D><ipAddress>10.20.30.40</ipAddress></D>", "ipv4"),
        ("a.xml", "<D><serialNumber>DS-7616NXI-K2/ABC123456</serialNumber></D>", "serial_number"),
        ("a.xml", '<D xmlns="urn:x"><serialNumber> abc </serialNumber></D>', "serial_number"),
        ("a.xml", "<D><deviceID>11111111-2222-3333-4444-555555555555</deviceID></D>", "uuid"),
        (
            "a.xml",
            "<D><deviceID>00000000-0000-0000-0000-0000000000AB</deviceID><x>"
            "ABCDEF01-2345-6789-ABCD-EF0123456789</x></D>",
            "uuid",
        ),
        ("a.xml", "<D><password>hunter2</password></D>", "credential_field"),
        ("a.xml", "<D><userName>admin</userName></D>", "credential_field"),
        (
            "a.xml",
            '<D xmlns="urn:x"><ns:password xmlns:ns="urn:y">hunter2</ns:password></D>',
            "credential_field",
        ),
        ("a.txt", "see 8.8.4.4 for details\n", "ipv4"),
        ("a.md", "device at 203.0.113.9\n", "ipv4"),
    ],
)
def test_scanner_detects_violation_variants(
    tmp_path: Path, name: str, content: str, rule: str
) -> None:
    assert rule in _scan_profile(tmp_path, {name: content})


def test_scanner_detects_broken_xml_with_secrets_via_text_fallback(tmp_path: Path) -> None:
    rules = _scan_profile(tmp_path, {"a.xml": "<D><macAddress>44:19:B6:11:22:33</macAddress><"})
    assert "mac_address" in rules


@pytest.mark.parametrize(
    "provenance",
    [
        "origin: real\n",
        "origin: Synthetic\n",
        "",
        "origin: [synthetic]\n",
        "- origin: synthetic\n",
        "origin: synthetic\n: bad: yaml: [",
        "author: x\n",
    ],
)
def test_scanner_provenance_negative_variants(tmp_path: Path, provenance: str) -> None:
    assert "provenance" in _scan_profile(tmp_path, {"a.xml": "<D/>"}, provenance)


def test_scanner_flags_missing_scan_path_and_exit_code(tmp_path: Path) -> None:
    from tools.scan_fixture_secrets import main

    findings = scan([tmp_path / "does-not-exist"])
    assert findings and findings[0].rule == "path"
    assert main([str(tmp_path / "does-not-exist")]) == 1
    assert main([]) == 2


def test_scanner_clean_over_repo_profiles_and_tests() -> None:
    assert scan([SRC / "simulation" / "profiles", REPO / "tests"]) == []


def test_scanner_detects_dash_separated_mac(tmp_path: Path) -> None:
    rules = _scan_profile(tmp_path, {"a.xml": "<D><macAddress>44-19-B6-11-22-33</macAddress></D>"})
    assert "mac_address" in rules
