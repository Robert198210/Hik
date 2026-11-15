from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.scan_fixture_secrets import Finding, scan  # noqa: E402


def _rules_in(findings: list[Finding]) -> set[str]:
    return {f.rule for f in findings}


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")


@pytest.fixture
def scratch(tmp_path: Path) -> Path:
    root = tmp_path / "simulation" / "profiles" / "scratch" / "negative-sample"
    root.mkdir(parents=True)
    return root


def test_scanner_detects_mac_violation(scratch: Path) -> None:
    _write(
        scratch / "bad_mac.xml",
        """\
        <?xml version="1.0" encoding="UTF-8"?>
        <DeviceInfo>
          <macAddress>AA:BB:CC:DD:EE:FF</macAddress>
        </DeviceInfo>
        """,
    )
    _write(
        scratch / "provenance.yaml",
        "origin: synthetic\n",
    )
    findings = scan([scratch.parent.parent.parent])
    assert "mac_address" in _rules_in(findings)


def test_scanner_detects_ipv4_violation(scratch: Path) -> None:
    _write(scratch / "note.txt", "gateway 10.0.0.1\n")
    _write(scratch / "provenance.yaml", "origin: synthetic\n")
    findings = scan([scratch.parent.parent.parent])
    assert "ipv4" in _rules_in(findings)


def test_scanner_allows_contiguous_subnet_mask(scratch: Path) -> None:
    _write(
        scratch / "network_interfaces.xml",
        """\
        <?xml version="1.0" encoding="UTF-8"?>
        <NetworkInterfaceList>
          <NetworkInterface>
            <IPAddress>
              <subnetMask>255.255.255.0</subnetMask>
            </IPAddress>
          </NetworkInterface>
        </NetworkInterfaceList>
        """,
    )
    _write(scratch / "provenance.yaml", "origin: synthetic\n")
    findings = scan([scratch.parent.parent.parent])
    assert "ipv4" not in _rules_in(findings)


def test_scanner_detects_serial_violation(scratch: Path) -> None:
    _write(
        scratch / "bad_serial.xml",
        """\
        <?xml version="1.0" encoding="UTF-8"?>
        <DeviceInfo>
          <serialNumber>REAL-SN-12345</serialNumber>
        </DeviceInfo>
        """,
    )
    _write(scratch / "provenance.yaml", "origin: synthetic\n")
    findings = scan([scratch.parent.parent.parent])
    assert "serial_number" in _rules_in(findings)


def test_scanner_detects_uuid_violation(scratch: Path) -> None:
    _write(scratch / "note.txt", "device 12345678-1234-1234-1234-123456789abc\n")
    _write(scratch / "provenance.yaml", "origin: synthetic\n")
    findings = scan([scratch.parent.parent.parent])
    assert "uuid" in _rules_in(findings)


def test_scanner_detects_credential_violation(scratch: Path) -> None:
    _write(
        scratch / "creds.xml",
        """\
        <?xml version="1.0" encoding="UTF-8"?>
        <User>
          <userName>admin</userName>
        </User>
        """,
    )
    _write(scratch / "provenance.yaml", "origin: synthetic\n")
    findings = scan([scratch.parent.parent.parent])
    assert "credential_field" in _rules_in(findings)


def test_scanner_detects_missing_provenance(scratch: Path) -> None:
    _write(scratch / "ok.xml", "<DeviceInfo/>")
    prov = scratch / "provenance.yaml"
    if prov.exists():
        prov.unlink()
    findings = scan([scratch])
    assert "provenance" in _rules_in(findings)


def test_scanner_detects_non_synthetic_provenance(scratch: Path) -> None:
    _write(scratch / "ok.xml", "<DeviceInfo/>")
    _write(scratch / "provenance.yaml", "origin: live_capture\n")
    findings = scan([scratch])
    assert "provenance" in _rules_in(findings)

