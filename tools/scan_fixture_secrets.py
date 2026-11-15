"""Scan fixture trees for disallowed real-device identifiers and missing provenance."""

from __future__ import annotations

import ipaddress
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree as ET

import yaml
from defusedxml import ElementTree as DefusedET
from defusedxml.common import DefusedXmlException

SYNTH_MAC_RE = re.compile(
    r"\b00:00:5E:00:53:[0-9A-F]{2}\b",
    re.IGNORECASE,
)
ANY_MAC_RE = re.compile(
    r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b",
)
SYNTH_MAC_DASH_RE = re.compile(
    r"\b00-00-5E-00-53-[0-9A-Fa-f]{2}\b",
    re.IGNORECASE,
)
ANY_MAC_DASH_RE = re.compile(
    r"\b(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}\b",
)
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
)
SYNTH_UUID_RE = re.compile(
    r"\b00000000-0000-0000-0000-0000000000[0-9a-f]{2}\b",
    re.IGNORECASE,
)
ANY_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
ALLOWED_TEST_NET = ipaddress.IPv4Network("192.168.250.0/24")
ALLOWED_IPV4 = frozenset(
    {
        ipaddress.IPv4Address("127.0.0.1"),
        ipaddress.IPv4Address("0.0.0.0"),  # noqa: S104
    }
)
CREDENTIAL_TAGS = frozenset({"password", "userName"})
SKIP_EXTENSIONS = frozenset({".pyc", ".pyo"})
FIXTURE_TEXT_EXTENSIONS = frozenset({".xml", ".yaml", ".yml", ".json", ".txt", ".md", ".csv"})


@dataclass(frozen=True, slots=True)
class Finding:
    """A single policy violation detected in a scanned path."""

    path: str
    rule: str
    message: str


def _allowed_ipv4(addr: ipaddress.IPv4Address) -> bool:
    return addr in ALLOWED_IPV4 or addr in ALLOWED_TEST_NET


def _scan_text_content(path: Path, text: str, findings: list[Finding]) -> None:
    rel = str(path)
    for match in ANY_MAC_RE.finditer(text):
        mac = match.group(0)
        if not SYNTH_MAC_RE.fullmatch(mac):
            findings.append(
                Finding(
                    rel,
                    "mac_address",
                    f"MAC address not in synthetic range: {mac}",
                )
            )
    for match in ANY_MAC_DASH_RE.finditer(text):
        mac = match.group(0)
        if not SYNTH_MAC_DASH_RE.fullmatch(mac):
            findings.append(
                Finding(
                    rel,
                    "mac_address",
                    f"MAC address not in synthetic range: {mac}",
                )
            )
    for match in IPV4_RE.finditer(text):
        try:
            addr = ipaddress.IPv4Address(match.group(0))
        except ValueError:
            continue
        if not _allowed_ipv4(addr):
            findings.append(
                Finding(
                    rel,
                    "ipv4",
                    f"IPv4 outside allowed test ranges: {addr}",
                )
            )
    for match in ANY_UUID_RE.finditer(text):
        uid = match.group(0)
        if not SYNTH_UUID_RE.fullmatch(uid):
            findings.append(
                Finding(
                    rel,
                    "uuid",
                    f"UUID not matching synthetic pattern: {uid}",
                )
            )


def _local_tag(elem: ET.Element) -> str:
    if "}" in elem.tag:
        return elem.tag.split("}", 1)[1]
    return elem.tag


def _scan_xml_tree(path: Path, root: ET.Element, findings: list[Finding]) -> None:
    rel = str(path)
    for elem in root.iter():
        tag = _local_tag(elem)
        if tag == "serialNumber" and elem.text:
            value = elem.text.strip()
            if value and not value.startswith("SYNTH-"):
                findings.append(
                    Finding(
                        rel,
                        "serial_number",
                        f"serialNumber must start with SYNTH-: {value!r}",
                    )
                )
        if tag in CREDENTIAL_TAGS and elem.text:
            value = elem.text.strip()
            if value and value != "synthetic":
                findings.append(
                    Finding(
                        rel,
                        "credential_field",
                        f"{tag} must be empty or 'synthetic': {value!r}",
                    )
                )


def _scan_xml_file(path: Path, findings: list[Finding]) -> None:
    try:
        tree = DefusedET.parse(path)
    except (ET.ParseError, DefusedXmlException):
        _scan_text_content(path, path.read_text(encoding="utf-8", errors="replace"), findings)
        return
    _scan_xml_tree(path, tree.getroot(), findings)
    _scan_text_content(path, path.read_text(encoding="utf-8", errors="replace"), findings)


def _is_profile_directory_v2(directory: Path) -> bool:
    """True for .../simulation/profiles/<device_id>/<profile_name>/."""
    if directory.name.startswith("."):
        return False
    try:
        if directory.parent.parent.name != "profiles":
            return False
        if directory.parent.parent.parent.name != "simulation":
            return False
    except IndexError:
        return False
    return True


def _check_provenance(profile_dir: Path, findings: list[Finding]) -> None:
    prov_path = profile_dir / "provenance.yaml"
    rel = str(profile_dir)
    if not prov_path.is_file():
        findings.append(
            Finding(
                rel,
                "provenance",
                "profile directory missing provenance.yaml",
            )
        )
        return
    try:
        data = yaml.safe_load(prov_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        findings.append(Finding(rel, "provenance", f"invalid provenance.yaml: {exc}"))
        return
    if not isinstance(data, dict) or data.get("origin") != "synthetic":
        findings.append(
            Finding(
                rel,
                "provenance",
                "provenance.yaml must declare origin: synthetic",
            )
        )


def _collect_profile_dirs(root: Path) -> set[Path]:
    found: set[Path] = set()
    for profiles_root in root.rglob("profiles"):
        if profiles_root.name != "profiles" or not profiles_root.is_dir():
            continue
        for device_dir in profiles_root.iterdir():
            if not device_dir.is_dir() or device_dir.name.startswith("."):
                continue
            for profile_dir in device_dir.iterdir():
                if profile_dir.is_dir() and not profile_dir.name.startswith("."):
                    found.add(profile_dir.resolve())
    return found


def scan(paths: list[Path]) -> list[Finding]:
    """Scan files and simulation profile directories under ``paths`` for policy violations."""
    findings: list[Finding] = []
    seen_files: set[Path] = set()
    profile_dirs: set[Path] = set()

    for root in paths:
        root = root.resolve()
        if not root.exists():
            findings.append(
                Finding(str(root), "path", f"scan path does not exist: {root}"),
            )
            continue
        profile_dirs |= _collect_profile_dirs(root)
        if _is_profile_directory_v2(root):
            profile_dirs.add(root)

        targets = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()]

        for file_path in targets:
            suffix = file_path.suffix.lower()
            if suffix in SKIP_EXTENSIONS or suffix == ".py":
                continue
            resolved = file_path.resolve()
            if resolved in seen_files:
                continue
            seen_files.add(resolved)

            if suffix == ".xml":
                _scan_xml_file(file_path, findings)
            elif suffix in FIXTURE_TEXT_EXTENSIONS:
                try:
                    text = file_path.read_text(encoding="utf-8", errors="replace")
                except OSError as exc:
                    findings.append(Finding(str(file_path), "path", str(exc)))
                    continue
                _scan_text_content(file_path, text, findings)

    for profile_dir in sorted(profile_dirs):
        _check_provenance(profile_dir, findings)

    findings.sort(key=lambda f: (f.path, f.rule, f.message))
    return findings


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print("usage: scan_fixture_secrets.py <path>...", file=sys.stderr)
        return 2
    scan_paths = [Path(p) for p in args]
    results = scan(scan_paths)
    for item in results:
        print(f"{item.path}: [{item.rule}] {item.message}")
    return 1 if results else 0


if __name__ == "__main__":
    raise SystemExit(main())