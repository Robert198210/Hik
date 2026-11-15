from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml
from defusedxml import ElementTree as DefusedET

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.scan_fixture_secrets import scan  # noqa: E402

PROFILES_DIR = REPO_ROOT / "src/haca/simulation/profiles"
TESTS_DIR = REPO_ROOT / "tests"

SKIP_PARSE = frozenset(
    {
        "malformed.xml",
        "xxe.xml",
        "billion_laughs.xml",
        "empty.xml",
    }
)


def _xml_fixture_paths() -> list[Path]:
    return sorted(p for p in PROFILES_DIR.rglob("*.xml") if p.name not in SKIP_PARSE)


@pytest.mark.parametrize(
    "fixture_path",
    _xml_fixture_paths(),
    ids=lambda p: p.relative_to(PROFILES_DIR).as_posix(),
)
def test_fixture_xml_parses(fixture_path: Path) -> None:
    DefusedET.parse(fixture_path)


def test_fixture_scanner_reports_no_findings() -> None:
    findings = scan([PROFILES_DIR, TESTS_DIR])
    assert findings == [], "\n".join(f"{f.path}: [{f.rule}] {f.message}" for f in findings)


def test_cam01_provenance_is_synthetic_only() -> None:
    prov_path = PROFILES_DIR / "cam01/synthetic-default/provenance.yaml"
    data = yaml.safe_load(prov_path.read_text(encoding="utf-8"))
    assert data["origin"] == "synthetic"
    assert data["real_device_validated"] is False