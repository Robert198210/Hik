from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]


def _run_audit(scenario: str) -> tuple[int, Path, Path]:
    out = Path(tempfile.mkdtemp())
    db = out / "audit.db"
    cmd = [
        sys.executable,
        "-m",
        "haca",
        "audit",
        "--simulate",
        "--scenario",
        scenario,
        "--out",
        str(out),
        "--db",
        str(db),
    ]
    proc = subprocess.run(cmd, cwd=_REPO, capture_output=True, text=True)  # noqa: S603
    json_files = list(out.glob("haca-audit-*.json"))
    assert json_files
    md = json_files[0].with_suffix(".md")
    return proc.returncode, json_files[0], md


def test_cli_audit_conflicts_writes_reports() -> None:
    code, json_path, md_path = _run_audit("conflicts")
    assert code == 3
    assert json_path.is_file()
    assert md_path.is_file()
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["meta"]["simulated"] is True
    md = md_path.read_text(encoding="utf-8")
    assert "SIMULATED" in md
    assert "Coverage matrix" in md


def test_cli_audit_clean_exits_zero() -> None:
    code, _, _ = _run_audit("clean")
    assert code == 0


def test_reports_mask_secrets() -> None:
    _, json_path, md_path = _run_audit("clean")
    text = json_path.read_text(encoding="utf-8") + md_path.read_text(encoding="utf-8")
    assert "SYNTH-" not in re.findall(r"SYNTH-[A-Z0-9]{6,}", text)
