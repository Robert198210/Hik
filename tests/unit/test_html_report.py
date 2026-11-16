from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]


def test_html_report_rendered_and_masking() -> None:
    out = Path(tempfile.mkdtemp())
    cmd = [
        sys.executable,
        "-m",
        "haca",
        "audit",
        "--simulate",
        "--scenario",
        "clean",
        "--out",
        str(out),
        "--format",
        "html,json",
    ]
    proc = subprocess.run(cmd, cwd=_REPO, capture_output=True, text=True)  # noqa: S603
    assert proc.returncode == 0
    html_files = list(out.glob("haca-audit-*.html"))
    assert html_files
    text = html_files[0].read_text(encoding="utf-8")
    assert "<html" in text
    assert "SYNTH-" not in re.findall(r"SYNTH-[A-Z0-9]{6,}", text)