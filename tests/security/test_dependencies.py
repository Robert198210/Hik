from __future__ import annotations

import importlib.metadata
import re
import tomllib
from pathlib import Path

import pytest

_FORBIDDEN = re.compile(r"^(anthropic|openai|cursor.*|claude.*)$", re.IGNORECASE)


@pytest.mark.security
def test_runtime_dependencies_exclude_forbidden_ai_packages() -> None:
    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    raw_deps = data["project"]["dependencies"]
    optional_ai = data["project"].get("optional-dependencies", {}).get("ai", [])
    assert any(dep.startswith("google-genai") for dep in optional_ai)
    declared = {
        dep.split("[")[0].split(">")[0].split("=")[0].strip() for dep in raw_deps
    }
    installed = {dist.metadata["Name"] for dist in importlib.metadata.distributions()}
    names = declared | installed
    offenders = sorted(name for name in names if _FORBIDDEN.match(name))
    assert not offenders, f"forbidden dependencies present: {offenders}"