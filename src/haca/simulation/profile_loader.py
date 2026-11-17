"""Load packaged simulation HTTP response profiles."""

from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

_SHARED_EDGE = files("haca.simulation") / "profiles" / "shared" / "edge-cases"


@dataclass(frozen=True, slots=True)
class PathResponse:
    status: int
    body: bytes
    method: str = "GET"


def simulation_profiles_root() -> Traversable:
    return files("haca.simulation") / "profiles"


def _read_node_bytes(node: Traversable) -> bytes:
    return node.read_bytes()


def _read_node_text(node: Traversable) -> str:
    return node.read_text(encoding="utf-8")


def _resolve_fixture_node(profile_dir: Traversable | Path, file_name: str) -> Traversable | Path:
    """Resolve a fixture path, including ``..`` segments relative to the profile directory."""
    rel = PurePosixPath(file_name)
    if isinstance(profile_dir, Path):
        return (profile_dir / rel).resolve()

    node: Traversable | None = profile_dir
    for part in rel.parts:
        if node is None:
            break
        if part == "..":
            parent = getattr(node, "parent", None)
            if parent is None:
                msg = f"cannot resolve parent for fixture {file_name!r}"
                raise ValueError(msg)
            node = parent
            continue
        if part == ".":
            continue
        node = node.joinpath(part)
    if node is None:
        msg = f"invalid fixture path {file_name!r}"
        raise ValueError(msg)
    return node


def _load_index(index_source: Traversable | Path) -> dict[str, Any]:
    if isinstance(index_source, Path):
        text = index_source.read_text(encoding="utf-8")
    else:
        text = _read_node_text(index_source)
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        msg = "profile index.yaml root must be a mapping"
        raise ValueError(msg)
    return data


def load_path_responses(profile_dir: Traversable | Path) -> dict[str, PathResponse]:
    """Load ``index.yaml`` path map from a profile directory."""
    index_path = (
        profile_dir / "index.yaml"
        if isinstance(profile_dir, Path)
        else profile_dir.joinpath("index.yaml")
    )
    data = _load_index(index_path)
    raw_paths = data.get("paths")
    if not isinstance(raw_paths, dict):
        msg = "profile index.yaml must define a 'paths' mapping"
        raise ValueError(msg)

    responses: dict[str, PathResponse] = {}
    for path, entry in raw_paths.items():
        if not isinstance(entry, dict):
            continue
        file_name = entry.get("file")
        status = int(entry.get("status", 200))
        method = str(entry.get("method", "GET")).upper()
        if method not in {"GET", "POST"}:
            msg = f"profile path {path!r} has unsupported method {method!r}"
            raise ValueError(msg)
        if not isinstance(file_name, str):
            continue
        target = _resolve_fixture_node(profile_dir, file_name)
        body = target.read_bytes() if isinstance(target, Path) else _read_node_bytes(target)
        responses[str(path)] = PathResponse(status=status, body=body, method=method)
    return responses


def shared_not_support_body() -> bytes:
    return _read_node_bytes(_SHARED_EDGE.joinpath("response_status_not_support.xml"))


def shared_url_not_found_body() -> bytes:
    return _read_node_bytes(_SHARED_EDGE.joinpath("response_status_url_not_found.xml"))


def shared_malformed_body() -> bytes:
    return _read_node_bytes(_SHARED_EDGE.joinpath("malformed.xml"))