"""Snapshot diff between two persisted runs."""

from __future__ import annotations

import fnmatch
from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict

from haca.store.repositories import load_settings


class SnapshotDiff(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    added: list[tuple[str, str, str]]
    removed: list[tuple[str, str, str]]
    changed: list[tuple[str, str, str, str]]


_DEFAULT_IGNORE = ("*.localTime", "*.freeSpace", "*.online")


def _ignored(path: str, patterns: Sequence[str]) -> bool:
    leaf = path.split(".")[-1]
    for pattern in patterns:
        if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(leaf, pattern):
            return True
    return False


def diff_runs(
    session_a: object,
    session_b: object,
    run_a: str,
    run_b: str,
    *,
    ignore_patterns: Sequence[str] = _DEFAULT_IGNORE,
) -> SnapshotDiff:
    left = load_settings(session_a, run_a)  # type: ignore[arg-type]
    right = load_settings(session_b, run_b)  # type: ignore[arg-type]
    keys_left = set(left)
    keys_right = set(right)
    added: list[tuple[str, str, str]] = []
    removed: list[tuple[str, str, str]] = []
    changed: list[tuple[str, str, str, str]] = []
    for key in sorted(keys_right - keys_left):
        device_id, path = key
        if _ignored(path, ignore_patterns):
            continue
        added.append((device_id, path, right[key]))
    for key in sorted(keys_left - keys_right):
        device_id, path = key
        if _ignored(path, ignore_patterns):
            continue
        removed.append((device_id, path, left[key]))
    for key in sorted(keys_left & keys_right):
        device_id, path = key
        if _ignored(path, ignore_patterns):
            continue
        if left[key] != right[key]:
            changed.append((device_id, path, left[key], right[key]))
    return SnapshotDiff(added=added, removed=removed, changed=changed)