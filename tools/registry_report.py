#!/usr/bin/env python3
"""Regenerate the ISAPI endpoint table in docs/isapi-endpoint-registry.md."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from haca.isapi.registry.loader import load_registry_entries  # noqa: E402

_DOC = _REPO / "docs/isapi-endpoint-registry.md"
_BEGIN = "<!-- registry:begin -->"
_END = "<!-- registry:end -->"


def _format_roles(roles: tuple[str, ...]) -> str:
    return ", ".join(roles)


def _format_gate(gate: str | None) -> str:
    return gate if gate else "—"


def _format_variants(variants: tuple[str, ...]) -> str:
    if not variants:
        return "—"
    return "; ".join(f"`{v}`" for v in variants)


def build_table() -> str:
    entries = load_registry_entries()
    lines = [
        "| id | path | roles | capability gate | verification | sensitivity |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for entry in entries:
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{entry.id}`",
                    f"`{entry.path}`",
                    _format_roles(entry.device_roles),
                    _format_gate(entry.capability_gate),
                    entry.verification,
                    entry.sensitivity,
                ]
            )
            + " |"
        )
    lines.append("")
    lines.append(f"_Total endpoints: {len(entries)}._")
    lines.append("")
    variant_paths = tuple(v for e in entries for v in e.variants)
    if variant_paths:
        lines.append(f"Variant paths: {_format_variants(variant_paths)}.")
    return "\n".join(lines)


def render_doc(table: str) -> str:
    text = _DOC.read_text(encoding="utf-8")
    if _BEGIN not in text or _END not in text:
        marker_block = f"\n{_BEGIN}\n{table}{_END}\n"
        if "## Endpoint table" in text:
            before, _, after = text.partition("## Endpoint table")
            head = before + "## Endpoint table\n\n"
            tail = after.split("\n", 1)
            rest = tail[1] if len(tail) > 1 else ""
            return head + marker_block + rest.lstrip("\n")
        return text.rstrip() + "\n\n## Endpoint table\n\n" + marker_block

    pre, _, post = text.partition(_BEGIN)
    _, _, post = post.partition(_END)
    return pre + _BEGIN + "\n" + table + _END + post


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if the doc is out of date (do not write).",
    )
    args = parser.parse_args()

    table = build_table()
    new_doc = render_doc(table)

    if args.check:
        current = _DOC.read_text(encoding="utf-8") if _DOC.is_file() else ""
        if current != new_doc:
            print("docs/isapi-endpoint-registry.md is out of date; run tools/registry_report.py")
            return 1
        print("registry doc is up to date")
        return 0

    _DOC.write_text(new_doc, encoding="utf-8")
    print(f"updated {_DOC}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())