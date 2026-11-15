"""Flatten ISAPI XML documents to dotted paths."""

from __future__ import annotations

from xml.etree.ElementTree import Element

from haca.isapi.xml import XmlDocument


def _local_name(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _element_id(elem: Element) -> str | None:
    for child in elem:
        if _local_name(child.tag) == "id" and child.text and child.text.strip():
            return child.text.strip()
    return None


def flatten(doc: XmlDocument) -> dict[str, str]:
    """Stable dotted paths using local element names."""
    out: dict[str, str] = {}

    def walk(elem: Element, prefix: str) -> None:
        local = _local_name(elem.tag)
        path = f"{prefix}.{local}" if prefix else local
        child_locals: dict[str, int] = {}
        for child in elem:
            child_local = _local_name(child.tag)
            child_locals[child_local] = child_locals.get(child_local, 0) + 1
        for child in elem:
            child_local = _local_name(child.tag)
            child_id = _element_id(child)
            if child_id is not None:
                child_path = f"{path}.{child_local}[{child_id}]"
            else:
                index = child_locals[child_local]
                child_locals[child_local] -= 1
                child_path = f"{path}.{child_local}[{index}]"
            if len(child):
                walk(child, child_path)
            else:
                text = (child.text or "").strip()
                if text:
                    out[child_path] = text
        if not len(elem) and (elem.text or "").strip():
            out[path] = elem.text.strip()  # type: ignore[union-attr]

    walk(doc._root, "")  # noqa: SLF001
    return out