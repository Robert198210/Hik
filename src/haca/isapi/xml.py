"""Safe ISAPI XML parsing."""

from __future__ import annotations

from dataclasses import dataclass
from xml.etree.ElementTree import Element

from defusedxml.ElementTree import ParseError, fromstring  # type: ignore[import-untyped]

from haca.isapi.errors import XmlParseError
from haca.security.redaction import mask_device_identifiers

_MAX_PREVIEW = 80


@dataclass(frozen=True)
class XmlElement:
    tag: str
    text: str | None
    attrib: dict[str, str]


@dataclass(frozen=True)
class XmlDocument:
    root_tag: str
    namespace: str | None
    version: str | None
    _root: Element

    def text(self, path: str) -> str | None:
        element = self._find(path)
        if element is None:
            return None
        if element.text is not None and element.text.strip():
            return element.text.strip()
        if len(element) == 0:
            return None
        parts: list[str] = []
        for child in element:
            if child.text and child.text.strip():
                parts.append(child.text.strip())
        return "".join(parts) if parts else None

    def elements(self, path: str) -> list[XmlElement]:
        element = self._find(path)
        if element is None:
            return []
        return [
            XmlElement(
                tag=child.tag.split("}", 1)[-1],
                text=(child.text or "").strip() or None,
                attrib=dict(child.attrib),
            )
            for child in element
        ]

    def _find(self, path: str) -> Element | None:
        current: Element | None = self._root
        for segment in path.split("/"):
            if segment == "":
                continue
            if current is None:
                return None
            current = _find_child_local(current, segment)
        return current


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _find_child_local(parent: Element, local: str) -> Element | None:
    for child in parent:
        if _local_name(child.tag) == local:
            return child
    return None


def _preview(body: bytes) -> str:
    text = body[:_MAX_PREVIEW].decode("utf-8", errors="replace")
    if len(body) > _MAX_PREVIEW:
        text += "…"
    return mask_device_identifiers(text)


def parse_xml(body: bytes, max_bytes: int = 5_000_000) -> XmlDocument:
    if len(body) > max_bytes:
        raise XmlParseError("", "", f"XML body exceeds limit ({len(body)} bytes)")
    data = body
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    data = data.strip()
    try:
        root = fromstring(
            data,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except (ParseError, ValueError, TypeError, LookupError) as exc:
        preview = _preview(data)
        raise XmlParseError("", "", f"XML parse error ({preview})") from exc

    tag = root.tag
    namespace: str | None = None
    if tag.startswith("{") and "}" in tag:
        namespace = tag[1 : tag.index("}")]
    local = _local_name(tag)
    version = root.attrib.get("version")
    return XmlDocument(
        root_tag=local,
        namespace=namespace,
        version=version,
        _root=root,
    )