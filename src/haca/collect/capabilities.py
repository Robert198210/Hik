"""Smart capability flag parsing."""

from __future__ import annotations

from haca.isapi.xml import XmlDocument

_CAP_PREFIX = "smart."


def parse_smart_capabilities(doc: XmlDocument) -> dict[str, bool]:
    """Return capability flags keyed like ``smart.isSupportLineDetection``."""
    flags: dict[str, bool] = {}
    for child in doc._root:  # noqa: SLF001
        local = child.tag.split("}", 1)[-1] if "}" in child.tag else child.tag
        if not local.startswith("isSupport"):
            continue
        text = (child.text or "").strip().lower()
        if text in ("true", "1", "yes"):
            flags[f"{_CAP_PREFIX}{local}"] = True
        elif text in ("false", "0", "no"):
            flags[f"{_CAP_PREFIX}{local}"] = False
    return flags