"""Hikvision ResponseStatus XML."""

from __future__ import annotations

from dataclasses import dataclass

from haca.isapi.xml import XmlDocument


@dataclass(frozen=True)
class ResponseStatus:
    request_url: str | None
    status_code: int | None
    status_string: str | None
    sub_status_code: str | None
    description: str | None

    @property
    def is_success(self) -> bool:
        return self.status_code == 1 or self.sub_status_code == "ok"


def _parse_int(text: str | None) -> int | None:
    if text is None:
        return None
    try:
        return int(text.strip())
    except ValueError:
        return None


def parse_response_status(doc: XmlDocument) -> ResponseStatus | None:
    if doc.root_tag != "ResponseStatus":
        return None
    return ResponseStatus(
        request_url=doc.text("requestURL"),
        status_code=_parse_int(doc.text("statusCode")),
        status_string=doc.text("statusString"),
        sub_status_code=doc.text("subStatusCode"),
        description=doc.text("description"),
    )