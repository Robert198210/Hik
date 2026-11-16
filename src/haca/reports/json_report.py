"""Serialize audit reports to JSON."""

from __future__ import annotations

import json

from haca.reports.masking import mask_structure
from haca.reports.models import AuditReport


def report_to_json(report: AuditReport, *, indent: int = 2) -> str:
    payload = report.model_dump(mode="json")
    masked = mask_structure(payload)
    return json.dumps(masked, indent=indent)


def write_report_json(report: AuditReport, path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(report_to_json(report))
        handle.write("\n")
