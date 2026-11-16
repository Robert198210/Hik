"""Render audit reports as Markdown."""

from __future__ import annotations

from collections import Counter

from haca.analysis.models import Finding
from haca.reports.masking import mask_text
from haca.reports.models import AuditReport


def render_markdown(report: AuditReport) -> str:
    lines: list[str] = []
    if report.meta.simulated:
        lines.extend(["# SIMULATED", "", "Synthetic fixtures only; no live device contacted.", ""])

    class_counts = Counter(f.classification.value for f in report.findings)
    sev_counts = Counter(f.severity.value for f in report.findings)
    lines.extend(
        [
            "## Summary",
            "",
            f"- classifications: {dict(class_counts)}",
            f"- severities: {dict(sev_counts)}",
            "",
        ]
    )

    if report.needs_decision:
        lines.extend(["## Needs decision", ""])
        for item in report.needs_decision:
            lines.append(f"- `{item['field']}` — {item.get('note', '')}")
        lines.append("")

    by_sev: dict[str, list[Finding]] = {}
    for finding in report.findings:
        by_sev.setdefault(finding.severity.value, []).append(finding)
    lines.extend(["## Findings", ""])
    for sev in ("critical", "high", "medium", "low", "info"):
        for f in by_sev.get(sev, []):
            sim = " (would be CONFIRMED on live)" if f.simulated_confirmed else ""
            lines.append(f"- **{f.rule_id}** {f.classification.value}{sim}")
            lines.append(f"  - devices: {', '.join(f.devices)}")
            if f.current_value or f.recommended_value:
                current = mask_text(f.current_value or "—")
                recommended = mask_text(f.recommended_value or "—")
                lines.append(f"  - current → recommended: `{current}` → `{recommended}`")
            lines.append(f"  - {f.rationale}")
            for ev in f.evidence:
                observed = mask_text(ev.observed_value)
                lines.append(
                    f"  - evidence: `{ev.endpoint_id}` `{ev.xpath}` = `{observed}`"
                )
            if f.orp_refs:
                lines.append(f"  - ORP: {', '.join(f.orp_refs)}")
        if by_sev.get(sev):
            lines.append("")

    lines.extend(["## Coverage matrix", "", report.coverage_statement, ""])
    for device_id, categories in report.coverage.per_device.items():
        lines.append(f"### {device_id}")
        for category, counts in sorted(categories.items()):
            lines.append(f"- {category}: {counts}")
        lines.append("")

    lines.extend(["## Manual checks (not inspectable via ISAPI)", ""])
    for manual_id in report.manual_checks:
        lines.append(f"- {manual_id}")
    lines.append("")

    inaccessible = [e for e in report.coverage_entries if e.status == "INACCESSIBLE"]
    if inaccessible:
        lines.extend(["## Unsupported / inaccessible", ""])
        for entry in inaccessible[:50]:
            lines.append(f"- {entry.device_id} `{entry.setting_id}` — {entry.reason}")
        lines.append("")

    lines.extend(["## Method and limitations", ""])
    lines.append("Candidate ISAPI endpoints; coverage is limited to the HACA catalog.")
    if report.meta.simulated:
        lines.append("Data source: **SIMULATED** synthetic profiles.")
    lines.append("")
    return "\n".join(lines)
