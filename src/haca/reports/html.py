"""Render audit reports as self-contained HTML."""

from __future__ import annotations

from jinja2 import Environment, PackageLoader, select_autoescape

from haca.reports.masking import mask_structure
from haca.reports.models import AuditReport


def render_html(report: AuditReport) -> str:
    env = Environment(
        loader=PackageLoader("haca.reports", "templates"),
        autoescape=select_autoescape(enabled_extensions=("html", "j2")),
    )
    template = env.get_template("report.html.j2")
    payload = mask_structure(report.model_dump(mode="json"))
    css = """
    body { font-family: system-ui, sans-serif; margin: 1.5rem; color: #1a1a1a; }
    h1, h2, h3 { color: #0f2d52; }
    .simulated { background: #fff3cd; padding: 0.75rem; border-left: 4px solid #856404; }
    table { border-collapse: collapse; width: 100%; margin: 0.5rem 0 1rem; }
    th, td { border: 1px solid #ccc; padding: 0.35rem 0.5rem; text-align: left; }
    th { background: #eef3f8; }
    .severity-high { color: #b00020; font-weight: 600; }
    .ai-rejected { color: #6b4c00; }
    """
    return template.render(report=payload, css=css)
