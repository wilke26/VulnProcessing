"""
app/services/ticket_templates.py

Template-Engine für Ticket-E-Mails.
Verwendet Jinja2 für flexible, system-spezifische Templates.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from app.core.logging import get_logger
from app.models.findings import Finding

logger = get_logger(__name__)

TEMPLATES_DIR = Path(__file__).parent.parent / "templates" / "tickets"


class TicketTemplateEngine:
    """Rendert Ticket-Templates für verschiedene Systeme."""

    def __init__(self, templates_dir: Path = TEMPLATES_DIR):
        self.env = Environment(
            loader=FileSystemLoader(str(templates_dir)),
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        # Custom Filters
        self.env.filters["format_priority"] = self._format_priority
        self.env.filters["format_cvss"] = self._format_cvss

    def render_docbee_ticket(
        self,
        finding: Finding,
        tenant_name: str,
        additional_context: dict[str, Any] | None = None,
    ) -> tuple[str, str, str]:
        """
        Rendert DocBee-Ticket.

        Returns:
            (subject, body_text, body_html)
        """

        template = self.env.get_template("docbee_ticket.jinja2")

        context = self._build_context(finding, tenant_name, additional_context)

        # Vollständiger Render (enthält Subject + Body)
        rendered = template.render(**context)

        # Subject aus erster Zeile extrahieren
        lines = rendered.split("\n", 1)
        subject = lines[0].replace("Subject: ", "").strip()
        body_text = lines[1].strip() if len(lines) > 1 else ""

        # HTML-Version (optional)
        html_template = self.env.get_template("docbee_ticket.html.jinja2")
        body_html = html_template.render(**context)

        return subject, body_text, body_html

    def render_mks_ticket(
        self,
        finding: Finding,
        tenant_name: str,
        additional_context: dict[str, Any] | None = None,
    ) -> tuple[str, str, str]:
        """Rendert MKS.Goliath-Ticket (analog zu DocBee)."""
        template = self.env.get_template("mks_ticket.jinja2")
        context = self._build_context(finding, tenant_name, additional_context)

        rendered = template.render(**context)
        lines = rendered.split("\n", 1)
        subject = lines[0].replace("Subject: ", "").strip()
        body_text = lines[1].strip() if len(lines) > 1 else ""

        return subject, body_text, ""  # MKS: nur Plain-Text

    def _build_context(
        self,
        finding: Finding,
        tenant_name: str,
        additional: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Erstellt Template-Context aus Finding."""
        context = {
            "finding": finding,
            "tenant": tenant_name,
            "cve_id": finding.cve_id or "N/A",
            "risk": finding.risk,
            "priority_level": finding.priority_level or "MEDIUM",
            "priority_score": finding.priority_score or 0.0,
            "cvss_score": finding.cvss_base_score,
            "target": finding.target,
            "products": ", ".join(finding.products) if finding.products else "Unbekannt",
            "amount": finding.amount,
            "extended_solution": finding.extendedSolution,
        }

        if additional:
            context.update(additional)

        return context

    def _format_priority(self, priority: str) -> str:
        """Formatiert Priorität für E-Mail."""
        priority_map = {
            "CRITICAL": "Kritisch",
            "HIGH": "Hoch",
            "MEDIUM": "Mittel",
            "LOW": "Niedrig",
        }
        return priority_map.get(priority, priority)

    def _format_cvss(self, score: float | None) -> str:
        """Formatiert CVSS-Score."""
        if score is None:
            return "N/A"
        if score >= 9.0:
            return f"{score:.1f} (Critical)"
        elif score >= 7.0:
            return f"{score:.1f} (High)"
        elif score >= 4.0:
            return f"{score:.1f} (Medium)"
        else:
            return f"{score:.1f} (Low)"
