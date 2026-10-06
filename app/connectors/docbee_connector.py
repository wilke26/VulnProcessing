"""
app/connectors/docbee_connector.py

DocBee-Connector: Erstellt Tickets per E-Mail.
"""

from __future__ import annotations

from app.core.config import settings
from app.core.logging import get_logger
from app.models.findings import Finding
from app.services.email_service import EmailService, EmailTicket
from app.services.ticket_templates import TicketTemplateEngine

logger = get_logger(__name__)


class DocBeeConnector:
    """Erstellt DocBee-Tickets per E-Mail."""

    def __init__(
        self,
        email_service: EmailService | None = None,
        template_engine: TicketTemplateEngine | None = None,
    ):
        self.email_service = email_service or EmailService()
        self.template_engine = template_engine or TicketTemplateEngine()
        self.ticket_address = settings.DOCBEE_TICKET_EMAIL

    async def create_ticket(
        self,
        finding: Finding,
        tenant_name: str,
    ) -> tuple[bool, str | None]:
        """
        Erstellt ein DocBee-Ticket per E-Mail.

        Returns:
            (success, error_message)
        """

        try:
            # Template rendern
            subject, body_text, body_html = self.template_engine.render_docbee_ticket(
                finding=finding,
                tenant_name=tenant_name,
            )

            # E-Mail-Ticket erstellen
            email_ticket = EmailTicket(
                to=self.ticket_address,
                subject=subject,
                body_text=body_text,
                body_html=body_html,
                headers={
                    # DocBee-spezifische Header (falls unterstützt)
                    "X-Ticket-Priority": getattr(finding, "priority_level", "MEDIUM") or "MEDIUM",
                    "X-Ticket-Tenant": tenant_name,
                    "X-Finding-ID": str(finding.id) if finding.id else "",
                },
            )

            # E-Mail senden
            success = await self.email_service.send_ticket_email(email_ticket)

            if success:
                # Einfacher String statt Keyword-Args
                logger.info(
                    f"DocBee-Ticket erstellt für Finding {finding.id} "
                    f"(Tenant: {tenant_name}): {subject}"
                )
                return True, None
            else:
                return False, "E-Mail konnte nicht versendet werden"

        except Exception as e:
            # Einfacher String mit exc_info
            logger.error(
                f"DocBee-Ticket-Erstellung fehlgeschlagen für Finding {finding.id} "
                f"(Tenant: {tenant_name}): {e}",
                exc_info=True,
            )
            return False, str(e)

    async def create_tickets_batch(
        self,
        findings: list[Finding],
        tenant_name: str,
    ) -> dict[int, tuple[bool, str | None]]:
        """
        Erstellt mehrere Tickets parallel.

        Returns:
            Dict[finding_id, (success, error)]
        """

        import asyncio

        tasks = [self.create_ticket(finding, tenant_name) for finding in findings]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Explizite Type-Narrowing mit separaten Branches
        result_dict: dict[int, tuple[bool, str | None]] = {}

        for finding, result in zip(findings, results, strict=False):
            # Finding-ID mit Fallback
            finding_id = finding.id if finding.id is not None else 0

            # Explizites Type-Narrowing
            if isinstance(result, BaseException):
                # Exception → Tuple mit False und Error-Message
                result_dict[finding_id] = (False, str(result))
            elif isinstance(result, tuple) and len(result) == 2:
                # Bereits korrektes Tuple[bool, Optional[str]]
                success, error = result
                result_dict[finding_id] = (success, error)
            else:
                # Sollte nicht passieren, aber für Robustheit
                result_dict[finding_id] = (False, f"Unerwarteter Rückgabewert: {type(result)}")

        return result_dict
