"""
app/connectors/mks_connector.py

MKS.Goliath-Connector: Erstellt Tickets per E-Mail.
"""

from app.core.config import settings
from app.core.logging import get_logger
from app.models.findings import Finding
from app.services.email_service import EmailService, EmailTicket
from app.services.ticket_templates import TicketTemplateEngine

logger = get_logger(__name__)


class MKSConnector:
    """MKS-Tickets per E-Mail."""

    def __init__(
        self,
        email_service: EmailService | None = None,
        template_engine: TicketTemplateEngine | None = None,
    ):
        self.email_service = email_service or EmailService()
        self.template_engine = template_engine or TicketTemplateEngine()
        self.ticket_address = settings.MKS_TICKET_EMAIL

    async def create_ticket(
        self,
        finding: Finding,
        tenant_name: str,
    ) -> tuple[bool, str | None]:
        """Erstellt ein MKS-Ticket per E-Mail."""
        try:
            subject, body_text, _ = self.template_engine.render_mks_ticket(
                finding=finding,
                tenant_name=tenant_name,
            )

            email_ticket = EmailTicket(
                to=self.ticket_address,
                subject=subject,
                body_text=body_text,
            )

            success = await self.email_service.send_ticket_email(email_ticket)

            if success:
                logger.info(
                    f"MKS-Ticket erstellt für Finding {finding.id} "
                    f"(Tenant: {tenant_name}): {subject}"
                )
                return True, None
            else:
                return False, "E-Mail-Versand fehlgeschlagen"

        except Exception as e:
            logger.error(
                f"MKS-Ticket-Erstellung fehlgeschlagen für Finding {finding.id}: {e}",
                exc_info=True,
            )
            return False, str(e)
