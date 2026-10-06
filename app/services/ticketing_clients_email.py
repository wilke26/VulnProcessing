"""
E-Mail-basierte Ticket-Clients.

Diese Clients verwenden den EmailService und senden ein Ticket als E-Mail.
"""

from __future__ import annotations

import uuid

from app.core.config import settings as app_settings
from app.core.logging import get_logger
from app.services.email_service import EmailService, EmailTicket

logger = get_logger(__name__)


class DocBeeEmailClient:
    """DocBee Ticket-Client via E-Mail."""

    name = "DocBee (Email)"

    def __init__(
        self,
        email_service: EmailService | None = None,
        ticket_address: str | None = None,
    ) -> None:
        self.email_service = email_service or EmailService()
        self.ticket_address = ticket_address or app_settings.DOCBEE_TICKET_EMAIL

    async def create_ticket(
        self,
        title: str,
        description: str,
        priority: str,
        tenant: str,
        *,
        batch_id: int | None = None,
        dispatch_token: str | None = None,
    ) -> str:
        headers = {
            "X-Ticket-Priority": priority,
            "X-Ticket-Tenant": str(tenant),
        }
        if batch_id is not None and dispatch_token is not None:
            headers["X-VulnProcessing-Batch-ID"] = str(batch_id)
            headers["X-VulnProcessing-Dispatch-Token"] = dispatch_token
        ticket = EmailTicket(
            to=self.ticket_address,
            subject=title,
            body_text=description,
            headers=headers,
        )

        success = await self.email_service.send_ticket_email(ticket)
        if not success:
            raise RuntimeError("E-Mail-Versand an DocBee fehlgeschlagen")

        return f"email-{uuid.uuid4()}"


class MKSEmailClient:
    """MKS Ticket-Client via E-Mail."""

    name = "MKS (Email)"

    def __init__(
        self,
        email_service: EmailService | None = None,
        ticket_address: str | None = None,
    ) -> None:
        self.email_service = email_service or EmailService()
        self.ticket_address = ticket_address or app_settings.MKS_TICKET_EMAIL

    async def create_ticket(
        self,
        title: str,
        description: str,
        priority: str,
        tenant: str,
        *,
        batch_id: int | None = None,
        dispatch_token: str | None = None,
    ) -> str:
        headers = {
            "X-Ticket-Priority": priority,
            "X-Ticket-Tenant": str(tenant),
        }
        if batch_id is not None and dispatch_token is not None:
            headers["X-VulnProcessing-Batch-ID"] = str(batch_id)
            headers["X-VulnProcessing-Dispatch-Token"] = dispatch_token
        ticket = EmailTicket(
            to=self.ticket_address,
            subject=title,
            body_text=description,
            headers=headers,
        )

        success = await self.email_service.send_ticket_email(ticket)
        if not success:
            raise RuntimeError("E-Mail-Versand an MKS fehlgeschlagen")

        return f"email-{uuid.uuid4()}"
