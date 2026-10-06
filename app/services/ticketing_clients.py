"""
Abstraktionen und Registry fuer Ticket-Clients.

Erlaubt DIP-konforme Anbindung von Ticketsystemen,
indem der Dispatcher gegen ein schmales Interface arbeitet.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Protocol

from app.core.config import Settings
from app.core.logging import get_logger
from app.services.ticketing_clients_email import DocBeeEmailClient, MKSEmailClient
from app.services.ticketing_clients_rest import DocBeeRestClient, MKSRestClient

logger = get_logger(__name__)


class TicketClient(Protocol):
    """Strategy-Pattern: Schmales Interface fuer externe Ticketsysteme."""

    name: str

    async def create_ticket(
        self,
        title: str,
        description: str,
        priority: str,
        tenant: str,
        *,
        batch_id: int | None = None,
        dispatch_token: str | None = None,
    ) -> str: ...


class TicketDispatcherProtocol(Protocol):
    """Schmales Interface fuer Dispatcher."""

    async def dispatch(
        self,
        findings: Iterable[object],
        *,
        batch_id: int | None = None,
        dispatch_token: str | None = None,
    ) -> None: ...


class TicketClientRegistry:
    """Strategy-Pattern: Registry verwaltet aktive Client-Strategien."""

    def __init__(self, clients: Sequence[TicketClient]) -> None:
        self._clients = list(clients)

    def active(self) -> list[TicketClient]:
        return list(self._clients)


def build_ticket_client_registry(settings: Settings) -> TicketClientRegistry:
    """Erzeugt eine Registry anhand der Konfiguration."""
    clients: list[TicketClient] = []

    if settings.DOCBEE_EMAIL_ENABLED:
        clients.append(DocBeeEmailClient())
    if settings.MKS_EMAIL_ENABLED:
        clients.append(MKSEmailClient())

    if settings.DOCBEE_REST_ENABLED:
        if settings.DOCBEE_URL and settings.DOCBEE_API_KEY:
            clients.append(
                DocBeeRestClient(base_url=settings.DOCBEE_URL, api_key=settings.DOCBEE_API_KEY)
            )
        else:
            logger.warning("DOCBEE_REST_ENABLED ist aktiv, aber URL oder API-Key fehlen.")

    if settings.MKS_REST_ENABLED:
        if settings.MKS_URL and settings.MKS_USERNAME and settings.MKS_PASSWORD:
            clients.append(
                MKSRestClient(
                    base_url=settings.MKS_URL,
                    username=settings.MKS_USERNAME,
                    password=settings.MKS_PASSWORD,
                )
            )
        else:
            logger.warning("MKS_REST_ENABLED ist aktiv, aber URL oder Zugangsdaten fehlen.")

    return TicketClientRegistry(clients)
