"""
Abstraktionen und Registry fuer Ticket-Clients.

Erlaubt DIP-konforme Anbindung von Ticketsystemen,
indem der Dispatcher gegen ein schmales Interface arbeitet.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Protocol

from app.core.config import Settings
from app.core.logging import get_logger
from app.services.ticketing_clients_email import DocBeeEmailClient, MKSEmailClient
from app.services.ticketing_clients_rest import DocBeeRestClient, MKSRestClient

logger = get_logger(__name__)


@dataclass(frozen=True)
class TicketDispatchAttempt:
    """Result of sending one finding to one configured ticket client."""

    finding_id: int | None
    client_name: str
    success: bool
    external_id: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class TicketDispatchResult:
    """Aggregate result for one dispatcher invocation."""

    finding_count: int
    client_count: int
    attempts: tuple[TicketDispatchAttempt, ...] = ()

    def __post_init__(self) -> None:
        if self.finding_count < 0 or self.client_count < 0:
            raise ValueError("Dispatch result counts must not be negative")
        if len(self.attempts) != self.expected_attempts:
            raise ValueError("Dispatch result must contain one attempt per finding and client")

    @property
    def expected_attempts(self) -> int:
        return self.finding_count * self.client_count

    @property
    def successful_attempts(self) -> int:
        return sum(attempt.success for attempt in self.attempts)

    @property
    def failed_attempts(self) -> int:
        return sum(not attempt.success for attempt in self.attempts)

    @property
    def no_clients(self) -> bool:
        return self.client_count == 0

    @property
    def succeeded(self) -> bool:
        return not self.no_clients and self.failed_attempts == 0

    @property
    def partially_failed(self) -> bool:
        return self.successful_attempts > 0 and self.failed_attempts > 0

    @property
    def successful_finding_ids(self) -> frozenset[int]:
        return frozenset(
            attempt.finding_id
            for attempt in self.attempts
            if attempt.success and attempt.finding_id is not None
        )

    def failure_summary(self) -> str:
        if self.no_clients:
            return "No active ticket clients configured"
        return f"{self.failed_attempts} of {self.expected_attempts} ticket dispatch attempts failed"


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
    ) -> TicketDispatchResult: ...


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
