"""
Composition Root fuer Ticketing-bezogene Services.

Zentralisiert die Erzeugung von Services und Abhaengigkeiten.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.connectors.copilot_client import CopilotStudioClient
from app.core.config import Settings, settings
from app.services.batch_ticketing_service import BatchTicketingService
from app.services.dispatcher import TicketDispatcher
from app.services.remediation_service import RemediationService
from app.services.ticket_preparation import (
    TicketPreparationService,
    build_ticket_preparation_service,
)
from app.services.ticket_workflow import TicketWorkflowOrchestrator
from app.services.ticketing_clients import (
    TicketClient,
    TicketClientRegistry,
    build_ticket_client_registry,
)


def build_ticket_preparation(settings_obj: Settings = settings) -> TicketPreparationService:
    return build_ticket_preparation_service(settings_obj=settings_obj)


def build_batch_ticketing_service(
    settings_obj: Settings = settings,
    batch_size: int = 5,
    db_session: Session | None = None,
    prep_service: TicketPreparationService | None = None,
) -> BatchTicketingService:
    service = BatchTicketingService(
        batch_size=batch_size,
        max_candidates_per_operation=settings_obj.MAX_BATCH_CANDIDATES_PER_OPERATION,
        db_session=db_session,
        prep_service=prep_service or build_ticket_preparation(settings_obj=settings_obj),
    )
    return service


def build_ticket_dispatcher(
    settings_obj: Settings = settings,
    client_registry: TicketClientRegistry | None = None,
    clients: list[TicketClient] | None = None,
    remediation_service: RemediationService | None = None,
) -> TicketDispatcher:
    registry = client_registry or build_ticket_client_registry(settings_obj)
    remediation = remediation_service or RemediationService(settings_obj, CopilotStudioClient())
    return TicketDispatcher(
        settings=settings_obj,
        remediation_service=remediation,
        client_registry=registry,
        clients=clients,
    )


def build_ticket_workflow_orchestrator(
    settings_obj: Settings = settings,
    batch_size: int = 5,
    db_session: Session | None = None,
    prep_service: TicketPreparationService | None = None,
) -> TicketWorkflowOrchestrator:
    batch_service = build_batch_ticketing_service(
        settings_obj=settings_obj,
        batch_size=batch_size,
        db_session=db_session,
        prep_service=prep_service,
    )
    return TicketWorkflowOrchestrator(batch_service=batch_service)
