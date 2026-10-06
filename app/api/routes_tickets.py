"""
Dieses Modul stellt die API-Endpunkte für die Ticket-Erstellung und Batch-Verarbeitung bereit.
Es ermöglicht das Erstellen von Tickets für Sicherheitsergebnisse, die Gruppierung in Batches,
das Senden an externe Systeme und die Nachverfolgung des Status.
"""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy.orm import Session

from app.api.errors import error_detail, sanitized_validation_errors
from app.core.config import settings
from app.core.logging import get_logger
from app.core.management_auth import (
    BATCHES_CREATE,
    BATCHES_DISPATCH,
    BATCHES_READ,
    TICKETS_CREATE,
    TICKETS_DISPATCH,
    ManagementPrincipal,
    authenticate_management_request,
    require_management_operation,
    require_tenant_access,
)
from app.core.resource_limits import enforce_management_capacity
from app.core.security import (
    WebhookAuthenticationError,
    WebhookConfigurationError,
    verify_webhook_signature,
)
from app.db.database import get_db
from app.db.models import Finding, FindingStatus, Tenant
from app.db.repository import UnitOfWork
from app.services.composition_root import (
    build_batch_ticketing_service,
    build_ticket_dispatcher,
    build_ticket_preparation,
)
from app.services.ticketing_clients import TicketDispatchResult

# Logger initialisieren
logger = get_logger(__name__)

# APIRouter mit Präfix und Tags für die Ticket-API
management_router = APIRouter(
    prefix="/tickets",
    tags=["tickets"],
    dependencies=[Depends(authenticate_management_request)],
)
webhook_router = APIRouter(prefix="/tickets", tags=["tickets"])
router = APIRouter()

CONFIRMATION_ERROR_MESSAGES = {
    "batch_not_found": "Batch nicht gefunden",
    "invalid_batch_state": "Batch wartet nicht auf diese Bestätigung",
    "invalid_confirmation_counts": "Bestätigungszahlen passen nicht zum Batch",
    "invalid_confirmation_details": "Einzelbestätigungen passen nicht zum Batch",
}


@management_router.post("/create", dependencies=[Depends(enforce_management_capacity)])
async def create_tickets(
    tenant_name: str | None = Query(None, description="Filter nach Tenant (Mandant)"),
    min_risk: float | None = Query(None, description="Minimaler Risk-Score zur Filterung"),
    principal: ManagementPrincipal = Depends(require_management_operation(TICKETS_CREATE)),
):
    """
    Ermittelt offene Findings für die historische, seiteneffektfreie Ticket-Vorschau.

    Workflow:
    1. Lädt offene Findings aus der Datenbank.
    2. Filtert nach optionalem Tenant und minimalem Risk-Score.
    3. Wendet TicketPreparationService an (z.B. Windows-Patch-Filterung über N-Central).
    4. Liefert eine Vorschau der Findings, die für eine Ticketerstellung vorgesehen wären.

    Dieser ältere Kompatibilitätsendpunkt hat bewusst keine externen Seiteneffekte.
    Der tatsächliche Versand erfolgt über ``/tickets/dispatch`` oder die Batch-Endpunkte.

    Args:
        tenant_name (str, optional): Der Name des Mandanten.
        min_risk (float, optional): Der minimale Risikowert.

    Returns:
        dict: Informationen über die Anzahl der vorgemerkten und gefilterten Tickets.

    Raises:
        HTTPException: Bei Fehlern während des Prozesses.
    """
    try:
        # 1. Findings aus der Datenbank laden unter Verwendung des Unit of Work Patterns
        with UnitOfWork() as uow:
            query = uow.findings.get_all()

            query = query.join(Finding.tenant)

            # Tenant-Filter ausschließlich innerhalb des serverseitigen Scopes anwenden
            if tenant_name:
                require_tenant_access(principal, tenant_name)
                query = query.filter(Tenant.name == tenant_name)
            elif not principal.has_all_tenants:
                query = query.filter(Tenant.name.in_(principal.tenants))

            # Optionalen Filter nach minimalem Risiko anwenden
            if min_risk:
                query = query.filter(Finding.risk >= min_risk)

            # Nur Findings mit Status 'new' berücksichtigen
            findings = _load_bounded_ticket_findings(
                query.filter(Finding.status == FindingStatus.NEW.value)
            )

        # Wenn keine Findings gefunden wurden, frühzeitig zurückkehren
        if not findings:
            return {
                "created": 0,
                "message": "Keine offenen Findings gefunden",
                "error": None,
                "code": None,
            }

        logger.info(f"{len(findings)} offene Findings gefunden")

        # 2. Findings vorbereiten (z.B. Abgleich mit Patch-Status in N-Central)
        prep_service = build_ticket_preparation()
        filtered_findings = await prep_service.prepare_for_ticketing(findings)

        # Wenn nach der Filterung keine Findings übrig bleiben
        if not filtered_findings:
            return {
                "created": 0,
                "message": "Alle Findings wurden ausgefiltert (bereits gepatcht)",
                "error": None,
                "code": None,
            }

        # 3. Vorschau für den seiteneffektfreien Kompatibilitätsendpunkt erzeugen.
        # Der echte Versand ist ausschließlich Aufgabe der Dispatch-Endpunkte.
        created_count = 0

        for finding in filtered_findings:
            # Die historische Antwortstruktur bezeichnet vorgemerkte Findings als "created".
            logger.info(f"Würde Ticket erstellen für Finding: {finding.name}")
            created_count += 1

        return {
            "created": created_count,
            "filtered": len(findings) - len(filtered_findings),
            "total": len(findings),
            "error": None,
            "code": None,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Fehler bei Ticket-Erstellung")
        raise HTTPException(
            status_code=500,
            detail=error_detail("ticket_create_failed", "Ticket-Erstellung fehlgeschlagen"),
        ) from e


@management_router.post("/dispatch", dependencies=[Depends(enforce_management_capacity)])
async def dispatch_tickets(
    tenant_name: str | None = Query(None, description="Filter nach Tenant (Mandant)"),
    min_risk: float | None = Query(None, description="Minimaler Risk-Score zur Filterung"),
    dry_run: bool = Query(False, description="Nur simulieren, keine Tickets senden"),
    principal: ManagementPrincipal = Depends(require_management_operation(TICKETS_DISPATCH)),
):
    """
    Dispatcht Findings an konfigurierte Ticketsysteme (E-Mail/REST Clients).

    Workflow:
    1. Lädt offene Findings aus der Datenbank.
    2. Filtert nach optionalem Tenant und minimalem Risk-Score.
    3. Wendet TicketPreparationService an.
    4. Dispatcht an konfigurierte Ticket-Clients.
    """
    try:
        with UnitOfWork() as uow:
            query = uow.findings.get_all()
            query = query.join(Finding.tenant)
            if tenant_name:
                require_tenant_access(principal, tenant_name)
                query = query.filter(Tenant.name == tenant_name)
            elif not principal.has_all_tenants:
                query = query.filter(Tenant.name.in_(principal.tenants))
            if min_risk:
                query = query.filter(Finding.risk >= min_risk)
            findings = _load_bounded_ticket_findings(
                query.filter(Finding.status == FindingStatus.NEW.value)
            )

        if not findings:
            # Den Dispatcher auch bei leerer Auswahl initialisieren, damit Fehler in seiner
            # Konfiguration nicht durch das leere Ergebnis verdeckt werden.
            if not dry_run:
                dispatcher = build_ticket_dispatcher()
                dispatch_result = await dispatcher.dispatch([])
                _require_successful_dispatch(dispatch_result)
            return {
                "dispatched": 0,
                "filtered": 0,
                "total": 0,
                "dry_run": dry_run,
                "message": "Keine offenen Findings gefunden",
                "batch_status": None,
                "error": None,
                "code": None,
            }

        prep_service = build_ticket_preparation()
        filtered_findings = await prep_service.prepare_for_ticketing(findings)
        if not filtered_findings:
            return {
                "dispatched": 0,
                "filtered": len(findings),
                "total": len(findings),
                "dry_run": dry_run,
                "message": "Alle Findings wurden ausgefiltert (bereits gepatcht)",
                "batch_status": None,
                "error": None,
                "code": None,
            }

        if not dry_run:
            dispatcher = build_ticket_dispatcher()
            dispatch_result = await dispatcher.dispatch(filtered_findings)
            _require_successful_dispatch(dispatch_result)

        return {
            "dispatched": len(filtered_findings),
            "filtered": len(findings) - len(filtered_findings),
            "total": len(findings),
            "dry_run": dry_run,
            "batch_status": None,
            "error": None,
            "code": None,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Fehler beim Dispatching von Tickets")
        raise HTTPException(
            status_code=500,
            detail=error_detail("dispatch_failed", "Ticket-Dispatch fehlgeschlagen"),
        ) from e


class TicketConfirmation(BaseModel):
    finding_id: int = Field(gt=0)
    status: Literal["confirmed", "failed"]


class BatchConfirmation(BaseModel):
    """
    Pydantic-Modell für die Bestätigung der Batch-Verarbeitung.
    """

    batch_id: int = Field(gt=0)
    successful_count: int = Field(ge=0)
    failed_count: int = Field(default=0, ge=0)
    ticket_confirmations: list[TicketConfirmation] | None = Field(default=None, max_length=100)
    dispatch_token: str = Field(min_length=43, max_length=43, pattern=r"^[A-Za-z0-9_-]{43}$")


@management_router.post("/batch/create", dependencies=[Depends(enforce_management_capacity)])
async def create_ticket_batch(
    tenant_name: str,
    min_risk: float = 0.0,
    target_system: str = "mks",
    db: Session = Depends(get_db),
    principal: ManagementPrincipal = Depends(require_management_operation(BATCHES_CREATE)),
):
    """
    Erstellt einen neuen Batch von maximal 5 Findings für die Ticket-Erstellung.

    Die Funktion prüft automatisch:
    - Ob bereits ein unverarbeiteter Batch für diesen Tenant existiert.
    - Den Windows-Patch-Status der betroffenen Systeme (via N-Central).
    - Priorisiert die Findings nach ihrem Risk-Score.

    Args:
        tenant_name (str): Name des Mandanten.
        min_risk (float): Minimaler Risk-Score (Standard: 0.0).
        target_system (str): Ziel-Ticketsystem (z.B. 'mks', 'docbee').
        db (Session): Die injizierte Datenbank-Session.

    Returns:
        dict: Informationen zum erstellten Batch oder eine Status-Meldung.

    Raises:
        HTTPException: Wenn der Tenant nicht gefunden wurde oder ein Fehler auftritt.
    """
    try:
        require_tenant_access(principal, tenant_name)
        # BatchTicketingService initialisieren und Datenbank-Session übergeben
        service = build_batch_ticketing_service(batch_size=5, db_session=db)
        result = await service.create_next_batch(
            tenant_name=tenant_name,
            min_risk=min_risk,
            target_system=target_system,
        )

        if not result:
            # Falls kein Tenant gefunden wurde (der Service gibt ein leeres Ergebnis zurück)
            raise HTTPException(status_code=404, detail="Mandant nicht gefunden")

        result.setdefault("error", None)
        result.setdefault("code", None)
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Fehler bei Batch-Erstellung")
        raise HTTPException(
            status_code=500,
            detail=error_detail("batch_create_failed", "Batch-Erstellung fehlgeschlagen"),
        ) from e


@management_router.post(
    "/batch/{batch_id}/send", dependencies=[Depends(enforce_management_capacity)]
)
async def send_batch(
    batch_id: int,
    principal: ManagementPrincipal = Depends(require_management_operation(BATCHES_DISPATCH)),
):
    """
    Sendet einen vorbereiteten Batch an das externe Ticketsystem.

    Args:
        batch_id (int): Die ID des zu sendenden Batches.

    Returns:
        dict: Ergebnis der Übertragung und die externe Batch-ID.

    Raises:
        HTTPException: Wenn der Batch nicht gefunden wurde.
    """
    try:
        _require_batch_tenant_access(batch_id, principal)
        # Veralteter Kompatibilitätsendpunkt mit demselben Dispatch-Ablauf wie
        # /tickets/batch/{id}/dispatch.
        service = build_batch_ticketing_service()
        dispatcher = build_ticket_dispatcher()
        result = await service.dispatch_batch(batch_id=batch_id, dispatcher=dispatcher)

        if not result.get("success"):
            raise HTTPException(
                status_code=422,
                detail=error_detail("batch_dispatch_failed", "Batch-Dispatch fehlgeschlagen"),
            )

        result.setdefault("batch_status", "pending")
        result.setdefault("error", None)
        result.setdefault("code", None)
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Fehler beim Senden des Batches")
        raise HTTPException(
            status_code=500,
            detail=error_detail("batch_dispatch_failed", "Batch-Dispatch fehlgeschlagen"),
        ) from e


@management_router.post(
    "/batch/{batch_id}/dispatch", dependencies=[Depends(enforce_management_capacity)]
)
async def dispatch_batch(
    batch_id: int,
    principal: ManagementPrincipal = Depends(require_management_operation(BATCHES_DISPATCH)),
):
    """
    Dispatcht einen vorbereiteten Batch an die konfigurierten Ticket-Clients.
    """
    try:
        _require_batch_tenant_access(batch_id, principal)
        service = build_batch_ticketing_service()
        dispatcher = build_ticket_dispatcher()
        result = await service.dispatch_batch(batch_id=batch_id, dispatcher=dispatcher)

        if not result.get("success"):
            raise HTTPException(
                status_code=422,
                detail=error_detail("batch_dispatch_failed", "Batch-Dispatch fehlgeschlagen"),
            )

        result.setdefault("batch_status", "pending")
        result.setdefault("error", None)
        result.setdefault("code", None)
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Fehler beim Dispatching des Batches")
        raise HTTPException(
            status_code=500,
            detail=error_detail("batch_dispatch_failed", "Batch-Dispatch fehlgeschlagen"),
        ) from e


@webhook_router.post(
    "/batch/confirm",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": BatchConfirmation.model_json_schema()}},
        }
    },
)
async def confirm_batch(
    request: Request,
    webhook_signature: Annotated[str | None, Header(alias="X-Webhook-Signature")] = None,
    webhook_timestamp: Annotated[str | None, Header(alias="X-Webhook-Timestamp")] = None,
):
    """
    Bestätigt die erfolgreiche Abarbeitung eines Batches durch ein externes System.

    Dieser Endpunkt kann von Webhooks externer Systeme oder manuellen Prozessen aufgerufen werden.

    Args:
        request (Request): Roher, signierter JSON-Request-Body zur Bestätigung.

    Returns:
        dict: Bestätigung der durchgeführten Aktualisierung in der Datenbank.

    Raises:
        HTTPException: Wenn der Batch nicht gefunden wurde oder die Bestätigung fehlschlägt.
    """
    try:
        body = await request.body()
        verify_webhook_signature(
            body=body,
            signature=webhook_signature,
            timestamp=webhook_timestamp,
            secret=settings.BATCH_CONFIRM_WEBHOOK_SECRET,
            max_age_seconds=settings.BATCH_CONFIRM_WEBHOOK_MAX_AGE_SECONDS,
            clock_skew_seconds=settings.BATCH_CONFIRM_WEBHOOK_CLOCK_SKEW_SECONDS,
        )
    except WebhookConfigurationError as exc:
        logger.error("Batch-Webhook-Authentifizierung ist nicht konfiguriert")
        raise HTTPException(
            status_code=503,
            detail=error_detail("webhook_unavailable", "Webhook nicht verfügbar"),
        ) from exc
    except WebhookAuthenticationError as exc:
        raise HTTPException(
            status_code=401,
            detail=error_detail("invalid_webhook_auth", "Ungültige Webhook-Authentifizierung"),
        ) from exc

    try:
        confirmation = BatchConfirmation.model_validate_json(body)
    except ValidationError as exc:
        errors = sanitized_validation_errors(exc.errors(), location_prefix=("body",))
        raise HTTPException(status_code=422, detail=errors) from exc

    try:
        service = build_batch_ticketing_service()
        # Aufruf der Geschäftslogik zur Bestätigung des Batches
        result = service.confirm_batch_completion(
            batch_id=confirmation.batch_id,
            successful_count=confirmation.successful_count,
            failed_count=confirmation.failed_count,
            ticket_confirmations=(
                [item.model_dump() for item in confirmation.ticket_confirmations]
                if confirmation.ticket_confirmations is not None
                else None
            ),
            dispatch_token=confirmation.dispatch_token,
        )

        if not result.get("success"):
            code = result.get("code", "batch_confirmation_rejected")
            status_code = 404 if code == "batch_not_found" else 409
            raise HTTPException(
                status_code=status_code,
                detail=error_detail(
                    code,
                    CONFIRMATION_ERROR_MESSAGES.get(code, "Batch-Bestätigung abgelehnt"),
                ),
            )

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Fehler bei Batch-Bestätigung")
        raise HTTPException(
            status_code=500,
            detail=error_detail("batch_confirmation_failed", "Batch-Bestätigung fehlgeschlagen"),
        ) from e


@management_router.get("/batch/status/{batch_id}")
async def get_batch_status(
    batch_id: int,
    db: Session = Depends(get_db),
    principal: ManagementPrincipal = Depends(require_management_operation(BATCHES_READ)),
):
    """
    Ruft detaillierte Informationen und den aktuellen Status eines Batches ab.

    Args:
        batch_id (int): Die ID des abzufragenden Batches.
        db (Session): Datenbank-Session.

    Returns:
        dict: Details zum Batch inklusive der enthaltenen Findings.

    Raises:
        HTTPException: Wenn der Batch nicht gefunden wurde.
    """
    try:
        with UnitOfWork() as uow:
            batch = uow.batches.get_batch_by_id(batch_id)
            if not batch:
                raise HTTPException(status_code=404, detail="Batch nicht gefunden")
            if not principal.allows_tenant(batch.tenant.name):
                raise HTTPException(status_code=404, detail="Batch nicht gefunden")

            return {
                "batch_id": batch.id,
                "batch_number": batch.batch_number,
                "status": batch.status,
                "tenant_id": batch.tenant_id,
                "total_findings": batch.total_findings,
                "successful_tickets": batch.successful_tickets,
                "failed_tickets": batch.failed_tickets,
                "target_system": batch.target_system,
                "external_batch_id": batch.external_batch_id,
                "created_at": batch.created_at.isoformat() if batch.created_at else None,
                "sent_at": batch.sent_at.isoformat() if batch.sent_at else None,
                "completed_at": batch.completed_at.isoformat() if batch.completed_at else None,
                "findings": [
                    {
                        "id": f.id,
                        "name": f.name,
                        "target": f.target,
                        "risk": f.risk,
                        "status": f.status,
                        "ticket_external_id": f.ticket_external_id,
                        "ticket_url": f.ticket_url,
                    }
                    for f in batch.findings
                ],
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Fehler beim Abrufen des Batch-Status")
        raise HTTPException(
            status_code=500,
            detail=error_detail(
                "batch_status_failed", "Batch-Status konnte nicht abgerufen werden"
            ),
        ) from e


@management_router.get("/batch/statistics/{tenant_name}")
async def get_batch_statistics(
    tenant_name: str,
    principal: ManagementPrincipal = Depends(require_management_operation(BATCHES_READ)),
):
    """
    Liefert statistische Informationen über alle Batches eines bestimmten Tenants.

    Args:
        tenant_name (str): Name des Mandanten.

    Returns:
        dict: Statistiken gruppiert nach Batch-Status.

    Raises:
        HTTPException: Wenn der Tenant nicht existiert.
    """
    try:
        require_tenant_access(principal, tenant_name)
        with UnitOfWork() as uow:
            # Mandant anhand des Namens suchen
            tenant = uow.tenants.get_by_name(tenant_name)
            if not tenant:
                raise HTTPException(status_code=404, detail="Mandant nicht gefunden")

            # Statistiken über das Repository abrufen
            stats = uow.batches.get_batch_statistics(tenant.id)
            return stats

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Fehler beim Abrufen der Statistiken")
        raise HTTPException(
            status_code=500,
            detail=error_detail(
                "batch_statistics_failed",
                "Batch-Statistiken konnten nicht abgerufen werden",
            ),
        ) from e


def _require_batch_tenant_access(batch_id: int, principal: ManagementPrincipal) -> None:
    """Authorize a batch using its server-side tenant relation before side effects."""

    with UnitOfWork() as uow:
        batch = uow.batches.get_batch_by_id(batch_id)
        if not batch:
            raise HTTPException(status_code=404, detail="Batch nicht gefunden")
        if not principal.allows_tenant(batch.tenant.name):
            raise HTTPException(status_code=404, detail="Batch nicht gefunden")


def _load_bounded_ticket_findings(query):
    """Materialize at most the configured number of findings before expensive work."""

    limit = settings.MAX_FINDINGS_PER_TICKET_OPERATION
    findings = query.limit(limit + 1).all()
    if len(findings) > limit:
        raise HTTPException(
            status_code=422,
            detail=error_detail(
                "operation_item_limit_exceeded",
                "Zu viele Findings; Tenant- oder Risiko-Filter weiter einschränken",
            ),
        )
    return findings


def _require_successful_dispatch(result: TicketDispatchResult) -> None:
    """Reject direct dispatches that produced no complete external delivery."""

    if not isinstance(result, TicketDispatchResult):
        raise RuntimeError("TicketDispatcher returned no structured dispatch result")
    if result.no_clients:
        raise HTTPException(
            status_code=503,
            detail=error_detail("dispatch_unavailable", "Keine Ticket-Clients konfiguriert"),
        )
    if not result.succeeded:
        raise HTTPException(
            status_code=502,
            detail=error_detail("dispatch_failed", "Ticket-Dispatch fehlgeschlagen"),
        )


router.include_router(management_router)
router.include_router(webhook_router)
