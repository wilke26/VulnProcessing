"""
Dieses Modul implementiert den BatchTicketingService, der die automatisierte und gesteuerte
Erstellung von Tickets in externen Systemen (wie MKS oder DocBee) orchestratiert.

Der Service unterstützt:
- Batch-Verarbeitung zur Laststeuerung mit konfigurierbarer Batch-Größe.
- Zustandsüberwachung der Batches (CREATED, PENDING, PROCESSING, COMPLETED, FAILED).
- Vorbereitung der Findings (z.B. Filterung bereits gepatchter Windows-Systeme).
- Transaktionssicherheit über das Unit-of-Work-Pattern.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import update
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.core.security import (
    issue_dispatch_confirmation_token,
    verify_dispatch_confirmation_token,
)
from app.db.models import FindingStatus, TicketBatch, TicketBatchStatus
from app.db.repository import FindingRepository, TenantRepository, TicketBatchRepository, UnitOfWork
from app.services.ticket_preparation import (
    TicketPreparationService,
    build_ticket_preparation_service,
)
from app.services.ticketing_clients import TicketDispatcherProtocol, TicketDispatchResult

# Logger initialisieren
logger = get_logger(__name__)


class BatchTicketingService:
    """
    Orchestriert die Batch-weise Ticketerstellung für einen Mandanten.

    Der Workflow umfasst:
    1. Suche nach offenen Findings ('new'), die den Risiko-Schwellenwert erfüllen.
    2. Anwendung von Vorbereitungsfiltern (z.B. Windows-Patch-Status).
    3. Gruppierung der Findings in einen Batch.
    4. Versand an das Ziel-Ticketsystem.
    5. Überwachung des Bestätigungsstatus.
    """

    def __init__(
        self,
        batch_size: int = 5,
        max_candidates_per_operation: int = 50,
        db_session: Session | None = None,
        prep_service: TicketPreparationService | None = None,
    ):
        """
        Initialisiert den Batch-Ticketing-Service.

        Args:
            batch_size (int): Maximale Anzahl an Findings, die in einem Batch
                zusammengefasst werden.
            max_candidates_per_operation (int): Maximale Anzahl geprüfter Findings pro Aufruf.
            db_session (Session, optional): Eine bestehende SQLAlchemy-Session (primär für Tests).
        """
        self.batch_size = batch_size
        self.max_candidates_per_operation = max_candidates_per_operation
        self.prep_service = prep_service or build_ticket_preparation_service()
        self._db_session = db_session

    async def create_next_batch(
        self, tenant_name: str, min_risk: float = 0.0, target_system: str = "mks"
    ) -> dict[str, Any] | None:
        """
        Ermittelt offene Findings für einen Tenant und erstellt daraus den nächsten Batch.

        Diese Methode ist der Haupteinstiegspunkt für die Batch-Erstellung. Sie entscheidet,
        ob eine neue Session gestartet werden muss oder eine bestehende verwendet wird.

        Args:
            tenant_name (str): Der Name des Mandanten.
            min_risk (float): Minimaler Risk-Score, ab dem Findings berücksichtigt werden.
            target_system (str): Das Zielsystem für die Ticketerstellung.

        Returns:
            dict | None: Metadaten des erstellten Batches oder Fehlermeldung/Status.
        """
        if self._db_session is not None:
            # Lokale Variable für Type-Safety und Verwendung der bereitgestellten Session
            session: Session = self._db_session
            result = await self._create_batch_with_session(
                session, tenant_name, min_risk, target_system
            )
            session.commit()
            return result
        else:
            # Standardmodus: Nutzung des UnitOfWork Patterns für automatische Transaktionsverwaltung
            with UnitOfWork() as uow:
                result = await self._create_batch_with_session(
                    uow.session, tenant_name, min_risk, target_system
                )
                return result

    async def _create_batch_with_session(
        self,
        session: Session,
        tenant_name: str,
        min_risk: float,
        target_system: str,
        remaining_candidates: int | None = None,
    ) -> dict[str, Any] | None:
        """
        Interne Geschäftslogik zur Erstellung eines Batches innerhalb einer aktiven Session.

        1. Validiert den Tenant.
        2. Prüft auf bereits aktive Batches (Block-Mechanismus).
        3. Ruft offene Findings ab.
        4. Wendet TicketPreparationService Filter an.
        5. Erstellt den Batch in der Datenbank.

        Args:
            session (Session): Die aktive SQLAlchemy-Session.
            tenant_name (str): Name des Mandanten.
            min_risk (float): Risiko-Schwellenwert.
            target_system (str): Zielsystem.

        Returns:
            dict: Ergebnisbericht über die Batch-Erstellung.
        """
        if remaining_candidates is None:
            remaining_candidates = self.max_candidates_per_operation
        if remaining_candidates <= 0:
            return {
                "status": "limit_reached",
                "message": "Candidate limit reached before a dispatchable batch was found",
            }

        # Repositories initialisieren
        tenant_repo = TenantRepository(session)
        finding_repo = FindingRepository(session)
        batch_repo = TicketBatchRepository(session)

        # 1. Tenant validieren
        tenant = tenant_repo.get_by_name(tenant_name)
        if not tenant:
            logger.error(f"Tenant '{tenant_name}' nicht gefunden")
            return {"status": "error", "message": f"Tenant '{tenant_name}' not found"}

        # 2. Sequentialitäts-Prüfung: Nur ein offener Batch pro Tenant erlaubt
        pending_batch = batch_repo.get_next_pending_batch(tenant.id)
        if pending_batch:
            logger.warning(
                f"Batch #{pending_batch.batch_number} wartet noch auf "
                f"Bestätigung. Keine neuen Batches bis zur Bestätigung."
            )
            return {
                "status": "pending",
                "message": "Previous batch still pending",
                "pending_batch_id": pending_batch.id,
                "pending_batch_number": pending_batch.batch_number,
            }

        # 3. Unverarbeitete Findings laden
        findings = finding_repo.get_unprocessed_findings(
            tenant_id=tenant.id,
            limit=min(self.batch_size, remaining_candidates),
            min_risk=min_risk,
        )

        if not findings:
            logger.info(f"Keine unverarbeiteten Findings für '{tenant_name}'")
            return {"status": "no_findings", "message": "No unprocessed findings available"}

        logger.info(f"Erstelle Batch mit {len(findings)} Findings für '{tenant_name}'")

        # 4. Windows-Patch-Filterung (falls aktiviert)
        filtered_findings = await self.prep_service.prepare_for_ticketing(findings)

        if not filtered_findings:
            logger.info("Alle Findings wurden ausgefiltert (bereits gepatcht)")
            # Original-Findings als FILTERED markieren
            for finding in findings:
                finding.status = FindingStatus.FILTERED.value
            session.flush()

            # Rekursiv nächsten Batch versuchen
            return await self._create_batch_with_session(
                session,
                tenant_name,
                min_risk,
                target_system,
                remaining_candidates=remaining_candidates - len(findings),
            )

        # 5. Batch erstellen
        batch = batch_repo.create_batch(
            tenant_id=tenant.id, findings=filtered_findings, target_system=target_system
        )

        session.flush()

        logger.info(
            f"Batch #{batch.batch_number} erstellt mit {len(filtered_findings)} Findings "
            f"(ID: {batch.id})"
        )

        return {
            "status": "created",
            "batch_id": batch.id,
            "batch_number": batch.batch_number,
            "findings_count": len(filtered_findings),
            "filtered_count": len(findings) - len(filtered_findings),
            "findings": [
                {"id": f.id, "name": f.name, "target": f.target, "risk": f.risk}
                for f in filtered_findings
            ],
        }

    async def send_batch_to_ticketsystem(
        self, batch_id: int, ticket_connector: Any
    ) -> dict[str, Any]:
        # Sendet einen Batch an das Ticketsystem.

        # Args:
        #     batch_id: ID des Batches
        #     ticket_connector: Connector zum Ticketsystem

        # Returns:
        #     Dict mit Ergebnis

        if self._db_session is not None:
            # Lokale Variable für Type-Safety
            session: Session = self._db_session
            return await self._send_batch_with_session(session, batch_id, ticket_connector)
        else:
            # Ohne injizierte Session verwaltet UnitOfWork die Transaktion.
            with UnitOfWork() as uow:
                return await self._send_batch_with_session(uow.session, batch_id, ticket_connector)

    async def dispatch_batch(
        self, batch_id: int, dispatcher: TicketDispatcherProtocol
    ) -> dict[str, Any]:
        # Dispatcht einen Batch über den konfigurierten TicketDispatcher.
        if self._db_session is not None:
            session: Session = self._db_session
            return await self._dispatch_batch_with_session(session, batch_id, dispatcher)
        else:
            with UnitOfWork() as uow:
                return await self._dispatch_batch_with_session(uow.session, batch_id, dispatcher)

    async def _dispatch_batch_with_session(
        self, session: Session, batch_id: int, dispatcher: TicketDispatcherProtocol
    ) -> dict[str, Any]:
        # Interne Methode zum Dispatch mit TicketDispatcher.
        batch_repo = TicketBatchRepository(session)
        FindingRepository(session)

        batch = batch_repo.get_batch_by_id(batch_id)
        if not batch:
            return {"success": False, "error": "Batch not found"}

        if batch.status != TicketBatchStatus.CREATED.value:
            return {
                "success": False,
                "error": f"Batch has status '{batch.status}', expected 'created'",
            }

        findings = batch.findings

        try:
            confirmation_token, confirmation_token_hash = issue_dispatch_confirmation_token()
            dispatch_result = await dispatcher.dispatch(
                findings,
                batch_id=batch.id,
                dispatch_token=confirmation_token,
            )

            if not isinstance(dispatch_result, TicketDispatchResult):
                raise TypeError("TicketDispatcher returned no structured dispatch result")

            if not dispatch_result.succeeded:
                failure_summary = dispatch_result.failure_summary()
                if dispatch_result.partially_failed:
                    batch_repo.mark_batch_dispatch_partially_failed(
                        batch,
                        failure_summary,
                        dispatch_result.successful_finding_ids,
                    )
                else:
                    batch_repo.mark_batch_failed(batch, failure_summary)
                session.commit()
                return {
                    "success": False,
                    "error": failure_summary,
                    "batch_id": batch.id,
                    "batch_status": batch.status,
                    "successful_attempts": dispatch_result.successful_attempts,
                    "failed_attempts": dispatch_result.failed_attempts,
                }

            # Findings als ticketing_in_progress markieren
            for finding in findings:
                finding.status = FindingStatus.TICKETING_IN_PROGRESS.value
            session.flush()

            # Batch als pending markieren (wartet auf Confirmation)
            batch.status = TicketBatchStatus.PENDING.value
            batch.external_batch_id = f"DISPATCH-{batch.id}"
            batch.sent_at = datetime.now(UTC)
            batch.confirmation_token_hash = confirmation_token_hash
            session.flush()

            return {
                "success": True,
                "batch_id": batch.id,
                "tickets_dispatched": len(findings),
                "successful_attempts": dispatch_result.successful_attempts,
                "failed_attempts": 0,
                "batch_status": batch.status,
                "dispatch_token": confirmation_token,
            }

        except Exception as exc:
            logger.exception("Fehler beim Dispatching des Batches: %s", exc)
            batch_repo.mark_batch_failed(batch, str(exc))
            session.commit()
            return {"success": False, "error": str(exc)}

    async def _send_batch_with_session(
        self, session: Session, batch_id: int, ticket_connector: Any
    ) -> dict[str, Any]:
        # Interne Methode zum Senden mit expliziter Session.
        batch_repo = TicketBatchRepository(session)
        finding_repo = FindingRepository(session)

        batch = batch_repo.get_batch_by_id(batch_id)
        if not batch:
            return {"success": False, "error": "Batch not found"}

        if batch.status != TicketBatchStatus.CREATED.value:
            return {
                "success": False,
                "error": f"Batch has status '{batch.status}', expected 'created'",
            }

        findings = batch.findings

        try:
            # Tickets im externen System erstellen
            results = await ticket_connector.create_tickets_batch(findings)

            # Externe Batch-ID speichern
            external_batch_id = results.get("batch_id")
            confirmation_token, confirmation_token_hash = issue_dispatch_confirmation_token()

            # Batch als gesendet markieren
            batch_repo.mark_batch_sent(batch, external_batch_id, confirmation_token_hash)

            # Einzelne Findings mit Ticket-IDs aktualisieren
            ticket_mappings = results.get("tickets", [])
            for mapping in ticket_mappings:
                finding_id = mapping.get("finding_id")
                external_id = mapping.get("ticket_id")
                ticket_url = mapping.get("ticket_url")

                finding = next((f for f in findings if f.id == finding_id), None)
                if finding:
                    finding_repo.mark_finding_ticket_created(finding, external_id, ticket_url)

            session.commit()

            logger.info(
                f"Batch #{batch.batch_number} erfolgreich an {batch.target_system} "
                f"gesendet (External ID: {external_batch_id})"
            )

            return {
                "success": True,
                "batch_id": batch.id,
                "external_batch_id": external_batch_id,
                "tickets_created": len(ticket_mappings),
                "dispatch_token": confirmation_token,
            }

        except Exception as e:
            logger.exception(f"Fehler beim Senden von Batch #{batch.batch_number}")
            batch_repo.mark_batch_failed(batch, str(e))
            session.commit()

            return {"success": False, "error": str(e), "batch_id": batch.id}

    def confirm_batch_completion(
        self,
        batch_id: int,
        successful_count: int,
        failed_count: int = 0,
        ticket_confirmations: list[dict[str, Any]] | None = None,
        dispatch_token: str | None = None,
    ) -> dict[str, Any]:
        # Bestätigt die Abarbeitung eines Batches.

        # Args:
        #     batch_id: ID des Batches
        #     successful_count: Anzahl erfolgreich erstellter Tickets
        #     failed_count: Anzahl fehlgeschlagener Tickets
        #     ticket_confirmations: Optional: Liste mit Finding-ID → Status-Mappings

        # Returns:
        #     Dict mit Ergebnis

        if self._db_session is not None:
            # Lokale Variable für Type-Safety
            session: Session = self._db_session
            return self._confirm_batch_with_session(
                session,
                batch_id,
                successful_count,
                failed_count,
                ticket_confirmations,
                dispatch_token,
            )
        else:
            # Ohne injizierte Session verwaltet UnitOfWork die Transaktion.
            with UnitOfWork() as uow:
                return self._confirm_batch_with_session(
                    uow.session,
                    batch_id,
                    successful_count,
                    failed_count,
                    ticket_confirmations,
                    dispatch_token,
                )

    def _confirm_batch_with_session(
        self,
        session: Session,
        batch_id: int,
        successful_count: int,
        failed_count: int,
        ticket_confirmations: list[dict[str, Any]] | None,
        dispatch_token: str | None,
    ) -> dict[str, Any]:
        # Interne Methode zur Bestätigung mit expliziter Session.
        batch_repo = TicketBatchRepository(session)
        finding_repo = FindingRepository(session)

        batch = batch_repo.get_batch_by_id(batch_id)
        if not batch:
            return {"success": False, "error": "Batch not found", "code": "batch_not_found"}

        if batch.status != TicketBatchStatus.PENDING.value:
            return {
                "success": False,
                "error": "Batch is not awaiting confirmation",
                "code": "invalid_batch_state",
            }

        if batch.sent_at is None or not verify_dispatch_confirmation_token(
            dispatch_token, batch.confirmation_token_hash
        ):
            return {
                "success": False,
                "error": "Confirmation does not match the active dispatch",
                "code": "invalid_batch_state",
            }

        if successful_count < 0 or failed_count < 0:
            return {
                "success": False,
                "error": "Confirmation counts must not be negative",
                "code": "invalid_confirmation_counts",
            }

        if successful_count + failed_count != batch.total_findings:
            return {
                "success": False,
                "error": "Confirmation counts do not match the batch size",
                "code": "invalid_confirmation_counts",
            }

        if ticket_confirmations is None:
            if failed_count:
                return {
                    "success": False,
                    "error": "Failed tickets require per-finding confirmations",
                    "code": "invalid_confirmation_details",
                }
        else:
            expected_ids = {finding.id for finding in batch.findings}
            supplied_ids = [confirmation.get("finding_id") for confirmation in ticket_confirmations]
            statuses = [confirmation.get("status") for confirmation in ticket_confirmations]
            if (
                len(supplied_ids) != len(expected_ids)
                or len(set(supplied_ids)) != len(supplied_ids)
                or set(supplied_ids) != expected_ids
                or statuses.count("confirmed") != successful_count
                or statuses.count("failed") != failed_count
            ):
                return {
                    "success": False,
                    "error": "Per-finding confirmations do not match the batch result",
                    "code": "invalid_confirmation_details",
                }

        claim = session.execute(
            update(TicketBatch)
            .where(
                TicketBatch.id == batch_id,
                TicketBatch.status == TicketBatchStatus.PENDING.value,
                TicketBatch.confirmation_token_hash == batch.confirmation_token_hash,
            )
            .values(
                status=TicketBatchStatus.PROCESSING.value,
                confirmation_token_hash=None,
            )
        )
        if claim.rowcount != 1:
            return {
                "success": False,
                "error": "Batch is not awaiting confirmation",
                "code": "invalid_batch_state",
            }

        # Batch als abgeschlossen markieren
        batch_repo.mark_batch_completed(batch, successful_count, failed_count)

        # Einzelne Findings aktualisieren
        if ticket_confirmations:
            for confirmation in ticket_confirmations:
                finding_id = confirmation.get("finding_id")
                status = confirmation.get("status")

                finding = next((f for f in batch.findings if f.id == finding_id), None)

                if finding and status == "confirmed":
                    finding_repo.mark_finding_confirmed(finding)
                elif finding and status == "failed":
                    finding.status = FindingStatus.NEW.value
                    finding.batch_id = None
        else:
            # Fallback: Alle Findings als bestätigt markieren
            for finding in batch.findings:
                if finding.status == FindingStatus.TICKETING_IN_PROGRESS.value:
                    finding_repo.mark_finding_confirmed(finding)

        session.commit()

        logger.info(
            f"Batch #{batch.batch_number} abgeschlossen: {successful_count} erfolgreich, "
            f"{failed_count} fehlgeschlagen"
        )

        return {
            "success": True,
            "batch_id": batch.id,
            "batch_status": batch.status,
            "successful": successful_count,
            "failed": failed_count,
        }
