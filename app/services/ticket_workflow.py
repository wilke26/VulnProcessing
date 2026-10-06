"""
app/services/ticket_workflow.py

End-to-End Workflow-Orchestrierung für Ticketerstellung.
Koordiniert alle Schritte von Batch-Erstellung bis Bestätigung.
"""

from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.services.batch_ticketing_service import BatchTicketingService

logger = get_logger(__name__)


class TicketWorkflowOrchestrator:
    """
    Orchestriert den gesamten Ticketing-Workflow.

    Workflow:
    1. Erstelle Batch
    2. Sende an Ticketsystem
    3. Warte auf Bestätigung (extern)
    4. Wiederhole für nächsten Batch
    """

    def __init__(self, batch_service: BatchTicketingService | None = None) -> None:
        self.batch_service = batch_service or BatchTicketingService(batch_size=5)

    async def process_all_findings(
        self,
        tenant_name: str,
        min_risk: float = 0.0,
        auto_send: bool = False,
    ) -> dict[str, Any]:
        """
        Verarbeitet alle Findings eines Tenants in 5er-Batches.

        Args:
            tenant_name: Name des Mandanten
            min_risk: Minimaler Risk-Score
            auto_send: Automatisch an Ticketsystem senden (ohne manuelle Bestätigung)

        Returns:
            Zusammenfassung der Verarbeitung
        """

        batches_created: list[int] = []
        total_findings: int = 0

        while True:
            # Nächsten Batch erstellen
            result = await self.batch_service.create_next_batch(
                tenant_name=tenant_name,
                min_risk=min_risk,
            )

            # Typ-Narrowing: ab hier ist result ein Dict[str, Any]
            if result is None:
                logger.info(
                    f"Kein Resultat von create_next_batch (Tenant '{tenant_name}' "
                    "nicht gefunden oder Fehler)."
                )
                break

            status = str(result.get("status") or "")

            if status == "no_findings":
                logger.info("Keine weiteren Findings zu verarbeiten")
                break

            if status == "pending":
                logger.warning(
                    f"Batch #{result.get('pending_batch_number')} wartet noch auf "
                    "Bestätigung. Pausiere..."
                )
                break

            if status == "created":
                batch_id_raw = result.get("batch_id")
                findings_count_raw = result.get("findings_count")

                # Batch-ID nur aufnehmen, wenn sie wirklich ein int ist
                if isinstance(batch_id_raw, int):
                    batches_created.append(batch_id_raw)
                    batch_id_for_log = batch_id_raw
                else:
                    batch_id_for_log = batch_id_raw or "unknown"

                # findings_count defensiv in int konvertieren
                try:
                    findings_count = int(findings_count_raw or 0)
                except (TypeError, ValueError):
                    findings_count = 0

                total_findings += findings_count

                logger.info(
                    f"Batch #{result.get('batch_number')} erstellt mit {findings_count} Findings"
                )

                # Optional: Automatisch senden
                if auto_send:
                    # TODO: Integration mit echtem Ticketsystem
                    logger.info(f"Auto-Send ist aktiviert, würde Batch {batch_id_for_log} senden")
                    # await self.batch_service.send_batch_to_ticketsystem(...)
                else:
                    # Warte auf manuelle Bestätigung via API
                    logger.info(
                        f"Batch {batch_id_for_log} wartet auf manuelles Senden via "
                        f"POST /tickets/batch/{batch_id_for_log}/send"
                    )
                    break  # Stoppe hier, warte auf externe Bestätigung

            else:
                # Unerwarteter Status – zur Sicherheit abbrechen
                logger.warning(f"Unerwarteter Batch-Status: {status!r}, breche ab.")
                break

        return {
            "batches_created": len(batches_created),
            "batch_ids": batches_created,
            "total_findings": total_findings,
            "tenant": tenant_name,
        }
