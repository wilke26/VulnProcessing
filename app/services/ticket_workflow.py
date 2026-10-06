"""
app/services/ticket_workflow.py

Historischer Workflow-Helfer für die sequenzielle Batch-Erstellung.

Die aktiven HTTP-Pfade verwenden den Dispatcher direkt. Dieser Helfer erstellt
Batches und wartet auf externes Senden beziehungsweise Bestätigen; sein
``auto_send``-Zweig ist nur eine dokumentierte Simulation ohne externe Seiteneffekte.
"""

from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.services.batch_ticketing_service import BatchTicketingService

logger = get_logger(__name__)


class TicketWorkflowOrchestrator:
    """
    Orchestriert die Batch-Erstellung bis zur Grenze des externen Versands.

    Workflow:
    1. Erstelle Batch
    2. Halte für externen Versand und Bestätigung an
    3. Wiederhole nach Bestätigung für den nächsten Batch
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
        Erstellt sequenziell Batches, bis ein externer Verarbeitungsschritt erforderlich ist.

        Args:
            tenant_name: Name des Mandanten
            min_risk: Minimaler Risk-Score
            auto_send: Historischer Simulationsschalter. Protokolliert den vorgesehenen
                Versand, löst aber keinen externen Aufruf aus.

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

                # Historischer Simulationszweig für einen früher geplanten Auto-Send-Modus.
                if auto_send:
                    # Bewusst nur Simulation: Der aktive Versandpfad benötigt einen
                    # TicketDispatcher und wird über die HTTP-Dispatch-Endpunkte aufgerufen.
                    logger.info(f"Auto-Send ist aktiviert, würde Batch {batch_id_for_log} senden")
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
