"""
app/services/ticket_preparation.py

Service zur Vorbereitung von Findings für die Ticketerstellung.

Orchestriert die Filterung nach installierten Windows-Updates und
weitere Pre-Processing-Schritte vor dem Ticketing.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol

from app.connectors.ncentral_client import NCentralClient
from app.core.config import Settings, settings
from app.core.logging import get_logger
from app.core.priority_config import PriorityConfig
from app.services.deduplication_service import DeduplicationService
from app.services.enrichment_service import EnrichmentService
from app.services.prioritization_service import PrioritizationService
from app.services.windows_patch_filter import WindowsPatchFilter

logger = get_logger(__name__)


class TicketPreparationStep(Protocol):
    """Schritt in der Ticket-Vorbereitung."""

    async def run(self, findings: list[Any]) -> list[Any]: ...


class WindowsPatchFilterStep:
    """Optionaler Filter basierend auf installierten Windows-Updates."""

    def __init__(self, patch_filter: WindowsPatchFilter, settings_obj: Settings) -> None:
        self.patch_filter = patch_filter
        self.settings = settings_obj

    async def run(self, findings: list[Any]) -> list[Any]:
        if not findings:
            return []
        if self.settings.ENABLE_WINDOWS_PATCH_FILTER:
            return await self.patch_filter.filter_findings_batch(findings)
        logger.debug("Windows-Patch-Filterung deaktiviert")
        return findings


class EnrichmentStep:
    """Anreicherung mit externen Metadaten."""

    def __init__(self, enricher: EnrichmentService) -> None:
        self.enricher = enricher

    async def run(self, findings: list[Any]) -> list[Any]:
        return await self.enricher.enrich_findings(findings)


class DeduplicationStep:
    """Deduplizierung nach Tenant/CVE/Target."""

    def __init__(self, deduplicator: DeduplicationService) -> None:
        self.deduplicator = deduplicator

    async def run(self, findings: list[Any]) -> list[Any]:
        return self.deduplicator.deduplicate(findings)


class PrioritizationStep:
    """Priorisierung der Findings."""

    def __init__(self, prioritizer: PrioritizationService) -> None:
        self.prioritizer = prioritizer

    async def run(self, findings: list[Any]) -> list[Any]:
        return self.prioritizer.prioritize_findings(findings)


class TicketPreparationService:
    """
    Strategy-Pattern: Orchestrator, der eine Liste von Steps (Strategien) ausführt.

    Workflow:
    1. Windows-Patch-Filterung (falls aktiviert)
    2. Priorisierung
    3. Deduplizierung
    4. Enrichment (Remediation Guides, CVE-Daten)
    """

    def __init__(
        self, steps: Sequence[TicketPreparationStep], settings_obj: Settings = settings
    ) -> None:
        self.steps = list(steps)
        self.settings = settings_obj

    async def prepare_for_ticketing(self, findings: list[Any]) -> list[Any]:
        """
        Bereitet Findings für die Ticketerstellung vor.

        Args:
            findings: Liste von Finding-Objekten (SQLAlchemy-Modelle).

        Returns:
            Gefilterte, angereicherte und priorisierte Finding-Liste (Pydantic-Modelle).
        """
        if not findings:
            return []

        logger.info(f"Bereite {len(findings)} Findings für Ticketing vor")

        current: list[Any] = findings
        for step in self.steps:
            if not current:
                break
            current = await step.run(current)

        if not current:
            return []

        final_findings = self._map_priorities_to_sql(findings, current)

        logger.info(f"Ticket-Vorbereitung abgeschlossen: {len(final_findings)} Findings verbleiben")
        return final_findings

    def _map_priorities_to_sql(self, sql_findings: list[Any], prioritized: list[Any]) -> list[Any]:
        """Map back to SQL objects and filter findings list to match prioritized selection"""
        pydantic_map = {
            getattr(f, "id", None): f for f in prioritized if getattr(f, "id", None) is not None
        }
        final_findings: list[Any] = []

        for sql_finding in sql_findings:
            if getattr(sql_finding, "id", None) in pydantic_map:
                p_finding = pydantic_map[sql_finding.id]
                if hasattr(p_finding, "priority_score"):
                    sql_finding.priority_score = p_finding.priority_score
                # Falls weitere Felder angereichert wurden, hier mappen
                final_findings.append(sql_finding)

        # Sortieren der SQL-Objekte nach dem berechneten Score
        final_findings.sort(key=lambda x: getattr(x, "priority_score", 0.0) or 0.0, reverse=True)
        return final_findings


def build_ticket_preparation_service(settings_obj: Settings = settings) -> TicketPreparationService:
    """Composition Root fuer TicketPreparationService."""
    prioritizer = PrioritizationService(PriorityConfig())
    enricher = EnrichmentService()
    deduplicator = DeduplicationService()

    steps: list[TicketPreparationStep] = []
    if settings_obj.ENABLE_WINDOWS_PATCH_FILTER:
        ncentral_client = NCentralClient(settings_obj)
        patch_filter = WindowsPatchFilter(ncentral_client)
        steps.append(WindowsPatchFilterStep(patch_filter, settings_obj))
    else:
        logger.debug("N-Central-Windows-Patch-Filterung nicht konfiguriert")

    steps.extend(
        [
            EnrichmentStep(enricher),
            DeduplicationStep(deduplicator),
            PrioritizationStep(prioritizer),
        ]
    )
    return TicketPreparationService(steps=steps, settings_obj=settings_obj)
