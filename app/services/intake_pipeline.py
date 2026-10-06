"""Schlanker Intake-Helfer für NVD-Anreicherung und Priorisierung."""

from collections.abc import Sequence
from typing import TypedDict

from app.core.priority_config import PriorityConfig
from app.models.findings import Finding, FindingsEnvelope
from app.services.enrichment_service import EnrichmentService
from app.services.prioritization_service import PrioritizationService


class ProcessedFinding(TypedDict):
    """Öffentliche Ergebnisstruktur des Intake-Helfers."""

    name: str
    risk: float
    priority_score: int
    target: str


async def process_findings(
    input_data: FindingsEnvelope | Sequence[Finding],
    *,
    enrichment_service: EnrichmentService | None = None,
    prioritization_service: PrioritizationService | None = None,
) -> list[ProcessedFinding]:
    """
    Verarbeitet eine Liste von Findings oder ein Findings-Envelope.

    Der Helfer verwendet dieselben Services und dieselbe Standardkonfiguration wie
    die Ticketvorbereitung. Abhängigkeiten können für Tests oder alternative
    Composition Roots explizit übergeben werden.

    Args:
        input_data: Entweder ein FindingsEnvelope oder eine Liste von Finding-Objekten.

    Returns:
        Priorisierte Ergebnisobjekte mit dem einheitlichen Feld ``priority_score``.
    """
    if isinstance(input_data, FindingsEnvelope):
        findings = list(input_data.items)
    else:
        findings = list(input_data)

    enricher = enrichment_service or EnrichmentService()
    prioritizer = prioritization_service or PrioritizationService(PriorityConfig())

    enriched = await enricher.enrich_findings(findings)
    prioritized = prioritizer.prioritize_findings(enriched)

    return [
        ProcessedFinding(
            name=finding.name,
            risk=finding.risk,
            priority_score=int(finding.priority_score or 0),
            target=finding.target,
        )
        for finding in prioritized
    ]
