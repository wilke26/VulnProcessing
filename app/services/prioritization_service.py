"""
app/services/prioritization_service.py

Dienst zur Priorisierung von Findings basierend auf CVSS-Scores und Regeln.
"""

from app.core.priority_config import PriorityConfig
from app.models.enrichment import EnrichedFinding, EnrichmentStatus
from app.models.findings import Finding


class PrioritizationService:
    """Service zur Berechnung von Prioritäts-Scores für Findings."""

    def __init__(self, config: PriorityConfig):
        self.config = config

    def compute_priority(self, finding: Finding) -> int:
        """Berechnet den Prioritäts-Score für ein einzelnes Finding."""
        score = self.config.default_weight

        cvss_score = self._best_cvss_score(finding)
        rules = self.config.cvss_rules if cvss_score is not None else self.config.risk_rules
        value = cvss_score if cvss_score is not None else finding.risk

        for rule in rules:
            if value >= rule.threshold:
                score += rule.weight
                break

        # Produkt-basierte Gewichtung (Summe der Gewichte)
        for product in finding.products:
            score += self.config.product_weights.get(product, 0)

        status = self._dominant_status(finding)
        if status:
            score += self.config.enrichment_status_weights.get(status, 0)

        return score

    def prioritize_findings(self, findings: list[Finding]) -> list[Finding]:
        """Anreichern und Sortieren von Findings nach dem berechneten Score."""
        return sorted(findings, key=self.compute_priority, reverse=True)

    def _best_cvss_score(self, finding: Finding) -> float | None:
        if not isinstance(finding, EnrichedFinding):
            return None

        scores = [
            enrichment.cvss.base_score
            for enrichment in finding.enrichments
            if enrichment.status == EnrichmentStatus.ENRICHED and enrichment.cvss is not None
        ]
        return max(scores) if scores else None

    def _dominant_status(self, finding: Finding) -> str | None:
        if not isinstance(finding, EnrichedFinding) or not finding.enrichments:
            return None

        status_order = [
            EnrichmentStatus.ENRICHED,
            EnrichmentStatus.NOT_FOUND,
            EnrichmentStatus.ERROR,
            EnrichmentStatus.DUPLICATE,
        ]

        for status in status_order:
            if any(en.status == status for en in finding.enrichments):
                return status.value
        return None
