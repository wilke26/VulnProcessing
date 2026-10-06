"""Tests für den konsolidierten Intake-Helfer."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from app.core.priority_config import PriorityConfig, RiskRule
from app.models.enrichment import CVSSVector, EnrichedFinding, EnrichmentStatus, NVDEnrichment
from app.models.findings import Finding, FindingsEnvelope
from app.services.enrichment_service import EnrichmentService
from app.services.intake_pipeline import process_findings
from app.services.prioritization_service import PrioritizationService


def _finding(name: str, risk: float) -> Finding:
    return Finding(
        name=name,
        tenant="Tenant A",
        risk=risk,
        amount=1,
        target="server-a",
        extendedSolution=["Fix"],
        products=["Unknown"],
    )


@pytest.mark.asyncio
async def test_process_findings_uses_shared_services_and_priority_contract():
    low = _finding("Low", 3.0)
    critical = _finding("CVE-2026-12345", 0.0)
    enriched = [
        EnrichedFinding(**low.model_dump(), enrichments=[]),
        EnrichedFinding(
            **critical.model_dump(),
            enrichments=[
                NVDEnrichment(
                    cve_id="CVE-2026-12345",
                    status=EnrichmentStatus.ENRICHED,
                    cvss=CVSSVector(version="3.1", base_score=9.8),
                )
            ],
        ),
    ]
    enricher = AsyncMock(spec=EnrichmentService)
    enricher.enrich_findings.return_value = enriched
    prioritizer = PrioritizationService(
        PriorityConfig(
            risk_rules=[RiskRule(threshold=5.0, weight=10)],
            cvss_rules=[RiskRule(threshold=9.0, weight=100)],
            product_weights={},
            enrichment_status_weights={"enriched": 5},
            default_weight=1,
        )
    )
    envelope = FindingsEnvelope(
        generated_at=datetime.now(UTC),
        items=[low, critical],
    )

    result = await process_findings(
        envelope,
        enrichment_service=enricher,
        prioritization_service=prioritizer,
    )

    assert result == [
        {
            "name": "CVE-2026-12345",
            "risk": 0.0,
            "priority_score": 106,
            "target": "server-a",
        },
        {"name": "Low", "risk": 3.0, "priority_score": 1, "target": "server-a"},
    ]
    enricher.enrich_findings.assert_awaited_once_with([low, critical])
    assert critical.risk == 0.0


@pytest.mark.asyncio
async def test_process_findings_accepts_plain_empty_list():
    enricher = AsyncMock(spec=EnrichmentService)
    enricher.enrich_findings.return_value = []

    result = await process_findings([], enrichment_service=enricher)

    assert result == []
    enricher.enrich_findings.assert_awaited_once_with([])
