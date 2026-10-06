"""
Unit-Tests für die Anreicherungsmodelle (Enrichment).
Validiert die Pydantic-Modelle für CVSS-Vektoren und angereicherte Findings,
inklusive der Bereichsprüfungen für Risikowerte.
"""

import pytest

from app.models.enrichment import CVSSVector, EnrichedFinding, EnrichmentStatus, NVDEnrichment
from app.models.findings import Finding

# Markierung, dass diese Tests keine Datenbank benötigen
pytestmark = pytest.mark.no_db


def _base_finding() -> Finding:
    """
    Hilfsfunktion zum Erstellen eines Basis-Findings für Tests.
    """
    return Finding(
        name="CVE-2024-0001 in package",
        tenant="tenant-a",
        risk=5.0,
        amount=1,
        target="host",
        extendedSolution=["fix"],
        products=["pkg"],
        windowsVersionHint="",
    )


def test_cvss_validation_range():
    """
    Prüft die Validierung des CVSS-Basis-Scores (muss zwischen 0.0 und 10.0 liegen).
    """
    # Gültiger Score
    cvss = CVSSVector(version="3.1", base_score=9.8, vector="CVSS:3.1/...")
    assert cvss.base_score == 9.8

    # Ungültiger Score (außerhalb des Bereichs) -> Validierungsfehler erwartet
    with pytest.raises(Exception):
        CVSSVector(version="3.1", base_score=11.0)


def test_enriched_finding_schema():
    """
    Verifiziert, dass ein EnrichedFinding korrekt aus einem Basis-Finding und
    NVD-Anreicherungsdaten zusammengesetzt werden kann.
    """
    base = _base_finding()
    enrichment = NVDEnrichment(
        cve_id="CVE-2024-0001",
        status=EnrichmentStatus.ENRICHED,
        description="Demo Beschreibung",
        cvss=CVSSVector(version="3.1", base_score=7.5),
        references=["https://example.com"],
    )

    # Act: Erstellen des angereicherten Findings
    data = base.model_dump()
    data.pop("priority_score", None)
    enriched = EnrichedFinding(**data, enrichments=[enrichment], priority_score=10)

    # Assert: Korrekte Übernahme der Daten prüfen
    assert enriched.priority_score == 10
    assert enriched.enrichments[0].cvss is not None
    assert enriched.enrichments[0].cvss.base_score == 7.5
