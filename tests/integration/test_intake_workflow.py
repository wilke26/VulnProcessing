"""
Integrations-Tests für den vollständigen Intake-Workflow.
Validiert die Verarbeitung von Findings-Envelopes, einschließlich der automatischen Anlage
von Datenbank-Entitäten (Tenant, Asset, ImportRun) und der korrekten Persistierung.
"""

from datetime import UTC, datetime

from app.db import models as orm_models
from app.models.findings import Finding as PydanticFinding
from app.models.findings import FindingsEnvelope
from app.services.db_intake import intake_findings


def _make_finding(
    name: str,
    tenant: str = "Tenant A",
    target: str = "server01.local",
    risk: float = 5.0,
) -> PydanticFinding:
    """
    Hilfsfunktion zum Erstellen eines Finding-DTOs für Tests.
    """
    return PydanticFinding(
        name=name,
        tenant=tenant,
        risk=risk,
        amount=1,
        target=target,
        extendedSolution=["Schritt 1", "Schritt 2"],
        windowsVersionHint="",
        products=["Produkt X"],
    )


def test_intake_creates_all_entities(db_session):
    """
    Testet, ob ein vollständiger Intake-Lauf alle erforderlichen Datenbank-Einträge
    korrekt erzeugt und den Status des Import-Laufs setzt.
    """
    # Arrange: Vorbereitung eines Envelopes mit zwei Findings
    f1 = _make_finding(name="Schwachstelle 1")
    f2 = _make_finding(name="Schwachstelle 2")

    envelope = FindingsEnvelope(
        schema_version=1,
        source="lywand",
        generated_at=datetime.now(UTC),
        items=[f1, f2],
    )

    # Act: Durchführung des Intake-Workflows
    saved_count = intake_findings(envelope)

    # Assert: Anzahl verarbeiteter Findings
    assert saved_count == 2

    # DB-Zustand über db_session prüfen
    tenants = db_session.query(orm_models.Tenant).all()
    assert len(tenants) == 1
    assert tenants[0].name == "Tenant A"

    assets = db_session.query(orm_models.Asset).all()
    assert len(assets) == 1
    assert assets[0].name == "server01.local"

    findings = db_session.query(orm_models.Finding).all()
    assert len(findings) == 2

    import_runs = db_session.query(orm_models.ImportRun).all()
    assert len(import_runs) == 1
    ir = import_runs[0]
    assert ir.source == "lywand"
    assert ir.total_records == 2
    assert ir.successful_records == 2
    assert ir.failed_records == 0
    assert ir.status == "completed"
    assert ir.completed_at is not None


def test_intake_findings_deduplicates_by_unique_key(db_session):
    """
    Stellt sicher, dass aufeinanderfolgende Intake-Läufe mit denselben Unique-Keys
    bestehende Datensätze aktualisieren (Upsert), statt neue Duplikate zu erzeugen.
    """
    # Arrange: zwei Läufe mit identischen Unique-Keys (tenant, asset, name, target)
    f1 = _make_finding(name="Schwachstelle A", risk=4.0)
    f2 = _make_finding(name="Schwachstelle B", risk=6.0)

    envelope1 = FindingsEnvelope(
        schema_version=1,
        source="lywand",
        generated_at=datetime.now(UTC),
        items=[f1, f2],
    )

    # Erster Intake
    saved1 = intake_findings(envelope1)
    assert saved1 == 2

    # Zweiter Intake mit geänderten Risiken, aber gleichen Keys
    f1_b = _make_finding(name="Schwachstelle A", risk=8.0)
    f2_b = _make_finding(name="Schwachstelle B", risk=9.0)

    envelope2 = FindingsEnvelope(
        schema_version=1,
        source="lywand",
        generated_at=datetime.now(UTC),
        items=[f1_b, f2_b],
    )

    saved2 = intake_findings(envelope2)
    assert saved2 == 2  # beide Datensätze wurden verarbeitet (Upsert)

    # Prüfen, dass weiterhin nur 2 Findings existieren,
    # die aber mit den neuen Risikowerten aktualisiert wurden.
    findings = db_session.query(orm_models.Finding).order_by(orm_models.Finding.name).all()
    assert len(findings) == 2

    f_a, f_b = findings
    assert f_a.name == "Schwachstelle A"
    assert f_b.name == "Schwachstelle B"

    assert f_a.risk == 8.0
    assert f_b.risk == 9.0
