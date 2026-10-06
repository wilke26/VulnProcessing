"""
Unit-Tests für das FindingRepository.
Validiert die Upsert-Logik für Findings, einschließlich der Behandlung von
Erst- und Letztsichtungen sowie der korrekten Serialisierung von JSON-Daten.
"""

import json
from datetime import timedelta

from app.db import models as orm_models
from app.db.repository import FindingRepository
from app.models.findings import Finding as PydanticFinding


def _make_pydantic_finding(
    name: str = "Unsichere TLS-Konfiguration",
    tenant: str = "Tenant A",
    target: str = "server01.local",
    risk: float = 7.5,
    amount: int = 3,
) -> PydanticFinding:
    """
    Hilfsfunktion zum Erstellen eines Pydantic-Finding-DTOs für Tests.
    """
    return PydanticFinding(
        name=name,
        tenant=tenant,
        risk=risk,
        amount=amount,
        target=target,
        extendedSolution=[
            "TLS auf Version 1.2 oder höher konfigurieren.",
            "Unsichere Cipher Suites deaktivieren.",
        ],
        windowsVersionHint="Windows Server 2019",
        products=["IIS", "Windows Server"],
    )


def test_upsert_inserts_new_finding(db_session):
    """
    Verifiziert, dass ein neues Finding korrekt in die Datenbank eingefügt wird,
    wenn noch kein passender Datensatz existiert.
    """
    # Arrange: Mandant und Asset anlegen
    tenant = orm_models.Tenant(name="Tenant A")
    asset = orm_models.Asset(tenant=tenant, name="server01.local")
    db_session.add_all([tenant, asset])
    db_session.commit()

    repo = FindingRepository(db_session)
    dto = _make_pydantic_finding()

    # Act: Upsert ausführen
    finding = repo.upsert_from_dto(
        tenant=tenant,
        asset=asset,
        dto=dto,
        import_run=None,
    )
    db_session.commit()

    # Assert: Korrekte Persistierung aller Felder prüfen
    assert finding.id is not None
    assert finding.tenant_id == tenant.id
    assert finding.asset_id == asset.id
    assert finding.name == dto.name
    assert finding.risk == dto.risk
    assert finding.amount == dto.amount
    assert finding.target == dto.target
    assert finding.windows_version_hint == dto.windowsVersionHint
    assert json.loads(finding.extended_solution_json) == dto.extendedSolution
    assert finding.status == "new"
    assert finding.first_seen is not None
    assert finding.last_seen is not None


def test_upsert_updates_existing_finding_and_keeps_first_seen(db_session):
    """
    Stellt sicher, dass bei einem Upsert eines bereits existierenden Findings (gleicher Unique-Key)
    der Datensatz aktualisiert wird, wobei das 'first_seen' Datum erhalten bleibt.
    """
    # Arrange: Mandant und Asset anlegen
    tenant = orm_models.Tenant(name="Tenant A")
    asset = orm_models.Asset(tenant=tenant, name="server01.local")
    db_session.add_all([tenant, asset])
    db_session.commit()

    repo = FindingRepository(db_session)

    # Erstes DTO (wird neu angelegt)
    dto1 = _make_pydantic_finding()
    finding1 = repo.upsert_from_dto(
        tenant=tenant,
        asset=asset,
        dto=dto1,
        import_run=None,
    )
    db_session.commit()

    # Zeitstempel merken
    first_seen_initial = finding1.first_seen
    last_seen_initial = finding1.last_seen

    # Simuliertes „Altern“ des Datensatzes um einen Tag
    finding1.first_seen = first_seen_initial - timedelta(days=1)
    finding1.last_seen = last_seen_initial - timedelta(days=1)
    db_session.commit()

    # Zweites DTO mit geänderten Werten (Risiko, Anzahl, Lösung), aber gleichem Unique-Key
    dto2 = _make_pydantic_finding(risk=9.0, amount=10)
    dto2.extendedSolution = ["Neue Maßnahme 1", "Neue Maßnahme 2"]

    # Act: Erneutes Upsert mit den aktualisierten Daten
    finding2 = repo.upsert_from_dto(
        tenant=tenant,
        asset=asset,
        dto=dto2,
        import_run=None,
    )
    db_session.commit()

    # Assert: ID muss gleich bleiben (Update statt Insert)
    assert finding2.id == finding1.id

    # Erstsichtung muss erhalten bleiben, Letztsichtung muss aktualisiert sein
    assert finding2.first_seen == finding1.first_seen
    assert finding2.last_seen >= finding1.last_seen

    # Die fachlichen Werte müssen die neuen aus dto2 sein
    assert finding2.risk == dto2.risk
    assert finding2.amount == dto2.amount
    assert json.loads(finding2.extended_solution_json) == dto2.extendedSolution
