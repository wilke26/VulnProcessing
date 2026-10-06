"""
End-to-End-Tests für die Intake-Pipeline.

Diese Tests decken den gesamten Weg von einer JSON-Datei auf der Festplatte
über die Pydantic-Validierung und das ORM-Mapping bis hin zur Persistierung
in der Datenbank mittels Unit of Work ab.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import TypeAdapter
from sqlalchemy import select

from app.db import models as orm_models
from app.db.repository import UnitOfWork
from app.models.findings import Finding, FindingsEnvelope, FindingsInput
from app.services.mappers import map_pydantic_to_orm

# Adapter zur Unterstützung polymorpher Eingaben (Envelope oder flache Liste)
UnifiedAdapter = TypeAdapter(FindingsEnvelope | FindingsInput)


def load_and_normalize(path: Path) -> list[Finding]:
    """
    Liest eine JSON-Datei ein, validiert sie gegen den Data Contract
    und gibt unabhängig vom Eingabeformat eine Liste von Finding-Objekten zurück.
    """
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    parsed = UnifiedAdapter.validate_python(data)

    # Normalisieren: immer eine List[Finding] zurückgeben
    if isinstance(parsed, list):
        return parsed
    else:  # FindingsEnvelope
        return parsed.items


def load_and_store(
    path: str,
    tenant_id: int = 1,
    asset_id: int = 1,
    import_run_id: int | None = None,
) -> int:
    """
    Simuliert eine vollständige E2E-Pipeline:
    1. JSON von Platte lesen
    2. Gegen Pydantic-Modelle validieren
    3. In ORM-Entities transformieren (Mapping)
    4. Über UnitOfWork in die Datenbank persistieren
    """
    findings = load_and_normalize(Path(path))
    saved = 0

    with UnitOfWork() as uow:
        for finding in findings:
            orm_obj = map_pydantic_to_orm(
                finding,
                tenant_id=tenant_id,
                asset_id=asset_id,
                import_run_id=import_run_id,
            )
            uow.findings.add(orm_obj)
            saved += 1

    return saved


# ---------------------------------------------------------------------------
# Test-Helfer
# ---------------------------------------------------------------------------


def _make_finding_dict(
    name: str = "E2E Finding",
    risk: float = 5.0,
    target: str = "server01.local",
    tenant: str = "TenantE2E",
) -> dict:
    """
    Erzeugt ein Dictionary, das dem JSON-Format eines Findings entspricht.
    Wird zur Generierung von Test-Dateien verwendet.
    """
    product_name = f"Produkt für {name}"  # sorgt für eindeutige Namen pro Finding

    return {
        "tenant": tenant,
        "name": name,
        "risk": risk,
        "amount": 1,
        "target": target,
        "extendedSolution": ["Schritt 1", "Schritt 2"],
        "products": [product_name],
    }


# ---------------------------------------------------------------------------
# E2E-Tests
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("db_session")
def test_intake_pipeline_raw_array(tmp_path, db_session):
    """
    E2E-Test: Durchlauf der Pipeline mit einem Raw-Array (flache JSON-Liste).

    Prüft die korrekte Verkettung von:
    JSON -> Pydantic -> Mapping -> Repository/UoW -> DB.
    """
    # --- Arrange: Tenant + Asset in der DB anlegen ---
    tenant = orm_models.Tenant(name="TenantE2E")
    db_session.add(tenant)
    db_session.flush()

    asset = orm_models.Asset(tenant_id=tenant.id, name="server01.local")
    db_session.add(asset)
    db_session.flush()

    # Wichtig: commit, damit eine andere Session (UnitOfWork) die Daten sieht
    db_session.commit()

    # --- Arrange: Raw-Array vorbereiten ---
    findings_data = [
        _make_finding_dict(name="E2E Raw 1", tenant="TenantE2E"),
        _make_finding_dict(name="E2E Raw 2", tenant="TenantE2E"),
    ]

    json_path = tmp_path / "findings_raw.json"
    json_path.write_text(json.dumps(findings_data, ensure_ascii=False), encoding="utf-8")

    # --- Act ---
    saved = load_and_store(str(json_path), tenant_id=tenant.id, asset_id=asset.id)

    # --- Assert: Anzahl gespeicherter Findings ---
    assert saved == 2

    # Und in der DB nachschauen
    stmt = select(orm_models.Finding)
    all_findings = list(db_session.scalars(stmt))

    assert len(all_findings) == 2
    names = {f.name for f in all_findings}
    assert names == {"E2E Raw 1", "E2E Raw 2"}

    for f in all_findings:
        assert f.tenant_id == tenant.id
        assert f.asset_id == asset.id


@pytest.mark.usefixtures("db_session")
def test_intake_pipeline_envelope(tmp_path, db_session):
    """
    E2E-Test: Durchlauf der Pipeline mit dem Envelope-Format (v1).

    Prüft, ob auch bei Verwendung von Envelopes alle Findings korrekt
    den zugehörigen Tenants und Assets zugeordnet werden.
    """
    # --- Arrange: Tenant + Asset in der DB anlegen ---
    tenant = orm_models.Tenant(name="TenantE2E2")
    db_session.add(tenant)
    db_session.flush()

    asset = orm_models.Asset(tenant_id=tenant.id, name="server01.local")
    db_session.add(asset)
    db_session.flush()
    db_session.commit()

    # --- Arrange: Envelope mit Items ---
    items = [
        _make_finding_dict(name="E2E Envelope 1", tenant="TenantE2E2"),
        _make_finding_dict(name="E2E Envelope 2", tenant="TenantE2E2"),
    ]

    envelope = {
        "schema_version": 1,
        "source": "lywand",
        "generated_at": "2025-01-01T12:00:00Z",
        "items": items,
    }

    json_path = tmp_path / "findings_envelope.json"
    json_path.write_text(json.dumps(envelope, ensure_ascii=False), encoding="utf-8")

    # --- Act ---
    saved = load_and_store(str(json_path), tenant_id=tenant.id, asset_id=asset.id)

    # --- Assert ---
    assert saved == 2

    stmt = select(orm_models.Finding)
    all_findings = list(db_session.scalars(stmt))

    assert len(all_findings) == 2
    names = {f.name for f in all_findings}
    assert names == {"E2E Envelope 1", "E2E Envelope 2"}

    for f in all_findings:
        assert f.tenant_id == tenant.id
        assert f.asset_id == asset.id
