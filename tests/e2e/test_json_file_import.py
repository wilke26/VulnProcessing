"""
End-to-End-Tests für den Import von Findings aus JSON-Dateien.

Diese Tests validieren den vollständigen Prozess vom Einlesen einer JSON-Datei
bis zur Speicherung der Findings in der Datenbank. Es werden sowohl einfache
Listenformate als auch das strukturierte Envelope-Format unterstützt.
"""

import json
from datetime import UTC, datetime

import pytest

from app.db import models as orm_models
from app.services.intake import load_and_store


def _make_finding_dict(
    name: str = "E2E-Schwachstelle",
    tenant: str = "TenantE2E",
    target: str = "host01.local",
    risk: float = 5.0,
    amount: int = 1,
) -> dict:
    """
    Hilfsfunktion zum Erzeugen eines Finding-JSON-Objekts für Testzwecke.
    Das Format entspricht dem Pydantic-Data-Contract der Anwendung.
    """

    return {
        "name": name,
        "tenant": tenant,
        "risk": risk,
        "amount": amount,
        "target": target,
        "extendedSolution": [
            "Schritt 1: Sofortmaßnahme durchführen.",
            "Schritt 2: Dauerhafte Konfiguration anpassen.",
        ],
        "windowsVersionHint": "",
        "products": ["Produkt A", "Produkt B"],
    }


@pytest.mark.usefixtures("db_session")
def test_json_file_import_raw_array(tmp_path):
    """
    E2E-Test: Import einer flachen Liste (Raw-Array) von Findings aus einer JSON-Datei.

    Prüft:
    - Ob die Datei korrekt eingelesen und validiert wird.
    - Ob die Daten (Tenant, Asset, Findings) konsistent in der DB gespeichert werden.
    """
    # Testdaten vorbereiten (Raw-Array)
    findings_data = [
        _make_finding_dict(name="E2E Raw 1"),
        _make_finding_dict(name="E2E Raw 2"),
    ]

    json_path = tmp_path / "findings_raw.json"
    json_path.write_text(json.dumps(findings_data, ensure_ascii=False), encoding="utf-8")

    # Import ausführen
    saved = load_and_store(str(json_path))
    assert saved == 2

    # DB-Zustand prüfen (über eine neue Session aus dem Fixture)
    from app.db.engine import SessionLocal

    session = SessionLocal()
    try:
        tenants = session.query(orm_models.Tenant).all()
        assert len(tenants) == 1
        assert tenants[0].name == "TenantE2E"

        assets = session.query(orm_models.Asset).all()
        assert len(assets) == 1
        assert assets[0].name == "host01.local"

        findings = session.query(orm_models.Finding).all()
        assert len(findings) == 2

        # Namen prüfen
        names = sorted(f.name for f in findings)
        assert names == ["E2E Raw 1", "E2E Raw 2"]
    finally:
        session.close()


@pytest.mark.usefixtures("db_session")
def test_json_file_import_envelope(tmp_path):
    """
    E2E-Test: Import von Findings im Envelope-Format (v1) aus einer JSON-Datei.

    Prüft:
    - Die korrekte Verarbeitung von Metadaten wie 'source' und 'schema_version'.
    - Den erfolgreichen Import der enthaltenen Items in die Datenbank.
    """
    # Envelope-Daten vorbereiten
    items = [
        _make_finding_dict(name="E2E Envelope 1", tenant="TenantE2E2"),
        _make_finding_dict(name="E2E Envelope 2", tenant="TenantE2E2"),
    ]

    envelope = {
        "schema_version": 1,
        "source": "lywand",
        "generated_at": datetime.now(UTC).isoformat(),
        "items": items,
    }

    json_path = tmp_path / "findings_envelope.json"
    json_path.write_text(json.dumps(envelope, ensure_ascii=False), encoding="utf-8")

    # Import ausführen
    saved = load_and_store(str(json_path))
    assert saved == 2

    # DB-Zustand prüfen
    from app.db.engine import SessionLocal

    session = SessionLocal()
    try:
        tenants = session.query(orm_models.Tenant).all()
        assert len(tenants) == 1
        assert tenants[0].name == "TenantE2E2"

        assets = session.query(orm_models.Asset).all()
        assert len(assets) == 1
        assert assets[0].name == "host01.local"

        findings = session.query(orm_models.Finding).all()
        assert len(findings) == 2

        names = sorted(f.name for f in findings)
        assert names == ["E2E Envelope 1", "E2E Envelope 2"]
    finally:
        session.close()
