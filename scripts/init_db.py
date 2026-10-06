"""
Initialisiert die lokale SQLite-Datenbank für VulnProcessing.

Dieses Skript erstellt die notwendigen Datenbanktabellen gemäß den SQLAlchemy-Modellen,
stellt sicher, dass das Datenverzeichnis existiert, und fügt optional erste Testdaten ein.
Es unterstützt das Zurücksetzen der Datenbank sowie das Überspringen der Schema-Erstellung.

Verwendung:
    python -m scripts.init_db [--skip-schema] [--reset]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Lokales Projekt importierbar machen, falls als Modul ausgeführt
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db.engine import DATABASE_URL, SessionLocal, init_db
from app.db.models import Asset, Finding, ImportRun, Tenant


def insert_test_data() -> None:
    """
    Erzeugt grundlegende Testdaten in der Datenbank (Tenant, Asset, ImportRun, Finding),
    um die Funktionalität der Anwendung sofort testen zu können.
    """
    print("Füge Testdaten hinzu...")
    with SessionLocal() as session:
        # Prüfen, ob Testdaten bereits vorhanden sind (Vermeidung von Duplikaten)
        existing_tenant = session.query(Tenant).filter(Tenant.name == "test-tenant").first()
        if existing_tenant:
            print("Testdaten existieren bereits, überspringe Einfügen.")
            return

        # 1. Test-Mandant erstellen
        tenant = Tenant(name="test-tenant")
        session.add(tenant)
        session.flush()

        # 2. Test-Asset (Server) erstellen
        asset = Asset(tenant_id=tenant.id, name="test-asset", kind="server")
        session.add(asset)
        session.flush()

        # 3. Test-Import-Lauf protokollieren
        import_run = ImportRun(
            tenant_id=tenant.id,
            source="test-source",
            status="completed",
            total_records=1,
            successful_records=1,
            failed_records=0,
        )
        session.add(import_run)
        session.flush()

        # 4. Beispiel-Finding anlegen
        finding = Finding(
            tenant_id=tenant.id,
            asset_id=asset.id,
            import_id=import_run.id,
            name="Test Finding",
            risk=5.5,
            amount=2,
            target="localhost",
            windows_version_hint="Windows 10",
            extended_solution_json='["Patchen über KB123456", "Antivirus aktualisieren"]',
            status="new",
        )
        session.add(finding)

        # Alle Änderungen in einer Transaktion bestätigen
        session.commit()

        print(f"Erstellt: Tenant '{tenant.name}' (ID: {tenant.id})")
        print(f"Erstellt: Asset '{asset.name}' (ID: {asset.id})")
        print(f"Erstellt: Finding '{finding.name}' (ID: {finding.id})")


def main() -> int:
    """
    Haupteinstiegspunkt für das Initialisierungsskript.
    Wertet CLI-Parameter aus und steuert den Ablauf (Reset, Schema-Init, Testdaten).
    """
    parser = argparse.ArgumentParser(
        description="Initialisiert oder befüllt die VulnProcessing-Datenbank."
    )
    parser.add_argument(
        "--skip-schema",
        action="store_true",
        help="Überspringt das Erstellen der Tabellen (nur Testdaten einfügen).",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Löscht die bestehende Datenbankdatei und erstellt alles neu.",
    )
    args = parser.parse_args()

    # Datenbankpfad aus der Konfigurations-URL extrahieren (sqlite:///...)
    db_path = Path(DATABASE_URL.split("///")[-1])
    data_dir = db_path.parent

    print(f"Datenverzeichnis: {data_dir.resolve()}")
    print(f"Datenbankdatei:   {db_path.name}")

    # Datenbank zurücksetzen (Datei löschen), falls angefordert
    if args.reset and db_path.exists():
        print(f"Lösche bestehende Datenbank: {db_path}")
        db_path.unlink()

    # Datenbankschema initialisieren
    if not args.skip_schema:
        print("Initialisiere Tabellenstruktur...")
        try:
            init_db()
            print("Schema erfolgreich erstellt oder aktualisiert.")
        except Exception as e:
            print(f"CRITICAL: Fehler beim Erstellen des Schemas: {e}")
            return 1
    else:
        print("Information: Schema-Erstellung wurde übersprungen.")

    # Testdaten einfügen
    try:
        insert_test_data()
        print("Vorgang erfolgreich abgeschlossen.")
    except Exception as e:
        print(f"ERROR: Fehler beim Einfügen von Testdaten: {e}")
        return 1

    print("\nDatenbank-Setup ist bereit!")
    return 0


if __name__ == "__main__":
    # Script-Verzeichnis zum Pfad hinzufügen für korrekte Modulauflösung
    sys.exit(main())
