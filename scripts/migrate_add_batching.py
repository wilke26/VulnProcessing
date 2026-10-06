"""
Migrations-Skript zum Hinzufügen der Batch-Funktionalität zur bestehenden Datenbank.

Dieses Skript aktualisiert das Datenbankschema, um die Gruppierung von Findings in Ticket-Batches
zu ermöglichen. Es stellt sicher, dass alle erforderlichen Tabellen vorhanden sind und bringt
bestehende Datensätze in einen konsistenten Status.

Durchgeführte Schritte:
1. Initialisierung/Aktualisierung der Tabellenstruktur über SQLAlchemy.
2. Normalisierung des Statusfeldes für bestehende Findings.
"""

from sqlalchemy import text

from app.db.engine import engine, init_db


def run_migration() -> None:
    """
    Führt die notwendigen Datenbank-Migrationen für das Batch-System aus.
    """
    print("Starte Datenbank-Migration für die Batch-Funktionalität...")

    # 1. Sicherstellen, dass die neuen Tabellen (ticket_batch) existieren
    try:
        init_db()
        print("✓ Datenbanktabellen wurden erstellt oder sind bereits aktuell.")
    except Exception as e:
        print(f"Fehler bei der Initialisierung der Tabellen: {e}")
        return

    # 2. Bestehende Daten bereinigen und für das neue System vorbereiten
    try:
        with engine.connect() as conn:
            # Findings ohne Status oder mit leerem Status auf 'new' setzen
            result = conn.execute(
                text("UPDATE finding SET status = 'new' WHERE status IS NULL OR status = ''")
            )
            conn.commit()
            print(f"✓ {result.rowcount} bestehende Findings wurden auf Status 'new' gesetzt.")
    except Exception as e:
        print(f"Fehler bei der Datenaktualisierung: {e}")
        return

    print("Migration erfolgreich abgeschlossen!")


if __name__ == "__main__":
    run_migration()
