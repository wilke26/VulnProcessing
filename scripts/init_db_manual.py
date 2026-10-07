"""
Initialisiert die VulnProcessing-SQLite-Datenbank manuell ohne Verwendung von
SQLAlchemy oder Alembic.

Dieses Hilfsprogramm ist für Umgebungen gedacht, in denen keine ORM-Bibliotheken
zur Verfügung stehen. Es nutzt das Standard-Python-Modul 'sqlite3', um das
Datenbankschema über native SQL-Befehle zu erstellen.
Das hier definierte Schema ist identisch mit den SQLAlchemy-Modellen in 'app/db/models.py'.

Optionale Funktionen:
- Zurücksetzen der Datenbank (Löschen der bestehenden Datei).
- Einfügen eines initialen Satzes von Testdaten.

Verwendung:
    python scripts/init_db_manual.py [--reset]
"""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

# Basisverzeichnis des Projekts und Standardpfad zur Datenbank
BASE_DIR = Path(__file__).resolve().parents[1]
DB_PATH = BASE_DIR / "data" / "vulnprocessing.sqlite3"


def create_schema(conn: sqlite3.Connection) -> None:
    """
    Erzeugt alle erforderlichen Tabellen, Indizes und Constraints für die Anwendung.

    Args:
        conn (sqlite3.Connection): Eine aktive Verbindung zur SQLite-Datenbank.
    """
    cursor = conn.cursor()

    # Sicherstellen, dass Foreign Key Constraints in SQLite beachtet werden
    cursor.execute("PRAGMA foreign_keys=ON")

    # Tabelle für Mandanten (Tenants)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tenant (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            created_at DATETIME DEFAULT (datetime('now'))
        )
        """)

    # Tabelle für Assets (Geräte/Hosts)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS asset (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            kind TEXT,
            metadata_json TEXT,
            created_at DATETIME DEFAULT (datetime('now')),
            FOREIGN KEY(tenant_id) REFERENCES tenant(id) ON DELETE CASCADE,
            UNIQUE (tenant_id, name)
        )
        """)

    # Tabelle für Produkte
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS product (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            created_at DATETIME DEFAULT (datetime('now'))
        )
        """)

    # Tabelle für CVE-Stammdaten
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cve (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL UNIQUE,
            description TEXT,
            severity TEXT,
            created_at DATETIME DEFAULT (datetime('now'))
        )
        """)

    # Tabelle zur Überwachung von Importvorgängen
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS import_run (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            source TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            total_records INTEGER DEFAULT 0,
            successful_records INTEGER DEFAULT 0,
            failed_records INTEGER DEFAULT 0,
            error_message TEXT,
            started_at DATETIME DEFAULT (datetime('now')),
            completed_at DATETIME,
            FOREIGN KEY(tenant_id) REFERENCES tenant(id) ON DELETE CASCADE
        )
        """)

    # Tabelle für die Batch-Verarbeitung von Tickets
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ticket_batch (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            batch_number INTEGER NOT NULL,
            status TEXT DEFAULT 'created',
            total_findings INTEGER DEFAULT 0,
            successful_tickets INTEGER DEFAULT 0,
            failed_tickets INTEGER DEFAULT 0,
            external_batch_id TEXT,
            confirmation_token_hash TEXT,
            target_system TEXT DEFAULT '',
            created_at DATETIME DEFAULT (datetime('now')),
            sent_at DATETIME,
            completed_at DATETIME,
            retry_count INTEGER DEFAULT 0,
            last_error TEXT,
            FOREIGN KEY(tenant_id) REFERENCES tenant(id) ON DELETE CASCADE,
            UNIQUE (tenant_id, batch_number)
        )
        """)

    # Haupttabelle für Findings (Sicherheitsergebnisse)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS finding (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            asset_id INTEGER NOT NULL,
            import_id INTEGER,
            name TEXT NOT NULL,
            cve_id TEXT,
            risk REAL NOT NULL,
            amount INTEGER NOT NULL,
            target TEXT NOT NULL,
            ticket_target TEXT,
            windows_version_hint TEXT DEFAULT '',
            extended_solution_json TEXT NOT NULL,
            priority_score REAL,
            status TEXT DEFAULT 'new',
            first_seen DATETIME DEFAULT (datetime('now')),
            last_seen DATETIME DEFAULT (datetime('now')),
            created_at DATETIME DEFAULT (datetime('now')),
            updated_at DATETIME DEFAULT (datetime('now')),
            batch_id INTEGER,
            ticket_external_id TEXT,
            ticket_url TEXT,
            ticket_created_at DATETIME,
            ticket_confirmed_at DATETIME,
            FOREIGN KEY(tenant_id) REFERENCES tenant(id) ON DELETE CASCADE,
            FOREIGN KEY(asset_id) REFERENCES asset(id) ON DELETE CASCADE,
            FOREIGN KEY(import_id) REFERENCES import_run(id) ON DELETE SET NULL,
            FOREIGN KEY(batch_id) REFERENCES ticket_batch(id) ON DELETE SET NULL,
            UNIQUE (tenant_id, asset_id, name, target),
            CHECK (risk >= 0.0 AND risk <= 10.0),
            CHECK (amount >= 1)
        )
        """)

    # Zuordnung Finding <-> Produkt (Many-to-Many)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS finding_product (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT (datetime('now')),
            FOREIGN KEY(finding_id) REFERENCES finding(id) ON DELETE CASCADE,
            FOREIGN KEY(product_id) REFERENCES product(id) ON DELETE CASCADE,
            UNIQUE (finding_id, product_id)
        )
        """)

    # Zuordnung Finding <-> CVE (Many-to-Many)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS finding_cve (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER NOT NULL,
            cve_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT (datetime('now')),
            FOREIGN KEY(finding_id) REFERENCES finding(id) ON DELETE CASCADE,
            FOREIGN KEY(cve_id) REFERENCES cve(id) ON DELETE CASCADE,
            UNIQUE (finding_id, cve_id)
        )
        """)

    # Tabelle für Einzel-Tickets
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ticket (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER NOT NULL,
            external_id TEXT NOT NULL,
            status TEXT DEFAULT 'open',
            url TEXT,
            created_at DATETIME DEFAULT (datetime('now')),
            updated_at DATETIME DEFAULT (datetime('now')),
            FOREIGN KEY(finding_id) REFERENCES finding(id) ON DELETE CASCADE
        )
        """)

    # Tabelle für das Audit-Log (Änderungshistorie)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            old_values TEXT,
            new_values TEXT,
            created_at DATETIME DEFAULT (datetime('now')),
            FOREIGN KEY(tenant_id) REFERENCES tenant(id) ON DELETE CASCADE
        )
        """)

    conn.commit()


def insert_test_data(conn: sqlite3.Connection) -> None:
    """
    Fügt einen minimalen Satz an Beispieldaten für Tests ein.

    Args:
        conn (sqlite3.Connection): Eine aktive Verbindung zur SQLite-Datenbank.
    """
    cursor = conn.cursor()

    # Doppeltes Einfügen verhindern
    cursor.execute("SELECT id FROM tenant WHERE name = ?", ("test-tenant",))
    if cursor.fetchone():
        print("Testdaten existieren bereits, überspringe Einfügen.")
        return

    # 1. Mandant
    cursor.execute("INSERT INTO tenant (name) VALUES (?)", ("test-tenant",))
    tenant_id = cursor.lastrowid

    # 2. Asset
    cursor.execute(
        "INSERT INTO asset (tenant_id, name, kind) VALUES (?, ?, ?)",
        (tenant_id, "test-asset", "server"),
    )
    asset_id = cursor.lastrowid

    # 3. Importlauf
    cursor.execute(
        """
        INSERT INTO import_run (
            tenant_id, source, status, total_records,
            successful_records, failed_records
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (tenant_id, "test-source", "completed", 1, 1, 0),
    )
    import_id = cursor.lastrowid

    # 4. Finding
    cursor.execute(
        """
        INSERT INTO finding (
            tenant_id, asset_id, import_id, name, risk, amount,
            target, windows_version_hint, extended_solution_json, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            tenant_id,
            asset_id,
            import_id,
            "Test Finding",
            5.5,
            2,
            "localhost",
            "Windows 10",
            '["Patchen über KB123456", "Antivirus aktualisieren"]',
            "new",
        ),
    )
    finding_id = cursor.lastrowid

    conn.commit()

    print(f"Erstellt: Mandant 'test-tenant' (ID: {tenant_id})")
    print(f"Erstellt: Asset 'test-asset' (ID: {asset_id})")
    print(f"Erstellt: Finding 'Test Finding' (ID: {finding_id})")


def main() -> int:
    """
    Hauptfunktion zur Steuerung des Setups.
    """
    parser = argparse.ArgumentParser(
        description="Initialisiert die VulnProcessing-Datenbank über native SQL-Befehle."
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Löscht die bestehende Datenbankdatei vor dem Erstellen des Schemas.",
    )
    args = parser.parse_args()

    # Sicherstellen, dass der Datenordner existiert
    db_dir = DB_PATH.parent
    db_dir.mkdir(parents=True, exist_ok=True)

    # Datenbank zurücksetzen, falls gewünscht
    if args.reset and DB_PATH.exists():
        print(f"Lösche bestehende Datenbankdatei: {DB_PATH}")
        DB_PATH.unlink()

    # Verbindung zur SQLite-Datenbank herstellen
    conn = sqlite3.connect(DB_PATH)

    try:
        print("Erstelle Tabellenstruktur...")
        create_schema(conn)
        print("Schema erfolgreich erstellt.")

        print("Füge initiale Testdaten hinzu...")
        insert_test_data(conn)
        print("Testdaten erfolgreich eingefügt.")
    except Exception as e:
        print(f"CRITICAL: Fehler während der Datenbank-Initialisierung: {e}")
        return 1
    finally:
        conn.close()

    print("\nManueller Datenbank-Setup abgeschlossen!")
    return 0


if __name__ == "__main__":
    # Script beenden und Exit-Code an das OS übergeben
    raise SystemExit(main())
