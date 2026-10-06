"""
Unit-Tests für die Datenbank-Basisfunktionen.
Prüft die Initialisierung und Verbindung zur SQLite-Datenbank.
"""

import os
import time

from app.db.database import DB_PATH, init_db


def test_init_db_creates_file():
    """
    Stellt sicher, dass init_db() die Datenbankdatei erstellt.
    """
    # Sicherstellen, dass die Engine keine offenen Verbindungen hält
    # Importieren der Engine hier lokal, um Seiteneffekte zu minimieren
    from app.db.engine import engine

    engine.dispose()

    # Sicherstellen, dass die Datei nicht existiert
    if DB_PATH.exists():
        # Versuche mehrmals zu löschen, falls die Datei noch gesperrt ist (Windows Problem)
        for _ in range(5):
            try:
                os.remove(DB_PATH)
                break
            except PermissionError:
                time.sleep(0.1)

    init_db()
    assert DB_PATH.exists()
