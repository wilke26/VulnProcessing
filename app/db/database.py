"""
Dieses Modul bietet Hilfsfunktionen für den Zugriff auf die SQLite-Datenbank.
Es enthält sowohl direkte SQLite-Verbindungs-Helper als auch SQLAlchemy-Session-Provider.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from sqlite3 import Connection

from sqlalchemy.orm import Session

from app.db.engine import SessionLocal

# Standard-Pfad zur SQLite-Datenbankdatei
DB_PATH = Path("./data/vulnprocessing.sqlite3")


def init_db() -> None:
    """
    Initialisiert die Datenbank-Infrastruktur und erstellt Basistabellen,
    falls diese noch nicht existieren.
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        cur = conn.cursor()
        # Beispiel-Schema für die Tabelle "findings" (Legacy/Direct SQLite)
        cur.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    tenant TEXT NOT NULL,
                    risk REAL NOT NULL,
                    amount INTEGER NOT NULL,
                    target TEXT NOT NULL,
                    windows_version_hint TEXT DEFAULT '',
                    products_json TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(name, tenant, target)
                );
            """)
        conn.commit()


def _connect() -> Connection:
    """
    Erstellt eine neue Verbindung zur SQLite-Datenbank.

    Returns:
        Connection: Eine sqlite3 Connection-Instanz.
    """
    return sqlite3.connect(DB_PATH.as_posix())


@contextmanager
def get_conn() -> Iterator[Connection]:
    """
    Kontextmanager für direkte SQLite-Datenbank-Verbindungen.
    Handhabt Commits bei Erfolg und Rollbacks im Fehlerfall automatisch.

    Yields:
        Iterator[Connection]: Eine aktive SQLite-Verbindung.
    """
    conn = _connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_db() -> Iterator[Session]:
    """
    FastAPI-Dependency, die eine SQLAlchemy-Datenbank-Session bereitstellt.
    Stellt sicher, dass die Session nach der Verwendung geschlossen wird.

    Yields:
        Iterator[Session]: Eine SQLAlchemy-Session für Datenbankoperationen.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
