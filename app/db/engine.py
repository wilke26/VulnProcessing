"""
Dieses Modul konfiguriert die SQLAlchemy-Engine und die Session-Fabrik.
Es enthält zudem Initialisierungslogik für das Datenbankschema.
"""

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings

from .models import Base

# Erstellen der SQLAlchemy-Engine
# 'check_same_thread': False ist für SQLite in Verbindung mit FastAPI (Multithreading) erforderlich.
engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False},
)


# Event-Listener für SQLite, um Foreign Key Constraints zu aktivieren,
# da diese in SQLite standardmäßig oft deaktiviert sind.
@event.listens_for(engine, "connect")
def _fk_pragma_on_connect(dbapi_con, con_record):
    """
    Aktiviert Foreign Keys für jede neue SQLite-Verbindung.
    """
    cursor = dbapi_con.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


# Konfiguration der Session-Fabrik
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def get_db():
    """
    Generator für Datenbank-Sessions (Dependency Injection).
    """
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """
    Erstellt alle in 'models.py' definierten Tabellen in der Datenbank,
    sofern sie noch nicht existieren.
    """
    Base.metadata.create_all(bind=engine)
