"""
Unit-Tests für das Unit-of-Work (UoW) Pattern.
Validiert das transaktionale Verhalten des UnitOfWork-Kontextmanagers,
insbesondere die automatischen Commits bei Erfolg und Rollbacks im Fehlerfall.
"""

from unittest.mock import MagicMock, patch

from sqlalchemy import create_engine

from app.db.models import Base
from app.db.repository import UnitOfWork


def test_uow_context_manager_commit():
    """
    Testet, ob das UnitOfWork bei erfolgreicher Ausführung des Blocks einen Commit durchführt.
    """
    # In-Memory Datenbank für den Test vorbereiten
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)

    # SessionLocal patchen, um die Interaktion mit der Datenbank-Session zu prüfen
    with patch("app.db.repository.SessionLocal") as mock_session_local:
        mock_session = MagicMock()
        mock_session_local.return_value = mock_session

        # Act: Erfolgreicher Block innerhalb des Kontextmanagers
        with UnitOfWork():
            pass  # Simuliert erfolgreiche Verarbeitung

        # Assert: Commit und Schließen der Session verifizieren
        mock_session.commit.assert_called_once()
        mock_session.close.assert_called_once()


def test_uow_context_manager_rollback_on_error():
    """
    Stellt sicher, dass das UnitOfWork bei einer Exception innerhalb des Blocks
    ein Rollback durchführt, um die Datenintegrität zu wahren.
    """
    with patch("app.db.repository.SessionLocal") as mock_session_local:
        mock_session = MagicMock()
        mock_session_local.return_value = mock_session

        # Act: Block mit absichtlichem Fehler
        try:
            with UnitOfWork():
                raise ValueError("test error")
        except ValueError:
            # Fehler abfangen, um den Test nicht abbrechen zu lassen
            pass

        # Assert: Rollback und anschließendes Schließen der Session prüfen
        mock_session.rollback.assert_called_once()
        mock_session.close.assert_called_once()
