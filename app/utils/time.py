"""
Hilfsfunktionen für die Zeit- und Datumsverarbeitung.
Stellt sicher, dass Zeitstempel konsistent im UTC-Format generiert werden.
"""

from datetime import UTC, datetime


def now_utc() -> datetime:
    """
    Gibt den aktuellen Zeitpunkt als Aware-Datetime-Objekt in UTC zurück.

    Returns:
        datetime: Aktueller Zeitstempel in UTC.
    """
    return datetime.now(UTC)
