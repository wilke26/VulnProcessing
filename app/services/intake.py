"""
Dieses Modul stellt High-Level-Funktionen für den Intake-Prozess von Findings bereit.
Es übernimmt das Laden von JSON-Dateien, die Validierung gegen Pydantic-Modelle
und die Normalisierung von verschiedenen Eingabeformaten (Raw-Array oder Envelope).
"""

import json
from typing import Any, cast

from pydantic import TypeAdapter

from app.models.findings import (
    Finding,
    FindingsEnvelope,
    UnifiedFindingsInput,
)

# Pydantic-Adapter zur Unterstützung von polymorphen Eingaben (Liste oder Envelope)
adapter = TypeAdapter(UnifiedFindingsInput)


def load_any(path: str) -> list[Finding]:
    """
    Lädt Findings aus einer JSON-Datei, unabhängig vom Format.

    Unterstützt sowohl eine flache Liste von Findings als auch das
    strukturierte Envelope-Format (v1).

    Args:
        path (str): Der Dateipfad zur JSON-Datei.

    Returns:
        list[Finding]: Eine Liste von validierten Finding-Objekten.
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    parsed = adapter.validate_python(data)

    if isinstance(parsed, list):
        # Fall: JSON enthält direkt ein Array von Findings
        return parsed
    else:
        # Fall: JSON enthält ein FindingsEnvelope-Objekt
        return cast(FindingsEnvelope, parsed).items


def load_and_store(path: str) -> int:
    """
    Convenience-Funktion zum Laden und sofortigen Persistieren von Findings.

    Diese Funktion liest die Datei ein, validiert den Inhalt und stößt den
    vollständigen Datenbank-Intake-Workflow (inkl. Protokollierung) an.

    Args:
        path (str): Der Dateipfad zur JSON-Datei.

    Returns:
        int: Die Anzahl der erfolgreich importierten Findings.
    """
    from app.services.db_intake import intake_findings

    # Rohdaten einlesen
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    # In das einheitliche Eingabemodell parsen
    unified = adapter.validate_python(data)

    # In die Datenbank überführen (inkl. Deduplizierung, Tenant-Anlage etc.)
    return intake_findings(unified)


def validate_data(data: Any) -> list[Finding]:
    """
    Validiert beliebige Python-Daten (z.B. aus einem API-Request) gegen die
    Finding-Modelle und normalisiert sie in eine Liste.

    Args:
        data (Any): Die zu validierenden Daten (dict oder list).

    Returns:
        list[Finding]: Eine Liste von validierten Finding-Objekten.
    """
    parsed = adapter.validate_python(data)
    if isinstance(parsed, list):
        return parsed
    else:
        return list(cast(FindingsEnvelope, parsed).items)


def normalize_unified_input(data: Any) -> tuple[str, list[Finding]]:
    """
    Validiert Daten und extrahiert zusätzlich die Datenquelle (Source).

    Dies ist nützlich für die Protokollierung von Import-Läufen, um festzustellen,
    woher die Daten stammen (z.B. "lywand").

    Args:
        data (Any): Die zu validierenden Daten.

    Returns:
        tuple[str, list[Finding]]: Ein Tupel aus (Datenquelle, Liste der Findings).
    """
    parsed = adapter.validate_python(data)
    if isinstance(parsed, list):
        # Standard-Quelle für einfache Listen-Eingaben
        return "lywand", parsed

    env = cast(FindingsEnvelope, parsed)
    return env.source, list(env.items)
