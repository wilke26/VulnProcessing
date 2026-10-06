"""
CLI-Skript zum Importieren von Sicherheitsfindings aus einer JSON-Datei in die Datenbank.

Das Skript unterstützt sowohl einfache JSON-Arrays von Findings als auch das
strukturierte Envelope-Format (v1). Es validiert die Daten gegen das Pydantic-Schema,
bevor sie persistiert werden.

Verwendung:
    python -m scripts.import_file <pfad_zur_json_datei>
"""

import argparse
import json
from pathlib import Path

from pydantic import TypeAdapter, ValidationError

from app.db import init_db
from app.models.findings import Finding, UnifiedFindingsInput
from app.services.db_intake import save_findings

# Pydantic-Adapter für die Unterstützung von flachen Listen oder Envelopes
adapter = TypeAdapter(UnifiedFindingsInput)


def main() -> None:
    """
    Hauptfunktion zur Steuerung des CLI-Imports.
    Wertet Argumente aus, liest die Datei, validiert sie und speichert die Daten.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Importiert Sicherheitsergebnisse aus einer JSON-Datei "
            "(Array oder Envelope) in die Datenbank."
        )
    )
    parser.add_argument("file", help="Der Pfad zur zu importierenden JSON-Datei.")
    args = parser.parse_args()

    # Initialisierung der Datenbank-Infrastruktur (Tabellen anlegen, falls nötig)
    init_db()

    path = Path(args.file)
    if not path.exists():
        raise SystemExit(f"Fehler: Die Datei '{path}' wurde nicht gefunden.")

    # Dateiinhalt einlesen und JSON parsen
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise SystemExit(f"Fehler beim Lesen oder Parsen der JSON-Datei: {e}") from e

    # Pydantic-Validierung gegen das UnifiedFindingsInput Modell
    try:
        parsed = adapter.validate_python(data)
    except ValidationError as e:
        # Detaillierte Fehlermeldung bei Schema-Verletzungen
        raise SystemExit(f"Schema-Validierung fehlgeschlagen:\n{e}") from e

    # Normalisierung der Daten zu einer Liste von Finding-Objekten
    findings: list[Finding]
    if isinstance(parsed, list):
        # Fall: Direktes Array
        findings = parsed
    else:
        # Fall: Envelope (items-Attribut extrahieren)
        findings = parsed.items  # type: ignore[attr-defined]

    # Speichern der Findings in der Datenbank (inkl. Deduplizierung)
    try:
        count = save_findings(findings)
        print(f"Import abgeschlossen: {count} Einträge wurden erfolgreich verarbeitet.")
    except Exception as e:
        raise SystemExit(f"Ein Fehler ist während der Persistierung aufgetreten: {e}") from e


if __name__ == "__main__":
    main()
