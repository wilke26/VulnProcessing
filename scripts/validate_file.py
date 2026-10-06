"""
CLI-Tool zur Validierung und Normalisierung von Finding-JSON-Dateien.

Dieses Skript überprüft, ob eine JSON-Datei dem definierten Data Contract entspricht.
Es unterstützt sowohl das Roh-Array-Format als auch das strukturierte Envelope-Format (v1).
Bei erfolgreicher Validierung können die Findings in ein einheitliches Listenformat
normalisiert und optional ausgegeben werden.

Verwendung:
    python scripts/validate_file.py <pfad_zur_json> [--dump-normalized]
"""

import argparse
import json
import sys
from pathlib import Path
from typing import cast

from pydantic import TypeAdapter, ValidationError

from app.models.findings import (
    Finding,
    FindingsEnvelope,  # Struktur: { schema_version, source, generated_at, items: [...] }
    FindingsInput,  # Struktur: List[Finding]
)

# TypeAdapter zur Unterstützung polymorpher Eingaben (Envelope oder flache Liste)
UnifiedAdapter = TypeAdapter(FindingsEnvelope | FindingsInput)


def load_and_normalize(path: Path) -> list[Finding]:
    """
    Lädt eine JSON-Datei, validiert sie gegen den Data Contract und normalisiert das Ergebnis.

    Unabhängig davon, ob die Eingabe ein Envelope oder ein einfaches Array ist,
    gibt diese Funktion immer eine flache Liste von Finding-Objekten zurück.

    Args:
        path (Path): Pfad zur JSON-Datei.

    Returns:
        list[Finding]: Eine Liste validierter Finding-Objekte.
    """
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    # Validierung gegen die kombinierte Typ-Definition
    parsed = UnifiedAdapter.validate_python(data)

    # Normalisierungsschritt
    if isinstance(parsed, list):
        # Fall: Eingabe war bereits ein flaches Array
        return parsed
    else:
        # Fall: Eingabe war ein Envelope -> 'items' extrahieren
        env = cast(FindingsEnvelope, parsed)
        return env.items


def main() -> int:
    """
    Hauptfunktion des Validierungs-Tools.
    Wertet CLI-Argumente aus und behandelt potenzielle Fehler bei Dateizugriff oder Validierung.
    """
    parser = argparse.ArgumentParser(
        description="Validiert eine Finding-JSON-Datei (Array oder Envelope v1) gegen das Schema."
    )
    parser.add_argument("file", help="Pfad zur zu validierenden JSON-Datei.")
    parser.add_argument(
        "--dump-normalized",
        action="store_true",
        help="Gibt die normalisierten Findings als JSON-Liste auf der Standardausgabe aus.",
    )
    args = parser.parse_args()

    path = Path(args.file)

    try:
        findings = load_and_normalize(path)
    except FileNotFoundError:
        print(f"Fehler: Datei nicht gefunden: {path}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as e:
        print(f"Fehler: Ungültiges JSON-Format in {path}: {e}", file=sys.stderr)
        return 3
    except ValidationError as e:
        # Detaillierte Pydantic-Validierungsfehler ausgeben
        print(f"Fehler: Schema-Validierung fehlgeschlagen für {path}:\n{e}\n", file=sys.stderr)
        return 4
    except Exception as e:
        print(f"Unerwarteter Fehler: {e}", file=sys.stderr)
        return 5

    # Erfolgsmeldung bei bestandener Validierung
    print(f"Erfolg: '{path}' ist valide und enthält {len(findings)} Findings.")

    if args.dump_normalized:
        # Normalisierte Daten für die Weiterverarbeitung (z.B. in Pipes) ausgeben
        # Wir nutzen model_dump(), um saubere Dictionaries für die JSON-Serialisierung zu erhalten
        out = [f.model_dump() for f in findings]
        json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
        print()  # Abschließender Zeilenumbruch

    return 0


if __name__ == "__main__":
    # Beenden mit entsprechendem Exit-Code
    sys.exit(main())
