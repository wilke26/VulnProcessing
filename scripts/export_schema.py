"""
Hilfsskript zum Exportieren der Pydantic-Modell-Schemas als JSON-Dateien.

Dieses Skript generiert JSON-Schema-Dateien für die Finding-Modelle (Rohformat und Envelope),
die zur Validierung externer Datenquellen oder für die Dokumentation verwendet werden können.
Die exportierten Dateien werden im Verzeichnis './schema' abgelegt.
"""

import json
from pathlib import Path

from pydantic import TypeAdapter

# Importieren der v2-konformen Modelle
from app.models.findings import FindingsEnvelope, FindingsInput


def write_schema(obj, out_path: Path) -> None:
    """
    Generiert ein JSON-Schema für ein gegebenes Pydantic-Objekt und schreibt es in eine Datei.

    Args:
        obj: Das Pydantic-Modell oder der Typ (z.B. FindingsInput).
        out_path (Path): Der Zielpfad für die JSON-Datei.
    """
    # TypeAdapter zur Generierung des Schemas verwenden
    adapter = TypeAdapter(obj)
    schema = adapter.json_schema()

    # Sicherstellen, dass das Zielverzeichnis existiert
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Schema-Daten serialisieren und in Datei schreiben
    out_path.write_text(json.dumps(schema, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Schema erfolgreich exportiert nach: {out_path.resolve()}")


def main() -> None:
    """
    Hauptfunktion des Skripts. Definiert die zu exportierenden Modelle und Zielpfade.
    """
    out_dir = Path("./schema")

    # Export des Schemas für die einfache Liste von Findings (Legacy/Raw)
    write_schema(FindingsInput, out_dir / "lywand_findings_raw_v1.schema.json")

    # Export des Schemas für das strukturierte Envelope-Format (v1)
    write_schema(FindingsEnvelope, out_dir / "lywand_findings_envelope_v1.schema.json")


if __name__ == "__main__":
    main()
