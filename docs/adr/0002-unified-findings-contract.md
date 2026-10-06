# ADR-0002: Einen einheitlichen Pydantic-Vertrag für Findings verwenden

- Status: Accepted (reconstructed)
- Ursprünglicher Zeitraum: November 2025
- Rekonstruiert: 2026-10-06
- Vertrauensgrad: High

## Kontext

Lywand-Daten können als Roharray oder als versionierter Envelope eintreffen. HTTP-,
Datei- und CLI-Importe benötigen dieselben Feldregeln und eine gemeinsame interne
Repräsentation.

## Entscheidung

Pydantic-v2-Modelle in `app/models/findings.py` sind der kanonische Vertrag. Die
Importpfade akzeptieren Rohlisten und Envelopes, validieren sie über denselben Adapter
und leiten normalisierte Findings an die Intake- und Persistenzschicht weiter. JSON
Schema wird aus den Modellen erzeugt.

## Konsequenzen

- Eingabevalidierung und Schemaartefakte haben eine gemeinsame Quelle.
- Neue Felder oder Invarianten müssen im Modell und in den Kompatibilitätstests landen.
- HTTP-Größen- und Anzahlgrenzen sind zusätzliche Laufzeitkontrollen und nicht Teil des
  fachlichen Schemas.
- Parallel bestehende ältere Intake-Pfade müssen denselben Vertrag respektieren oder
  konsolidiert werden.

## Historische Evidenz

- Die ersten Commits `c01ff28` und `811e948` vom 10. November 2025 enthalten bereits
  `app/models/findings.py` und die anfängliche Projektstruktur.
- `app/api/routes_import.py`, `app/services/intake.py` und `scripts/import_file.py`
  verwenden den gemeinsamen Vertrag.
- Tests unter `tests/unit` und `tests/integration` belegen Rohlisten- und Envelope-Fälle.
- Nicht erhalten ist, welche alternativen Schemaansätze ursprünglich erwogen wurden.
