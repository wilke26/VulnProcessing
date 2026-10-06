# Data Contract

Die Lywand-Vorfilterung liefert pro Verarbeitungslauf JSON-Daten, welche Findings enthalten.  
Damit diese Daten reproduzierbar, versionierbar und automatisiert validierbar verarbeitet werden können, wird der Datenaustausch durch einen Data Contract formal beschrieben.

## Motivation

* Ein Data Contract schafft eine eindeutige, maschinenlesbare Schnittstelle.
* Änderungen an Feldern oder Struktur werden eindeutig versioniert.
* Fehler im Input werden früh erkannt und niemals „still“ ignoriert.
* Code und Schema werden aus einer einzigen Quelle generiert (Single Source of Truth).

## Format

Im aktuellen Stand unterstützt die Anwendung zwei Formen der Eingabe:

| Format  | Beschreibung | Zweck |
|---------|--------------|-------|
| Raw     | historisches Format: ein reines JSON-Array von Findings | abwärtskompatibel |
| Envelope v1 | objekt-basiert: enthält zusätzlich `schema_version`, `source`, `generated_at`, `items` | zukünftiger Standard |

Beispiel Envelope v1:

```json
{
  "schema_version": 1,
  "source": "lywand",
  "generated_at": "2025-11-07T08:30:00Z",
  "items": [ { … Finding … } ]
}
