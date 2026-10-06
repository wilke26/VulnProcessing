# ADR-0004: Ticketing tenantbezogen in Batches verarbeiten

- Status: Accepted (reconstructed)
- Ursprünglicher Zeitraum: November 2025
- Rekonstruiert: 2026-10-06
- Vertrauensgrad: High

## Kontext

Findings sollen nicht nur einzeln versendet werden. Der Verarbeitungsstand muss pro
Tenant nachvollziehbar sein, und eine externe Verarbeitung benötigt eine gemeinsame
Bestätigung für die Findings eines Versands.

## Entscheidung

VulnProcessing gruppiert vorbereitete Findings in tenantbezogene Ticket-Batches. Ein
Batch besitzt eine Nummer, einen Status, Findings, Versandzeitpunkte, externe Referenzen
und Bestätigungsinformationen. Ein noch offener Batch blockiert die Erzeugung des
nächsten Batches für denselben Tenant.

Der Dispatch gilt nur als erfolgreich, wenn jedes Finding an jeden aktivierten Client
übertragen wurde. Vollständige Fehler und fehlende Clients führen zu `failed` und geben
die Findings für einen späteren Versuch frei. Teilerfolge führen zum terminalen Zustand
`partially_failed`; bereits erfolgreiche Findings bleiben dem Batch zugeordnet, um eine
blinde Wiederholung mit möglichen Ticket-Duplikaten zu verhindern. Nur ein vollständig
erfolgreicher Dispatch erzeugt einen bestätigbaren `pending`-Batch.

## Konsequenzen

- Tenantgrenzen werden im Datenmodell sichtbar.
- Zustandsübergänge sind Teil der Geschäftslogik und müssen atomar erfolgen.
- Versandfehler, Teilerfolg und fehlende Clients besitzen eindeutige Zustände und
  Erfolgsregeln; eine manuelle Auflösung von `partially_failed` bleibt erforderlich.
- Externe Nebenwirkungen brauchen Idempotenz, da sie nicht gemeinsam mit der Datenbank
  transaktional abgeschlossen werden können.

## Historische Evidenz

- Commit `067c668` vom 18. November 2025 führte `batch_ticketing_service.py`, den
  Ticket-Workflow sowie zugehörige Modelle und Repositories ein.
- Commit `6ec013a` vom 19. November 2025 ergänzte Batch-, Workflow- und API-Tests.
- `app/services/batch_ticketing_service.py`, `app/db/models.py` und
  `app/api/routes_tickets.py` bilden den heutigen Ablauf.
- Die Regeln für Dispatch-Teilfehler wurden bei der Portfolio-Härtung ergänzt; sie sind
  daher eine nachträgliche Entscheidung und keine rekonstruierte historische Vorgabe.
