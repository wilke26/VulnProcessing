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

## Konsequenzen

- Tenantgrenzen werden im Datenmodell sichtbar.
- Zustandsübergänge sind Teil der Geschäftslogik und müssen atomar erfolgen.
- Versandfehler, Teilerfolg, Wiederholung und fehlende Clients benötigen eindeutige
  Zustände und Erfolgsregeln.
- Externe Nebenwirkungen brauchen Idempotenz, da sie nicht gemeinsam mit der Datenbank
  transaktional abgeschlossen werden können.

## Historische Evidenz

- Commit `067c668` vom 18. November 2025 führte `batch_ticketing_service.py`, den
  Ticket-Workflow sowie zugehörige Modelle und Repositories ein.
- Commit `6ec013a` vom 19. November 2025 ergänzte Batch-, Workflow- und API-Tests.
- `app/services/batch_ticketing_service.py`, `app/db/models.py` und
  `app/api/routes_tickets.py` bilden den heutigen Ablauf.
- Die ursprünglichen fachlichen Regeln für Teilfehler sind nicht vollständig erhalten
  und im heutigen Code noch nicht abschließend modelliert.
