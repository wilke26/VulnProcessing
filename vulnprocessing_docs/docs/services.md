---
title: Services
---

# Services

Die Service‑Klassen kapseln Geschäftslogik und orchestrieren die Verarbeitungsschritte innerhalb des VulnProcessing‑Projekts. Sie sind in `app/services/` implementiert und werden über die Repository‑Schicht sowie externe Connectoren unterstützt.

## EnrichmentService

Der `EnrichmentService` ist verantwortlich für die Anreicherung von Findings mit zusätzlichen Daten aus der **National Vulnerability Database (NVD)**. Er ruft für jede CVE‑ID die entsprechenden Metadaten ab (CVSS‑Scores, Beschreibung, Referenzen) und speichert diese in der Datenbank. Dabei wird ein Cache verwendet, um Mehrfachabfragen zu vermeiden. Der Service bietet Methoden zum Laden von CVE‑IDs, zum Bauen von Enrichment‑Objekten und zur Normalisierung der CVSS‑Version.

## DeduplicationService

Findings können in unterschiedlichen Importen mehrfach auftreten. Der `DeduplicationService` führt diese zusammen, wenn sie sich auf denselben Tenant, Asset, Namen und Target beziehen. Dabei werden Risikowerte aggregiert, die Anzahl betroffener Systeme angepasst und die Produkt‑ und CVE‑Referenzen zusammengeführt. Außerdem ermittelt der Service den Status (neu, bekannt, behoben).

## PrioritizationService

Der `PrioritizationService` ermittelt für jedes Finding einen Prioritätswert. Dieser basiert auf dem CVSS Base Score, der Kritikalität der betroffenen Produkte, der Anzahl betroffener Systeme sowie dem Enrichment‑Status. Die Gewichtung kann über eine YAML‑Konfigurationsdatei angepasst werden. Ein höherer `priority_score` führt zu einer schnelleren Abarbeitung der Schwachstelle.

## TicketPreparationService

Der `TicketPreparationService` orchestriert mehrere Verarbeitungsschritte, um eine Liste von Findings für die Ticketerstellung vorzubereiten. Die Schritte sind als Pipeline konzipiert und werden per Composition Root zusammengesetzt. Standardmaessig umfasst der Ablauf:

1. **Patch‑Filterung:** Mit Hilfe des `WindowsPatchFilter` und des `NCentralClient` wird überprüft, ob ein Finding bereits durch einen installierten Patch behoben ist.
2. **Enrichment:** Laden zusätzlicher CVE‑Daten.
3. **Deduplizierung:** Zusammenführen doppelter Findings.
4. **Priorisierung:** Ermitteln der Prioritätswerte für die verbleibenden Findings.

Der Service liefert eine Liste priorisierter Findings und mappt die Prioritaetswerte zurueck auf die SQL‑Objekte.

## BatchTicketingService

Der `BatchTicketingService` erstellt Ticket‑Batches aus priorisierten Findings und kann diese an konfigurierte Ticket‑Clients dispatchen. Dazu wird pro Tenant und Zielsystem ein neuer `TicketBatch` angelegt. Der Batch‑Status (`created`, `pending`, `processing`, `completed`, `failed`, `partially_failed`, `partially_completed`) sowie Erfolgs‑ und Fehlermeldungen werden dokumentiert. Nur vollständig erfolgreiche Dispatches werden `pending`. Ein vollständiger Fehler gibt Findings für einen späteren Versuch frei; ein Teilerfolg bleibt zur manuellen Auflösung terminal, damit bereits erzeugte Tickets nicht dupliziert werden.

## TicketDispatcher

Der `TicketDispatcher` sendet Findings an konfigurierte Ticket‑Clients. Er arbeitet gegen ein schmales Interface (`TicketClient`) und wird über eine Registry aufgebaut. E‑Mail‑ und REST‑Clients sind über Feature‑Flags aktivierbar. Das Ergebnis enthält für jede Kombination aus Finding und aktivem Client einen erfolgreichen oder fehlgeschlagenen Versuch.

## Retry-Konfiguration

Externe API-Clients nutzen Retry-Logik mit folgenden Settings:
- `RETRY_ATTEMPTS`
- `RETRY_MIN_SECONDS`
- `RETRY_MAX_SECONDS`

## Logging JSON Schema (structlog)

Wenn `STRUCTLOG_JSON=1` gesetzt ist, werden Logs als JSON ausgegeben. Typische Felder:
- `timestamp`
- `level`
- `event`
- `logger`
- `request_id`
- `pid`
- `thread`

## Ticketing API (Kurz)

- `POST /tickets/dispatch`: Dispatcht offene Findings an konfigurierte Clients. Optional `dry_run=true`.
- `POST /tickets/batch/{id}/dispatch`: Dispatcht einen vorbereiteten Batch.

## RemediationService

Der `RemediationService` stellt für Findings automatisierte Lösungsvorschläge bereit. Dafür wird ein externer AI‑Dienst (Copilot Studio) genutzt. Der Service generiert **Remediation Guides** und cachet diese mit einer definierbaren TTL. So wird vermieden, dass identische Anfragen mehrfach gestellt werden. Er bietet Methoden zum Abrufen von Guides für einzelne oder mehrere Findings.

## WindowsPatchFilter

Dieser Service prüft über den `NCentralClient`, ob auf einem Asset bereits ein Windows‑Patch für das betroffene KB‑Update installiert ist. Ist dies der Fall, wird das Finding herausgefiltert. Er bietet Methoden, um KB‑Nummern aus Lösungshinweisen zu extrahieren und Assets zu filtern.

---

Weitere Services (z. B. Ticket‑Vorlagen, E‑Mail‑Benachrichtigungen) können in zukünftigen Versionen ergänzt werden. Details zu ihren Methoden und Parametern finden sich in der API‑Referenz oder im Quellcode.
