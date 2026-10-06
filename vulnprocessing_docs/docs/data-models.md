---
title: Datenmodell
---

# Datenmodell

Das Datenmodell der Anwendung bildet die zentralen Domänenobjekte ab, die im Rahmen des Schwachstellenmanagements benötigt werden. Die Implementation erfolgt mit **SQLAlchemy** als ORM und umfasst eindeutige Identifikatoren, Constraints und Beziehungen. Im Folgenden werden die wichtigsten Entitäten beschrieben.

## Mandant (`Tenant`)

Ein *Tenant* repräsentiert einen Kunden oder eine organisatorische Einheit. Alle übrigen Entitäten sind einem Tenant zugeordnet. Beim Löschen eines Tenants werden die zugehörigen Daten (Assets, Findings, Import Runs, Ticket Batches, Audit‑Logs) kaskadierend mit entfernt.

**Felder**

- `id`: Primärschlüssel
- `name`: eindeutiger Name
- `created_at`: Zeitstempel der Anlage

**Beziehungen**

- `assets`: 1:n‑Beziehung zu Assets
- `findings`: 1:n‑Beziehung zu Findings
- `import_runs`: 1:n‑Beziehung zu Import Runs
- `ticket_batches`: 1:n‑Beziehung zu Ticket Batches
- `audit_log`: 1:n‑Beziehung zu Audit‑Logs

## Asset (`Asset`)

Ein *Asset* bezeichnet ein Gerät, einen Server oder ein anderes Objekt innerhalb eines Tenants. Die Kombination aus Tenant und Asset‑Name muss eindeutig sein.

**Felder**

- `id`, `tenant_id`, `name`, `kind` (z. B. *server*, *workstation*), `metadata_json` (optionale Metadaten), `created_at`

**Beziehungen**

- `findings`: 1:n‑Beziehung zu Findings

## Produkt (`Product`)

Repräsentiert ein Software‑ oder Hardware‑Produkt, das in Findings vorkommt. Produktnamen sind global eindeutig.

**Felder**

- `id`, `name`, `created_at`

**Beziehungen**

- `finding_products`: n:m‑Beziehung zu Findings (über die Zuordnungstabelle `finding_product`)

## Schwachstelle (`Finding`)

Ein *Finding* repräsentiert eine erkannte Schwachstelle oder Fehlkonfiguration. Es wird einem Tenant, einem Asset und optional einem Importlauf zugeordnet. Über Constraints wird verhindert, dass pro Tenant, Asset, Name und Target doppelte Findings existieren.

**Wichtige Felder**

- `name`: Bezeichnung der Schwachstelle
- `cve_id`: optionaler Freitext (unabhängig von der CVE‑Tabelle)
- `risk`: Risikobewertung (0–10)
- `amount`: Anzahl der betroffenen Systeme
- `target`: Zielsystem oder -komponente
- `extended_solution_json`: JSON‑String mit Lösungshinweisen
- `priority_score`: optional berechneter Prioritätswert
- `status`: Workflow‑Status (z. B. `new`, `queued`, `ticket_created`)
- Zeitstempel: `first_seen`, `last_seen`, `created_at`, `updated_at`
- Ticket‑Informationen: Verweise auf das erzeugte Ticket und Ticket‑Batch

**Beziehungen**

- `tenant`, `asset`, `import_run`: je 1:n‑Beziehung
- `products`: n:m‑Beziehung zu Produkten über `FindingProduct`
- `cves`: n:m‑Beziehung zu CVEs über `FindingCVE`
- `tickets`: 1:n‑Beziehung zu externen Tickets
- `ticket_batch`: n:1‑Beziehung zu `TicketBatch`

## Importlauf (`ImportRun`)

Ein *ImportRun* dokumentiert einen einzelnen Importvorgang. Er speichert Statistiken über gelesene Datensätze und den Verarbeitungsstatus (`pending`, `completed`, `failed`).

## Ticket Batch (`TicketBatch`)

Ticket‑Batches gruppieren mehrere Findings, um sie gesammelt an ein externes Ticketsystem zu übergeben. Sie speichern den Verarbeitungsstatus (z. B. `created`, `pending`, `processing`, `completed`), die Anzahl der verarbeiteten Findings und ggf. eine externe Batch‑ID.

## Ticket (`Ticket`)

Repräsentiert ein Ticket in einem externen System (DocBee, MKS.Goliath). Tickets verweisen auf ein Finding und speichern neben der externen ID den Status (`open`, `in_progress`, `resolved`, `closed`), die URL und Zeitstempel.

## Audit‑Log (`AuditLog`)

Das Audit‑Log speichert Änderungen an Entitäten für Revisionszwecke. Es umfasst die Art der Entität (`entity_type`), deren ID, die Aktion, alte und neue Werte sowie einen Zeitstempel.

---

Weitere Details, inklusive Validierungsregeln und Constraints, findest du direkt im Quellcode in `app/db/models.py`.