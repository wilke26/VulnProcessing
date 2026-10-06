# VulnProcessing

VulnProcessing ist eine Pipeline zur automatisierten Verarbeitung von Findings aus der Lywand-Plattform.  
Eingehende JSON-Daten werden über einen **Data Contract** formal definiert, validiert und im Anschluss zur Ticket-Erstellung verwendet.

## English summary

VulnProcessing is a reference implementation for processing vulnerability findings from
the Lywand platform. It validates incoming JSON against a Pydantic data contract,
persists findings in SQLite, prepares tenant-scoped ticket batches and integrates
external systems through adapters. The repository focuses on explicit security
boundaries, testable service composition and reconstructed architecture decisions.
It is maintained as a portfolio project and is not currently operated in production.

Die verbindliche Projektdokumentation ist auf Deutsch verfasst. Quellcode,
Bezeichner und Commit-Nachrichten verwenden überwiegend Englisch.

## Features

- Data Contract per Pydantic v2 (Single Source of Truth)
- automatische Generierung von JSON Schema Artefakten
- Validierung von Eingabedateien (raw und Envelope)
- FastAPI Service inkl. `/health` und `/version`
- lokal ausführbarer FastAPI-Service; kein aktueller Produktivbetrieb
- vorbereitete, derzeit unvollständige Docker-Compose-Konfiguration
- Ticket-Dispatching via Composition Root und konfigurierbare Clients

## Repository-Struktur (Kurzform)

app/ → Anwendungscode (FastAPI, Models, Services)
schema/ → generierte JSON-Schemas (nicht manuell ändern)
scripts/ → export_schema.py, validate_file.py
deploy/ → Deployment (z. B. Azure, Docker)
tests/ → Unit/Integration-Tests
docs/ → Projektdokumentation

## Architektur und Entscheidungen

- [Aktuelle Architektur](docs/architecture.md)
- [Architecture Decision Records](docs/adr/README.md)
- [Webhook-Bestätigung und Referenz-Client](docs/06_Webhook_Bestaetigung.md)

Die Architekturübersicht beschreibt den tatsächlich implementierten Stand. Historische
Entscheidungen, die erst nachträglich aus Code, Tests und Commits hergeleitet wurden,
sind in den ADRs ausdrücklich als rekonstruiert gekennzeichnet.

## Tests

Tests laufen mit `pytest`. Es gibt Unit- und Integrationstests, inkl. Ticket-Dispatching Endpoints.
Property-based Tests (Hypothesis) sind mit dem Marker `property` versehen. Schnelllauf:
`make test-fast`

## Logging (structlog)

Strukturierte Logs sind optional aktivierbar. JSON-Logs fuer Produktions-Stacks:
`STRUCTLOG_JSON=1`.

## Retry (tenacity)

Externe API-Clients nutzen zentrale Retry-Settings:
`RETRY_ATTEMPTS`, `RETRY_MIN_SECONDS`, `RETRY_MAX_SECONDS`.
## Ticketing Konfiguration (Kurz)

Ticket-Dispatching nutzt einen Composition Root (`app/services/composition_root.py`) und aktiviert Clients
über Settings. E-Mail- und REST-Clients sind implementiert, aber aktuell nicht produktiv angebunden.

Aktive Flags:
- `DOCBEE_EMAIL_ENABLED` / `MKS_EMAIL_ENABLED`
- `DOCBEE_REST_ENABLED` / `MKS_REST_ENABLED`
- `ENABLE_WINDOWS_PATCH_FILTER` aktiviert die optionale N-Central-Prüfung. Nur dann
  müssen `NCENTRAL_API_URL` und `NCENTRAL_API_KEY` gesetzt sein.

API:
- `POST /tickets/dispatch` dispatcht offene Findings an konfigurierte Clients.
- `POST /tickets/batch/{id}/dispatch` dispatcht einen vorbereiteten Batch.

### Management-Authentifizierung

Alle Import-, Ticket- und Batch-Management-Routen benötigen ein Bearer-Credential.
`/health` und `/version` bleiben öffentlich; `/tickets/batch/confirm` verwendet
weiterhin ausschließlich die unten dokumentierte Webhook-Authentifizierung. Ohne
`MANAGEMENT_CREDENTIALS` sind Management-Routen standardmäßig deaktiviert und antworten
mit `503 management_auth_unavailable`.

Die Credentials werden als JSON-Liste über die Deploymentumgebung konfiguriert. Tokens
müssen mindestens 32 Zeichen lang sein und gehören nicht in versionierte Dateien:

```text
MANAGEMENT_CREDENTIALS=[{"subject":"portfolio-admin","token":"<secret>","tenants":["*"],"operations":["*"]}]
Authorization: Bearer <secret>
```

Ein Token kann beispielsweise lokal mit `python -c "import secrets;
print(secrets.token_urlsafe(32))"` erzeugt werden. Statt `*` können Tenant-Namen und
Operations-Scopes explizit freigegeben werden:

- `findings:import`
- `tickets:create`
- `tickets:dispatch`
- `batches:create`
- `batches:dispatch`
- `batches:read`

Tenant-Scope und Operation werden serverseitig aus dem Credential abgeleitet. Ein
weggelassener Tenant-Filter erweitert die Berechtigung nicht; die Abfrage bleibt auf
die freigegebenen Tenants begrenzt. Fehlende oder ungültige Tokens ergeben `401`, eine
fehlende Operation oder ein nicht freigegebener expliziter Tenant `403`. Nicht
freigegebene Batch-IDs werden wie unbekannte IDs mit `404` beantwortet. Außerhalb eines
lokalen Loopback-Setups muss eine vorgeschaltete, verifizierte HTTPS-Verbindung das
Bearer-Credential auf dem Transportweg schützen.

## Sicherheitseinstellungen

- `MANAGEMENT_CREDENTIALS` authentifiziert Management-Aufrufe und begrenzt sie auf
  konfigurierte Tenants und Operations-Scopes.
- `SMTP_USE_TLS=true` aktiviert STARTTLS mit System-Truststore, verpflichtender
  Zertifikatsprüfung und Hostnamenabgleich gegen `SMTP_HOST`. Private CAs müssen in den
  Truststore der Laufzeit aufgenommen werden; bei aktiviertem TLS gibt es bewusst keinen
  Schalter zum Abschalten der Zertifikatsprüfung. `SMTP_USE_TLS=false` behält den
  bisherigen unverschlüsselten Modus ausschließlich für isolierte lokale
  Entwicklungs-Relays bei.
- `BATCH_CONFIRM_WEBHOOK_SECRET` ist für `POST /tickets/batch/confirm` erforderlich.
  Der Aufrufer signiert `<Unix-Timestamp>.<unveränderter Request-Body>` mit HMAC-SHA256
  und sendet das Ergebnis als `X-Webhook-Signature: sha256=<hex>` sowie den Timestamp
  als `X-Webhook-Timestamp`. Der beim Versand zurückgegebene `dispatch_token` muss als
  gleichnamiges Feld in den signierten JSON-Body der Bestätigung übernommen werden. Das
  Token gilt nur für diesen Versandversuch und wird bei erfolgreicher Bestätigung verbraucht.
  REST-Clients erhalten `batch_id` und `dispatch_token` im Ticket-Payload; E-Mail-Clients
  erhalten sie als `X-VulnProcessing-Batch-ID` und `X-VulnProcessing-Dispatch-Token`.
- `BATCH_CONFIRM_WEBHOOK_MAX_AGE_SECONDS` begrenzt das zulässige Alter einer Signatur
  (Standard: 300 Sekunden).
- `BATCH_CONFIRM_WEBHOOK_CLOCK_SKEW_SECONDS` erlaubt eine begrenzte Uhrzeitabweichung
  zwischen den Systemen (Standard: 30 Sekunden, immer kleiner als das Signaturalter).
- Vor dem ersten Deployment dieses Schutzes muss die tatsächlich verwendete Datenbank
  explizit geprüft werden, zum Beispiel mit
  `python -m scripts.migrate_webhook_confirmations --check-only --database-url sqlite:////absoluter/pfad/vulnprocessing.sqlite3`.
  Meldet der Befehl eine fehlende Dispatch-Token-Spalte, wird sie mit
  `python -m scripts.migrate_webhook_confirmations --apply --database-url <SQLAlchemy-URL>`
  ergänzt. Alte `pending`-Batches ohne Token können nicht sicher migriert werden und müssen
  vor dem Deployment abgeschlossen oder zurückgesetzt werden. `--check-only` beendet sich
  mit Status 1, wenn eine Migration oder manuelle Bereinigung erforderlich ist.
- `MAX_IMPORT_BYTES` und `MAX_FINDINGS_PER_IMPORT` begrenzen JSON-Imports
  (Standard: 10 MiB beziehungsweise 10.000 Findings).

Das vollständige Request-Schema, Signaturverfahren, Fehlercodes und ein ausführbarer
Referenz-Client sind in [docs/06_Webhook_Bestaetigung.md](docs/06_Webhook_Bestaetigung.md)
dokumentiert.

## Voraussetzungen

- Python >= 3.12
- Poetry >= 1.8
- optional: Docker für lokale Entwicklung

## Setup

```bash
poetry install
poetry run python scripts/export_schema.py
```

Beim Start des FastAPI-Service wird das lokale SQLite-Schema bei Bedarf unter
`data/vulnprocessing.sqlite3` erzeugt. Die Laufzeitdatenbank ist bewusst nicht
versioniert.

Vor einem Export als öffentliche Referenz prüft
`poetry run python scripts/check_public_snapshot.py` ausschließlich die von Git
getrackten Dateien auf SQLite-Inhalte, `.env`-Dateien einschließlich lokaler und
umgebungsspezifischer Varianten, JWT-ähnliche Credentials und
private Schlüssel. Ignorierte lokale Dateien werden dabei nicht in den Snapshot
übernommen.
