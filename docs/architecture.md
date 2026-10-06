# Architektur v1.0

## Zweck und Geltungsbereich

Dieses Dokument beschreibt den tatsächlich im Repository vorhandenen Stand von
VulnProcessing. Es ist eine aus Quellcode, Tests und erhaltener Git-Historie
rekonstruierte **As-is-Architektur**. Es beschreibt weder einen laufenden
Produktivbetrieb noch eine vollständig bereitgestellte Cloud-Infrastruktur.

VulnProcessing importiert Findings aus der Lywand-Plattform, normalisiert und
persistiert sie, reichert sie optional über externe Dienste an und bereitet sie für
die Übergabe an Ticketsysteme vor. DocBee und MKS sind als konfigurierbare Adapter
vorhanden; aktuell existiert kein produktiver Aufrufer der Batch-Bestätigung.

## Systemkontext

```text
                           optionale externe Dienste
                    ┌──────── NVD ────────┐
                    ├───── N-Central ─────┤
                    └── Copilot Studio ───┘
                                  ▲
                                  │ Anreicherung / Filterung
                                  │
JSON-Datei ─┐                     │
HTTP-Import ├─► Pydantic Contract ─► SQLAlchemy ─► Ticketvorbereitung
CLI-Import ─┘       und Intake          │                 │
                                          │                 ▼
                                          │          tenantbezogener Batch
                                          │                 │
                                          ▼                 ▼
                                    Statusabfragen      Dispatcher
                                                             │
                                                   ┌─────────┴─────────┐
                                                   ▼                   ▼
                                             SMTP-Adapter         REST-Adapter
                                             DocBee / MKS         DocBee / MKS
                                                   │                   │
                                                   └─────────┬─────────┘
                                                             ▼
                                               signierte Batch-Bestätigung
```

## Komponenten und Abhängigkeiten

- `app/models` besitzt die externen und internen Pydantic-Verträge.
- `app/api` stellt Health-, Versions-, Import- und Ticketing-Routen bereit.
- `app/services` enthält Intake, Anreicherung, Priorisierung, Batch-Lebenszyklus,
  Dispatch und die Composition Roots.
- `app/connectors` kapselt NVD, N-Central und Copilot Studio.
- `app/db` besitzt SQLAlchemy-Modelle, Repositories, Sessions und Transaktionen.
- `scripts` enthält operative Hilfsprogramme wie Dateiimport, Schemaexport,
  Migration und den Webhook-Referenz-Client.
- `schema` enthält aus den Pydantic-Modellen abgeleitete JSON-Schemas.

Die Abhängigkeitsrichtung ist nicht vollständig hexagonal: API-Routen bauen Services
über Composition Roots auf, Services verwenden sowohl Domänenmodelle als auch
SQLAlchemy-Modelle, und einige ältere Intake-Pfade existieren parallel. Diese
Beschreibung bildet den vorhandenen Stand ab und behauptet keine weitergehende
Schichtung.

## Daten- und Verarbeitungsfluss

1. Findings gelangen über den HTTP-Upload, einen konfigurierten Dateipfad oder ein
   CLI-Skript in die Anwendung.
2. Pydantic validiert Rohlisten oder den versionierten Envelope.
3. Der Intake normalisiert Tenant, Asset, Finding, Produkt- und CVE-Beziehungen.
4. SQLAlchemy persistiert den Zustand in SQLite. `DATABASE_URL` kann den Pfad der
   SQLite-Datei konfigurieren; andere SQLAlchemy-Dialekte werden von der aktuellen
   Engine-Initialisierung nicht unterstützt.
5. Die Ticketvorbereitung kann Findings priorisieren, über NVD anreichern und über
   N-Central auf bereits installierte Windows-Patches prüfen.
6. Ein tenantbezogener Batch fasst Findings zusammen und übergibt sie an alle
   aktivierten Ticket-Clients.
7. Der Dispatcher liefert ein Ergebnis pro Finding und Client. Nur wenn alle Versuche
   erfolgreich waren, wechselt der zuvor atomar beanspruchte `dispatching`-Batch nach
   `pending`; kein Client beziehungsweise vollständiges Scheitern führt zu `failed`,
   ein Teilerfolg zu `partially_failed`. Ein unklar abgebrochener Versand bleibt zur
   manuellen Klärung in `dispatching`.
8. Bei erfolgreichem Batch-Dispatch wird ein zufälliges Bestätigungstoken ausgegeben;
   gespeichert wird nur dessen SHA-256-Digest.
9. Die Bestätigung prüft HMAC, Zeitfenster, Dispatch-Token, Batch-Zustand und
   Ergebniszahlen, bevor sie den Zustand atomar beansprucht und abschließt.

## Persistenz- und Konsistenzgrenze

Die Datenbank ist Teil der Anwendung und enthält unter anderem Tenants, Assets,
Findings, Importläufe, Tickets und Ticket-Batches. Der `UnitOfWork` bündelt
Repository-Zugriffe in einer SQLAlchemy-Transaktion. Der aktuelle Engine-Code ist durch
`check_same_thread` und `PRAGMA foreign_keys=ON` SQLite-spezifisch. Eine URL für
PostgreSQL, MySQL oder einen anderen Dialekt ist daher kein unterstützter
Konfigurationspfad. Backend-Portabilität würde eine dialektabhängige Initialisierung,
Migrationen und eigene Integrationstests erfordern.

Externe Ticket-Erstellung und lokale Datenbanktransaktionen bilden keine gemeinsame
Transaktion. Dadurch sind Idempotenz, atomare Dispatch-Claims und explizite
Fehlerzustände wesentliche Anforderungen an eine spätere produktive Nutzung.

## Sicherheitsgrenzen

- Die Batch-Bestätigung besitzt eine an den exakten Request-Body gebundene
  HMAC-Signatur und ein einmaliges, dispatchgebundenes Token.
- Import- und Management-Routen besitzen eine zentrale, standardmäßig ablehnende
  Bearer-Authentifizierung. Serverseitig konfigurierte Credentials begrenzen sowohl
  Operations als auch Tenant-Namen; globale Batch-IDs werden vor Lesen oder Dispatch
  gegen den Tenant-Scope geprüft.
- `/health` und `/version` bleiben bewusst öffentlich. Die externe Batch-Bestätigung
  bleibt außerhalb der Management-Authentifizierung und verwendet ihre eigene HMAC-
  und Dispatch-Token-Grenze.
- Zugangsdaten und Zieladressen werden über Umgebungsvariablen beziehungsweise eine
  lokale, nicht einzucheckende `.env` konfiguriert.
- Ausgehende Verbindungen verlassen die Vertrauensgrenze der Anwendung. Der
  SMTP-Adapter prüft bei STARTTLS Zertifikatskette und Hostnamen. Zielsystemfreigabe,
  Antwortgrößen und entsprechende Garantien der übrigen Adapter bleiben explizite
  Anforderungen. Eingehende Body-Größe, teure gleichzeitige Management-Aufrufe,
  Ticket-Kandidaten und Batch-Scans sind pro Prozess begrenzt; mehrere Worker brauchen
  zusätzlich Admission Control auf Proxy- oder Orchestrator-Ebene.
- Das Repository ist Quellcode für eine Bewerbungsreferenz. Es ist keine Freigabe für
  ein öffentlich erreichbares Deployment.

Die geplante Management- und Deployment-Grenze ist in
[ADR-0008](adr/0008-secure-management-and-deployment-boundary.md) beschrieben.

## Laufzeit und Deployment

Der implementierte Einstiegspunkt ist `app.main:app`. Beim Start werden die
SQLAlchemy-Tabellen initialisiert, optional ein konfigurierter Dateiimport ausgeführt
und ein monatlicher Scheduler gestartet.

Das Repository enthält Hinweise auf Azure App Service und Docker Compose, aber keine
vollständig belegte oder aktuell betriebene Produktivbereitstellung. Fehlende
Dockerfiles, leere Azure-Platzhalter und nicht implementierte Worker-Pfade sind keine
unterstützten Deploymentvarianten. Für die Bewerbungsreferenz gilt daher die in
[ADR-0007](adr/0007-curated-portfolio-reference.md) festgehaltene Grenze.

## Bekannte Architekturarbeit

- atomarer und idempotenter Claim vor externen Dispatch-Nebenwirkungen;
- Antwortgrößen- und Item-Limits für externe Adapter sowie Fleet-weite Admission Control;
- verifizierte Transportverschlüsselung für die übrigen credentialtragenden Adapter;
- Bereinigung der parallelen alten und neuen Persistenz-/Intake-Pfade;
- Entscheidung über eine unterstützte Deploymentform oder Entfernung unvollständiger
  Deploymentartefakte.

## Entscheidungsnachweise

Die Architekturentscheidungen, ihre Rekonstruktionsmethode und die jeweils verfügbare
Evidenz sind im [ADR-Index](adr/README.md) dokumentiert.
