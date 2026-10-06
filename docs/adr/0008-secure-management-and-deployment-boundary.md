# ADR-0008: Eine sichere Management- und Deployment-Grenze voraussetzen

- Status: Proposed
- Datum: 2026-10-06
- Vertrauensgrad: High

## Kontext

Import, Ticketvorbereitung, Dispatch, Batchstatus und Statistiken sind
Managementfunktionen. Der ursprüngliche Stand besaß für diese Routen keine zentrale
Authentifizierung oder serverseitige Mandantenautorisierung. Diese Teilentscheidung ist
inzwischen durch fail-closed Bearer-Credentials mit Operations- und Tenant-Scopes
umgesetzt. Weitere offene Grenzen
betreffen verifizierte SMTP-TLS-Verbindungen, Ressourcenlimits, Dispatch-Idempotenz und
öffentliche Fehlerdetails.

Der Quellcode darf als Referenz öffentlich sein. Daraus folgt jedoch keine Freigabe, den
Service unverändert einem nicht vertrauenswürdigen Netzwerk auszusetzen.

## Vorgeschlagene Entscheidung

Eine zukünftige Bereitstellung gilt nur dann als unterstützt, wenn sie folgende
Eigenschaften nachweisbar erfüllt:

- zentrale, standardmäßig ablehnende Authentifizierung aller Management-Routen;
- serverseitige Mandanten- und Operationsautorisierung;
- nur ausdrücklich öffentliche Health-/Versionsinformationen;
- verifizierte TLS-Verbindungen und freigegebene Ziele für externe Adapter;
- Größen-, Anzahl-, Laufzeit- und Parallelitätsgrenzen vor teurer Verarbeitung;
- atomare Dispatch-Claims, Idempotenz und explizite Fehler-/Retryzustände;
- stabile öffentliche Fehlercodes ohne interne Exceptions oder Dateipfade;
- Secrets ausschließlich über die Deploymentumgebung;
- dokumentierte Datenbankmigration und Backups vor Zustandsänderungen.

## Konsequenzen

- Ein lokaler Demonstrationsbetrieb bleibt möglich, muss aber als lokal gekennzeichnet
  und standardmäßig an Loopback gebunden sein.
- Ein zukünftiges Deployment braucht automatisierte Sicherheits- und
  Autorisierungstests.
- Unvollständige Azure-, Docker- oder Workerartefakte dürfen nicht als unterstützte
  Produktionspfade beschrieben werden.
- Dieses ADR wechselt erst nach Implementierung und Verifikation auf `Accepted`.

## Umsetzungsstand

- Management-Routen sind zentral authentifiziert und serverseitig nach Operation und
  Tenant begrenzt.
- Health und Version bleiben öffentlich; die Batch-Bestätigung behält ihre unabhängige
  HMAC-Authentifizierung.
- Lokale Standardstarter binden den veröffentlichten Port an Loopback.
- Die übrigen Anforderungen dieses ADRs bleiben offen; der Gesamtstatus ist deshalb
  weiterhin `Proposed`.

## Evidenz

- Standard-Sicherheitsreview des Stands `9ee6a51` vom 5. Oktober 2026.
- `app/core/management_auth.py` implementiert die zentrale Management-Authentifizierung
  und serverseitige Operations- und Tenant-Scopes.
- `app/services/email_service.py` besitzt noch keinen expliziten verifizierenden
  `SSLContext`.
- `app/services/batch_ticketing_service.py` führt externe Nebenwirkungen vor einem
  atomaren Dispatch-Claim aus.
- `app/api/routes_tickets.py` gibt an mehreren Stellen interne Fehlerdetails zurück.
