# ADR-0008: Eine sichere Management- und Deployment-Grenze voraussetzen

- Status: Proposed
- Datum: 2026-10-06
- Vertrauensgrad: High

## Kontext

Import, Ticketvorbereitung, Dispatch, Batchstatus und Statistiken sind
Managementfunktionen. Der ursprüngliche Stand besaß für diese Routen keine zentrale
Authentifizierung oder serverseitige Mandantenautorisierung. Diese Teilentscheidung ist
inzwischen durch fail-closed Bearer-Credentials mit Operations- und Tenant-Scopes
umgesetzt. STARTTLS-Verbindungen des SMTP-Adapters prüfen inzwischen Zertifikatskette
und Hostnamen. Eingehende Request-Bodies, teure Management-Operationen,
Ticket-Kandidatenmengen, Batch-Scans und bekannte Adapterlaufzeiten sind inzwischen
begrenzt. Weitere offene Grenzen betreffen insbesondere Antwortgrößen externer Adapter,
Fleet-weite Admission Control, Dispatch-Idempotenz und öffentliche Fehlerdetails.

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
- Der SMTP-Adapter verwendet bei aktiviertem STARTTLS einen verifizierenden
  System-`SSLContext`; Zertifikatsfehler verhindern Anmeldung und Versand.
- Ein Streaming-Limit begrenzt Request-Bodies vor vollständigem Multipart-/JSON-Parsing.
  Teure Management-Operationen teilen sich ein fail-fast Parallelitätsbudget pro
  Prozess; Datenbankkandidaten und Batch-Scans besitzen feste Obergrenzen.
- SMTP, Copilot, N-Central und NVD besitzen validierte endliche Einzelaufruf-Timeouts;
  die REST-Ticketclients verwenden weiterhin ihren expliziten Timeout.
- Lokale Standardstarter binden den veröffentlichten Port an Loopback.
- Die übrigen Anforderungen dieses ADRs bleiben offen; der Gesamtstatus ist deshalb
  weiterhin `Proposed`.

## Evidenz

- Standard-Sicherheitsreview des Stands `9ee6a51` vom 5. Oktober 2026.
- `app/core/management_auth.py` implementiert die zentrale Management-Authentifizierung
  und serverseitige Operations- und Tenant-Scopes.
- `app/services/email_service.py` übergibt einen mit `ssl.create_default_context()`
  erzeugten, verifizierenden `SSLContext` an STARTTLS.
- `app/core/resource_limits.py` implementiert Streaming-Body-Limit und prozesslokale
  Admission Control; die Ticket- und Batch-Services begrenzen materialisierte
  Kandidaten vor externer Verarbeitung.
- `app/services/batch_ticketing_service.py` führt externe Nebenwirkungen vor einem
  atomaren Dispatch-Claim aus.
- `app/api/routes_tickets.py` gibt an mehreren Stellen interne Fehlerdetails zurück.
