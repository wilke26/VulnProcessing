# ADR-0001: Persistenten Domänenzustand mit SQLAlchemy auf SQLite verwalten

- Status: Accepted (reconstructed)
- Ursprünglicher Zeitraum: November 2025
- Rekonstruiert: 2026-10-06
- Vertrauensgrad: High

## Kontext

Findings müssen Tenant- und Assetbeziehungen, Importläufe, Ticketstatus und später auch
Batchzustände über einzelne Requests hinweg behalten. Die ältere Dokumentation behauptete
teilweise, die Anwendung besitze keine dauerhafte Datenhaltung; der erhaltene Code und
die Historie widersprechen dieser Aussage.

## Entscheidung

VulnProcessing verwendet SQLAlchemy-Modelle, Repositories und einen `UnitOfWork` für den
persistenten Domänenzustand. Der unterstützte Backend-Dialekt ist SQLite;
`DATABASE_URL` konfiguriert die zugehörige SQLite-Datei. Die Engine-Initialisierung ist
durch `check_same_thread` und `PRAGMA foreign_keys=ON` SQLite-spezifisch und begründet
keine Portabilität zu anderen SQLAlchemy-Dialekten.

## Konsequenzen

- Tenant-, Asset-, Finding-, Import-, Ticket- und Batchzustände sind Teil der Anwendung.
- Transaktionsgrenzen können innerhalb der Datenbank konsistent umgesetzt werden.
- Schemaänderungen benötigen explizite Migrationen und Deploymentprüfungen.
- Eine getrackte Laufzeitdatenbank ist kein geeignetes öffentliches Beispielartefakt.
- Externe Ticketing-Nebenwirkungen bleiben außerhalb der Datenbanktransaktion.
- PostgreSQL, MySQL oder andere Backends benötigen zuerst eine dialektabhängige
  Engine-Initialisierung, Migrationen und Integrationstests.

## Historische Evidenz

- Commit `5ef87cf` vom 11. November 2025 führte `app/db/models.py` ein.
- Commit `067c668` vom 18. November 2025 ergänzte Batchmodelle und -repositories.
- `app/db/models.py`, `app/db/repository.py` und `app/db/engine.py` bilden den heutigen
  Persistenzpfad; `app/db/engine.py` enthält die SQLite-spezifischen Einstellungen.
- Die ursprüngliche Diskussion über alternative Datenbanken ist nicht erhalten.
