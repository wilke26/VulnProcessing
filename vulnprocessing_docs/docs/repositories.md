---
title: Repositories
---

# Repository‑Schicht

Die Repository‑Schicht kapselt den Zugriff auf die Datenbank und sorgt dafür, dass Services und andere Teile der Anwendung keine direkten SQL‑Befehle ausführen. Dies erhöht die Wartbarkeit und testet die Datenzugriffe isoliert.

## BaseRepository

Das abstrakte `BaseRepository` definiert grundlegende Methoden wie `add()`, `get_by_id()`, `get_or_create()` und `list()`. Konkrete Repository‑Klassen erben davon und spezialisieren sich auf bestimmte Entitäten.

## Konkrete Repositories

- **TenantRepository**: Methoden zum Anlegen und Abrufen von Mandanten.
- **AssetRepository**: Verwaltung von Assets eines Tenants.
- **ProductRepository**: Verwaltung der Produktliste und Suche nach Produktnamen.
- **CVERepository**: Zugriff auf CVE‑Einträge.
- **ImportRunRepository**: Lesen und Schreiben von Importlauf‑Statistiken.
- **TicketBatchRepository**: Verwaltung von Ticket‑Batches und Suche nach offenen Batches.
- **FindingRepository**: Zentrale Klasse zum Erfassen und Aktualisieren von Findings; enthält Logik zur Deduplizierung und Statusberechnung.
- Weitere Repositories können bei Bedarf hinzugefügt werden.

## Unit‑of‑Work

Die Klasse `UnitOfWork` bündelt eine Datenbanksession zusammen mit den verschiedenen Repository‑Instanzen. Sie wird pro Verarbeitungseinheit erzeugt und stellt sicher, dass alle Änderungen entweder gemeinsam bestätigt oder im Fehlerfall zurückgerollt werden. Über die Unit‑of‑Work haben Services Zugriff auf die Repositories (`uow.findings`, `uow.tenants` etc.).

```python
from app.db.repository import UnitOfWork

with UnitOfWork() as uow:
    tenant = uow.tenants.get_by_id(tenant_id)
    new_finding = Finding(...)
    uow.findings.add(new_finding)
    uow.commit()  # persistiert alle Änderungen
```

---

Weitere Details, inklusive Methoden und Transaktionen, findest du im Modul `app/db/repository.py`.