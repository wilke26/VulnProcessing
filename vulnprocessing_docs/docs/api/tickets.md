---
title: API-Referenz – Tickets
---

# API-Referenz – Tickets

## POST /tickets/dispatch

Dispatcht offene Findings an konfigurierte Ticket-Clients.

Query-Parameter:
- `tenant_name` (optional): Filtert nach Tenant
- `min_risk` (optional): Minimaler Risk-Score
- `dry_run` (optional, default false): Nur simulieren, keine Tickets senden

Fehler:
- `502`: Mindestens ein externer Versandversuch ist fehlgeschlagen (`detail.code = dispatch_failed`)
- `503`: Es ist kein Ticket-Client aktiviert (`detail.code = dispatch_unavailable`)
- `500`: Dispatch fehlgeschlagen (`detail.code = dispatch_failed`)
Siehe auch: `api/errors.md`

Antwort (Beispiel):

```json
{
  "dispatched": 5,
  "filtered": 2,
  "total": 7,
  "dry_run": false,
  "batch_status": null,
  "error": null,
  "code": null
}
```

Ein Aufruf gilt nur dann als erfolgreich, wenn jedes ausgewählte Finding an jeden
aktivierten Client übertragen wurde.

## POST /tickets/batch/{id}/dispatch

Dispatcht einen vorbereiteten Batch an konfigurierte Ticket-Clients.

Fehler:
- `422`: Dispatch fehlgeschlagen (`detail.code = batch_dispatch_failed`)
- `500`: Interner Fehler (`detail.code = batch_dispatch_failed`)
Siehe auch: `api/errors.md`

Antwort (Beispiel):

```json
{
  "success": true,
  "batch_id": 12,
  "tickets_dispatched": 5,
  "batch_status": "pending",
  "error": null,
  "code": null
}
```

Der Batch wechselt nur bei vollständig erfolgreichem Versand nach `pending`. Ohne
aktive Clients oder bei ausschließlich fehlgeschlagenen Versuchen wird er `failed`.
Gemischte Ergebnisse werden als `partially_failed` gespeichert und nicht automatisch
erneut versendet, damit bereits erzeugte externe Tickets nicht dupliziert werden.

## POST /tickets/batch/{id}/send (deprecated)

Alias auf `/tickets/batch/{id}/dispatch`.
