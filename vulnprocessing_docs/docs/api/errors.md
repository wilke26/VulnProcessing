---
title: API-Referenz – Fehlerformate
---

# API-Referenz – Fehlerformate

Alle Ticket-Dispatch-Endpunkte liefern Fehler als JSON mit folgenden Feldern:

- `error`: menschenlesbare Fehlermeldung
- `code`: maschinenlesbarer Fehlercode

Beispiel:

```json
{
  "detail": {
    "error": "Dispatch fehlgeschlagen",
    "code": "batch_dispatch_failed"
  }
}
```

## Fehlercodes (Auszug)

| Code | Bedeutung | Endpoints |
|------|-----------|-----------|
| `dispatch_failed` | Fehler beim Dispatch von Findings | `POST /tickets/dispatch` |
| `batch_dispatch_failed` | Fehler beim Dispatch eines Batches | `POST /tickets/batch/{id}/dispatch`, `POST /tickets/batch/{id}/send` |
| `ticket_create_failed` | Fehler beim Ticket-Create-Flow | `POST /tickets/create` |
| `batch_create_failed` | Fehler beim Erstellen eines Batches | `POST /tickets/batch/create` |

## Fehlerformat (Schema)

Ticket-Endpoints liefern Fehler in folgendem Format:

```json
{
  "detail": {
    "error": "…",
    "code": "…"
  }
}
```
