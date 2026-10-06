---
title: API-Referenz – Fehlerformate
---

# API-Referenz – Fehlerformate

Alle Ticket-Dispatch-Endpunkte liefern Fehler als JSON mit folgenden Feldern:

- `error`: menschenlesbare Fehlermeldung
- `code`: maschinenlesbarer Fehlercode

Interne Exception-Texte, Datenbankdetails, Backend-URLs und lokale Dateipfade werden
nicht an Aufrufer ausgegeben. Unerwartete Fehler werden vollständig im Server-Log
protokolliert; die HTTP-Antwort enthält nur einen stabilen Code und eine neutrale Meldung.
Validierungsfehler nennen weiterhin Typ und Feldposition, spiegeln den abgelehnten
Eingabewert jedoch nicht zurück.

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
| `batch_status_failed` | Batch-Status konnte nicht gelesen werden | `GET /tickets/batch/status/{id}` |
| `batch_statistics_failed` | Batch-Statistiken konnten nicht gelesen werden | `GET /tickets/batch/statistics/{tenant}` |
| `internal_server_error` | Unerwarteter, nicht näher offengelegter Serverfehler | alle Endpoints |

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
