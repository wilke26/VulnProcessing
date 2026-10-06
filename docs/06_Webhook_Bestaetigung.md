# Schnittstelle zur Batch-Bestätigung

Der Endpunkt `POST /tickets/batch/confirm` nimmt die abschließende Rückmeldung eines
Ticketsystems oder Integrationsdienstes entgegen. DocBee oder MKS können diese Schnittstelle
später direkt oder über einen Integrationsdienst anbinden.

## Voraussetzungen

- Die Anwendung und der Aufrufer besitzen dasselbe starke
  `BATCH_CONFIRM_WEBHOOK_SECRET`.
- Der Batch wurde über `/tickets/batch/{batch_id}/dispatch` oder den veralteten Alias
  `/tickets/batch/{batch_id}/send` versendet.
- Der Aufrufer übernimmt `batch_id` und `dispatch_token` aus dem Dispatch. REST-Clients
  erhalten beide Werte im JSON-Payload, E-Mail-Clients in den Headern
  `X-VulnProcessing-Batch-ID` und `X-VulnProcessing-Dispatch-Token`.
- Produktionsaufrufe verwenden ausschließlich HTTPS.

## Request

```http
POST /tickets/batch/confirm HTTP/1.1
Content-Type: application/json
X-Webhook-Timestamp: 1760000000
X-Webhook-Signature: sha256=<64 kleingeschriebene Hex-Zeichen>
```

Minimaler Body bei ausschließlich erfolgreichen Tickets:

```json
{"batch_id":42,"successful_count":2,"failed_count":0,"dispatch_token":"<43-Zeichen-Token>"}
```

Sobald mindestens ein Ticket fehlgeschlagen ist, muss `ticket_confirmations` jedes Finding
des Batches genau einmal enthalten. Die Summen der Statuswerte müssen den beiden Zählern
entsprechen:

```json
{
  "batch_id": 42,
  "successful_count": 1,
  "failed_count": 1,
  "dispatch_token": "<43-Zeichen-Token>",
  "ticket_confirmations": [
    {"finding_id": 101, "status": "confirmed"},
    {"finding_id": 102, "status": "failed"}
  ]
}
```

Das Dispatch-Token ist an genau einen Versandversuch gebunden. Nach erfolgreicher
Bestätigung wird es verbraucht. Ein Token eines früheren Versuchs oder eines anderen Batches
wird abgelehnt.

## Signaturverfahren

1. Den Unix-Zeitstempel in ganzen Sekunden als ASCII-Dezimalzahl bilden.
2. Den JSON-Body vollständig in UTF-8 serialisieren. Nach dem Signieren darf er nicht mehr
   verändert oder neu formatiert werden.
3. Die zu signierenden Bytes bilden:

   ```text
   <timestamp-ascii>.<exakte-request-body-bytes>
   ```

4. Darüber HMAC-SHA256 mit `BATCH_CONFIRM_WEBHOOK_SECRET` berechnen.
5. Den kleingeschriebenen Hex-Digest als `X-Webhook-Signature: sha256=<digest>` senden.

Der Server akzeptiert standardmäßig Signaturen bis 300 Sekunden Alter und höchstens 30
Sekunden in der Zukunft. Diese Werte werden durch `BATCH_CONFIRM_WEBHOOK_MAX_AGE_SECONDS`
und `BATCH_CONFIRM_WEBHOOK_CLOCK_SKEW_SECONDS` gesteuert.

## Antworten und Fehlercodes

Erfolg liefert HTTP 200 mit dem Batch-Status und den bestätigten Zählern:

```json
{"success":true,"batch_id":42,"batch_status":"completed","successful":2,"failed":0}
```

Fehlerantworten verwenden – abgesehen von FastAPI-Schemafehlern – dieses Format:

```json
{"detail":{"error":"Menschenlesbare Meldung","code":"maschinenlesbarer_code"}}
```

| HTTP | `code` | Bedeutung |
| --- | --- | --- |
| 401 | `invalid_webhook_auth` | Header fehlen, sind falsch formatiert, abgelaufen oder die HMAC-Signatur stimmt nicht. |
| 404 | `batch_not_found` | Die angegebene Batch-ID existiert nicht. |
| 409 | `invalid_batch_state` | Batch ist nicht `pending`, Versandzeit oder Dispatch-Token fehlen beziehungsweise das Token gehört nicht zum aktiven Versand. |
| 409 | `invalid_confirmation_counts` | Zähler sind negativ oder passen nicht zur Batch-Größe. |
| 409 | `invalid_confirmation_details` | Einzelbestätigungen fehlen, sind doppelt oder passen nicht zu Findings und Zählern. |
| 422 | FastAPI-Validierungsfehler | JSON oder Feldformat entspricht nicht dem Request-Schema. |
| 503 | `webhook_unavailable` | Das Webhook-Secret ist serverseitig nicht konfiguriert. |
| 500 | `batch_confirmation_failed` | Unerwarteter interner Fehler ohne Offenlegung interner Details. |

Bei HTTP 401 oder 422 muss der Request korrigiert und neu signiert werden. HTTP 409 darf
nur nach Prüfung des aktuellen Batch- und Dispatch-Zustands erneut versucht werden.

## Referenz-Client

Das Skript `scripts/confirm_batch_webhook.py` verwendet ausschließlich die
Python-Standardbibliothek. Secret und Dispatch-Token werden aus Umgebungsvariablen gelesen,
damit sie nicht als Kommandozeilenargumente in der Prozessliste erscheinen. In produktiven
Umgebungen sollten die Variablen über die dortige Secret-Verwaltung gesetzt werden; die
folgenden `export`-Befehle verwenden lediglich Beispielwerte und können in der Shell-Historie
gespeichert werden.

```bash
export BATCH_CONFIRM_WEBHOOK_SECRET='ein-langes-zufaelliges-secret'
export BATCH_CONFIRM_DISPATCH_TOKEN='<Token aus dem Dispatch>'

python -m scripts.confirm_batch_webhook \
  --url 'https://example.invalid/tickets/batch/confirm' \
  --batch-id 42 \
  --successful-count 2
```

Ohne `--send` zeigt das Skript Request-Header und den exakt signierten Body an. Diese Ausgabe
enthält das Dispatch-Token und ist vertraulich zu behandeln. Mit `--send` wird der Request
gesendet:

```bash
python -m scripts.confirm_batch_webhook \
  --url 'https://vulnprocessing.example/tickets/batch/confirm' \
  --batch-id 42 \
  --successful-count 1 \
  --failed-count 1 \
  --confirmation 101=confirmed \
  --confirmation 102=failed \
  --send
```

Der Client folgt keinen HTTP-Redirects und erlaubt unverschlüsseltes HTTP nur für
`localhost`, `127.0.0.1` und `::1`.
