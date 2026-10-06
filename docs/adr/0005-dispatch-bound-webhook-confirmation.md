# ADR-0005: Batch-Bestätigungen an den konkreten Dispatch binden

- Status: Accepted
- Datum: 2026-10-05
- Vertrauensgrad: High

## Kontext

Eine HMAC-signierte Bestätigung beweist die Kenntnis des gemeinsamen Webhook-Secrets,
unterscheidet allein aber keinen alten von einem neuen Versandversuch desselben Batches.
Außerdem dürfen Bestätigungen nicht vor dem tatsächlichen Versand akzeptiert werden.

## Entscheidung

Jeder Dispatch erzeugt ein kryptographisch zufälliges Einmal-Token. Nur dessen
SHA-256-Digest wird im Batch gespeichert. Das Klartexttoken wird dem Ticketempfänger
übergeben und muss Bestandteil des exakt signierten Bestätigungsbodys sein. Die
Bestätigung prüft zusätzlich Zeitfenster, Batchzustand, Zähler und Detailergebnisse und
beansprucht die Verarbeitung atomar. Erfolgreiche Bestätigung verbraucht das Token.

## Konsequenzen

- Ein zeitlich gültiger alter Request reicht ohne Token des aktuellen Dispatchs nicht.
- Der externe Aufrufer muss Token und HMAC-Secret getrennt korrekt behandeln.
- Bestehende offene Batches ohne Token benötigen vor einem Deployment eine Migration
  oder fachliche Bereinigung.
- TLS bleibt eine zusätzliche Transportanforderung.

## Evidenz

- PR #1 wurde am 5. Oktober 2026 zusammengeführt.
- Commit `6695482` bindet Bestätigungen an Dispatch-Versuche.
- `app/core/security.py` implementiert Signatur- und Token-Hilfen.
- `app/services/batch_ticketing_service.py` implementiert Zustands- und Tokenprüfung.
- `tests/integration/test_api_security_controls.py` und `tests/unit/test_security.py`
  dokumentieren die Randfälle.
