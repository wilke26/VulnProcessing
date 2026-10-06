# ADR-0006: Einen Referenz-Client statt einer Dummy-Integration bereitstellen

- Status: Accepted
- Datum: 2026-10-05
- Vertrauensgrad: High

## Kontext

DocBee/MKS war als externer Aufrufer der Bestätigung vorgesehen, wird für dieses Projekt
aber nicht mehr produktiv weiterentwickelt. Ein künstlicher Dummy würde eine Integration
vorspiegeln, deren fachliches Verhalten und Betriebsvertrag nicht existieren.

## Entscheidung

Das Repository dokumentiert den Aufrufervertrag und liefert ein minimales CLI-Skript,
das eine gültige signierte Bestätigung erzeugen und optional senden kann. Es wird kein
produktiver DocBee/MKS-Aufrufer simuliert.

## Konsequenzen

- Das Signaturverfahren ist reproduzierbar und integrationsfähig dokumentiert.
- Spätere Aufrufer besitzen eine ausführbare Vorlage, aber keine behauptete
  Produktionsintegration.
- Beispiel und Dokumentation müssen mit dem Serververtrag getestet werden.
- Der Referenz-Client erzwingt HTTPS für entfernte Ziele und kontrollierte URL-Fehler.

## Evidenz

- PR #2 wurde am 5. Oktober 2026 zusammengeführt.
- Commit `5cb6ad5` dokumentiert die Integration und führt
  `scripts/confirm_batch_webhook.py` ein.
- Commit `e45ad95` ergänzt die kontrollierte Validierung ungültiger Ports.
- `docs/06_Webhook_Bestaetigung.md` beschreibt Request, Signatur und Fehlercodes.
