---
title: Connectors
---

# Connectoren

Connectoren bilden die Brücke zwischen VulnProcessing und externen Systemen. Jede Connector‑Klasse kapselt die spezifische API‑Kommunikation und sorgt dafür, dass andere Teile der Anwendung von Details wie Authentifizierung, Datenformaten und Fehlerbehandlung abstrahiert werden.

## NVDClient

Der `NVDClient` ist für die Kommunikation mit der **National Vulnerability Database (NVD)** zuständig. Er ruft CVE‑Details ab und liefert sie als JSON zurück. Um API‑Limits einzuhalten, implementiert der Client ein eigenes Throttling sowie Caching. Anfragen, die fehlschlagen, werden protokolliert und können erneut versucht werden.

## DocBeeConnector

Dieser Connector erzeugt Tickets im **DocBee**‑System. Er wandelt Findings in das erforderliche Datenformat um und übermittelt sie per REST‑API. Erfolgreich erzeugte Tickets liefern eine externe Ticket‑ID zurück, die im Finding gespeichert wird. Fehlerhafte Übertragungen werden im Batch‑Status vermerkt.

## Ticket Clients (E-Mail)

Die E-Mail‑Clients (`DocBeeEmailClient`, `MKSEmailClient`) senden Tickets via SMTP. Sie werden ueber Flags in den Settings aktiviert und vom `TicketDispatcher` verwendet.

## Ticket Clients (REST)

REST‑Clients sind aktuell als Platzhalter vorhanden (`DocBeeRestClient`, `MKSRestClient`). Die Registry warnt, wenn REST aktiviert ist, aber die Clients noch nicht verdrahtet sind.

## MksConnector

Ähnlich zum DocBee‑Connector verbindet der `MksConnector` VulnProcessing mit dem **MKS.Goliath**‑System. Er unterstützt sowohl REST‑API als auch CSV‑Importe (z. B. für Massenimporte). Die genaue Implementierung der API‑Endpunkte kann variieren und muss konfigurierbar sein.

## NCentralClient

Der `NCentralClient` wird vom `WindowsPatchFilter` genutzt, um den Patch‑Status von Assets abzufragen. Er stellt Funktionen bereit, um installierte KB‑Updates pro Device abzufragen und liefert eine Statusübersicht zurück.

## CopilotStudioClient

Der `CopilotStudioClient` ermöglicht den Zugriff auf ein externes KI‑System, das Handlungsempfehlungen (Remediation Guides) liefert. Er sendet strukturierte Anfragen und erhält Antworten in einem definierten Format. Der `RemediationService` nutzt diesen Client, um automatisierte Lösungsschritte für Findings bereitzustellen.

---

Weitere Connectoren, z. B. für zusätzliche Ticketsysteme oder Schwachstellenquellen, können durch Ableitung aus einer gemeinsamen Basisklasse ergänzt werden.
