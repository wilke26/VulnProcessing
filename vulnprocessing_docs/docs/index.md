---
title: Startseite
---

# VulnProcessing – Entwicklerdokumentation

Diese Dokumentation beschreibt Aufbau, Architektur und Nutzung des Projekts **VulnProcessing**. Das Projekt entstand im Rahmen des Abschlussprojekts der Fachinformatiker‑Ausbildung und dient der automatisierten Weiterverarbeitung von vorgefilterten Schwachstellendaten.

## Überblick

VulnProcessing übernimmt JSON‑Berichte aus der Schwachstellenplattform **Lywand**, validiert diese anhand eines versionierten Datenvertrags, reichert die Daten mit zusätzlichen CVE‑Informationen aus der NVD an, dedupliziert und priorisiert die Findings und bereitet sie zur Übergabe an Ticketsysteme (DocBee, MKS.Goliath) vor.

Die Software ist als modularer Mikroservice in Python umgesetzt und verwendet **FastAPI**, **SQLAlchemy**, **Pydantic** und weitere Open‑Source‑Bibliotheken. Die hier gezeigte Dokumentation gliedert sich in eine konzeptionelle Beschreibung (Datenmodell, Services, Repository‑Schicht, Connectors) sowie eine API‑Referenz, die automatisch mit **mkdocstrings** aus dem Quellcode generiert werden kann.

## Projektziele

- Automatisierte Weiterverarbeitung großer Mengen an Schwachstellendaten
- Transparente und nachvollziehbare Verarbeitungsschritte (Audit‑Log)
- Mandantenfähigkeit und flexible Priorisierung
- Integration in bestehende Ticketsysteme
- Erweiterbarkeit für zukünftige Schwachstellenquellen und weitere Ticketsysteme

## Struktur der Dokumentation

| Bereich | Inhalt |
|--------|---------|
| **Datenmodell** | Beschreibt die ORM‑Entitäten (Tenants, Assets, Findings usw.) und deren Beziehungen |
| **Services** | Erläutert die einzelnen Service‑Klassen zur Enrichment, Deduplizierung, Priorisierung, Ticketing usw. |
| **Repositories** | Zeigt das Repository‑Pattern und die Unit‑of‑Work‑Verwendung |
| **Connectors** | Beschreibt die Anbindungen an externe Systeme (NVD, DocBee, MKS.Goliath, N‑Central, Copilot Studio) |
| **API‑Referenz** | Enthält automatisch generierte Dokumentation direkt aus dem Code |

Siehe auch: `docs/api/tickets.md` für die Ticket‑Endpoints.

Zur Erzeugung der API‑Dokumentation wird das Plugin **mkdocstrings** verwendet. Die Anleitung findest du im Abschnitt API‑Referenz.
