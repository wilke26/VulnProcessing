---
title: Startseite
---

# VulnProcessing – Entwicklerdokumentation

Diese Dokumentation beschreibt Aufbau, Architektur und Nutzung von **VulnProcessing**.
Das Projekt entstand im Rahmen eines Ausbildungsprojekts und wird heute als kuratierte,
nicht produktiv betriebene Bewerbungsreferenz gepflegt.

## Überblick

VulnProcessing übernimmt JSON‑Berichte aus der Schwachstellenplattform **Lywand**, validiert diese anhand eines versionierten Datenvertrags, reichert die Daten mit zusätzlichen CVE‑Informationen aus der NVD an, dedupliziert und priorisiert die Findings und bereitet sie zur Übergabe an Ticketsysteme (DocBee, MKS.Goliath) vor.

Die Software ist als modularer Python-Service umgesetzt und verwendet **FastAPI**,
**SQLAlchemy**, **Pydantic** und weitere Open-Source-Bibliotheken. Die Dokumentation
gliedert sich in eine konzeptionelle Beschreibung (Datenmodell, Services,
Repository-Schicht, Connectors) sowie eine API-Referenz, die mit **mkdocstrings** aus
dem Quellcode generiert werden kann. Die belastbare Einordnung des implementierten
Stands und seiner Grenzen steht in der Architekturübersicht im Repository unter
`docs/architecture.md`.

## Projektziele

- Automatisierte Weiterverarbeitung großer Mengen an Schwachstellendaten
- Transparente und nachvollziehbare Verarbeitungsschritte und Zustände
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
