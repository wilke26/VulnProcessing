# Analyse & Architekturentscheidungen

> **Historischer Stand:** Dieses Dokument beschreibt die ursprüngliche Analyse und das
> damalige Zielbild. Es ist keine Aussage über einen aktuell betriebenen Azure-Dienst.
> Der implementierte Ist-Stand und spätere Entscheidungen stehen in
> [architecture.md](architecture.md) und im [ADR-Index](adr/README.md).

Ziel der Analyse war es, die Datenbasis (Lywand-Findings) so zu strukturieren, dass eine reproduzierbare und automatisierte Weiterverarbeitung möglich wird. Die wesentlichen Erkenntnisse:

## (1) Input-Analyse

Die Quelle liefert JSON-Daten, deren Struktur zwar konsistent ist, aber formal **nicht versioniert** war.  
Es existieren zwei Formen des Inputs:
- historisch: reines Array
- technisch sinnvoll: Envelope mit Metadaten

Konsequenz: es wird ein **Data Contract** eingeführt.

## (2) Modellierung / Single Source of Truth

Der Data Contract wird in Pydantic v2 als Modell definiert.  
JSON-Schemas werden daraus automatisch generiert.  
Nicht umgekehrt.

Grund: Änderungen an Datenfeldern sollen **nur** an einer Stelle stattfinden.

## (3) Entscheidung: Envelope als Zielbild

Raw Array wird weiterhin akzeptiert (Kompatibilität), aber Envelope v1 wird bevorzugt.

Mehrwert:
- Versionierung möglich
- Traceability (source / generated_at)
- besser für zukünftige Erweiterungen (z. B. Kontextdaten)

## (4) Verarbeitungspipeline

Die Pipeline besteht aus:
- Validierung (gegen Data Contract)
- Normalisierung
- Weitergabe an Ticketsysteme

Konsequenz: Fehler werden *vor* Verarbeitung abgefangen (fail-fast Prinzip).

## (5) Betrieb / Deployment

Für die Projektarbeit wurde Azure App Service gewählt, da:
- keine Docker-Build-Infrastruktur notwendig
- geringere Komplexitätskosten
- integriertes Health-Checking

Alternative ACA wird dokumentiert, aber nicht umgesetzt.

## Fazit

Schwerpunkt der Analyse war die Stabilisierung der Schnittstelle und die Reduktion von impliziten Annahmen. Die Strukturierung über einen Data Contract ermöglicht nachvollziehbare Weiterentwicklung und klar definierte Verantwortungsgrenzen.
