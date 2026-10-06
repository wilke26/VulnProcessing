# Architektur

Die frühere Kurzbeschreibung auf dieser Seite entsprach nicht mehr dem implementierten
Stand: VulnProcessing besitzt inzwischen SQLAlchemy-Persistenz, Import- und
Ticketing-Routen, externe Connectoren und einen Batch-Lebenszyklus. Außerdem ist kein
aktueller produktiver Azure-Betrieb belegt.

Die kanonische, aus Code und erhaltener Historie rekonstruierte Beschreibung befindet
sich in [architecture.md](architecture.md).

Prägende Entscheidungen und ihre Evidenz werden im
[ADR-Index](adr/README.md) dokumentiert.
