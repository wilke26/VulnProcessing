# Betrieb in Azure App Service

> **Status: historisches Zielbild, nicht aktuell unterstützt.** Das Repository enthält
> keinen vollständigen Azure-Deploymentworkflow, und VulnProcessing wird derzeit nicht
> produktiv betrieben. Dieses Dokument bleibt als ursprünglicher Entwurf erhalten. Die
> belastbare aktuelle Einordnung steht in [architecture.md](architecture.md) und
> [ADR-0007](adr/0007-curated-portfolio-reference.md).

Als ursprüngliches Zielbild war eine Bereitstellung von VulnProcessing in Azure App
Service (Linux, Python 3.12) vorgesehen. Dieses Modell sollte den Plattformaufwand gering
halten und TLS-Terminierung, OS-Härtung und Deployment-Automatisierung an die Plattform
delegieren.

## Deployment

Der Entwurf sah ein Deployment über GitHub Actions vor: Nach erfolgreichen Lint- und
Testschritten sollten die JSON-Schemas erzeugt, eine `requirements.txt` exportiert und
die Anwendung durch Azure App Service mittels Oryx gestartet werden. Dieser Ablauf ist
im aktuellen Repository nicht vollständig implementiert oder verifiziert.

## Health und Version

Die Anwendung stellt folgende Endpunkte bereit:

- `GET /health` prüft unter anderem Schema-Artefakte und erwartete `schema_version`.
- `GET /version` liefert Name und Version der Anwendung.

Diese Endpunkte werden im App Service Health-Check hinterlegt, um nur gesunde Deployments zu aktivieren.

## Konfiguration

Relevante Konfiguration erfolgt über App Settings:

| Key | Beispielwert | Zweck |
|---|---|---|
| `LOG_LEVEL` | `info` | Logging-Verbosity |
| `SCHEMA_DIR` | `/home/site/wwwroot/schema` | Pfad zu JSON-Schema-Artefakten |
| `EXPECTED_SCHEMA_VERSION` | `1` | Versionierung des Data Contracts |

Secrets (API-Keys, Zugänge) werden nicht im Code abgelegt, sondern über App Settings bzw. Key-Vault-Referenzen eingebunden.

Damit bleibt der Betrieb reproduzierbar, schlank und ohne zusätzliche Infrastrukturkomponenten durchführbar.
