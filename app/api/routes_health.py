"""
Dieses Modul stellt Health-Check-Endpunkte für die API bereit.
Es überprüft die Verfügbarkeit von Schema-Dateien und gibt Metadaten zum Dienststatus zurück.
"""

from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from fastapi import APIRouter

# Erstellen des APIRouters für Health-Endpunkte
router = APIRouter()

# Basis-Verzeichnis des Projekts ermitteln (2 Ebenen hoch: app/api -> app -> project root)
BASE_DIR = Path(__file__).resolve().parents[2]
# Pfad zum Schema-Verzeichnis
SCHEMA_DIR = BASE_DIR / "schema"

# Definition der verwendeten Schema-Dateien
SCHEMAS = {
    "raw": SCHEMA_DIR / "lywand_findings_raw_v1.schema.json",
    "envelope": SCHEMA_DIR / "lywand_findings_envelope_v1.schema.json",
}

# Erwartete Version des Envelopes
EXPECTED_SCHEMA_VERSION = 1  # Envelope-Version


def file_meta(p: Path) -> dict:
    """
    Ermittelt Metadaten zu einer Datei (Existenz, Größe, Hash, Änderungsdatum).

    Args:
        p (Path): Der Pfad zur Datei.

    Returns:
        dict: Ein Dictionary mit Metadaten zur Datei.
    """
    # Überprüfen, ob die Datei existiert
    if not p.exists():
        return {"exists": False}

    # Dateiinhalt für Hash-Berechnung lesen
    data = p.read_bytes()
    # Dateistatistiken abrufen
    stat = p.stat()

    return {
        "exists": True,
        "size": len(data),
        "sha256": sha256(data).hexdigest()[:12],
        # Änderungszeitpunkt in UTC mit tzinfo, konsistent zur Service-Zeit
        "modified": datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat(),
        "path": str(p),
    }


@router.get("/health")
def health():
    """
    Health-Check Endpunkt.
    Gibt den aktuellen Status des Dienstes und die Verfügbarkeit der Schemas zurück.

    Returns:
        dict: Statusinformationen des Dienstes.
    """
    # Metadaten für die konfigurierten Schemas abrufen
    raw = file_meta(SCHEMAS["raw"])
    env = file_meta(SCHEMAS["envelope"])

    # Dienst gilt als 'ok', wenn beide Schemas vorhanden sind
    ok = raw.get("exists", False) and env.get("exists", False)

    return {
        "status": "ok" if ok else "degraded",
        "schemas": {
            "raw": raw,
            "envelope": env,
            "expected_schema_version": EXPECTED_SCHEMA_VERSION,
        },
        "service": {
            "name": "VulnProcessing",
            "time": datetime.now(UTC).isoformat(),
        },
    }
