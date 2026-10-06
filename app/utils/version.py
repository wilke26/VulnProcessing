"""
Dieses Modul bietet Funktionen zum Auslesen der aktuellen Anwendungsversion.
Es extrahiert Metadaten aus der 'pyproject.toml' und versucht, den aktuellen
Git-Hash für eine genauere Identifizierung des Builds zu ermitteln.
"""

from __future__ import annotations

import subprocess
import tomllib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

# Pfad zur pyproject.toml (Basisverzeichnis des Projekts)
PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"


@dataclass(frozen=True)
class AppVersion:
    """
    Hält Versionsinformationen der Anwendung.
    """

    name: str  # Name der Anwendung
    version: str  # Versionsnummer (z.B. 1.0.0)
    git: str | None = None  # Kurzer Git-SHA (falls verfügbar)


def _read_toml(path: Path) -> dict:
    """
    Liest eine TOML-Datei ein und gibt sie als Dictionary zurück.
    """
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return data


def _read_git_short_sha() -> str | None:
    """
    Ermittelt den kurzen SHA des aktuellen Git-Commits.

    Returns:
        str | None: Der kurze SHA oder None, falls git nicht verfügbar ist.
    """
    try:
        sha = (
            subprocess.check_output(
                ["git", "rev-parse", "--short", "HEAD"],
                stderr=subprocess.DEVNULL,
            )
            .decode("utf-8")
            .strip()
        )
        return sha or None
    except Exception:
        # Fehler (z.B. kein Git-Repo oder Git nicht installiert) ignorieren
        return None


@lru_cache(maxsize=1)
def get_app_version() -> AppVersion:
    """
    Ermittelt die Anwendungsversion aus den Projektdaten.

    Liest Name und Version aus der 'pyproject.toml' (PEP 621) aus.
    Ergänzt optional den Git-Status. Das Ergebnis wird für die Dauer
    der Laufzeit zwischengespeichert (LRU-Cache).

    Returns:
        AppVersion: Objekt mit den Versionsdetails.
    """
    # Überprüfen, ob pyproject.toml vorhanden ist (Fallback für Deployment)
    if not PYPROJECT.exists():
        return AppVersion(name="VulnProcessing", version="0.0.0-dev", git=_read_git_short_sha())

    data = _read_toml(PYPROJECT)

    # Extraktion der PEP 621 Felder aus [project]
    proj = data.get("project") or {}
    name = str(proj.get("name") or "VulnProcessing")
    version = str(proj.get("version") or "0.0.0-dev")

    return AppVersion(name=name, version=version, git=_read_git_short_sha())
