"""
Dieses Modul stellt einen Endpunkt bereit, um die aktuelle Version der Anwendung abzurufen.
Die Versionsinformationen werden aus den Projektmetadaten oder dem Git-Status generiert.
"""

from fastapi import APIRouter

from app.utils.version import get_app_version

# Erstellen des APIRouters für Versions-Endpunkte
router = APIRouter()


@router.get("/version")
def version():
    """
    Gibt die aktuelle Version der Anwendung und Git-Informationen zurück.

    Returns:
        dict: Ein Dictionary mit Name, Version und Git-Hash der Anwendung.
    """
    # Versionsinformationen über die Utility-Funktion abrufen
    v = get_app_version()

    return {"name": v.name, "version": v.version, "git": v.git}
