"""
Dieses Modul stellt Endpunkte für den Import von Sicherheitsergebnissen (Findings) bereit.
Es unterstützt den Import von JSON-Dateien im Rohformat oder im Envelope-Format.
"""

import json
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import TypeAdapter, ValidationError
from starlette.datastructures import UploadFile

from app.core.config import settings
from app.core.management_auth import (
    FINDINGS_IMPORT,
    ManagementPrincipal,
    authenticate_management_request,
    require_management_operation,
    require_tenant_access,
)
from app.models.findings import Finding, FindingsEnvelope, UnifiedFindingsInput
from app.services.db_intake import save_findings

# Erstellen des APIRouters für Import-Endpunkte
router = APIRouter(dependencies=[Depends(authenticate_management_request)])

# Pydantic TypeAdapter für die Validierung der Eingabedaten (UnifiedFindingsInput)
# Unterstützt sowohl eine Liste von Findings als auch ein Envelope-Objekt.
adapter = TypeAdapter(UnifiedFindingsInput)


async def _read_upload_limited(file: UploadFile, max_bytes: int) -> bytes:
    """Read an uploaded file without allowing unbounded memory consumption."""
    chunks: list[bytes] = []
    total = 0
    while chunk := await file.read(64 * 1024):
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(status_code=413, detail="Upload überschreitet die Größenbegrenzung")
        chunks.append(chunk)
    return b"".join(chunks)


@router.post(
    "/findings/import",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "required": ["file"],
                        "properties": {"file": {"type": "string", "format": "binary"}},
                    }
                }
            },
        }
    },
)
async def import_findings(
    request: Request,
    principal: ManagementPrincipal = Depends(require_management_operation(FINDINGS_IMPORT)),
):
    """
    Importiert eine JSON-Datei mit Findings (Roh-Array oder Envelope v1).
    Validiert die Struktur und persistiert die normalisierten Findings in der Datenbank.

    Args:
        request (Request): HTTP-Anfrage mit der JSON-Datei im Multipart-Feld ``file``.

    Returns:
        dict: Ein Dictionary mit der Anzahl der erfolgreich importierten Findings.

    Raises:
        HTTPException: Wenn das JSON ungültig ist (400) oder die Validierung fehlschlägt (422).
    """

    # Datei einlesen und JSON parsen
    try:
        async with request.form(max_files=1, max_fields=0) as form:
            file = form.get("file")
            if not isinstance(file, UploadFile):
                raise HTTPException(status_code=422, detail="Multipart-Feld 'file' fehlt")
            contents = await _read_upload_limited(file, settings.MAX_IMPORT_BYTES)
        data = json.loads(contents.decode("utf-8"))
    except HTTPException:
        raise
    except Exception as e:
        # Fehler beim Lesen der Datei oder Parsen des JSON
        raise HTTPException(status_code=400, detail="Ungültige JSON-Eingabe") from e

    # Pydantic-Validierung gegen das UnifiedFindingsInput Modell
    try:
        parsed = adapter.validate_python(data)
    except ValidationError as e:
        # Validierungsfehler zurückgeben
        raise HTTPException(status_code=422, detail=e.errors()) from e

    # Normalisierung der Daten zu einer Liste von Finding-Objekten
    if isinstance(parsed, list):
        # Wenn es bereits eine Liste ist, direkt verwenden
        findings: list[Finding] = parsed
    else:
        # Wenn es ein Envelope ist, die 'items' extrahieren
        findings = cast(FindingsEnvelope, parsed).items

    if len(findings) > settings.MAX_FINDINGS_PER_IMPORT:
        raise HTTPException(
            status_code=413,
            detail="Import überschreitet die maximale Anzahl von Findings",
        )

    for tenant_name in {finding.tenant for finding in findings}:
        require_tenant_access(principal, tenant_name)

    # Speichern der Findings in der Datenbank über den Intake-Service
    count = save_findings(findings)

    # Erfolgsantwort mit der Anzahl der importierten Einträge
    return {"imported": count}
