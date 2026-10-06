"""
Dieses Modul definiert Pydantic-Modelle für die Anreicherung von Findings mit externen Daten.
Es umfasst Status-Enums, CVSS-Vektoren und Datenstrukturen für NVD-Anreicherungen.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.models.findings import Finding, RiskFloat


class EnrichmentStatus(StrEnum):
    """
    Lebenszyklus-Status für Anreicherungsversuche.
    """

    ENRICHED = "enriched"  # Erfolgreich angereichert
    NOT_FOUND = "not_found"  # Keine Daten gefunden
    ERROR = "error"  # Fehler während der Anreicherung
    DUPLICATE = "duplicate"  # Dublette


class CVSSVector(BaseModel):
    """
    Vereinfachte CVSS-Repräsentation, die für die Priorisierung verwendet wird.
    """

    model_config = ConfigDict(extra="forbid")

    version: Literal["3.1", "3.0", "2.0"]
    base_score: RiskFloat
    vector: str | None = None
    source: Literal["NVD"] = "NVD"


class NVDEnrichment(BaseModel):
    """
    Normalisierte Anreicherungsdaten für eine einzelne CVE aus der
    National Vulnerability Database (NVD).
    """

    model_config = ConfigDict(extra="forbid")

    cve_id: str = Field(min_length=5)
    status: EnrichmentStatus = EnrichmentStatus.NOT_FOUND
    description: str | None = None
    cvss: CVSSVector | None = None
    references: list[str] = Field(default_factory=list)
    source: Literal["nvd"] = "nvd"


class EnrichedFinding(Finding):
    """
    Ein Finding, das um Anreicherungsdaten und Metadaten zur Priorisierung erweitert wurde.
    """

    model_config = ConfigDict(extra="forbid")

    enrichments: list[NVDEnrichment] = Field(default_factory=list)
    priority_score: int | None = None
