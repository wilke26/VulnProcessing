"""
Dieses Modul definiert die Pydantic-Modelle für Sicherheitsbefunde (Findings).
Es unterstützt sowohl einfache Listen von Findings als auch ein strukturiertes Envelope-Format (v1).
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Typ-Aliase mit Validierungsregeln
NonEmptyStr = Annotated[str, Field(min_length=1)]
RiskFloat = Annotated[float, Field(ge=0.0, le=10.0)]
AmountInt = Annotated[int, Field(ge=1)]
NonEmptyStrList = Annotated[list[NonEmptyStr], Field(min_length=1)]


class Finding(BaseModel):
    """
    Repräsentiert eine einzelne Schwachstelle oder Fehlkonfiguration (Finding).
    Enthält Basisinformationen sowie Metadaten zur Priorisierung und Anreicherung.
    """

    model_config = ConfigDict(extra="forbid", from_attributes=True, populate_by_name=True)

    name: NonEmptyStr
    cve_id: str | None = None
    tenant: NonEmptyStr
    risk: RiskFloat
    amount: AmountInt
    target: NonEmptyStr
    extendedSolution: NonEmptyStrList = Field(..., alias="extended_solution_json")
    windowsVersionHint: str = Field("", alias="windows_version_hint")
    products: NonEmptyStrList

    # Felder für Priorisierung und Enrichment
    priority_level: str | None = None  # Prioritätsstufe (z.B. "LOW", "CRITICAL")
    priority_score: float | None = None  # Berechneter Score (0.0 - 100.0)
    cvss_base_score: float | None = None  # CVSS Basis-Score (0.0 - 10.0)
    cvss_severity: str | None = None  # CVSS Schweregrad

    # Felder für die Datenbank-Persistierung
    id: int | None = None
    first_seen: datetime | str | None = None
    last_seen: datetime | str | None = None

    @field_validator("tenant", mode="before")
    @classmethod
    def transform_tenant(cls, v: Any) -> Any:
        if hasattr(v, "name"):
            return v.name
        return v

    @field_validator("extendedSolution", mode="before")
    @classmethod
    def transform_extended_solution(cls, v: Any) -> Any:
        if isinstance(v, str):
            try:
                data = json.loads(v)
                if isinstance(data, list):
                    return data
                return [str(data)]
            except json.JSONDecodeError:
                return [v]
        return v

    @field_validator("products", mode="before")
    @classmethod
    def transform_products(cls, v: Any) -> Any:
        if isinstance(v, list) and v and hasattr(v[0], "product"):
            return [p.product.name for p in v]
        if not v:
            return ["Unknown"]  # Fallback
        return v


# Definition für ein einfaches Array von Findings (Legacy-Unterstützung)
FindingsInput = list[Finding]


class FindingsEnvelope(BaseModel):
    """
    Strukturiertes Envelope-Format (v1) für den Import von Findings.
    Ermöglicht die Übergabe von Metadaten zusammen mit der Liste der Findings.
    """

    model_config = ConfigDict(extra="forbid", from_attributes=True)

    schema_version: Literal[1] = 1
    source: NonEmptyStr = "lywand"
    generated_at: datetime
    items: list[Finding]


# Kombinierter Eingabetyp, der sowohl die Liste als auch das Envelope akzeptiert.
UnifiedFindingsInput = UnifiedFindingsInput = FindingsEnvelope | FindingsInput
