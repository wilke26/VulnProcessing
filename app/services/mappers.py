"""
Dieses Modul bietet Mapping-Funktionen zur Konvertierung zwischen Pydantic-DTOs
und SQLAlchemy-ORM-Modellen. Es stellt sicher, dass Daten konsistent transformiert
werden, einschließlich der Serialisierung von JSON-Feldern.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from app.db import models as orm
from app.models.findings import Finding as PydanticFinding


def map_pydantic_to_orm(
    f: PydanticFinding,
    tenant_id: int,
    asset_id: int,
    import_run_id: int | None = None,
) -> orm.Finding:
    """
    Konvertiert ein Pydantic-Finding (DTO) in ein SQLAlchemy-ORM-Modell.

    Dabei werden Listenfelder wie 'extendedSolution' in JSON-Strings serialisiert,
    um sie in der SQLite-Datenbank speichern zu können.

    Args:
        f (PydanticFinding): Das Eingabe-DTO.
        tenant_id (int): Die ID des zugehörigen Mandanten.
        asset_id (int): Die ID des zugehörigen Assets.
        import_run_id (int, optional): Die ID des aktuellen Import-Laufs.

    Returns:
        orm.Finding: Die vorbereitete ORM-Entität.
    """
    now = datetime.now(UTC)

    finding = orm.Finding(
        tenant_id=tenant_id,
        asset_id=asset_id,
        import_id=import_run_id,
        name=f.name,
        risk=float(f.risk),
        amount=int(f.amount),
        target=f.target,
        windows_version_hint=getattr(f, "windowsVersionHint", ""),
        extended_solution_json=json.dumps(f.extendedSolution, ensure_ascii=False),
        priority_score=None,
        status="new",
        first_seen=now,
        last_seen=now,
    )

    # Produkte verknüpfen (Many-to-Many über die Zuordnungstabelle FindingProduct)
    for product_name in f.products:
        # Hinweis: In einer echten Anwendung sollte hier geprüft werden,
        # ob das Produkt bereits existiert
        finding_product = orm.FindingProduct(product=orm.Product(name=product_name))
        finding.products.append(finding_product)

    return finding


def map_orm_to_pydantic(finding: orm.Finding) -> PydanticFinding:
    """
    Konvertiert ein SQLAlchemy-ORM-Modell zurück in ein Pydantic-Finding (DTO).

    Deserialisiert JSON-Felder zurück in Python-Listen und aggregiert verknüpfte
    Daten wie Produktnamen.

    Args:
        finding (orm.Finding): Die ORM-Entität aus der Datenbank.

    Returns:
        PydanticFinding: Das resultierende DTO.
    """
    # JSON-String zurück in Liste umwandeln
    extended_solution = (
        json.loads(finding.extended_solution_json) if finding.extended_solution_json else []
    )

    # Produktnamen aus der Relation extrahieren
    products = [fp.product.name for fp in finding.products]

    return PydanticFinding(
        name=finding.name,
        tenant=f"tenant_{finding.tenant_id}",  # Platzhalter-Format für Tenant-Namen
        risk=finding.risk,
        amount=finding.amount,
        target=finding.target,
        extendedSolution=extended_solution,
        windowsVersionHint=finding.windows_version_hint,
        products=products,
    )
