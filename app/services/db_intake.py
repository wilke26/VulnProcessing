"""
Dieses Modul stellt Funktionen für den Import und die Persistierung von Findings
in der Datenbank bereit. Es bildet die Brücke zwischen den Pydantic-Modellen (API/Eingabe)
und der relationalen Datenbank (SQLAlchemy).

Hauptaufgaben:
- Normalisierung von verschiedenen Eingabeformaten (Raw-Liste oder Envelope).
- Deduplizierung von Findings vor dem Speichern.
- Transaktionale Verarbeitung über das Unit-of-Work-Pattern.
- Protokollierung von Importvorgängen (ImportRuns).
"""

from __future__ import annotations

import logging
from collections.abc import Iterable

from app.db.repository import UnitOfWork
from app.models.findings import (
    Finding as PydanticFinding,
)
from app.models.findings import (
    FindingsEnvelope,
    UnifiedFindingsInput,
)
from app.services.deduplication_service import DeduplicationService

# Logger initialisieren
logger = logging.getLogger(__name__)


def _normalize_unified_input(
    unified: UnifiedFindingsInput,
) -> tuple[str, list[PydanticFinding]]:
    """
    Normalisiert die unterschiedlichen Eingabeformen von Findings zu einem einheitlichen Format.
    Unterstützt:
    - FindingsEnvelope (v1): Extrahiert die Quelle und die Liste der Items.
    - Liste von Findings: Verwendet einen Standardwert ("lywand") als Quelle.
    Args:
        unified (UnifiedFindingsInput): Die zu normalisierende Eingabe.
    Returns:
        tuple[str, list[PydanticFinding]]: Ein Tupel bestehend aus
            (Datenquelle, Liste der Findings).
    """
    if isinstance(unified, list):
        # Einfache Liste von Findings (Legacy oder direktes Array)
        return "lywand", list(unified)

    # Strukturiertes Envelope-Format
    assert isinstance(unified, FindingsEnvelope)
    return unified.source, list(unified.items)


def save_findings(findings: Iterable[PydanticFinding]) -> int:
    """
    Persistiert eine Menge von validierten Findings in der Datenbank.

    Dieser Prozess beinhaltet:
    1. Deduplizierung der Findings im Speicher.
    2. Automatisches Anlegen von Tenants, falls nicht vorhanden.
    3. Automatisches Anlegen von Assets pro Tenant.
    4. Upsert (Insert oder Update) der Findings basierend auf ihrem Unique-Key.
    5. Verknüpfung mit Produkten.

    Hinweis: Diese Funktion führt keine Protokollierung eines ImportRun durch.
    Nutzen Sie 'intake_findings' für einen vollständigen Import-Workflow.

    Args:
        findings (Iterable[PydanticFinding]): Eine Sammlung von validierten Finding-Objekten.

    Returns:
        int: Die Anzahl der erfolgreich verarbeiteten Findings.
    """
    # In Liste umwandeln für mehrfache Iteration
    items = list(findings)
    if not items:
        return 0

    # 1. Schritt: Deduplizierung (z.B. gleiche CVE auf gleichem Host zusammenfassen)
    deduped_findings = DeduplicationService.deduplicate(items)
    saved_count = 0

    with UnitOfWork() as uow:
        for f in deduped_findings:
            # 1) Mandant (Tenant) sicherstellen
            tenant = uow.tenants.get_or_create(f.tenant)

            # 2) Asset (System) sicherstellen
            asset = uow.assets.get_or_create(
                tenant=tenant,
                name=f.target,
            )

            # 3) Finding persistieren (Neu oder Update)
            finding_orm = uow.findings.upsert_from_dto(
                tenant=tenant,
                asset=asset,
                dto=f,
                import_run=None,
            )

            # 4) Produktverknüpfungen aktualisieren/anlegen
            for product_name in f.products:
                product = uow.products.get_or_create(product_name)
                uow.findings.ensure_product_link(finding_orm, product)

            saved_count += 1

    return saved_count


def intake_findings(unified: UnifiedFindingsInput) -> int:
    """
    Führt einen vollständigen Import-Lauf für eine Menge von Findings durch.
    Im Gegensatz zu 'save_findings' wird hier ein 'ImportRun'-Datensatz erstellt,
    der den Status und die Statistik des Imports protokolliert.
    Ablauf:
    1. Normalisierung der Eingabedaten.
    2. Start eines ImportRun für den ermittelten Tenant.
    3. Iterative Verarbeitung und Persistierung der Findings.
    4. Abschluss des ImportRun mit Erfolg/Fehler-Statistik.
    Args:
        unified (UnifiedFindingsInput): Die zu importierenden Findings (Liste oder Envelope).
    Returns:
        int: Die Anzahl der erfolgreich importierten Findings.
    """
    source, items = _normalize_unified_input(unified)
    items_list = list(items)
    if not items_list:
        return 0

    # Deduplizierung vor dem Import
    deduped_items = DeduplicationService.deduplicate(items_list)

    success_count = 0
    failed_count = 0

    with UnitOfWork() as uow:
        if not deduped_items:
            return 0

        # Der erste Datensatz legt den Tenant des Importlaufs fest; abweichende
        # Datensätze werden unten als Fehler gezählt und nicht persistiert.
        tenant_name = deduped_items[0].tenant
        tenant = uow.tenants.get_or_create(tenant_name)

        # Flush erzwingen, um die Tenant-ID für den ImportRun zu erhalten
        assert uow.session is not None
        uow.session.flush()

        # Protokollierung des Imports starten
        import_run = uow.imports.start(
            tenant_id=tenant.id,
            source=source,
            total_records=len(deduped_items),
        )

        for dto in deduped_items:
            try:
                # Ein ImportRun ist genau einem Tenant zugeordnet.
                if dto.tenant != tenant_name:
                    logger.error(
                        f"Mandanten-Konflikt im Import-Lauf {import_run.id}: "
                        f"Erwartet wurde '{tenant_name}', gefunden wurde '{dto.tenant}' "
                        f"für Finding '{dto.name}' (Target: {dto.target})."
                    )
                    failed_count += 1
                    continue

                # Asset ermitteln bzw. anlegen
                asset = uow.assets.get_or_create(tenant=tenant, name=dto.target)

                # Finding upserten (CVE-basiert, fällt zurück auf Unique-Key, wenn keine CVE)
                finding_orm = uow.findings.upsert_by_cve(
                    tenant=tenant,
                    asset=asset,
                    dto=dto,
                    import_run=import_run,
                )

                # Produkte verknüpfen
                for product_name in dto.products:
                    product = uow.products.get_or_create(product_name)
                    uow.findings.ensure_product_link(finding_orm, product)

                success_count += 1
            except Exception as e:
                logger.exception(
                    f"Fehler beim Import eines Findings im Lauf {import_run.id} "
                    f"(Target: {dto.target}, Name: {dto.name}): {e}"
                )
                failed_count += 1

        # Import-Lauf in der Datenbank abschließen
        uow.imports.finish(
            import_run=import_run,
            successful_records=success_count,
            failed_records=failed_count,
        )

    return success_count
