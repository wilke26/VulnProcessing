"""
Dieses Modul implementiert das Repository-Pattern und das Unit-of-Work-Pattern.
Es bietet eine Abstraktionsschicht über den Datenbankzugriff für alle Hauptentitäten.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Query, Session

from app.db import models as orm_models
from app.db.engine import SessionLocal
from app.db.models import (
    FindingStatus,
    TicketBatch,
    TicketBatchStatus,
)
from app.models.findings import Finding as PydanticFinding

# ---------------------------------------------------------------------------
# Tenant Repository
# ---------------------------------------------------------------------------


class TenantRepository:
    """
    Repository für die Verwaltung von Mandanten (Tenants).
    """

    def __init__(self, session: Session):
        self.session = session

    def get_by_name(self, name: str) -> orm_models.Tenant | None:
        """Sucht einen Mandanten anhand seines Namens."""
        stmt = select(orm_models.Tenant).where(orm_models.Tenant.name == name)
        return self.session.scalars(stmt).first()

    def get_or_create(self, name: str) -> orm_models.Tenant:
        """Gibt einen Mandanten zurück oder erstellt ihn, falls er nicht existiert."""
        # 1) Zuerst in den neuen Objekten der Session suchen
        for obj in self.session.new:
            if isinstance(obj, orm_models.Tenant) and obj.name == name:
                return obj

        tenant = self.get_by_name(name)
        if tenant:
            return tenant
        tenant = orm_models.Tenant(name=name)
        self.session.add(tenant)
        return tenant


# ---------------------------------------------------------------------------
# Asset Repository
# ---------------------------------------------------------------------------


class AssetRepository:
    """
    Repository für die Verwaltung von Assets (Geräten).
    """

    def __init__(self, session: Session):
        self.session = session

    def add(self, entity: orm_models.Asset) -> None:
        """Fügt ein neues Asset hinzu."""
        self.session.add(entity)

    def get_or_create(self, tenant: orm_models.Tenant, name: str) -> orm_models.Asset:
        """Sucht ein Asset innerhalb eines Tenants oder erstellt es neu."""
        # 1) Zuerst in den neuen Objekten der Session suchen
        for obj in self.session.new:
            if isinstance(obj, orm_models.Asset) and obj.tenant is tenant and obj.name == name:
                return obj

        # 2) Falls Tenant schon eine ID hat, in der DB suchen
        if tenant.id is not None:
            stmt = select(orm_models.Asset).where(
                orm_models.Asset.tenant_id == tenant.id,
                orm_models.Asset.name == name,
            )
            asset = self.session.scalars(stmt).first()
            if asset:
                return asset

        # 3) Andernfalls neues Asset anlegen, Beziehung zum Tenant setzen
        asset = orm_models.Asset(tenant=tenant, name=name)
        self.session.add(asset)
        return asset


# ---------------------------------------------------------------------------
# Product Repository
# ---------------------------------------------------------------------------


class ProductRepository:
    """
    Repository für die Verwaltung von Software-Produkten.
    """

    def __init__(self, session: Session):
        self.session = session

    def add(self, entity: orm_models.Product) -> None:
        """Fügt ein neues Produkt hinzu."""
        self.session.add(entity)

    def get_or_create(self, name: str) -> orm_models.Product:
        """Sucht ein Produkt anhand des Namens oder erstellt es neu."""
        # 1) Zuerst in den neuen Objekten der Session suchen (noch nicht geflusht)
        for obj in self.session.new:
            if isinstance(obj, orm_models.Product) and obj.name == name:
                return obj

        # 2) In der Datenbank nach einem bestehenden Product suchen
        stmt = select(orm_models.Product).where(orm_models.Product.name == name)
        product = self.session.scalars(stmt).first()
        if product:
            return product

        # 3) Falls nicht vorhanden, neu anlegen
        product = orm_models.Product(name=name)
        self.session.add(product)
        return product


# ---------------------------------------------------------------------------
# CVE Repository
# ---------------------------------------------------------------------------


class CVERepository:
    """
    Repository für die Verwaltung von CVE-Einträgen.
    """

    def __init__(self, session: Session):
        self.session = session

    def add(self, entity: orm_models.CVE) -> None:
        """Fügt einen neuen CVE-Eintrag hinzu."""
        self.session.add(entity)

    def get_or_create(self, cve_id: str) -> orm_models.CVE:
        """Sucht einen CVE-Eintrag anhand seiner ID oder erstellt ihn neu."""
        stmt = select(orm_models.CVE).where(orm_models.CVE.cve_id == cve_id)
        cve = self.session.scalars(stmt).first()
        if not cve:
            cve = orm_models.CVE(cve_id=cve_id)
            self.session.add(cve)
        return cve


# ---------------------------------------------------------------------------
# ImportRun Repository
# ---------------------------------------------------------------------------


class ImportRunRepository:
    """
    Repository zur Protokollierung von Importvorgängen.
    """

    def __init__(self, session: Session):
        self.session = session

    def start(
        self,
        tenant_id: int,
        source: str,
        total_records: int,
    ) -> orm_models.ImportRun:
        """Markiert den Beginn eines neuen Importlaufs."""
        import_run = orm_models.ImportRun(
            tenant_id=tenant_id,
            source=source,
            status="pending",
            total_records=total_records,
            successful_records=0,
            failed_records=0,
            started_at=datetime.now(UTC),
        )
        self.session.add(import_run)
        return import_run

    def finish(
        self,
        import_run: orm_models.ImportRun,
        successful_records: int,
        failed_records: int,
        error_message: str | None = None,
    ) -> None:
        """Markiert einen Importlauf als abgeschlossen und speichert Statistiken."""
        import_run.successful_records = successful_records
        import_run.failed_records = failed_records
        import_run.status = (
            "completed" if failed_records == 0 and error_message is None else "failed"
        )
        import_run.error_message = error_message
        import_run.completed_at = datetime.now(UTC)


# ---------------------------------------------------------------------------
# TicketBatch Repository – für Ticket-Batch-Verwaltung
# ---------------------------------------------------------------------------


class TicketBatchRepository:
    """
    Repository für die Verwaltung von Ticket-Batches.
    Handhabt die Gruppierung von Findings für externe Systeme.
    """

    def __init__(self, session: Session):
        self.session = session

    def create_batch(
        self,
        tenant_id: int,
        findings: list[orm_models.Finding],
        target_system: str = "unknown",
    ) -> TicketBatch:
        """Erstellt einen neuen Batch für die Ticketerstellung."""
        # Nächste Batch-Nummer für diesen Tenant ermitteln
        max_batch = self.session.execute(
            select(func.max(TicketBatch.batch_number)).where(TicketBatch.tenant_id == tenant_id)
        ).scalar()

        next_batch_number = (max_batch or 0) + 1

        batch = TicketBatch(
            tenant_id=tenant_id,
            batch_number=next_batch_number,
            total_findings=len(findings),
            target_system=target_system,
            status=TicketBatchStatus.CREATED.value,
        )

        self.session.add(batch)
        self.session.flush()  # Batch-ID generieren

        # Findings mit Batch verknüpfen
        for finding in findings:
            finding.batch_id = batch.id
            finding.status = FindingStatus.QUEUED.value

        return batch

    def get_next_pending_batch(self, tenant_id: int) -> TicketBatch | None:
        """Sucht den nächsten zu verarbeitenden Batch eines Tenants."""
        return self.session.execute(
            select(TicketBatch)
            .where(
                TicketBatch.tenant_id == tenant_id,
                TicketBatch.status.in_(
                    [
                        TicketBatchStatus.CREATED.value,
                        TicketBatchStatus.PENDING.value,
                    ]
                ),
            )
            .order_by(TicketBatch.batch_number.asc())
            .limit(1)
        ).scalar_one_or_none()

    def mark_batch_sent(
        self,
        batch: TicketBatch,
        external_id: str | None = None,
        confirmation_token_hash: str | None = None,
    ) -> None:
        """Markiert einen Batch als an das externe System gesendet."""
        batch.status = TicketBatchStatus.PENDING.value
        batch.sent_at = datetime.now(UTC)
        batch.confirmation_token_hash = confirmation_token_hash
        if external_id:
            batch.external_batch_id = external_id

        # Findings im Batch aktualisieren
        for finding in batch.findings:
            finding.status = FindingStatus.TICKETING_IN_PROGRESS.value

    def mark_batch_completed(
        self,
        batch: TicketBatch,
        successful: int,
        failed: int = 0,
    ) -> None:
        """Markiert einen Batch als vollständig verarbeitet."""
        batch.successful_tickets = successful
        batch.failed_tickets = failed
        batch.completed_at = datetime.now(UTC)

        if failed == 0:
            batch.status = TicketBatchStatus.COMPLETED.value
        elif successful > 0:
            batch.status = TicketBatchStatus.PARTIALLY_COMPLETED.value
        else:
            batch.status = TicketBatchStatus.FAILED.value

    def mark_batch_failed(self, batch: TicketBatch, error_message: str) -> None:
        """Markiert einen Batch als fehlgeschlagen und setzt Findings zurück."""
        batch.status = TicketBatchStatus.FAILED.value
        batch.last_error = error_message
        batch.confirmation_token_hash = None
        batch.retry_count += 1
        batch.completed_at = datetime.now(UTC)

        # Findings zurücksetzen, damit sie erneut verarbeitet werden können
        for finding in batch.findings:
            finding.status = FindingStatus.NEW.value
            finding.batch_id = None

    def mark_batch_dispatch_partially_failed(
        self,
        batch: TicketBatch,
        error_message: str,
        successful_finding_ids: frozenset[int],
    ) -> None:
        """Record a terminal partial dispatch without retrying successful side effects."""

        failed_at = datetime.now(UTC)
        batch.status = TicketBatchStatus.PARTIALLY_FAILED.value
        batch.last_error = error_message
        batch.confirmation_token_hash = None
        batch.retry_count += 1
        batch.sent_at = failed_at
        batch.completed_at = failed_at

        for finding in batch.findings:
            finding.status = (
                FindingStatus.TICKET_CREATED.value
                if finding.id in successful_finding_ids
                else FindingStatus.QUEUED.value
            )

    def get_batch_by_id(self, batch_id: int) -> TicketBatch | None:
        """Ruft einen Batch anhand seiner ID ab."""
        return self.session.get(TicketBatch, batch_id)

    def get_batch_statistics(self, tenant_id: int) -> dict[str, Any]:
        """Ermittelt Statistiken über Batches eines Tenants."""
        stats = self.session.execute(
            select(
                TicketBatch.status,
                func.count(TicketBatch.id).label("count"),
                func.sum(TicketBatch.total_findings).label("total_findings"),
                func.sum(TicketBatch.successful_tickets).label("successful"),
                func.sum(TicketBatch.failed_tickets).label("failed"),
            )
            .where(TicketBatch.tenant_id == tenant_id)
            .group_by(TicketBatch.status)
        ).all()

        return {
            "by_status": [
                {
                    "status": row.status,
                    "count": row.count,
                    "total_findings": row.total_findings or 0,
                    "successful": row.successful or 0,
                    "failed": row.failed or 0,
                }
                for row in stats
            ]
        }


# ---------------------------------------------------------------------------
# Finding Repository – erweitert um Intake- und Ticketing-Funktionen
# ---------------------------------------------------------------------------


class FindingRepository:
    """
    Repository für die Verwaltung von Findings (Sicherheitsergebnissen).
    """

    def __init__(self, session: Session):
        self.session = session

    # ------------------------ Basis-CRUD ------------------------

    def add(self, entity: orm_models.Finding) -> None:
        """Fügt ein einzelnes Finding hinzu."""
        self.session.add(entity)

    def add_all(self, entities: Iterable[orm_models.Finding]) -> None:
        """Fügt mehrere Findings hinzu."""
        for e in entities:
            self.session.add(e)

    def get_all(self) -> Query:
        """Gibt eine Basis-Query für alle Findings zurück."""
        return self.session.query(orm_models.Finding)

    def get_by_id(self, id: int) -> orm_models.Finding | None:
        """Ruft ein Finding anhand seiner ID ab."""
        return self.session.get(orm_models.Finding, id)

    def get_by_tenant_asset(
        self,
        tenant_id: int,
        asset_id: int,
    ) -> list[orm_models.Finding]:
        """Sucht alle Findings für ein bestimmtes Asset eines Tenants."""
        stmt = select(orm_models.Finding).where(
            (orm_models.Finding.tenant_id == tenant_id) & (orm_models.Finding.asset_id == asset_id)
        )
        return list(self.session.scalars(stmt).all())

    def get_by_cve(
        self,
        tenant: orm_models.Tenant,
        cve_id: str,
    ) -> list[orm_models.Finding]:
        """Sucht Findings eines Tenants anhand einer CVE-ID."""
        stmt = select(orm_models.Finding).where(
            orm_models.Finding.tenant_id == tenant.id,
            orm_models.Finding.cve_id == cve_id,
        )
        return list(self.session.scalars(stmt).all())

    def upsert_by_cve(
        self,
        tenant: orm_models.Tenant,
        asset: orm_models.Asset,
        dto: PydanticFinding,
        import_run: orm_models.ImportRun | None = None,
    ) -> orm_models.Finding:
        """
        Legt ein Finding neu an oder aktualisiert es, wenn für denselben Tenant
        bereits Findings mit gleicher CVE-ID existieren.
        Aggregation über mehrere Assets hinweg: Risk = Max, Amount = Summe.
        """

        if not dto.cve_id:
            # Fallback: keine CVE-ID vorhanden → Standardverhalten
            return self.upsert_from_dto(tenant, asset, dto, import_run)

        existing_findings = self.get_by_cve(tenant, dto.cve_id)

        if existing_findings:
            # Aggregation über alle Findings mit derselben CVE-ID
            target_finding = max(existing_findings, key=lambda f: f.risk)

            target_finding.risk = max(target_finding.risk, dto.risk)
            target_finding.amount = sum(f.amount for f in existing_findings) + dto.amount
            target_finding.last_seen = datetime.now(UTC)
            target_finding.import_run = import_run

            return target_finding

        # Kein bestehendes Finding mit dieser CVE-ID → Standard-Anlage
        return self.upsert_from_dto(tenant, asset, dto, import_run)

    def delete(self, entity: orm_models.Finding) -> None:
        """Löscht ein Finding."""
        self.session.delete(entity)

    # ------------------------ Query-Hilfen für Batch-Ticketing ------------------------

    def get_unprocessed_findings(
        self,
        tenant_id: int,
        limit: int,
        min_risk: float = 0.0,
    ) -> list[orm_models.Finding]:
        """
        Liefert die nächsten unverarbeiteten Findings für einen Tenant,
        sortiert nach Risk (absteigend).
        """
        stmt = (
            select(orm_models.Finding)
            .where(orm_models.Finding.tenant_id == tenant_id)
            .where(orm_models.Finding.status == FindingStatus.NEW.value)
            .where(orm_models.Finding.risk >= min_risk)
            .order_by(orm_models.Finding.risk.desc())
            .limit(limit)
        )
        return list(self.session.scalars(stmt).all())

    # ------------------------ Intake-spezifische Hilfen ------------------------

    def get_by_unique_key(
        self,
        tenant: orm_models.Tenant,
        asset: orm_models.Asset,
        name: str,
        target: str,
    ) -> orm_models.Finding | None:
        """Sucht ein Finding anhand seines eindeutigen Schlüssels."""
        if tenant.id is None or asset.id is None:
            return None

        stmt = (
            select(orm_models.Finding)
            .where(orm_models.Finding.tenant_id == tenant.id)
            .where(orm_models.Finding.asset_id == asset.id)
            .where(orm_models.Finding.name == name)
            .where(orm_models.Finding.target == target)
        )
        return self.session.scalars(stmt).first()

    def upsert_from_dto(
        self,
        tenant: orm_models.Tenant,
        asset: orm_models.Asset,
        dto: PydanticFinding,
        import_run: orm_models.ImportRun | None = None,
    ) -> orm_models.Finding:
        """
        Legt ein Finding neu an oder aktualisiert es anhand des 'unique key'
        (tenant, asset, name, target).
        """
        now = datetime.now(UTC)

        existing = self.get_by_unique_key(
            tenant=tenant,
            asset=asset,
            name=dto.name,
            target=dto.target,
        )

        extended_solution_json = json.dumps(
            dto.extendedSolution,
            ensure_ascii=False,
        )

        if existing is not None:
            existing.risk = dto.risk
            existing.amount = dto.amount
            existing.target = dto.target
            existing.windows_version_hint = dto.windowsVersionHint
            existing.extended_solution_json = extended_solution_json
            existing.last_seen = now
            existing.import_run = import_run
            return existing

        finding = orm_models.Finding(
            tenant=tenant,
            asset=asset,
            import_run=import_run,
            name=dto.name,
            risk=dto.risk,
            amount=dto.amount,
            target=dto.target,
            windows_version_hint=dto.windowsVersionHint,
            extended_solution_json=extended_solution_json,
            first_seen=now,
            last_seen=now,
            status=FindingStatus.NEW.value,
        )
        self.session.add(finding)
        return finding

    def ensure_product_link(
        self,
        finding: orm_models.Finding,
        product: orm_models.Product,
    ) -> orm_models.FindingProduct:
        """Stellt sicher, dass eine Verknüpfung zwischen Finding und Produkt existiert."""
        for obj in self.session.new:
            if (
                isinstance(obj, orm_models.FindingProduct)
                and obj.finding is finding
                and obj.product is product
            ):
                return obj

        if finding.id is not None and product.id is not None:
            stmt = (
                select(orm_models.FindingProduct)
                .where(orm_models.FindingProduct.finding_id == finding.id)
                .where(orm_models.FindingProduct.product_id == product.id)
            )
            existing = self.session.scalars(stmt).first()
            if existing:
                return existing

        link = orm_models.FindingProduct(
            finding=finding,
            product=product,
        )
        self.session.add(link)
        return link

    # ------------------------ Ticket-spezifische Hilfen ------------------------

    def mark_finding_ticket_created(
        self,
        finding: orm_models.Finding,
        external_id: str | None,
        ticket_url: str | None,
    ) -> None:
        """Setzt den Status eines Findings auf 'ticket_created'."""
        finding.status = FindingStatus.TICKET_CREATED.value
        finding.ticket_external_id = external_id
        finding.ticket_url = ticket_url
        finding.ticket_created_at = datetime.now(UTC)

    def mark_finding_confirmed(
        self,
        finding: orm_models.Finding,
    ) -> None:
        """Markiert ein Finding als bestätigt."""
        finding.status = FindingStatus.TICKET_CONFIRMED.value
        finding.ticket_confirmed_at = datetime.now(UTC)


# ---------------------------------------------------------------------------
# Unit of Work – um neue Repositories erweitert
# ---------------------------------------------------------------------------


class UnitOfWork:
    """
    Implementiert das Unit-of-Work-Pattern zur Kapselung von Datenbanktransaktionen.
    Stellt Repositories als Properties bereit und automatisiert Commit/Rollback.
    """

    def __init__(self):
        self._session: Session | None = None

        self._tenants_repo: TenantRepository | None = None
        self._assets_repo: AssetRepository | None = None
        self._findings_repo: FindingRepository | None = None
        self._products_repo: ProductRepository | None = None
        self._cves_repo: CVERepository | None = None
        self._imports_repo: ImportRunRepository | None = None
        self._batches_repo: TicketBatchRepository | None = None

    @property
    def session(self) -> Session:
        """Gibt die aktuelle Datenbank-Session zurück."""
        if self._session is None:
            raise RuntimeError(
                "Session is not initialized. "
                "Use 'with UnitOfWork() as uow:' before accessing 'uow.session'."
            )
        return self._session

    def __enter__(self) -> UnitOfWork:
        """Initialisiert die Session beim Betreten des Kontexts."""
        self._session = SessionLocal()
        self._tenants_repo = None
        self._assets_repo = None
        self._findings_repo = None
        self._products_repo = None
        self._cves_repo = None
        self._imports_repo = None
        self._batches_repo = None
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb,
    ) -> None:
        """Führt Commit bei Erfolg oder Rollback bei Fehlern durch."""
        session = self._session
        if session is None:
            return
        try:
            if exc_type:
                session.rollback()
            else:
                session.commit()
        finally:
            session.close()
            self._session = None

    # ------------------------ Repositories als Properties ------------------------

    @property
    def tenants(self) -> TenantRepository:
        """Gibt das Tenant-Repository zurück."""
        assert self._session is not None
        if self._tenants_repo is None:
            self._tenants_repo = TenantRepository(self._session)
        return self._tenants_repo

    @property
    def assets(self) -> AssetRepository:
        """Gibt das Asset-Repository zurück."""
        assert self._session is not None
        if self._assets_repo is None:
            self._assets_repo = AssetRepository(self._session)
        return self._assets_repo

    @property
    def findings(self) -> FindingRepository:
        """Gibt das Finding-Repository zurück."""
        assert self._session is not None
        if self._findings_repo is None:
            self._findings_repo = FindingRepository(self._session)
        return self._findings_repo

    @property
    def products(self) -> ProductRepository:
        """Gibt das Produkt-Repository zurück."""
        assert self._session is not None
        if self._products_repo is None:
            self._products_repo = ProductRepository(self._session)
        return self._products_repo

    @property
    def cves(self) -> CVERepository:
        """Gibt das CVE-Repository zurück."""
        assert self._session is not None
        if self._cves_repo is None:
            self._cves_repo = CVERepository(self._session)
        return self._cves_repo

    @property
    def imports(self) -> ImportRunRepository:
        """Gibt das Import-Repository zurück."""
        assert self._session is not None
        if self._imports_repo is None:
            self._imports_repo = ImportRunRepository(self._session)
        return self._imports_repo

    @property
    def batches(self) -> TicketBatchRepository:
        """Gibt das Batch-Repository zurück."""
        assert self._session is not None
        if self._batches_repo is None:
            self._batches_repo = TicketBatchRepository(self._session)
        return self._batches_repo
