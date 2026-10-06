"""
app/db/models.py

Datenbankmodelle für die VulnProcessing-Anwendung.

Diese Modelle definieren die zentralen Entitäten der Anwendung,
z. B. Mandanten, Assets, Produkte, CVEs, Findings und Tickets. Die
Definitionen basieren auf SQLAlchemys deklarativem ORM. Zur
Verwendung einer konsistenten Domänensprache werden mehrere Enum‑Typen
definiert, mit denen die verschiedenen Statusfelder der Anwendung
abgebildet werden.

Dieses Modul ist bewusst in sich geschlossen gehalten; jedes Modell
enthält Relationen, sinnvolle Defaults und Datenbank‑Constraints, um
Geschäftsregeln bereits auf Schemaebene durchzusetzen. Die Laufzeitinitialisierung
legt fehlende Tabellen an, migriert aber kein vorhandenes Schema. Modelländerungen
benötigen deshalb ein explizites, vor dem Deployment getestetes Migrationsskript.
"""

from __future__ import annotations

import enum
from datetime import UTC, datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """
    Basisklasse für alle ORM-Modelle.

    Eine gemeinsame Basisklasse ermöglicht es SQLAlchemy, alle Metadaten der Modelle
    an einer Stelle zu sammeln. Alle Modelle in diesem Modul erben von :class:`Base`
    und erhalten damit das Attribut ``metadata`` sowie das Standardverhalten für Primärschlüssel.
    """

    pass


class ImportRunStatus(enum.StrEnum):
    """
    Aufzählung aller zulässigen Zustände eines Importlaufs.

    Ein Importlauf entspricht einem Batch externer Daten, der ins System eingelesen wird.
    Der Status bildet den Lebenszyklus dieses Prozesses ab.
    """

    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"


class FindingStatus(enum.StrEnum):
    """
    Aufzählung aller zulässigen Zustände eines Findings.

    Findings durchlaufen mehrere Phasen: Sie werden zunächst als ``new`` angelegt,
    können als ``filtered`` markiert werden, wenn sie nicht relevant sind, gehen
    als ``queued`` in die Auswahl für die Ticketerstellung und wandern anschließend
    durch verschiedene Ticket-Status, bis sie schließlich ``resolved`` oder ``rejected`` sind.
    """

    NEW = "new"
    FILTERED = "filtered"
    QUEUED = "queued"
    TICKETING_IN_PROGRESS = "ticketing_in_progress"
    TICKET_CREATED = "ticket_created"
    TICKET_CONFIRMED = "ticket_confirmed"
    RESOLVED = "resolved"
    REJECTED = "rejected"


class TicketBatchStatus(enum.StrEnum):
    """
    Aufzählung aller zulässigen Zustände eines Ticket-Batches.
    Ticket-Batches fassen mehrere Findings zu einer Sammelverarbeitung für die
    Ticketerstellung zusammen. Der Status beschreibt den Fortschritt dieser Sammelverarbeitung.
    """

    CREATED = "created"
    DISPATCHING = "dispatching"
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIALLY_FAILED = "partially_failed"
    PARTIALLY_COMPLETED = "partially_completed"


class TicketStatus(enum.StrEnum):
    """
    Aufzählung aller zulässigen Zustände eines einzelnen Tickets.
    Tickets repräsentieren Arbeitsaufträge in einem externen System. Ihr Status
    spiegelt den Zustand in diesem externen System wieder. Ein Ticket startet
    mit ``open``, wechselt bei Bearbeitung zu ``in_progress`` und wird schließlich
    ``resolved`` oder ``closed``.
    """

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


class Tenant(Base):
    """
    Repräsentiert einen Mandanten bzw. eine organisatorische Einheit.
    Alle weiteren Entitäten im System sind über einen Fremdschlüssel einem Tenant zugeordnet.
    Das Löschen eines Tenants löscht alle zugehörigen Daten kaskadierend.
    """

    __tablename__ = "tenant"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))

    # Relationen
    assets: Mapped[list[Asset]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(back_populates="tenant")
    import_runs: Mapped[list[ImportRun]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan"
    )
    ticket_batches: Mapped[list[TicketBatch]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan"
    )


class Asset(Base):
    """
    Repräsentiert ein Gerät, einen Server oder ein sonstiges Asset eines Tenants.

    Die Kombination aus ``tenant_id`` und ``name`` muss eindeutig sein,
    um doppelte Assets innerhalb desselben Tenants zu verhindern.
    """

    __tablename__ = "asset"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_asset_tenant_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenant.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String, nullable=False)
    kind: Mapped[str | None] = mapped_column(String, nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))

    tenant: Mapped[Tenant] = relationship(back_populates="assets")
    findings: Mapped[list[Finding]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )


class Product(Base):
    """
    Repräsentiert ein Software- oder Hardware-Produkt, das in Findings vorkommt.

    Produkte werden von Findings über die Zuordnungstabelle ``FindingProduct``
    referenziert. Produktnamen sind global eindeutig.
    """

    __tablename__ = "product"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))

    finding_products: Mapped[list[FindingProduct]] = relationship(
        back_populates="product", cascade="all, delete-orphan"
    )


class CVE(Base):
    """
    Repräsentiert eine bekannte Schwachstellenkennung (Common Vulnerabilities and Exposures).
    """

    __tablename__ = "cve"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))

    finding_cves: Mapped[list[FindingCVE]] = relationship(
        back_populates="cve", cascade="all, delete-orphan"
    )


class ImportRun(Base):
    """
    Repräsentiert einen einzelnen Importvorgang für einen Tenant.

    Jeder Importlauf speichert, wie viele Datensätze verarbeitet wurden und ob
    der Vorgang erfolgreich war oder fehlgeschlagen ist. Mögliche Werte des
    Feldes ``status`` sind in :class:`ImportRunStatus` definiert.
    """

    __tablename__ = "import_run"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenant.id", ondelete="CASCADE"), nullable=False
    )
    source: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, default=ImportRunStatus.PENDING.value)
    total_records: Mapped[int] = mapped_column(Integer, default=0)
    successful_records: Mapped[int] = mapped_column(Integer, default=0)
    failed_records: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    tenant: Mapped[Tenant] = relationship(back_populates="import_runs")
    findings: Mapped[list[Finding]] = relationship(back_populates="import_run")


class TicketBatch(Base):
    """
    Fasst mehrere Findings für die Ticketerstellung zusammen.
    Müssen viele Findings an ein externes Ticketsystem übergeben werden, werden
    sie in einem Batch gebündelt. Der Batch speichert, wie viele Findings erfolgreich
    verarbeitet wurden und wie viele fehlgeschlagen sind.
    """

    __tablename__ = "ticket_batch"
    __table_args__ = (UniqueConstraint("tenant_id", "batch_number", name="uq_batch_tenant_number"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenant.id", ondelete="CASCADE"), nullable=False
    )
    batch_number: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String, default=TicketBatchStatus.CREATED.value)
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    successful_tickets: Mapped[int] = mapped_column(Integer, default=0)
    failed_tickets: Mapped[int] = mapped_column(Integer, default=0)
    external_batch_id: Mapped[str | None] = mapped_column(String, nullable=True)
    confirmation_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_system: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))
    sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    tenant: Mapped[Tenant] = relationship(back_populates="ticket_batches")
    findings: Mapped[list[Finding]] = relationship(
        back_populates="ticket_batch", foreign_keys="Finding.batch_id"
    )


class Finding(Base):
    """
    Repräsentiert eine einzelne Schwachstelle oder Fehlkonfiguration auf einem Asset.

    Jedes Finding gehört zu einem Tenant und einem Asset und optional zu einem
    Importlauf. Doppelte Findings innerhalb desselben Tenants (bezogen auf Asset,
    Name und Target) werden über eine Unique-Constraint verhindert.
    """

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "asset_id", "name", "target", name="uq_finding_tenant_asset_name_target"
        ),
        CheckConstraint("risk >= 0.0 AND risk <= 10.0", name="ck_finding_risk_range"),
        CheckConstraint("amount >= 1", name="ck_finding_amount_positive"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenant.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[int] = mapped_column(
        ForeignKey("asset.id", ondelete="CASCADE"), nullable=False
    )
    import_id: Mapped[int | None] = mapped_column(
        ForeignKey("import_run.id", ondelete="SET NULL"), nullable=True
    )

    name: Mapped[str] = mapped_column(String, nullable=False)
    # Hinweis: cve_id ist optionaler Freitext (muss nicht in der CVE‑Tabelle vorhanden sein)
    cve_id: Mapped[str | None] = mapped_column(String, nullable=True)
    risk: Mapped[float] = mapped_column(Float, nullable=False)
    amount: Mapped[int] = mapped_column(Integer, nullable=False)
    target: Mapped[str] = mapped_column(String, nullable=False)
    ticket_target: Mapped[str | None] = mapped_column(String, nullable=True)
    windows_version_hint: Mapped[str] = mapped_column(String, default="")
    extended_solution_json: Mapped[str] = mapped_column(Text, nullable=False)
    priority_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String, default=FindingStatus.NEW.value)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC)
    )
    batch_id: Mapped[int | None] = mapped_column(
        ForeignKey("ticket_batch.id", ondelete="SET NULL"), nullable=True
    )
    ticket_external_id: Mapped[str | None] = mapped_column(String, nullable=True)
    ticket_url: Mapped[str | None] = mapped_column(String, nullable=True)
    ticket_created_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ticket_confirmed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    tenant: Mapped[Tenant] = relationship(back_populates="findings")
    asset: Mapped[Asset] = relationship(back_populates="findings")
    import_run: Mapped[ImportRun | None] = relationship(back_populates="findings")
    products: Mapped[list[FindingProduct]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    cves: Mapped[list[FindingCVE]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    tickets: Mapped[list[Ticket]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    ticket_batch: Mapped[TicketBatch | None] = relationship(
        back_populates="findings", foreign_keys=[batch_id]
    )


class FindingProduct(Base):
    """Zuordnungstabelle, die Findings mit Produkten verknüpft."""

    __tablename__ = "finding_product"
    __table_args__ = (UniqueConstraint("finding_id", "product_id", name="uq_finding_product"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    product_id: Mapped[int] = mapped_column(
        ForeignKey("product.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))

    finding: Mapped[Finding] = relationship(back_populates="products")
    product: Mapped[Product] = relationship(back_populates="finding_products")


class FindingCVE(Base):
    """Zuordnungstabelle, die Findings mit CVEs verknüpft."""

    __tablename__ = "finding_cve"
    __table_args__ = (UniqueConstraint("finding_id", "cve_id", name="uq_finding_cve"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    cve_id: Mapped[int] = mapped_column(ForeignKey("cve.id", ondelete="CASCADE"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))

    finding: Mapped[Finding] = relationship(back_populates="cves")
    cve: Mapped[CVE] = relationship(back_populates="finding_cves")


class Ticket(Base):
    """Repräsentiert ein externes Ticket, das aus einem Finding erstellt wurde."""

    __tablename__ = "ticket"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    external_id: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, default=TicketStatus.OPEN.value)
    url: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC)
    )

    finding: Mapped[Finding] = relationship(back_populates="tickets")


class AuditLog(Base):
    """Speichert Änderungshistorien zu Entitäten für Audit‑Zwecke."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenant.id", ondelete="CASCADE"), nullable=False
    )
    entity_type: Mapped[str] = mapped_column(String, nullable=False)
    entity_id: Mapped[int] = mapped_column(Integer, nullable=False)
    action: Mapped[str] = mapped_column(String, nullable=False)
    old_values: Mapped[str | None] = mapped_column(Text, nullable=True)
    new_values: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))
