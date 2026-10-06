"""
Initiales Datenbankschema für VulnProcessing.

Diese Alembic-Migration legt die grundlegenden Tabellen für die Anwendung an.
Sie umfasst Entitäten für Mandanten (Tenants), Geräte (Assets), Produkte,
Schwachstellen (CVEs), Importprozesse, Sicherheitsergebnisse (Findings),
Ticket-Batches und Audit-Logs.

Hinweis: Um die Kompatibilität mit SQLite zu wahren, werden Statusfelder als
Strings und nicht als native Datenbank-Enums gespeichert.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# Revisions-Identifikatoren, von Alembic zur Versionssteuerung verwendet.
revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """
    Erstellt alle Tabellen und Constraints für das initiale Schema.
    Wird beim Ausführen von 'alembic upgrade head' aufgerufen.
    """
    # ### von Alembic automatisch generierte Anweisungen – bei Bedarf anpassen! ###

    # Tabelle für Mandanten/Kunden
    op.create_table(
        "tenant",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(), nullable=False, unique=True),
        sa.Column(
            "created_at", sa.DateTime(), nullable=True, server_default=sa.text("CURRENT_TIMESTAMP")
        ),
    )

    # Tabelle für Assets (Systeme/Hosts) eines Mandanten
    op.create_table(
        "asset",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=True),
        sa.Column("metadata_json", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(), nullable=True, server_default=sa.text("CURRENT_TIMESTAMP")
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenant.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "name", name="uq_asset_tenant_name"),
    )

    # Tabelle für Software-Produkte
    op.create_table(
        "product",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(), nullable=False, unique=True),
        sa.Column(
            "created_at", sa.DateTime(), nullable=True, server_default=sa.text("CURRENT_TIMESTAMP")
        ),
    )

    # Tabelle für CVE-Informationen (Katalog)
    op.create_table(
        "cve",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("cve_id", sa.String(), nullable=False, unique=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(), nullable=True, server_default=sa.text("CURRENT_TIMESTAMP")
        ),
    )

    # Tabelle zur Protokollierung von Importvorgängen
    op.create_table(
        "import_run",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=True, server_default=sa.text("'pending'")),
        sa.Column("total_records", sa.Integer(), nullable=True, server_default=sa.text("0")),
        sa.Column("successful_records", sa.Integer(), nullable=True, server_default=sa.text("0")),
        sa.Column("failed_records", sa.Integer(), nullable=True, server_default=sa.text("0")),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "started_at", sa.DateTime(), nullable=True, server_default=sa.text("CURRENT_TIMESTAMP")
        ),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenant.id"], ondelete="CASCADE"),
    )

    # Tabelle für zusammengefasste Ticket-Batches
    op.create_table(
        "ticket_batch",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("batch_number", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(), nullable=True, server_default=sa.text("'created'")),
        sa.Column("total_findings", sa.Integer(), nullable=True, server_default=sa.text("0")),
        sa.Column("successful_tickets", sa.Integer(), nullable=True, server_default=sa.text("0")),
        sa.Column("failed_tickets", sa.Integer(), nullable=True, server_default=sa.text("0")),
        sa.Column("external_batch_id", sa.String(), nullable=True),
        sa.Column("confirmation_token_hash", sa.String(length=64), nullable=True),
        sa.Column("target_system", sa.String(), nullable=True, server_default=sa.text("''")),
        sa.Column(
            "created_at", sa.DateTime(), nullable=True, server_default=sa.text("CURRENT_TIMESTAMP")
        ),
        sa.Column("sent_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("retry_count", sa.Integer(), nullable=True, server_default=sa.text("0")),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenant.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "batch_number", name="uq_batch_tenant_number"),
    )

    # Haupttabelle für Findings (Sicherheitsergebnisse)
    op.create_table(
        "finding",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("import_id", sa.Integer(), nullable=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("cve_id", sa.String(), nullable=True),
        sa.Column("risk", sa.Float(), nullable=False),
        sa.Column("amount", sa.Integer(), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("windows_version_hint", sa.String(), nullable=True, server_default=sa.text("''")),
        sa.Column("extended_solution_json", sa.Text(), nullable=False),
        sa.Column("priority_score", sa.Float(), nullable=True),
        sa.Column("status", sa.String(), nullable=True, server_default=sa.text("'new'")),
        sa.Column(
            "first_seen", sa.DateTime(), nullable=True, server_default=sa.text("CURRENT_TIMESTAMP")
        ),
        sa.Column(
            "last_seen", sa.DateTime(), nullable=True, server_default=sa.text("CURRENT_TIMESTAMP")
        ),
        sa.Column(
            "created_at", sa.DateTime(), nullable=True, server_default=sa.text("CURRENT_TIMESTAMP")
        ),
        sa.Column(
            "updated_at", sa.DateTime(), nullable=True, server_default=sa.text("CURRENT_TIMESTAMP")
        ),
        sa.Column("batch_id", sa.Integer(), nullable=True),
        sa.Column("ticket_external_id", sa.String(), nullable=True),
        sa.Column("ticket_url", sa.String(), nullable=True),
        sa.Column("ticket_created_at", sa.DateTime(), nullable=True),
        sa.Column("ticket_confirmed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenant.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["asset_id"], ["asset.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["import_id"], ["import_run.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["batch_id"], ["ticket_batch.id"], ondelete="SET NULL"),
        sa.UniqueConstraint(
            "tenant_id", "asset_id", "name", "target", name="uq_finding_tenant_asset_name_target"
        ),
        sa.CheckConstraint("risk >= 0.0 AND risk <= 10.0", name="ck_finding_risk_range"),
        sa.CheckConstraint("amount >= 1", name="ck_finding_amount_positive"),
    )

    # Zuordnungstabelle Findings <-> Produkte (Many-to-Many)
    op.create_table(
        "finding_product",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("finding_id", sa.Integer(), nullable=False),
        sa.Column("product_id", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(), nullable=True, server_default=sa.text("CURRENT_TIMESTAMP")
        ),
        sa.ForeignKeyConstraint(["finding_id"], ["finding.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["product_id"], ["product.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("finding_id", "product_id", name="uq_finding_product"),
    )

    # Zuordnungstabelle Findings <-> CVEs (Many-to-Many)
    op.create_table(
        "finding_cve",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("finding_id", sa.Integer(), nullable=False),
        sa.Column("cve_id", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(), nullable=True, server_default=sa.text("CURRENT_TIMESTAMP")
        ),
        sa.ForeignKeyConstraint(["finding_id"], ["finding.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["cve_id"], ["cve.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("finding_id", "cve_id", name="uq_finding_cve"),
    )

    # Tabelle für externe Tickets
    op.create_table(
        "ticket",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("finding_id", sa.Integer(), nullable=False),
        sa.Column("external_id", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=True, server_default=sa.text("'open'")),
        sa.Column("url", sa.String(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(), nullable=True, server_default=sa.text("CURRENT_TIMESTAMP")
        ),
        sa.Column(
            "updated_at", sa.DateTime(), nullable=True, server_default=sa.text("CURRENT_TIMESTAMP")
        ),
        sa.ForeignKeyConstraint(["finding_id"], ["finding.id"], ondelete="CASCADE"),
    )

    # Audit-Log zur Nachverfolgung von Änderungen
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("entity_type", sa.String(), nullable=False),
        sa.Column("entity_id", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("old_values", sa.Text(), nullable=True),
        sa.Column("new_values", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(), nullable=True, server_default=sa.text("CURRENT_TIMESTAMP")
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenant.id"], ondelete="CASCADE"),
    )
    # ### Ende der von Alembic generierten Anweisungen ###


def downgrade() -> None:
    """
    Entfernt alle Tabellen des Schemas in umgekehrter Reihenfolge.
    Wird beim Ausführen von 'alembic downgrade head-1' (oder ähnlichem) aufgerufen.
    """
    # ### von Alembic automatisch generierte Anweisungen – bei Bedarf anpassen! ###
    op.drop_table("audit_log")
    op.drop_table("ticket")
    op.drop_table("finding_cve")
    op.drop_table("finding_product")
    op.drop_table("finding")
    op.drop_table("ticket_batch")
    op.drop_table("import_run")
    op.drop_table("cve")
    op.drop_table("product")
    op.drop_table("asset")
    op.drop_table("tenant")
    # ### Ende der von Alembic generierten Anweisungen ###
