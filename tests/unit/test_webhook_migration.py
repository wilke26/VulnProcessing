from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine, text

from app.core.security import issue_dispatch_confirmation_token
from app.db.models import Tenant, TicketBatch, TicketBatchStatus
from app.services.composition_root import build_batch_ticketing_service
from scripts.migrate_webhook_confirmations import (
    backfill_legacy_pending_batches,
    count_legacy_pending_batches,
    count_pending_batches_without_token,
    main,
    needs_confirmation_token_column,
)


def test_backfill_updates_only_legacy_pending_batches_and_is_idempotent(db_session) -> None:
    tenant = Tenant(name="LegacyWebhookTenant")
    db_session.add(tenant)
    db_session.flush()
    existing_sent_at = datetime.now(UTC) - timedelta(days=1)
    legacy = TicketBatch(
        tenant_id=tenant.id,
        batch_number=1,
        status=TicketBatchStatus.PENDING.value,
        total_findings=1,
    )
    already_timestamped = TicketBatch(
        tenant_id=tenant.id,
        batch_number=2,
        status=TicketBatchStatus.PENDING.value,
        total_findings=1,
        sent_at=existing_sent_at,
    )
    created = TicketBatch(
        tenant_id=tenant.id,
        batch_number=3,
        status=TicketBatchStatus.CREATED.value,
        total_findings=1,
    )
    db_session.add_all([legacy, already_timestamped, created])
    db_session.commit()
    cutoff = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)

    connection = db_session.connection()
    assert count_legacy_pending_batches(connection) == 1
    assert backfill_legacy_pending_batches(connection, activated_at=cutoff) == 1
    db_session.commit()
    db_session.refresh(legacy)
    db_session.refresh(already_timestamped)
    db_session.refresh(created)

    assert legacy.sent_at == cutoff.replace(tzinfo=None)
    assert already_timestamped.sent_at == existing_sent_at.replace(tzinfo=None)
    assert created.sent_at is None
    assert count_legacy_pending_batches(connection) == 0
    assert (
        backfill_legacy_pending_batches(connection, activated_at=cutoff + timedelta(minutes=1)) == 0
    )
    db_session.refresh(legacy)
    assert legacy.sent_at == cutoff.replace(tzinfo=None)


def test_webhook_confirmation_requires_token_bound_to_active_dispatch(db_session) -> None:
    tenant = Tenant(name="LegacyWebhookConfirmationTenant")
    db_session.add(tenant)
    db_session.flush()
    stale_batch = TicketBatch(
        tenant_id=tenant.id,
        batch_number=1,
        status=TicketBatchStatus.PENDING.value,
        total_findings=0,
    )
    active_batch = TicketBatch(
        tenant_id=tenant.id,
        batch_number=2,
        status=TicketBatchStatus.PENDING.value,
        total_findings=0,
    )
    active_token, active_token_hash = issue_dispatch_confirmation_token()
    active_batch.confirmation_token_hash = active_token_hash
    db_session.add_all([stale_batch, active_batch])
    db_session.commit()
    cutoff = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)
    backfill_legacy_pending_batches(db_session.connection(), activated_at=cutoff)
    db_session.commit()
    service = build_batch_ticketing_service(db_session=db_session)

    stale_token, _ = issue_dispatch_confirmation_token()
    stale = service.confirm_batch_completion(
        batch_id=stale_batch.id,
        successful_count=0,
        dispatch_token=stale_token,
    )
    accepted = service.confirm_batch_completion(
        batch_id=active_batch.id,
        successful_count=0,
        dispatch_token=active_token,
    )

    assert stale["code"] == "invalid_batch_state"
    assert stale_batch.status == TicketBatchStatus.PENDING.value
    assert accepted["success"] is True
    assert active_batch.status == TicketBatchStatus.COMPLETED.value


def test_cli_uses_explicit_database_url_and_applies_backfill(tmp_path, capsys) -> None:
    database_url = f"sqlite:///{tmp_path / 'migration.sqlite3'}"
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE ticket_batch ("
                "id INTEGER PRIMARY KEY, status VARCHAR NOT NULL, sent_at DATETIME)"
            )
        )
        connection.execute(
            text("INSERT INTO ticket_batch (status, sent_at) VALUES ('completed', NULL)")
        )

    assert main(["--check-only", "--database-url", database_url]) == 1
    check_output = capsys.readouterr().out
    assert "Dispatch-token column required: True" in check_output
    assert main(["--apply", "--database-url", database_url]) == 0
    assert "Added dispatch-token column: True" in capsys.readouterr().out
    assert main(["--check-only", "--database-url", database_url]) == 0

    with engine.connect() as connection:
        assert needs_confirmation_token_column(connection) is False


def test_pending_batch_without_dispatch_token_remains_deployment_blocker(db_session) -> None:
    tenant = Tenant(name="TokenlessPendingTenant")
    db_session.add(tenant)
    db_session.flush()
    db_session.add(
        TicketBatch(
            tenant_id=tenant.id,
            batch_number=1,
            status=TicketBatchStatus.PENDING.value,
            total_findings=0,
            sent_at=datetime.now(UTC),
        )
    )
    db_session.commit()

    assert count_pending_batches_without_token(db_session.connection()) == 1
