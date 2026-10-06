"""Prepare legacy ticket batches for authenticated webhook confirmations."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import Connection, create_engine, inspect, text

_TICKET_BATCH_TABLE = "ticket_batch"
_CONFIRMATION_TOKEN_COLUMN = "confirmation_token_hash"


def needs_confirmation_token_column(connection: Connection) -> bool:
    """Return whether an existing batch table needs the dispatch-token column."""
    inspector = inspect(connection)
    if not inspector.has_table(_TICKET_BATCH_TABLE):
        return False
    columns = {column["name"] for column in inspector.get_columns(_TICKET_BATCH_TABLE)}
    return _CONFIRMATION_TOKEN_COLUMN not in columns


def add_confirmation_token_column(connection: Connection) -> bool:
    """Add the nullable token digest column to an existing batch table once."""
    if not needs_confirmation_token_column(connection):
        return False
    connection.execute(
        text("ALTER TABLE ticket_batch ADD COLUMN confirmation_token_hash VARCHAR(64)")
    )
    return True


def count_pending_batches_without_token(connection: Connection) -> int:
    """Count pending batches that cannot satisfy the dispatch-bound token contract."""
    inspector = inspect(connection)
    if not inspector.has_table(_TICKET_BATCH_TABLE):
        return 0
    if needs_confirmation_token_column(connection):
        statement = text("SELECT COUNT(*) FROM ticket_batch WHERE status = 'pending'")
    else:
        statement = text(
            "SELECT COUNT(*) FROM ticket_batch "
            "WHERE status = 'pending' AND confirmation_token_hash IS NULL"
        )
    return int(connection.scalar(statement) or 0)


def count_legacy_pending_batches(connection: Connection) -> int:
    """Count pending batches that predate persisted dispatch timestamps."""
    if not inspect(connection).has_table(_TICKET_BATCH_TABLE):
        return 0
    count = connection.scalar(
        text("SELECT COUNT(*) FROM ticket_batch " "WHERE status = 'pending' AND sent_at IS NULL")
    )
    return int(count or 0)


def backfill_legacy_pending_batches(
    connection: Connection,
    *,
    activated_at: datetime | None = None,
) -> int:
    """Set a rollout cutoff for legacy pending batches without changing other rows."""
    cutoff = activated_at or datetime.now(UTC)
    if cutoff.tzinfo is None:
        raise ValueError("activated_at must be timezone-aware")
    if not inspect(connection).has_table(_TICKET_BATCH_TABLE):
        return 0

    result = connection.execute(
        text(
            "UPDATE ticket_batch SET sent_at = :cutoff "
            "WHERE status = 'pending' AND sent_at IS NULL"
        ),
        {"cutoff": cutoff.astimezone(UTC).replace(tzinfo=None)},
    )
    return int(result.rowcount or 0)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Find or migrate pending ticket batches without a dispatch timestamp."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check-only", action="store_true", help="Report affected rows only.")
    mode.add_argument("--apply", action="store_true", help="Apply the idempotent backfill.")
    parser.add_argument(
        "--database-url",
        required=True,
        help="Explicit SQLAlchemy URL for the database to inspect or migrate.",
    )
    args = parser.parse_args(argv)

    engine = create_engine(args.database_url)
    try:
        with engine.begin() as connection:
            affected = count_legacy_pending_batches(connection)
            schema_change_required = needs_confirmation_token_column(connection)
            pending_without_token = count_pending_batches_without_token(connection)
            if args.check_only:
                print(f"Legacy pending batches without sent_at: {affected}")
                print(f"Dispatch-token column required: {schema_change_required}")
                print(f"Pending batches without a dispatch token: {pending_without_token}")
                return 1 if affected or schema_change_required or pending_without_token else 0

            column_added = add_confirmation_token_column(connection)
            migrated = backfill_legacy_pending_batches(connection)
            pending_without_token = count_pending_batches_without_token(connection)
            print(f"Added dispatch-token column: {column_added}")
            print(f"Migrated legacy pending batches: {migrated}")
            print(f"Pending batches without a dispatch token: {pending_without_token}")
            if pending_without_token:
                print(
                    "Pending batches without a token must be resolved before deployment; "
                    "a secure token cannot be backfilled for an already dispatched batch."
                )
                return 1
            return 0
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
