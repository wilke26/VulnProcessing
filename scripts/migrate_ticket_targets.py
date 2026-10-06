"""Add the optional filtered dispatch target to existing findings tables."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from sqlalchemy import Connection, create_engine, inspect, text

_FINDINGS_TABLE = "findings"
_TICKET_TARGET_COLUMN = "ticket_target"


def needs_ticket_target_column(connection: Connection) -> bool:
    """Return whether an existing findings table needs the dispatch-target column."""
    inspector = inspect(connection)
    if not inspector.has_table(_FINDINGS_TABLE):
        return False
    columns = {column["name"] for column in inspector.get_columns(_FINDINGS_TABLE)}
    return _TICKET_TARGET_COLUMN not in columns


def add_ticket_target_column(connection: Connection) -> bool:
    """Add the nullable dispatch-target column once."""
    if not needs_ticket_target_column(connection):
        return False
    connection.execute(text("ALTER TABLE findings ADD COLUMN ticket_target VARCHAR"))
    return True


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check or add the filtered ticket target column.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check-only", action="store_true", help="Report schema state only.")
    mode.add_argument("--apply", action="store_true", help="Apply the idempotent migration.")
    parser.add_argument(
        "--database-url",
        required=True,
        help="Explicit SQLAlchemy URL for the database to inspect or migrate.",
    )
    args = parser.parse_args(argv)

    engine = create_engine(args.database_url)
    try:
        with engine.begin() as connection:
            required = needs_ticket_target_column(connection)
            if args.check_only:
                print(f"Ticket-target column required: {required}")
                return 1 if required else 0

            added = add_ticket_target_column(connection)
            print(f"Added ticket-target column: {added}")
            return 0
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
