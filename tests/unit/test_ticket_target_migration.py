from __future__ import annotations

from sqlalchemy import create_engine, inspect, text

from scripts.migrate_ticket_targets import (
    add_ticket_target_column,
    main,
    needs_ticket_target_column,
)


def test_ticket_target_migration_is_idempotent(tmp_path, capsys) -> None:
    database_url = f"sqlite:///{tmp_path / 'ticket-target.sqlite3'}"
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE findings (id INTEGER PRIMARY KEY, target VARCHAR)"))
        assert needs_ticket_target_column(connection) is True
        assert add_ticket_target_column(connection) is True
        assert add_ticket_target_column(connection) is False

    with engine.connect() as connection:
        columns = {column["name"] for column in inspect(connection).get_columns("findings")}
        assert "ticket_target" in columns
    engine.dispose()

    assert main(["--check-only", "--database-url", database_url]) == 0
    assert "Ticket-target column required: False" in capsys.readouterr().out


def test_ticket_target_check_reports_missing_column(tmp_path, capsys) -> None:
    database_url = f"sqlite:///{tmp_path / 'ticket-target-check.sqlite3'}"
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE findings (id INTEGER PRIMARY KEY, target VARCHAR)"))
    engine.dispose()

    assert main(["--check-only", "--database-url", database_url]) == 1
    assert "Ticket-target column required: True" in capsys.readouterr().out
    assert main(["--apply", "--database-url", database_url]) == 0
    assert "Added ticket-target column: True" in capsys.readouterr().out
