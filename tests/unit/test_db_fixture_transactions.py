"""Regression tests for the database fixture's transaction boundary."""

from sqlalchemy import text


def test_application_sessions_leave_outer_test_transaction_active(db_session):
    """Application commit/rollback calls must stay inside their own savepoints."""

    import app.db.engine

    connection = db_session.get_bind()

    committed_session = app.db.engine.SessionLocal()
    committed_session.execute(text("SELECT 1"))
    committed_session.commit()
    committed_session.close()

    rolled_back_session = app.db.engine.SessionLocal()
    rolled_back_session.execute(text("SELECT 1"))
    rolled_back_session.rollback()
    rolled_back_session.close()

    assert connection.in_transaction()
