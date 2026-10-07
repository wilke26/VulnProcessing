"""Gemeinsame Test-Fixtures."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.management_auth import ManagementPrincipal, authenticate_management_request
from app.db.models import Base
from app.main import app

# In-Memory SQLite für schnelle Tests
TEST_DATABASE_URL = "sqlite:///:memory:"


@pytest.fixture(autouse=True)
def default_management_principal():
    """Keep existing endpoint tests focused while auth has dedicated integration tests."""

    app.dependency_overrides[authenticate_management_request] = lambda: ManagementPrincipal(
        subject="test-admin",
        tenants=frozenset({"*"}),
        operations=frozenset({"*"}),
    )
    yield
    app.dependency_overrides.pop(authenticate_management_request, None)


@pytest.fixture(scope="session")
def db_engine():
    engine = create_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False, "autocommit": False},
    )
    # Importiere alle Modelle, damit Base.metadata davon erfährt
    from app.db import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db_session(db_engine, monkeypatch):
    connection = db_engine.connect()
    transaction = connection.begin()

    SessionLocal = sessionmaker(bind=connection, join_transaction_mode="create_savepoint")
    session = SessionLocal()

    # Monkeypatch the engine and SessionLocal in app.db.engine
    # so the app uses our test database
    import app.db.engine

    monkeypatch.setattr(app.db.engine, "engine", db_engine)
    monkeypatch.setattr(app.db.engine, "SessionLocal", SessionLocal)

    # Wir müssen auch sicherstellen, dass UnitOfWork die SessionLocal aus app.db.engine nutzt
    import app.db.repository

    monkeypatch.setattr(app.db.repository, "SessionLocal", SessionLocal)

    # Und für FastAPI TestClient müssen wir sicherstellen, dass die App-Instanz
    # ebenfalls dieselbe Engine/Session nutzt. Da die App in main.py definiert ist
    # und Router importiert, die wiederum Services/DB nutzen.
    import app.api.routes_import
    import app.api.routes_tickets
    import app.db.database
    import app.main

    monkeypatch.setattr(app.db.database, "SessionLocal", SessionLocal)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def assert_error_detail():
    def _assert(detail: dict, code: str):
        assert isinstance(detail, dict)
        assert detail.get("code") == code
        assert detail.get("error")

    return _assert
