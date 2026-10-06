"""
Integrations-Tests für die Repository-Schicht.
Validiert die grundlegenden CRUD-Operationen des FindingRepository unter Verwendung
einer In-Memory-SQLite-Datenbank.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import Asset, Base, Tenant
from app.db.repository import FindingRepository
from app.models.findings import Finding as PydanticFinding
from app.services.mappers import map_pydantic_to_orm


@pytest.fixture
def session():
    """
    Stellt eine saubere In-Memory-Datenbank-Session für jeden Test bereit.
    """
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, future=True)
    sess = Session()
    yield sess
    sess.close()


def test_finding_repository_add_and_query(session):
    """
    Überprüft das Hinzufügen eines Findings über das Repository und dessen
    anschließenden Abruf nach ID sowie nach Mandant/Asset-Kombination.
    """
    # 1. Schritt: Minimalen Mandanten (Tenant) und Asset anlegen
    tenant = Tenant(name="test-tenant")
    session.add(tenant)
    session.flush()

    asset = Asset(tenant_id=tenant.id, name="test-asset")
    session.add(asset)
    session.flush()

    # 2. Schritt: Pydantic-Finding erstellen und in ORM-Modell transformieren
    p = PydanticFinding(
        name="RepoTest",
        tenant="ignored",
        risk=1.0,
        amount=1,
        target="host.local",
        extendedSolution=["step1"],
        windowsVersionHint="",
        products=["p1"],
    )
    orm_obj = map_pydantic_to_orm(p, tenant_id=tenant.id, asset_id=asset.id)

    # 3. Schritt: Speichern über das FindingRepository
    repo = FindingRepository(session)
    repo.add(orm_obj)
    session.commit()

    # 4. Schritt: Verifizierung durch Abruf nach ID
    fetched = repo.get_by_id(orm_obj.id)
    assert fetched is not None
    assert fetched.name == "RepoTest"

    # 5. Schritt: Verifizierung durch Abruf nach Tenant/Asset
    results = repo.get_by_tenant_asset(tenant_id=tenant.id, asset_id=asset.id)
    assert len(results) == 1
    assert results[0].id == orm_obj.id
