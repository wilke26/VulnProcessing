"""
Unit-Tests für die Mapper-Funktionen.
Validiert die Konvertierung zwischen Pydantic-DTOs und SQLAlchemy-ORM-Modellen
in beide Richtungen, inklusive der Serialisierung von Listenfeldern.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import Base
from app.db.models import Finding as ORMFinding
from app.models.findings import Finding as PydanticFinding
from app.services.mappers import map_orm_to_pydantic, map_pydantic_to_orm


@pytest.fixture
def session():
    """
    Erstellt eine temporäre In-Memory-Datenbank für die Mapping-Tests.
    """
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, future=True)
    sess = Session()
    yield sess
    sess.close()


def test_map_pydantic_to_orm_and_back(session):
    """
    Testet den Roundtrip: Konvertierung von Pydantic zu ORM und wieder zurück zu Pydantic.
    Stellt sicher, dass alle Attribute (inkl. Listen) korrekt erhalten bleiben.
    """
    # 1. Arrange: Ein Pydantic-Finding DTO erstellen
    p = PydanticFinding(
        name="TestFinding",
        tenant="ignored_by_mapper",
        risk=4.2,
        amount=3,
        target="127.0.0.1",
        extendedSolution=["Patch einspielen", "Dienst neu starten"],
        windowsVersionHint="Windows 10",
        products=["Produkt A"],
    )

    # 2. Act: Mapping zu ORM-Modell
    orm_obj = map_pydantic_to_orm(p, tenant_id=1, asset_id=2, import_run_id=None)
    session.add(orm_obj)
    session.commit()

    # Aus DB laden, um sicherzugehen, dass Serialisierung funktioniert hat
    got = session.query(ORMFinding).filter_by(name="TestFinding").one()

    # Mapping zurück zu Pydantic DTO
    p_back = map_orm_to_pydantic(got)

    # 3. Assert: Vergleich der ursprünglichen Daten mit dem Ergebnis nach dem Roundtrip
    assert p_back.name == p.name
    assert p_back.risk == pytest.approx(p.risk)
    assert p_back.amount == p.amount
    assert p_back.target == p.target
    assert p_back.extendedSolution == p.extendedSolution
    assert p_back.windowsVersionHint == p.windowsVersionHint
    assert p_back.products == p.products
