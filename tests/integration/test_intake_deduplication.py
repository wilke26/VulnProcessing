"""
Integrations-Tests für die Deduplizierung während des Intake-Prozesses.
Stellt sicher, dass redundante Findings korrekt zusammengeführt werden,
bevor sie in der Datenbank persistiert werden.
"""

from app.db.repository import UnitOfWork
from app.models.findings import Finding, UnifiedFindingsInput
from app.services.db_intake import intake_findings


def _make_finding(name: str, tenant: str, risk: float, amount: int, target: str):
    """
    Hilfsfunktion zum Erstellen eines Pydantic-Finding-Objekts für Tests.
    """
    return Finding(
        name=name,
        tenant=tenant,
        risk=risk,
        amount=amount,
        target=target,
        extendedSolution=["Fix it"],
        windowsVersionHint="",
        products=["ProductA"],
    )


def test_intake_deduplicates_before_persisting(db_session):
    """
    Testet, ob der Intake-Service Dubletten (gleicher Mandant, Name und Zielsystem)
    vor dem Speichern erkennt und aggregiert (Max-Risiko, Summe der Anzahl).
    """
    tenant_name = "Tenant Dedupe"

    # Zwei Dubletten: gleicher Tenant, Name, Target → sollen zusammengeführt werden
    f1 = _make_finding(
        name="OpenSSL",
        tenant=tenant_name,
        risk=7.5,
        amount=1,
        target="server-1",
    )
    f2 = _make_finding(
        name="OpenSSL",
        tenant=tenant_name,
        risk=9.0,
        amount=2,
        target="server-1",
    )

    unified: UnifiedFindingsInput = [f1, f2]

    # Act: Intake-Prozess mit den Dubletten ausführen
    processed = intake_findings(unified)

    # Assert: Überprüfung der Anzahl verarbeiteter Datensätze
    # Hinweis: intake_findings gibt die Anzahl der erfolgreichen
    # individuellen Persistierungen zurück.
    assert processed in (1, 2)

    # Assert: DB-Zustand über UnitOfWork validieren
    with UnitOfWork() as uow:
        tenant = uow.tenants.get_or_create(tenant_name)
        findings_for_tenant = uow.findings.get_by_tenant_asset(
            tenant_id=tenant.id,
            asset_id=uow.assets.get_or_create(tenant, "server-1").id,
        )

        # Erwartung: Es darf nur genau ein Finding in der Datenbank existieren
        assert len(findings_for_tenant) == 1
        db_f = findings_for_tenant[0]

        # Geschäftsregel: Höchstes Risiko gewinnt (Risk = max(7.5, 9.0))
        assert db_f.risk == 9.0
        # Geschäftsregel: Mengen werden addiert (Amount = 1 + 2)
        assert db_f.amount == 3
