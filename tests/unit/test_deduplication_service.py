"""
Unit-Tests für den DeduplicationService.
Verifiziert die Zusammenführung redundanter Findings basierend auf Mandant,
Name und Zielsystem sowie die Aggregationsregeln für Risiko und Anzahl.
"""

from app.models.findings import Finding
from app.services.deduplication_service import DeduplicationService


def _make_finding(name: str, tenant: str, risk: float, amount: int, target: str, products=None):
    """
    Hilfsfunktion zum Erstellen eines Finding-Objekts für Tests.
    """
    return Finding(
        name=name,
        tenant=tenant,
        risk=risk,
        amount=amount,
        target=target,
        extendedSolution=["Fix it"],
        windowsVersionHint="",
        products=products or ["ProductA"],
    )


def test_deduplicate_merges_same_tenant_and_name_and_target():
    """
    Prüft, ob Findings mit gleichem Mandanten, Namen und Zielsystem korrekt zusammengeführt werden.
    Dabei muss das höchste Risiko übernommen und die Anzahl addiert werden.
    """
    # Zwei Findings für denselben Host und dieselbe Schwachstelle
    f1 = _make_finding(
        name="OpenSSL",
        tenant="Tenant A",
        risk=7.5,
        amount=1,
        target="server-1",
        products=["OpenSSL"],
    )
    f2 = _make_finding(
        name="OpenSSL",
        tenant="Tenant A",
        risk=5.0,
        amount=2,
        target="server-1",
        products=["OpenSSL", "SSL"],
    )

    # Act: Deduplizierung ausführen
    deduped = DeduplicationService.deduplicate([f1, f2])

    # Assert: Es sollte genau ein Finding übrig bleiben
    assert len(deduped) == 1
    merged = deduped[0]

    # Geschäftsregel Risiko: max(7.5, 5.0) -> 7.5
    assert merged.risk == 7.5
    # Geschäftsregel Anzahl: 1 + 2 -> 3
    assert merged.amount == 3
    # Geschäftsregel Produkte: Vereinigung beider Listen
    assert set(merged.products) == {"OpenSSL", "SSL"}


def test_deduplicate_keeps_different_targets_separate():
    """
    Stellt sicher, dass Findings auf unterschiedlichen Zielsystemen nicht zusammengeführt werden,
    auch wenn es sich um dieselbe Schwachstelle handelt.
    """
    # Gleiche Schwachstelle, aber unterschiedliche Server
    f1 = _make_finding(
        name="OpenSSL",
        tenant="Tenant A",
        risk=7.5,
        amount=1,
        target="server-1",
    )
    f2 = _make_finding(
        name="OpenSSL",
        tenant="Tenant A",
        risk=9.0,
        amount=1,
        target="server-2",
    )

    # Act
    deduped = DeduplicationService.deduplicate([f1, f2])

    # Assert: Zwei unterschiedliche Targets müssen zwei separate Einträge ergeben
    assert len(deduped) == 2
    targets = {f.target for f in deduped}
    assert targets == {"server-1", "server-2"}
