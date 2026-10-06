"""Property-based Tests fuer DeduplicationService."""

from __future__ import annotations

from collections import defaultdict

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from app.models.findings import Finding
from app.services.deduplication_service import DeduplicationService


def _finding_strategy():
    non_empty = st.text(min_size=1, max_size=10).filter(lambda x: x.strip() != "")
    products = st.lists(non_empty, min_size=1, max_size=3)
    solutions = st.lists(non_empty, min_size=1, max_size=3)

    return st.builds(
        Finding,
        name=non_empty,
        cve_id=st.one_of(st.none(), non_empty),
        tenant=non_empty,
        risk=st.floats(min_value=0.0, max_value=10.0, allow_nan=False, allow_infinity=False),
        amount=st.integers(min_value=1, max_value=10),
        target=non_empty,
        extended_solution_json=solutions,
        windows_version_hint=st.just(""),
        products=products,
    )


def _key(f: Finding) -> tuple[str, str, str, str]:
    cve_key = f.cve_id or f.name
    return (f.tenant, cve_key, f.target, f.name)


@pytest.mark.property
@settings(max_examples=50)
@given(st.lists(_finding_strategy(), min_size=1, max_size=30))
def test_deduplicate_merges_by_key(findings: list[Finding]) -> None:
    deduped = DeduplicationService.deduplicate(findings)

    # Ergebnis darf niemals mehr Elemente als Input haben
    assert len(deduped) <= len(findings)

    # Keine doppelten Keys im Ergebnis
    keys = [_key(f) for f in deduped]
    assert len(keys) == len(set(keys))

    # Für jeden Key: Risiko ist Max, Amount ist Summe, Products ist Vereinigung
    by_key: dict[tuple[str, str, str, str], list[Finding]] = defaultdict(list)
    for f in findings:
        by_key[_key(f)].append(f)

    for f in deduped:
        group = by_key[_key(f)]
        assert f.risk == max(g.risk for g in group)
        assert f.amount == sum(g.amount for g in group)
        expected_products = set()
        for g in group:
            expected_products.update(g.products)
        assert set(f.products) == expected_products
