"""Property-based Tests fuer PrioritizationService."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from app.core.priority_config import PriorityConfig
from app.models.findings import Finding
from app.services.prioritization_service import PrioritizationService


def _finding_strategy():
    non_empty = st.text(min_size=1, max_size=10)
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


@pytest.mark.property
@settings(max_examples=50)
@given(st.lists(_finding_strategy(), min_size=1, max_size=30))
def test_prioritization_returns_sorted(findings: list[Finding]) -> None:
    service = PrioritizationService(PriorityConfig())
    prioritized = service.prioritize_findings(findings)

    # Gleiche Elemente (als Multiset) erhalten
    assert sorted(prioritized, key=lambda f: (f.name, f.target, f.tenant, f.risk)) == sorted(
        findings, key=lambda f: (f.name, f.target, f.tenant, f.risk)
    )

    # Nicht-aufsteigende Reihenfolge nach Score
    scores = [service.compute_priority(f) for f in prioritized]
    assert scores == sorted(scores, reverse=True)
