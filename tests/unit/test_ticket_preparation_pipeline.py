"""Unit-Tests fuer TicketPreparationService Pipeline."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from app.services.ticket_preparation import TicketPreparationService


@dataclass
class DummySqlFinding:
    id: int
    priority_score: float | None = None


@dataclass
class DummyPydanticFinding:
    id: int
    priority_score: float


class PassThroughStep:
    def __init__(self, result):
        self.result = result

    async def run(self, findings):
        return self.result


@pytest.mark.asyncio
async def test_pipeline_maps_priorities_and_sorts():
    sql_findings = [DummySqlFinding(id=1), DummySqlFinding(id=2)]
    prioritized = [
        DummyPydanticFinding(id=2, priority_score=90.0),
        DummyPydanticFinding(id=1, priority_score=10.0),
    ]

    service = TicketPreparationService(steps=[PassThroughStep(prioritized)])
    result = await service.prepare_for_ticketing(sql_findings)

    assert [f.id for f in result] == [2, 1]
    assert result[0].priority_score == 90.0
    assert result[1].priority_score == 10.0
