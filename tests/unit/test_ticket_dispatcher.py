"""Unit-Tests fuer TicketDispatcher."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from app.core.config import Settings
from app.services.dispatcher import TicketDispatcher


@dataclass
class DummyFinding:
    id: int
    name: str
    tenant: str
    priority_score: float


class DummyRemediationService:
    async def get_remediation_guides(self, findings):
        return {}


class DummyClient:
    name = "Dummy"

    def __init__(self):
        self.calls = []

    async def create_ticket(
        self,
        title: str,
        description: str,
        priority: str,
        tenant: str,
        **kwargs,
    ) -> str:
        self.calls.append(
            {
                "title": title,
                "description": description,
                "priority": priority,
                "tenant": tenant,
                **kwargs,
            }
        )
        return "EXT-1"


@pytest.mark.asyncio
async def test_dispatcher_uses_injected_clients():
    settings = Settings(
        NCENTRAL_API_URL="https://example.test",
        NCENTRAL_API_KEY="abc",
    )

    client = DummyClient()
    dispatcher = TicketDispatcher(
        settings=settings,
        remediation_service=DummyRemediationService(),
        clients=[client],
    )

    finding = DummyFinding(id=1, name="Finding A", tenant="TenantA", priority_score=95.0)
    await dispatcher.dispatch([finding], batch_id=7, dispatch_token="A" * 43)

    assert len(client.calls) == 1
    assert client.calls[0]["tenant"] == "TenantA"
    assert client.calls[0]["batch_id"] == 7
    assert client.calls[0]["dispatch_token"] == "A" * 43
    assert "Finding A" in client.calls[0]["title"]
