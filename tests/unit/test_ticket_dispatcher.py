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
    target: str = "original-host"
    ticket_target: str | None = None


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


class FailingClient(DummyClient):
    name = "Failing"

    async def create_ticket(self, **kwargs) -> str:
        raise RuntimeError("backend unavailable")


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
    result = await dispatcher.dispatch([finding], batch_id=7, dispatch_token="A" * 43)

    assert len(client.calls) == 1
    assert client.calls[0]["tenant"] == "TenantA"
    assert client.calls[0]["batch_id"] == 7
    assert client.calls[0]["dispatch_token"] == "A" * 43
    assert "Finding A" in client.calls[0]["title"]
    assert result.succeeded is True
    assert result.successful_attempts == 1
    assert result.failed_attempts == 0


@pytest.mark.asyncio
async def test_dispatcher_reports_missing_clients():
    dispatcher = TicketDispatcher(
        settings=Settings(),
        remediation_service=DummyRemediationService(),
        clients=[],
    )
    finding = DummyFinding(id=1, name="Finding A", tenant="TenantA", priority_score=95.0)

    result = await dispatcher.dispatch([finding])

    assert result.no_clients is True
    assert result.succeeded is False
    assert result.attempts == ()


@pytest.mark.asyncio
async def test_dispatcher_prefers_filtered_ticket_target():
    client = DummyClient()
    dispatcher = TicketDispatcher(
        settings=Settings(),
        remediation_service=DummyRemediationService(),
        clients=[client],
    )
    finding = DummyFinding(
        id=2,
        name="Finding B",
        tenant="TenantA",
        priority_score=70.0,
        target="server01, server02",
        ticket_target="server02",
    )

    await dispatcher.dispatch([finding])

    assert "Target: server02" in client.calls[0]["title"]
    assert "server01" not in client.calls[0]["title"]


@pytest.mark.asyncio
async def test_dispatcher_reports_partial_client_failure():
    dispatcher = TicketDispatcher(
        settings=Settings(),
        remediation_service=DummyRemediationService(),
        clients=[DummyClient(), FailingClient()],
    )
    finding = DummyFinding(id=7, name="Finding A", tenant="TenantA", priority_score=95.0)

    result = await dispatcher.dispatch([finding])

    assert result.succeeded is False
    assert result.partially_failed is True
    assert result.successful_attempts == 1
    assert result.failed_attempts == 1
    assert result.successful_finding_ids == frozenset({7})
