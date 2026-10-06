"""Unit-Tests fuer Ticket-Clients und Registry."""

from __future__ import annotations

import pytest

from app.core.config import Settings
from app.services import ticketing_clients_rest
from app.services.ticketing_clients import build_ticket_client_registry
from app.services.ticketing_clients_email import DocBeeEmailClient
from app.services.ticketing_clients_rest import DocBeeRestClient


class DummyEmailService:
    def __init__(self) -> None:
        self.sent = []

    async def send_ticket_email(self, ticket):
        self.sent.append(ticket)
        return True


@pytest.mark.asyncio
async def test_docbee_email_client_sends_ticket():
    service = DummyEmailService()
    client = DocBeeEmailClient(email_service=service, ticket_address="docbee@example.test")

    ext_id = await client.create_ticket(
        title="Finding X",
        description="Details",
        priority="High",
        tenant="TenantA",
        batch_id=7,
        dispatch_token="A" * 43,
    )

    assert ext_id.startswith("email-")
    assert len(service.sent) == 1
    ticket = service.sent[0]
    assert ticket.to == "docbee@example.test"
    assert ticket.subject == "Finding X"
    assert ticket.body_text == "Details"
    assert ticket.headers["X-Ticket-Priority"] == "High"
    assert ticket.headers["X-Ticket-Tenant"] == "TenantA"
    assert ticket.headers["X-VulnProcessing-Batch-ID"] == "7"
    assert ticket.headers["X-VulnProcessing-Dispatch-Token"] == "A" * 43


def test_registry_includes_email_clients_when_enabled():
    settings = Settings(
        NCENTRAL_API_URL="https://example.test",
        NCENTRAL_API_KEY="abc",
        DOCBEE_EMAIL_ENABLED=True,
        MKS_EMAIL_ENABLED=True,
    )

    registry = build_ticket_client_registry(settings)
    names = [client.name for client in registry.active()]

    assert "DocBee (Email)" in names
    assert "MKS (Email)" in names


@pytest.mark.asyncio
async def test_docbee_rest_client_includes_dispatch_context(monkeypatch):
    captured = {}

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"id": "REST-1"}

    class AsyncClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, url, **kwargs):
            captured.update(kwargs["json"])
            return Response()

    monkeypatch.setattr(ticketing_clients_rest.httpx, "AsyncClient", AsyncClient)
    client = DocBeeRestClient(base_url="https://docbee.example.test", api_key="key")

    await client.create_ticket(
        title="Finding X",
        description="Details",
        priority="High",
        tenant="TenantA",
        batch_id=7,
        dispatch_token="A" * 43,
    )

    assert captured["batch_id"] == 7
    assert captured["dispatch_token"] == "A" * 43
