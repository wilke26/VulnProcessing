"""Tests fuer TicketClientRegistry und Settings-Flags."""

from __future__ import annotations

from app.core.config import Settings
from app.services.ticketing_clients import build_ticket_client_registry


def test_registry_empty_when_no_flags_enabled():
    settings = Settings(
        NCENTRAL_API_URL="https://example.test",
        NCENTRAL_API_KEY="abc",
    )
    registry = build_ticket_client_registry(settings)
    assert registry.active() == []


def test_registry_includes_docbee_email_only():
    settings = Settings(
        NCENTRAL_API_URL="https://example.test",
        NCENTRAL_API_KEY="abc",
        DOCBEE_EMAIL_ENABLED=True,
        MKS_EMAIL_ENABLED=False,
    )
    registry = build_ticket_client_registry(settings)
    names = [client.name for client in registry.active()]
    assert names == ["DocBee (Email)"]


def test_registry_includes_mks_email_only():
    settings = Settings(
        NCENTRAL_API_URL="https://example.test",
        NCENTRAL_API_KEY="abc",
        DOCBEE_EMAIL_ENABLED=False,
        MKS_EMAIL_ENABLED=True,
    )
    registry = build_ticket_client_registry(settings)
    names = [client.name for client in registry.active()]
    assert names == ["MKS (Email)"]


def test_registry_includes_both_email_clients():
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
