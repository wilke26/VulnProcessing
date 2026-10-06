"""Tests fuer Dispatcher Registry/Settings Kombinationen."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.services.ticketing_clients import build_ticket_client_registry


def test_registry_raises_error_for_invalid_config():
    """
    Prüft, ob die Settings-Validierung einen Fehler wirft, wenn REST aktiviert
    ist, aber die Zugangsdaten fehlen.
    """
    with pytest.raises(ValidationError) as excinfo:
        Settings(
            NCENTRAL_API_URL="https://example.test",
            NCENTRAL_API_KEY="abc",
            DOCBEE_REST_ENABLED=True,
            DOCBEE_URL=None,
        )
    assert "DOCBEE_REST_ENABLED" in str(excinfo.value)


def test_registry_includes_email_clients_only(caplog):
    settings = Settings(
        NCENTRAL_API_URL="https://example.test",
        NCENTRAL_API_KEY="abc",
        DOCBEE_EMAIL_ENABLED=True,
        MKS_EMAIL_ENABLED=True,
    )

    with caplog.at_level("WARNING"):
        registry = build_ticket_client_registry(settings)

    assert len(registry.active()) == 2
    assert [c.name for c in registry.active()] == ["DocBee (Email)", "MKS (Email)"]
    assert not caplog.records
