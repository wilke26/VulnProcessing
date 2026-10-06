"""Unit-Tests fuer /tickets/dispatch API Endpoint (dry_run)."""

from __future__ import annotations

import pytest

from app.api import routes_tickets


@pytest.mark.asyncio
async def test_dispatch_dry_run_does_not_call_dispatcher(monkeypatch, db_session):
    # Minimaler End-to-End fuer dry_run, Dispatcher wird nicht aufgerufen.
    async def fake_prepare(findings):
        return findings

    async def fake_dispatch(_):
        raise AssertionError("Dispatcher should not be called in dry_run")

    monkeypatch.setattr(
        routes_tickets,
        "build_ticket_preparation",
        lambda: type("X", (), {"prepare_for_ticketing": fake_prepare})(),
    )
    monkeypatch.setattr(
        routes_tickets,
        "build_ticket_dispatcher",
        lambda: type("Y", (), {"dispatch": fake_dispatch})(),
    )

    # Kein Finding vorhanden -> dispatched 0
    result = await routes_tickets.dispatch_tickets(tenant_name=None, min_risk=None, dry_run=True)
    assert result["dispatched"] == 0
    assert result["dry_run"] is True
