"""Integrationstests fuer Dispatch-Fehlerfaelle."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.api import routes_tickets
from app.main import app


class DummyDispatcher:
    async def dispatch(self, findings):
        raise RuntimeError("boom")


class DummyPrepService:
    async def prepare_for_ticketing(self, findings):
        return findings


class TestDispatchFailures:
    def test_dispatch_without_findings_returns_zero(self, db_session):
        client = TestClient(app)
        response = client.post("/tickets/dispatch", params={"dry_run": True})
        assert response.status_code == 200
        data = response.json()
        assert data["dispatched"] == 0

    def test_dispatch_error_returns_500(self, db_session, monkeypatch, assert_error_detail):
        internal_detail = "/srv/private/vulnprocessing.sqlite3"

        class LeakingDispatcher:
            async def dispatch(self, findings):
                raise RuntimeError(internal_detail)

        monkeypatch.setattr(routes_tickets, "build_ticket_dispatcher", lambda: LeakingDispatcher())
        monkeypatch.setattr(routes_tickets, "build_ticket_preparation", lambda: DummyPrepService())

        client = TestClient(app)
        response = client.post("/tickets/dispatch")
        assert response.status_code == 500
        detail = response.json().get("detail", {})
        assert_error_detail(detail, "dispatch_failed")
        assert detail["error"] == "Ticket-Dispatch fehlgeschlagen"
        assert internal_detail not in response.text
