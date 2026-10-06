"""Integrationstests fuer Dispatch-Fehlerfaelle."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.api import routes_tickets
from app.main import app
from app.services.ticketing_clients import TicketDispatchAttempt, TicketDispatchResult


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

    def test_dispatch_without_active_clients_returns_503(self, db_session, monkeypatch):
        class NoClientDispatcher:
            async def dispatch(self, findings):
                return TicketDispatchResult(finding_count=len(list(findings)), client_count=0)

        monkeypatch.setattr(routes_tickets, "build_ticket_dispatcher", NoClientDispatcher)

        response = TestClient(app).post("/tickets/dispatch")

        assert response.status_code == 503
        assert response.json()["detail"]["code"] == "dispatch_unavailable"

    def test_partial_direct_dispatch_returns_502(self, db_session, monkeypatch):
        class PartialDispatcher:
            async def dispatch(self, findings):
                return TicketDispatchResult(
                    finding_count=1,
                    client_count=2,
                    attempts=(
                        TicketDispatchAttempt(1, "A", True, external_id="EXT"),
                        TicketDispatchAttempt(1, "B", False, error="backend unavailable"),
                    ),
                )

        monkeypatch.setattr(routes_tickets, "build_ticket_dispatcher", PartialDispatcher)

        response = TestClient(app).post("/tickets/dispatch")

        assert response.status_code == 502
        assert response.json()["detail"] == {
            "error": "Ticket-Dispatch fehlgeschlagen",
            "code": "dispatch_failed",
        }
        assert "backend unavailable" not in response.text
