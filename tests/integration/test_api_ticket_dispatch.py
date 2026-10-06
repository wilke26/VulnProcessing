"""Integrations-Tests fuer /tickets/dispatch (dry_run)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.api import routes_tickets
from app.db.models import Asset, Finding, FindingStatus, Tenant
from app.main import app


class DummyDispatcher:
    async def dispatch(self, findings):
        raise AssertionError("Dispatcher should not be called when dry_run=true")


class DummyPrepService:
    async def prepare_for_ticketing(self, findings):
        return findings


class TestDispatchTicketsEndpoint:
    def test_dispatch_dry_run(self, db_session, monkeypatch):
        tenant = Tenant(name="TestTenant_DispatchDry")
        asset = Asset(tenant=tenant, name="server01")
        db_session.add_all([tenant, asset])
        db_session.flush()

        for i in range(2):
            finding = Finding(
                tenant_id=tenant.id,
                asset_id=asset.id,
                name=f"Finding {i}",
                target="server01",
                risk=5.0,
                amount=1,
                extended_solution_json='["Fix"]',
                status=FindingStatus.NEW.value,
            )
            db_session.add(finding)
        db_session.commit()

        monkeypatch.setattr(routes_tickets, "build_ticket_dispatcher", lambda: DummyDispatcher())
        monkeypatch.setattr(routes_tickets, "build_ticket_preparation", lambda: DummyPrepService())

        client = TestClient(app)
        response = client.post("/tickets/dispatch", params={"dry_run": True})

        assert response.status_code == 200
        data = response.json()
        assert data["dispatched"] == 2
        assert data["dry_run"] is True
        assert data["batch_status"] is None
        assert data["error"] is None
        assert data["code"] is None
