"""Integrations-Tests fuer /tickets/batch/{id}/dispatch."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.api import routes_tickets
from app.db.models import Asset, Finding, FindingStatus, Tenant, TicketBatch
from app.main import app


class DummyDispatcher:
    async def dispatch(self, findings, **kwargs):
        return None


class TestBatchDispatchEndpoint:
    def test_dispatch_batch_endpoint(self, db_session, monkeypatch):
        tenant = Tenant(name="TestTenant_Dispatch")
        asset = Asset(tenant=tenant, name="server01")
        db_session.add_all([tenant, asset])
        db_session.flush()

        batch = TicketBatch(tenant_id=tenant.id, batch_number=1, status="created", total_findings=2)
        db_session.add(batch)
        db_session.flush()

        for i in range(2):
            finding = Finding(
                tenant_id=tenant.id,
                asset_id=asset.id,
                batch_id=batch.id,
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

        client = TestClient(app)
        response = client.post(f"/tickets/batch/{batch.id}/dispatch")

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["tickets_dispatched"] == 2
        assert data["batch_status"] == "pending"
        assert len(data["dispatch_token"]) == 43
        assert data["error"] is None
        assert data["code"] is None
