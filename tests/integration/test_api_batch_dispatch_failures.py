"""Integrationstests fuer Batch-Dispatch Fehlerfaelle."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.api import routes_tickets
from app.db.models import Asset, Finding, FindingStatus, Tenant, TicketBatch
from app.main import app


class DummyDispatcher:
    async def dispatch(self, findings, **kwargs):
        raise RuntimeError("boom")


class TestBatchDispatchFailures:
    def test_dispatch_nonexistent_batch_returns_422(self, db_session, assert_error_detail):
        client = TestClient(app)
        response = client.post("/tickets/batch/99999/dispatch")
        assert response.status_code == 422
        detail = response.json().get("detail", {})
        assert_error_detail(detail, "batch_dispatch_failed")

    def test_dispatch_error_returns_422(self, db_session, monkeypatch, assert_error_detail):
        tenant = Tenant(name="TestTenant_BatchDispatchFail")
        asset = Asset(tenant=tenant, name="server01")
        db_session.add_all([tenant, asset])
        db_session.flush()

        batch = TicketBatch(tenant_id=tenant.id, batch_number=1, status="created", total_findings=1)
        db_session.add(batch)
        db_session.flush()

        finding = Finding(
            tenant_id=tenant.id,
            asset_id=asset.id,
            batch_id=batch.id,
            name="Finding 0",
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
        assert response.status_code == 422
        detail = response.json().get("detail", {})
        assert_error_detail(detail, "batch_dispatch_failed")
