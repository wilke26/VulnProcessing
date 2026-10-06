"""Integrationstest fuer /tickets/batch/{id}/send Alias."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.api import routes_tickets
from app.db.models import Asset, Finding, FindingStatus, Tenant, TicketBatch
from app.main import app
from app.services.ticketing_clients import TicketDispatchAttempt, TicketDispatchResult


class DummyDispatcher:
    async def dispatch(self, findings, **kwargs):
        findings = list(findings)
        return TicketDispatchResult(
            finding_count=len(findings),
            client_count=1,
            attempts=tuple(
                TicketDispatchAttempt(finding.id, "Dummy", True, external_id="EXT")
                for finding in findings
            ),
        )


class TestBatchSendAlias:
    def test_send_alias_dispatches(self, db_session, monkeypatch):
        tenant = Tenant(name="TestTenant_SendAlias")
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
        response = client.post(f"/tickets/batch/{batch.id}/send")

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["tickets_dispatched"] == 1
        assert data["batch_status"] == "pending"
        assert len(data["dispatch_token"]) == 43
