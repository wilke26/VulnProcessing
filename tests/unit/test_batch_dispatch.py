"""Tests fuer BatchTicketingService.dispatch_batch."""

from __future__ import annotations

import pytest

from app.core.security import verify_dispatch_confirmation_token
from app.db.models import Asset, Finding, FindingStatus, Tenant, TicketBatch
from app.services.composition_root import build_batch_ticketing_service


class DummyDispatcher:
    def __init__(self):
        self.batch_id = None
        self.dispatch_token = None

    async def dispatch(self, findings, **kwargs):
        self.batch_id = kwargs.get("batch_id")
        self.dispatch_token = kwargs.get("dispatch_token")
        return None


class DummyFailDispatcher:
    async def dispatch(self, findings, **kwargs):
        raise RuntimeError("dispatch failed")


@pytest.mark.asyncio
async def test_dispatch_batch_marks_status_and_pending(db_session):
    tenant = Tenant(name="TestTenant")
    asset = Asset(tenant=tenant, name="server01")
    db_session.add_all([tenant, asset])
    db_session.flush()

    batch = TicketBatch(tenant_id=tenant.id, batch_number=1, status="created", total_findings=2)
    db_session.add(batch)
    db_session.flush()

    findings = []
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
        findings.append(finding)
    db_session.commit()

    service = build_batch_ticketing_service(db_session=db_session)
    dispatcher = DummyDispatcher()
    result = await service.dispatch_batch(batch_id=batch.id, dispatcher=dispatcher)

    assert result["success"] is True
    assert result["tickets_dispatched"] == 2
    assert batch.status == "pending"
    assert verify_dispatch_confirmation_token(
        result["dispatch_token"], batch.confirmation_token_hash
    )
    assert dispatcher.batch_id == batch.id
    assert dispatcher.dispatch_token == result["dispatch_token"]
    for finding in findings:
        assert finding.status == FindingStatus.TICKETING_IN_PROGRESS.value


@pytest.mark.asyncio
async def test_dispatch_batch_returns_error_on_failure(db_session):
    tenant = Tenant(name="TestTenant")
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

    service = build_batch_ticketing_service(db_session=db_session)
    result = await service.dispatch_batch(batch_id=batch.id, dispatcher=DummyFailDispatcher())

    assert result["success"] is False
    assert "dispatch failed" in result["error"]

    # NEU: Batch-Status in DB pruefen
    db_session.refresh(batch)
    assert batch.status == "failed"
    assert batch.last_error == "dispatch failed"

    # NEU: Findings sollten wieder auf "new" stehen und batch_id geloescht sein
    for finding in batch.findings:
        db_session.refresh(finding)
        assert finding.status == FindingStatus.NEW.value
        assert finding.batch_id is None
