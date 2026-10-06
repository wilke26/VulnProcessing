"""Tests fuer BatchTicketingService.dispatch_batch."""

from __future__ import annotations

import pytest

from app.core.config import Settings
from app.core.security import verify_dispatch_confirmation_token
from app.db.models import Asset, Finding, FindingStatus, Tenant, TicketBatch
from app.services.composition_root import build_batch_ticketing_service
from app.services.dispatcher import TicketDispatcher
from app.services.ticketing_clients import TicketDispatchAttempt, TicketDispatchResult


class DummyDispatcher:
    def __init__(self):
        self.batch_id = None
        self.dispatch_token = None

    async def dispatch(self, findings, **kwargs):
        findings = list(findings)
        self.batch_id = kwargs.get("batch_id")
        self.dispatch_token = kwargs.get("dispatch_token")
        return TicketDispatchResult(
            finding_count=len(findings),
            client_count=1,
            attempts=tuple(
                TicketDispatchAttempt(
                    finding_id=finding.id,
                    client_name="Dummy",
                    success=True,
                    external_id=f"EXT-{finding.id}",
                )
                for finding in findings
            ),
        )


class DummyFailDispatcher:
    async def dispatch(self, findings, **kwargs):
        raise RuntimeError("dispatch failed")


class NoClientDispatcher:
    async def dispatch(self, findings, **kwargs):
        return TicketDispatchResult(finding_count=len(list(findings)), client_count=0)


class PartialDispatcher:
    async def dispatch(self, findings, **kwargs):
        first, second = list(findings)
        return TicketDispatchResult(
            finding_count=2,
            client_count=1,
            attempts=(
                TicketDispatchAttempt(first.id, "Dummy", True, external_id="EXT-1"),
                TicketDispatchAttempt(second.id, "Dummy", False, error="backend unavailable"),
            ),
        )


class FailingClient:
    name = "Failing"

    async def create_ticket(self, **kwargs):
        raise RuntimeError("SMTP unavailable")


class NoRemediation:
    async def get_remediation_guides(self, findings):
        return {}


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
    assert result["successful_attempts"] == 2
    assert result["failed_attempts"] == 0
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


@pytest.mark.asyncio
async def test_dispatch_batch_fails_without_active_clients(db_session):
    batch, finding = _batch_with_findings(db_session, count=1, tenant_name="NoClientTenant")
    service = build_batch_ticketing_service(db_session=db_session)

    result = await service.dispatch_batch(batch.id, NoClientDispatcher())

    assert result["success"] is False
    assert result["batch_status"] == "failed"
    assert batch.confirmation_token_hash is None
    assert finding.status == FindingStatus.NEW.value
    assert finding.batch_id is None


@pytest.mark.asyncio
async def test_dispatch_batch_records_partial_failure_without_retrying_successes(db_session):
    batch, findings = _batch_with_findings(
        db_session,
        count=2,
        tenant_name="PartialDispatchTenant",
        return_list=True,
    )
    service = build_batch_ticketing_service(db_session=db_session)

    result = await service.dispatch_batch(batch.id, PartialDispatcher())

    assert result["success"] is False
    assert result["batch_status"] == "partially_failed"
    assert result["successful_attempts"] == 1
    assert result["failed_attempts"] == 1
    assert batch.confirmation_token_hash is None
    assert findings[0].status == FindingStatus.TICKET_CREATED.value
    assert findings[1].status == FindingStatus.QUEUED.value
    assert all(finding.batch_id == batch.id for finding in findings)


@pytest.mark.asyncio
async def test_caught_client_failure_does_not_leave_batch_pending(db_session):
    batch, finding = _batch_with_findings(
        db_session,
        count=1,
        tenant_name="CaughtClientFailureTenant",
    )
    dispatcher = TicketDispatcher(
        settings=Settings(),
        remediation_service=NoRemediation(),
        clients=[FailingClient()],
    )
    service = build_batch_ticketing_service(db_session=db_session)

    result = await service.dispatch_batch(batch.id, dispatcher)

    assert result["success"] is False
    assert result["batch_status"] == "failed"
    assert result["successful_attempts"] == 0
    assert result["failed_attempts"] == 1
    assert batch.status == "failed"
    assert batch.confirmation_token_hash is None
    assert finding.status == FindingStatus.NEW.value
    assert finding.batch_id is None


def _batch_with_findings(
    db_session,
    *,
    count: int,
    tenant_name: str,
    return_list: bool = False,
):
    tenant = Tenant(name=tenant_name)
    asset = Asset(tenant=tenant, name="server01")
    db_session.add_all([tenant, asset])
    db_session.flush()
    batch = TicketBatch(
        tenant_id=tenant.id,
        batch_number=1,
        status="created",
        total_findings=count,
    )
    db_session.add(batch)
    db_session.flush()
    findings = []
    for index in range(count):
        finding = Finding(
            tenant_id=tenant.id,
            asset_id=asset.id,
            batch_id=batch.id,
            name=f"Finding {index}",
            target="server01",
            risk=5.0,
            amount=1,
            extended_solution_json='["Fix"]',
            status=FindingStatus.QUEUED.value,
        )
        findings.append(finding)
        db_session.add(finding)
    db_session.commit()
    return batch, findings if return_list else findings[0]
