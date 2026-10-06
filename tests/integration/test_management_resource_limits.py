from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest
from fastapi.testclient import TestClient

import app.api.routes_tickets as routes_tickets
from app.core.config import settings
from app.db.models import Asset, Finding, FindingStatus, Tenant
from app.main import app


def test_streaming_request_limit_rejects_import_before_full_parse(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "MAX_REQUEST_BYTES", 128)

    response = TestClient(app).post(
        "/findings/import",
        files={"file": ("findings.json", b"x" * 1024, "application/json")},
    )

    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "request_too_large"


def test_streaming_request_limit_rejects_oversized_webhook_body(monkeypatch) -> None:
    monkeypatch.setattr(settings, "MAX_REQUEST_BYTES", 128)

    response = TestClient(app).post(
        "/tickets/batch/confirm",
        content=b"{" + b" " * 1024 + b"}",
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "request_too_large"


def test_webhook_confirmation_count_is_bounded_before_business_logic(monkeypatch) -> None:
    secret = "test-secret"
    timestamp = str(int(time.time()))
    monkeypatch.setattr(settings, "BATCH_CONFIRM_WEBHOOK_SECRET", secret)
    body = json.dumps(
        {
            "batch_id": 1,
            "successful_count": 101,
            "failed_count": 0,
            "dispatch_token": "A" * 43,
            "ticket_confirmations": [
                {"finding_id": index + 1, "status": "confirmed"} for index in range(101)
            ],
        },
        separators=(",", ":"),
    ).encode("utf-8")
    signature = hmac.new(
        secret.encode("utf-8"),
        timestamp.encode("ascii") + b"." + body,
        hashlib.sha256,
    ).hexdigest()

    response = TestClient(app).post(
        "/tickets/batch/confirm",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Webhook-Timestamp": timestamp,
            "X-Webhook-Signature": f"sha256={signature}",
        },
    )

    assert response.status_code == 422


def test_ticket_operation_rejects_more_than_configured_findings_before_preparation(
    db_session, monkeypatch
) -> None:
    tenant = Tenant(name="Bounded Tenant")
    asset = Asset(tenant=tenant, name="server.example")
    db_session.add_all([tenant, asset])
    db_session.flush()
    for index in range(2):
        db_session.add(
            Finding(
                tenant_id=tenant.id,
                asset_id=asset.id,
                name=f"Finding {index}",
                target="server.example",
                risk=7.0,
                amount=1,
                extended_solution_json=json.dumps(["Fix"]),
                status=FindingStatus.NEW.value,
            )
        )
    db_session.commit()
    monkeypatch.setattr(settings, "MAX_FINDINGS_PER_TICKET_OPERATION", 1)
    monkeypatch.setattr(
        routes_tickets,
        "build_ticket_preparation",
        lambda: pytest.fail("preparation must not run after the item limit"),
    )

    response = TestClient(app).post(
        "/tickets/dispatch",
        params={"tenant_name": "Bounded Tenant", "dry_run": True},
    )

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "operation_item_limit_exceeded"
