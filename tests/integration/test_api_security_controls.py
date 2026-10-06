from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from fastapi.testclient import TestClient

import app.api.routes_tickets as routes_tickets
from app.core.config import settings
from app.core.security import issue_dispatch_confirmation_token
from app.db.models import Tenant, TicketBatch, TicketBatchStatus
from app.main import app


def _signed_headers(secret: str, body: bytes, timestamp: str | None = None) -> dict[str, str]:
    timestamp = timestamp or str(int(time.time()))
    payload = timestamp.encode("ascii") + b"." + body
    signature = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-Webhook-Timestamp": timestamp,
        "X-Webhook-Signature": f"sha256={signature}",
    }


def _bind_dispatch_token(batch: TicketBatch) -> str:
    token, token_hash = issue_dispatch_confirmation_token()
    batch.confirmation_token_hash = token_hash
    return token


def test_batch_confirmation_requires_valid_signature(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "BATCH_CONFIRM_WEBHOOK_SECRET", "test-secret")
    client = TestClient(app)
    body = json.dumps(
        {
            "batch_id": 1,
            "successful_count": 1,
            "failed_count": 0,
            "dispatch_token": "A" * 43,
        },
        separators=(",", ":"),
    ).encode("utf-8")

    response = client.post(
        "/tickets/batch/confirm",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Webhook-Timestamp": str(int(time.time())),
            "X-Webhook-Signature": "sha256=invalid",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "invalid_webhook_auth"


def test_batch_confirmation_rejects_non_ascii_signature_as_unauthorized(
    db_session, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "BATCH_CONFIRM_WEBHOOK_SECRET", "test-secret")
    client = TestClient(app)
    body = json.dumps(
        {
            "batch_id": 1,
            "successful_count": 1,
            "failed_count": 0,
            "dispatch_token": "A" * 43,
        },
        separators=(",", ":"),
    ).encode("utf-8")

    response = client.post(
        "/tickets/batch/confirm",
        content=body,
        headers=[
            (b"content-type", b"application/json"),
            (b"x-webhook-timestamp", str(int(time.time())).encode("ascii")),
            (b"x-webhook-signature", b"sha256=\xe9"),
        ],
    )

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "invalid_webhook_auth"


def test_batch_confirmation_is_authenticated_and_not_replayable(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "BATCH_CONFIRM_WEBHOOK_SECRET", "test-secret")
    tenant = Tenant(name="WebhookTenant")
    db_session.add(tenant)
    db_session.flush()
    batch = TicketBatch(
        tenant_id=tenant.id,
        batch_number=1,
        status=TicketBatchStatus.PENDING.value,
        total_findings=2,
        sent_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    db_session.add(batch)
    dispatch_token = _bind_dispatch_token(batch)
    db_session.commit()

    body = json.dumps(
        {
            "batch_id": batch.id,
            "successful_count": 2,
            "failed_count": 0,
            "dispatch_token": dispatch_token,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    headers = _signed_headers("test-secret", body)
    client = TestClient(app)

    response = client.post("/tickets/batch/confirm", content=body, headers=headers)
    db_session.refresh(batch)
    assert batch.confirmation_token_hash is None
    replay = client.post("/tickets/batch/confirm", content=body, headers=headers)

    assert response.status_code == 200
    assert replay.status_code == 409


def test_batch_confirmation_rejects_impossible_counts(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "BATCH_CONFIRM_WEBHOOK_SECRET", "test-secret")
    tenant = Tenant(name="WebhookCountTenant")
    db_session.add(tenant)
    db_session.flush()
    batch = TicketBatch(
        tenant_id=tenant.id,
        batch_number=1,
        status=TicketBatchStatus.PENDING.value,
        total_findings=2,
        sent_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    db_session.add(batch)
    dispatch_token = _bind_dispatch_token(batch)
    db_session.commit()

    body = json.dumps(
        {
            "batch_id": batch.id,
            "successful_count": 3,
            "failed_count": 0,
            "dispatch_token": dispatch_token,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    client = TestClient(app)
    response = client.post(
        "/tickets/batch/confirm",
        content=body,
        headers=_signed_headers("test-secret", body),
    )

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "invalid_confirmation_counts"


def test_predispatch_confirmation_in_same_second_cannot_be_replayed_after_dispatch(
    db_session, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "BATCH_CONFIRM_WEBHOOK_SECRET", "test-secret")
    tenant = Tenant(name="WebhookReplayTenant")
    db_session.add(tenant)
    db_session.flush()
    batch = TicketBatch(
        tenant_id=tenant.id,
        batch_number=1,
        status=TicketBatchStatus.CREATED.value,
        total_findings=1,
    )
    db_session.add(batch)
    db_session.commit()

    signed_at = str(int(time.time()))
    stale_token, _ = issue_dispatch_confirmation_token()
    body = json.dumps(
        {
            "batch_id": batch.id,
            "successful_count": 1,
            "failed_count": 0,
            "dispatch_token": stale_token,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    headers = _signed_headers("test-secret", body, timestamp=signed_at)
    client = TestClient(app)

    before_dispatch = client.post("/tickets/batch/confirm", content=body, headers=headers)
    _, active_token_hash = issue_dispatch_confirmation_token()
    batch.status = TicketBatchStatus.PENDING.value
    batch.sent_at = datetime.fromtimestamp(int(signed_at), UTC) + timedelta(microseconds=1)
    batch.confirmation_token_hash = active_token_hash
    db_session.commit()
    replay = client.post("/tickets/batch/confirm", content=body, headers=headers)

    assert before_dispatch.status_code == 409
    assert replay.status_code == 409


def test_batch_confirmation_allows_configured_clock_skew(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "BATCH_CONFIRM_WEBHOOK_SECRET", "test-secret")
    monkeypatch.setattr(settings, "BATCH_CONFIRM_WEBHOOK_CLOCK_SKEW_SECONDS", 30)
    signed_at = int(time.time())
    tenant = Tenant(name="WebhookClockSkewTenant")
    db_session.add(tenant)
    db_session.flush()
    batch = TicketBatch(
        tenant_id=tenant.id,
        batch_number=1,
        status=TicketBatchStatus.PENDING.value,
        total_findings=1,
        sent_at=datetime.fromtimestamp(signed_at + 30, UTC),
    )
    db_session.add(batch)
    dispatch_token = _bind_dispatch_token(batch)
    db_session.commit()
    body = json.dumps(
        {
            "batch_id": batch.id,
            "successful_count": 1,
            "failed_count": 0,
            "dispatch_token": dispatch_token,
        },
        separators=(",", ":"),
    ).encode("utf-8")

    response = TestClient(app).post(
        "/tickets/batch/confirm",
        content=body,
        headers=_signed_headers("test-secret", body, timestamp=str(signed_at)),
    )

    assert response.status_code == 200


def test_batch_confirmation_rejects_clock_skew_beyond_limit(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "BATCH_CONFIRM_WEBHOOK_SECRET", "test-secret")
    monkeypatch.setattr(settings, "BATCH_CONFIRM_WEBHOOK_CLOCK_SKEW_SECONDS", 30)
    signed_at = int(time.time()) + 31
    tenant = Tenant(name="WebhookExcessiveClockSkewTenant")
    db_session.add(tenant)
    db_session.flush()
    batch = TicketBatch(
        tenant_id=tenant.id,
        batch_number=1,
        status=TicketBatchStatus.PENDING.value,
        total_findings=1,
        sent_at=datetime.now(UTC),
    )
    db_session.add(batch)
    dispatch_token = _bind_dispatch_token(batch)
    db_session.commit()
    body = json.dumps(
        {
            "batch_id": batch.id,
            "successful_count": 1,
            "failed_count": 0,
            "dispatch_token": dispatch_token,
        },
        separators=(",", ":"),
    ).encode("utf-8")

    response = TestClient(app).post(
        "/tickets/batch/confirm",
        content=body,
        headers=_signed_headers("test-secret", body, timestamp=str(signed_at)),
    )

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "invalid_webhook_auth"


def test_batch_confirmation_reports_unavailable_webhook_without_secret(
    db_session, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "BATCH_CONFIRM_WEBHOOK_SECRET", "")
    body = json.dumps(
        {
            "batch_id": 1,
            "successful_count": 1,
            "failed_count": 0,
            "dispatch_token": "A" * 43,
        },
        separators=(",", ":"),
    ).encode("utf-8")

    response = TestClient(app).post(
        "/tickets/batch/confirm",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Webhook-Timestamp": str(int(time.time())),
            "X-Webhook-Signature": "sha256=" + "0" * 64,
        },
    )

    assert response.status_code == 503
    assert response.json() == {
        "detail": {"error": "Webhook nicht verfügbar", "code": "webhook_unavailable"}
    }


def test_batch_confirmation_hides_unexpected_internal_errors(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "BATCH_CONFIRM_WEBHOOK_SECRET", "test-secret")
    internal_detail = "/srv/private/vulnprocessing.sqlite3"

    def _failing_confirmation(**_kwargs):
        raise RuntimeError(internal_detail)

    service = SimpleNamespace(confirm_batch_completion=_failing_confirmation)
    monkeypatch.setattr(routes_tickets, "build_batch_ticketing_service", lambda: service)
    body = json.dumps(
        {
            "batch_id": 1,
            "successful_count": 1,
            "failed_count": 0,
            "dispatch_token": "A" * 43,
        },
        separators=(",", ":"),
    ).encode("utf-8")

    response = TestClient(app).post(
        "/tickets/batch/confirm",
        content=body,
        headers=_signed_headers("test-secret", body),
    )

    assert response.status_code == 500
    assert response.json() == {
        "detail": {
            "error": "Batch-Bestätigung fehlgeschlagen",
            "code": "batch_confirmation_failed",
        }
    }
    assert internal_detail not in response.text


def test_import_rejects_file_over_configured_limit(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "MAX_IMPORT_BYTES", 8)
    client = TestClient(app)

    response = client.post(
        "/findings/import",
        files={"file": ("findings.json", b"[123456789]", "application/json")},
    )

    assert response.status_code == 413


def test_import_rejects_too_many_findings(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "MAX_IMPORT_BYTES", 1024 * 1024)
    monkeypatch.setattr(settings, "MAX_FINDINGS_PER_IMPORT", 1)
    finding = {
        "name": "Finding",
        "tenant": "Tenant",
        "risk": 5.0,
        "amount": 1,
        "target": "server01",
        "extendedSolution": ["Fix"],
        "products": ["Product"],
    }
    client = TestClient(app)

    response = client.post(
        "/findings/import",
        files={
            "file": (
                "findings.json",
                json.dumps([finding, finding]).encode("utf-8"),
                "application/json",
            )
        },
    )

    assert response.status_code == 413
