"""Regression tests for the non-sensitive public HTTP error contract."""

from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest
from fastapi.testclient import TestClient

from app.api import routes_health, routes_tickets
from app.core.config import settings
from app.main import app, create_app


class FailingUnitOfWork:
    marker = "/srv/private/vulnprocessing.sqlite3"

    def __enter__(self):
        raise RuntimeError(self.marker)

    def __exit__(self, *_args):
        return False


@pytest.mark.parametrize(
    ("method", "path", "expected_code"),
    [
        ("post", "/tickets/create", "ticket_create_failed"),
        ("post", "/tickets/dispatch", "dispatch_failed"),
        ("get", "/tickets/batch/status/1", "batch_status_failed"),
        ("get", "/tickets/batch/statistics/Tenant", "batch_statistics_failed"),
    ],
)
def test_ticket_routes_do_not_publish_exception_details(
    monkeypatch,
    method: str,
    path: str,
    expected_code: str,
) -> None:
    monkeypatch.setattr(routes_tickets, "UnitOfWork", FailingUnitOfWork)

    response = getattr(TestClient(app), method)(path)

    assert response.status_code == 500
    assert response.json()["detail"]["code"] == expected_code
    assert FailingUnitOfWork.marker not in response.text


def test_automatic_validation_does_not_echo_rejected_input() -> None:
    rejected_value = "private-batch-id"

    response = TestClient(app).get(f"/tickets/batch/status/{rejected_value}")

    assert response.status_code == 422
    assert rejected_value not in response.text
    error = response.json()["detail"][0]
    assert set(error) == {"type", "loc", "msg"}


def test_import_validation_does_not_echo_sensitive_finding_values() -> None:
    sensitive_value = "customer-secret.example.internal"
    finding = {
        "name": "Finding",
        "tenant": "Tenant",
        "risk": sensitive_value,
        "amount": 1,
        "target": "server01",
        "extendedSolution": ["Fix"],
        "products": ["Product"],
    }

    response = TestClient(app).post(
        "/findings/import",
        files={"file": ("findings.json", json.dumps([finding]), "application/json")},
    )

    assert response.status_code == 422
    assert sensitive_value not in response.text
    assert all(set(error) == {"type", "loc", "msg"} for error in response.json()["detail"])


def test_webhook_validation_does_not_echo_dispatch_token(monkeypatch) -> None:
    monkeypatch.setattr(settings, "BATCH_CONFIRM_WEBHOOK_SECRET", "test-secret")
    sensitive_token = "secret/token/from/private/backend".ljust(43, "!")
    timestamp = str(int(time.time()))
    body = json.dumps(
        {
            "batch_id": 1,
            "successful_count": 1,
            "failed_count": 0,
            "dispatch_token": sensitive_token,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    signature = hmac.new(
        b"test-secret",
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
    assert sensitive_token not in response.text
    assert all(set(error) == {"type", "loc", "msg"} for error in response.json()["detail"])


def test_health_metadata_does_not_publish_absolute_schema_paths(tmp_path, monkeypatch) -> None:
    schema = tmp_path / "private" / "schema.json"
    schema.parent.mkdir()
    schema.write_text("{}", encoding="utf-8")
    monkeypatch.setitem(routes_health.SCHEMAS, "raw", schema)
    monkeypatch.setitem(routes_health.SCHEMAS, "envelope", schema)

    response = TestClient(app).get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert str(tmp_path) not in response.text
    assert "path" not in response.json()["schemas"]["raw"]


def test_unhandled_exceptions_use_stable_public_error() -> None:
    internal_detail = "postgresql://admin:secret@internal-db/vulnprocessing"
    test_app = create_app()

    @test_app.get("/test-unhandled-error")
    async def fail() -> None:
        raise RuntimeError(internal_detail)

    response = TestClient(test_app, raise_server_exceptions=False).get("/test-unhandled-error")

    assert response.status_code == 500
    assert response.json() == {
        "detail": {"error": "Interner Serverfehler", "code": "internal_server_error"}
    }
    assert internal_detail not in response.text
