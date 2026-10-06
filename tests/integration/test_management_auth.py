from __future__ import annotations

import json
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

import app.api.routes_tickets as routes_tickets
from app.core.config import ManagementCredential, settings
from app.core.management_auth import (
    BATCHES_CREATE,
    BATCHES_DISPATCH,
    BATCHES_READ,
    FINDINGS_IMPORT,
    TICKETS_CREATE,
    TICKETS_DISPATCH,
    authenticate_management_request,
)
from app.db.models import Asset, Finding, FindingStatus, Tenant, TicketBatch
from app.main import app

TOKEN_A = "tenant-a-management-token-0000000001"
TOKEN_B = "tenant-b-management-token-0000000002"


def _credential(
    token: str,
    *,
    subject: str = "operator",
    tenants: list[str] | None = None,
    operations: list[str] | None = None,
) -> ManagementCredential:
    return ManagementCredential(
        subject=subject,
        token=token,
        tenants=tenants or ["Tenant A"],
        operations=operations or ["*"],
    )


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _finding_payload(tenant: str, name: str) -> dict[str, object]:
    return {
        "name": name,
        "tenant": tenant,
        "risk": 8.0,
        "amount": 1,
        "target": f"{tenant.lower().replace(' ', '-')}.example",
        "extended_solution_json": ["Update installieren"],
        "products": ["Example Product"],
    }


@pytest.fixture
def real_management_auth() -> Iterator[None]:
    override = app.dependency_overrides.pop(authenticate_management_request, None)
    try:
        yield
    finally:
        if override is not None:
            app.dependency_overrides[authenticate_management_request] = override


def test_public_routes_remain_anonymous_and_api_schema_is_disabled(real_management_auth) -> None:
    client = TestClient(app)

    assert client.get("/health").status_code == 200
    assert client.get("/version").status_code == 200
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("post", "/findings/import"),
        ("post", "/tickets/create"),
        ("post", "/tickets/dispatch"),
        ("post", "/tickets/batch/create"),
        ("post", "/tickets/batch/1/send"),
        ("post", "/tickets/batch/1/dispatch"),
        ("get", "/tickets/batch/status/1"),
        ("get", "/tickets/batch/statistics/Tenant%20A"),
    ],
)
def test_every_management_route_fails_closed_without_configuration(
    monkeypatch, real_management_auth, method: str, path: str
) -> None:
    monkeypatch.setattr(settings, "MANAGEMENT_CREDENTIALS", [])

    response = TestClient(app).request(method, path)

    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "management_auth_unavailable"


@pytest.mark.parametrize("authorization", [None, "Basic abc", "Bearer wrong-token"])
def test_management_routes_reject_missing_or_invalid_bearer_token(
    monkeypatch, real_management_auth, authorization: str | None
) -> None:
    monkeypatch.setattr(settings, "MANAGEMENT_CREDENTIALS", [_credential(TOKEN_A)])
    headers = {"Authorization": authorization} if authorization is not None else {}

    response = TestClient(app).post("/tickets/dispatch", params={"dry_run": True}, headers=headers)

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json()["detail"]["code"] == "invalid_management_auth"


def test_operation_scope_is_enforced(monkeypatch, real_management_auth) -> None:
    monkeypatch.setattr(
        settings,
        "MANAGEMENT_CREDENTIALS",
        [_credential(TOKEN_A, operations=[FINDINGS_IMPORT])],
    )

    response = TestClient(app).post(
        "/tickets/dispatch", params={"dry_run": True}, headers=_headers(TOKEN_A)
    )

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "management_operation_forbidden"


def test_unknown_allowed_tenant_is_404_but_out_of_scope_tenant_remains_403(
    db_session, monkeypatch, real_management_auth
) -> None:
    monkeypatch.setattr(
        settings,
        "MANAGEMENT_CREDENTIALS",
        [_credential(TOKEN_A, tenants=["MissingTenant"], operations=[BATCHES_CREATE])],
    )
    client = TestClient(app)

    missing = client.post(
        "/tickets/batch/create",
        params={"tenant_name": "MissingTenant"},
        headers=_headers(TOKEN_A),
    )
    outside_scope = client.post(
        "/tickets/batch/create",
        params={"tenant_name": "OtherTenant"},
        headers=_headers(TOKEN_A),
    )

    assert missing.status_code == 404
    assert missing.json()["detail"]["code"] == "tenant_not_found"
    assert outside_scope.status_code == 403
    assert outside_scope.json()["detail"]["code"] == "tenant_forbidden"


def test_unauthenticated_import_is_rejected_before_multipart_parsing(
    monkeypatch, real_management_auth
) -> None:
    monkeypatch.setattr(settings, "MANAGEMENT_CREDENTIALS", [_credential(TOKEN_A)])

    async def fail_if_form_is_parsed(*args, **kwargs):
        pytest.fail("multipart body was parsed before management authentication")

    monkeypatch.setattr("starlette.requests.Request.form", fail_if_form_is_parsed)

    response = TestClient(app).post(
        "/findings/import",
        content=b"not-a-valid-multipart-body",
        headers={"Content-Type": "multipart/form-data; boundary=missing"},
    )

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "invalid_management_auth"


def test_unauthenticated_oversized_import_is_rejected_before_body_consumption(
    monkeypatch, real_management_auth
) -> None:
    monkeypatch.setattr(settings, "MANAGEMENT_CREDENTIALS", [_credential(TOKEN_A)])
    monkeypatch.setattr(settings, "MAX_REQUEST_BYTES", 1)

    response = TestClient(app).post(
        "/findings/import",
        content=b"oversized but never consumed",
        headers={"Content-Type": "multipart/form-data; boundary=missing"},
    )

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "invalid_management_auth"


def test_ticket_creation_uses_finding_status_after_tenant_join(
    db_session, monkeypatch, real_management_auth
) -> None:
    monkeypatch.setattr(
        settings,
        "MANAGEMENT_CREDENTIALS",
        [_credential(TOKEN_A, operations=[TICKETS_CREATE])],
    )

    response = TestClient(app).post(
        "/tickets/create",
        params={"tenant_name": "Tenant A"},
        headers=_headers(TOKEN_A),
    )

    assert response.status_code == 200
    assert response.json()["created"] == 0


def test_mixed_tenant_import_is_rejected_before_database_writes(
    db_session, monkeypatch, real_management_auth
) -> None:
    monkeypatch.setattr(
        settings,
        "MANAGEMENT_CREDENTIALS",
        [_credential(TOKEN_A, tenants=["Tenant A"], operations=[FINDINGS_IMPORT])],
    )

    response = TestClient(app).post(
        "/findings/import",
        files={
            "file": (
                "findings.json",
                json.dumps(
                    [
                        _finding_payload("Tenant A", "Allowed"),
                        _finding_payload("Tenant B", "Forbidden"),
                    ]
                ),
                "application/json",
            )
        },
        headers=_headers(TOKEN_A),
    )

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "tenant_forbidden"
    assert db_session.query(Tenant).count() == 0


def test_omitted_tenant_filter_is_restricted_to_principal_scope(
    db_session, monkeypatch, real_management_auth
) -> None:
    class PassthroughPreparation:
        async def prepare_for_ticketing(self, findings):
            return findings

    tenant_a = Tenant(name="Tenant A")
    tenant_b = Tenant(name="Tenant B")
    asset_a = Asset(tenant=tenant_a, name="a.example")
    asset_b = Asset(tenant=tenant_b, name="b.example")
    db_session.add_all([tenant_a, tenant_b, asset_a, asset_b])
    db_session.flush()
    db_session.add_all(
        [
            Finding(
                tenant_id=tenant_a.id,
                asset_id=asset_a.id,
                name="Finding A",
                target="a.example",
                risk=7.0,
                amount=1,
                extended_solution_json='["Fix"]',
                status=FindingStatus.NEW.value,
            ),
            Finding(
                tenant_id=tenant_b.id,
                asset_id=asset_b.id,
                name="Finding B",
                target="b.example",
                risk=7.0,
                amount=1,
                extended_solution_json='["Fix"]',
                status=FindingStatus.NEW.value,
            ),
        ]
    )
    db_session.commit()
    monkeypatch.setattr(
        settings,
        "MANAGEMENT_CREDENTIALS",
        [_credential(TOKEN_A, tenants=["Tenant A"], operations=[TICKETS_DISPATCH])],
    )
    monkeypatch.setattr(
        routes_tickets,
        "build_ticket_preparation",
        lambda: PassthroughPreparation(),
    )

    response = TestClient(app).post(
        "/tickets/dispatch",
        params={"dry_run": True},
        headers=_headers(TOKEN_A),
    )

    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["dispatched"] == 1


@pytest.mark.parametrize(
    "path,operation",
    [
        ("/tickets/batch/status/{batch_id}", BATCHES_READ),
        ("/tickets/batch/{batch_id}/send", BATCHES_DISPATCH),
        ("/tickets/batch/{batch_id}/dispatch", BATCHES_DISPATCH),
    ],
)
def test_cross_tenant_batch_ids_are_hidden_before_dispatch(
    db_session, monkeypatch, real_management_auth, path: str, operation: str
) -> None:
    tenant_b = Tenant(name="Tenant B")
    db_session.add(tenant_b)
    db_session.flush()
    batch = TicketBatch(tenant_id=tenant_b.id, batch_number=1, total_findings=0)
    db_session.add(batch)
    db_session.commit()
    monkeypatch.setattr(
        settings,
        "MANAGEMENT_CREDENTIALS",
        [_credential(TOKEN_A, tenants=["Tenant A"], operations=[operation])],
    )
    monkeypatch.setattr(
        routes_tickets,
        "build_ticket_dispatcher",
        lambda: pytest.fail("unauthorized request reached the dispatcher"),
    )

    resolved_path = path.format(batch_id=batch.id)
    client = TestClient(app)
    response = (
        client.get(resolved_path, headers=_headers(TOKEN_A))
        if "/status/" in resolved_path
        else client.post(resolved_path, headers=_headers(TOKEN_A))
    )

    assert response.status_code == 404


def test_webhook_confirmation_does_not_require_management_token(
    monkeypatch, real_management_auth
) -> None:
    monkeypatch.setattr(settings, "MANAGEMENT_CREDENTIALS", [])
    monkeypatch.setattr(settings, "BATCH_CONFIRM_WEBHOOK_SECRET", "test-secret")

    response = TestClient(app).post(
        "/tickets/batch/confirm",
        json={
            "batch_id": 1,
            "successful_count": 1,
            "failed_count": 0,
            "dispatch_token": "A" * 43,
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "invalid_webhook_auth"
