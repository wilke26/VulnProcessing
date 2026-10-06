"""Authentication and tenant authorization for management API routes."""

from __future__ import annotations

import hmac
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status

from app.core.config import settings

ALL_SCOPE = "*"

FINDINGS_IMPORT = "findings:import"
TICKETS_CREATE = "tickets:create"
TICKETS_DISPATCH = "tickets:dispatch"
BATCHES_CREATE = "batches:create"
BATCHES_DISPATCH = "batches:dispatch"
BATCHES_READ = "batches:read"


@dataclass(frozen=True)
class ManagementPrincipal:
    """Authenticated management identity and its server-side scopes."""

    subject: str
    tenants: frozenset[str]
    operations: frozenset[str]

    def allows_operation(self, operation: str) -> bool:
        return ALL_SCOPE in self.operations or operation in self.operations

    def allows_tenant(self, tenant_name: str) -> bool:
        return ALL_SCOPE in self.tenants or tenant_name in self.tenants

    @property
    def has_all_tenants(self) -> bool:
        return ALL_SCOPE in self.tenants


def _authentication_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={
            "error": "Ungültige Management-Authentifizierung",
            "code": "invalid_management_auth",
        },
        headers={"WWW-Authenticate": "Bearer"},
    )


def authenticate_management_request(
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> ManagementPrincipal:
    """Authenticate an opaque bearer token without leaking configured values."""

    if not settings.MANAGEMENT_CREDENTIALS:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "Management-API ist nicht konfiguriert",
                "code": "management_auth_unavailable",
            },
        )

    scheme, separator, token = (authorization or "").partition(" ")
    if separator != " " or scheme.lower() != "bearer" or not token or len(token) > 512:
        raise _authentication_error()

    matched = None
    for credential in settings.MANAGEMENT_CREDENTIALS:
        configured_token = credential.token.get_secret_value()
        if hmac.compare_digest(token, configured_token):
            matched = credential

    if matched is None:
        raise _authentication_error()

    return ManagementPrincipal(
        subject=matched.subject,
        tenants=frozenset(matched.tenants),
        operations=frozenset(matched.operations),
    )


def require_management_operation(
    operation: str,
) -> Callable[..., ManagementPrincipal]:
    """Build a FastAPI dependency that enforces an operation scope."""

    def dependency(
        principal: Annotated[ManagementPrincipal, Depends(authenticate_management_request)],
    ) -> ManagementPrincipal:
        if not principal.allows_operation(operation):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "Management-Operation nicht erlaubt",
                    "code": "management_operation_forbidden",
                },
            )
        return principal

    return dependency


def require_tenant_access(principal: ManagementPrincipal, tenant_name: str) -> None:
    """Reject a tenant outside the authenticated principal's configured scope."""

    if not principal.allows_tenant(tenant_name):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Mandantenzugriff nicht erlaubt", "code": "tenant_forbidden"},
        )
