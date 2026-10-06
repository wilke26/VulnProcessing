"""Process-local admission control and streaming HTTP body limits."""

from __future__ import annotations

from collections.abc import AsyncIterator
from threading import Lock

from fastapi import HTTPException, status
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import settings


class RequestBodyTooLarge(Exception):
    """Raised while consuming a request body that crosses the configured limit."""


def _limit_detail(code: str, error: str) -> dict[str, str]:
    return {"error": error, "code": code}


class RequestBodyLimitMiddleware:
    """Reject oversized HTTP bodies without buffering them in application memory."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        max_bytes = settings.MAX_REQUEST_BYTES
        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > max_bytes:
                    raise RequestBodyTooLarge
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except RequestBodyTooLarge:
            if response_started:
                raise
            await self._send_error(scope, receive, send)

    @staticmethod
    async def _send_error(
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        response = JSONResponse(
            status_code=413,
            content={
                "detail": _limit_detail(
                    "request_too_large",
                    "Request überschreitet die konfigurierte Größenbegrenzung",
                )
            },
        )
        await response(scope, receive, send)


class _ManagementCapacityGate:
    """Small process-local, fail-fast gate shared by expensive management routes."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._active = 0

    def acquire(self, limit: int) -> bool:
        with self._lock:
            if self._active >= limit:
                return False
            self._active += 1
            return True

    def release(self) -> None:
        with self._lock:
            if self._active <= 0:
                raise RuntimeError("management capacity gate released without acquisition")
            self._active -= 1


_management_capacity = _ManagementCapacityGate()


async def enforce_management_capacity() -> AsyncIterator[None]:
    """Reserve one process-local slot for an expensive management operation."""

    if not _management_capacity.acquire(settings.MAX_CONCURRENT_MANAGEMENT_OPERATIONS):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=_limit_detail(
                "management_capacity_exceeded",
                "Zu viele gleichzeitige Management-Operationen",
            ),
            headers={"Retry-After": "1"},
        )
    try:
        yield
    finally:
        _management_capacity.release()
