"""Stable, non-sensitive error responses for the public HTTP boundary."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from typing import Any

from fastapi import Request, status
from fastapi.exceptions import RequestValidationError
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)


def error_detail(code: str, message: str) -> dict[str, str]:
    """Build the repository's stable public error envelope."""

    return {"error": message, "code": code}


def sanitized_validation_errors(
    errors: Iterable[Mapping[str, Any]],
    *,
    location_prefix: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    """Keep useful validation metadata without reflecting submitted values or internals."""

    sanitized: list[dict[str, Any]] = []
    for error in errors:
        location = (*location_prefix, *error.get("loc", ()))
        sanitized.append(
            {
                "type": str(error.get("type", "value_error")),
                "loc": location,
                "msg": str(error.get("msg", "Ungültiger Wert")),
            }
        )
    return sanitized


async def request_validation_error_response(
    _request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Return FastAPI validation errors without Pydantic's input, context, or URL fields."""

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={"detail": sanitized_validation_errors(exc.errors())},
    )


async def internal_error_response(_request: Request, exc: Exception) -> JSONResponse:
    """Log unexpected failures server-side and expose only a stable public response."""

    logger.error(
        "Unbehandelter Fehler bei der Request-Verarbeitung",
        exc_info=(type(exc), exc, exc.__traceback__),
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": error_detail(
                "internal_server_error",
                "Interner Serverfehler",
            )
        },
    )
