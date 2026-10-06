from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.core.config import settings
from app.core.resource_limits import enforce_management_capacity


@pytest.mark.asyncio
async def test_management_capacity_fails_fast_and_releases_slot(monkeypatch) -> None:
    monkeypatch.setattr(settings, "MAX_CONCURRENT_MANAGEMENT_OPERATIONS", 1)
    first = enforce_management_capacity()
    await anext(first)

    saturated = enforce_management_capacity()
    with pytest.raises(HTTPException) as exc_info:
        await anext(saturated)
    assert exc_info.value.status_code == 429
    assert exc_info.value.detail["code"] == "management_capacity_exceeded"
    assert exc_info.value.headers == {"Retry-After": "1"}

    await first.aclose()

    later = enforce_management_capacity()
    await anext(later)
    await later.aclose()
