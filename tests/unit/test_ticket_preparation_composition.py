"""Tests fuer die optionale N-Central-Komposition."""

from app.core.config import Settings
from app.services.ticket_preparation import (
    WindowsPatchFilterStep,
    build_ticket_preparation_service,
)


def test_build_service_omits_ncentral_step_when_filter_disabled() -> None:
    settings = Settings(
        ENABLE_WINDOWS_PATCH_FILTER=False,
        NCENTRAL_API_URL="",
        NCENTRAL_API_KEY="",
    )

    service = build_ticket_preparation_service(settings)

    assert not any(isinstance(step, WindowsPatchFilterStep) for step in service.steps)


def test_build_service_uses_configured_ncentral_client_when_filter_enabled() -> None:
    settings = Settings(
        ENABLE_WINDOWS_PATCH_FILTER=True,
        NCENTRAL_API_URL="https://ncentral.example.test/",
        NCENTRAL_API_KEY="test-key",
    )

    service = build_ticket_preparation_service(settings)

    patch_step = next(step for step in service.steps if isinstance(step, WindowsPatchFilterStep))
    assert patch_step.patch_filter.client.base_url == "https://ncentral.example.test"
    assert patch_step.patch_filter.client.api_key == "test-key"
