from __future__ import annotations

import hashlib
import hmac

import pytest

from app.core.config import ManagementCredential, Settings
from app.core.security import (
    WebhookAuthenticationError,
    WebhookConfigurationError,
    issue_dispatch_confirmation_token,
    verify_dispatch_confirmation_token,
    verify_webhook_signature,
)


def _signature(secret: str, timestamp: str, body: bytes) -> str:
    payload = timestamp.encode("ascii") + b"." + body
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def test_dispatch_confirmation_token_is_random_and_digest_bound() -> None:
    first_token, first_digest = issue_dispatch_confirmation_token()
    second_token, second_digest = issue_dispatch_confirmation_token()

    assert first_token != second_token
    assert first_digest != second_digest
    assert verify_dispatch_confirmation_token(first_token, first_digest)
    assert not verify_dispatch_confirmation_token(first_token, second_digest)
    assert not verify_dispatch_confirmation_token("invalid", first_digest)


def test_verify_webhook_signature_accepts_valid_request() -> None:
    body = b'{"batch_id":1,"successful_count":1,"failed_count":0}'
    timestamp = "1700000000"

    verified_timestamp = verify_webhook_signature(
        body=body,
        signature=f"sha256={_signature('secret', timestamp, body)}",
        timestamp=timestamp,
        secret="secret",
        max_age_seconds=300,
        now=1700000000,
    )

    assert verified_timestamp == 1700000000


@pytest.mark.parametrize(
    ("signature", "timestamp"),
    [
        (None, "1700000000"),
        ("invalid", "1700000000"),
        ("0" * 64, "1700000000"),
        ("SHA256=" + "0" * 64, "1700000000"),
        ("sha256=" + "A" * 64, "1700000000"),
        ("sha256=" + "0" * 63, "1700000000"),
        ("sha256=" + "0" * 65, "1700000000"),
        ("sha256=" + "0" * 63 + "é", "1700000000"),
        ("sha256=" + "0" * 64 + " ", "1700000000"),
        ("sha256=" + "0" * 64, "not-a-timestamp"),
        ("sha256=" + "0" * 64, "+1700000000"),
        ("sha256=" + "0" * 64, " 1700000000"),
        ("sha256=" + "0" * 64, "١٧٠٠٠٠٠٠٠٠"),
        ("sha256=" + "0" * 64, "1" * 21),
        ("sha256=" + "0" * 64, "1699990000"),
    ],
)
def test_verify_webhook_signature_rejects_invalid_request(
    signature: str | None, timestamp: str
) -> None:
    with pytest.raises(WebhookAuthenticationError):
        verify_webhook_signature(
            body=b"{}",
            signature=signature,
            timestamp=timestamp,
            secret="secret",
            max_age_seconds=300,
            now=1700000000,
        )


def test_verify_webhook_signature_applies_asymmetric_clock_skew() -> None:
    secret = "secret"
    body = b"{}"

    for timestamp in ("1699999700", "1700000030"):
        verify_webhook_signature(
            body=body,
            signature=f"sha256={_signature(secret, timestamp, body)}",
            timestamp=timestamp,
            secret=secret,
            max_age_seconds=300,
            clock_skew_seconds=30,
            now=1700000000,
        )

    for timestamp in ("1699999699", "1700000031"):
        with pytest.raises(WebhookAuthenticationError):
            verify_webhook_signature(
                body=body,
                signature=f"sha256={_signature(secret, timestamp, body)}",
                timestamp=timestamp,
                secret=secret,
                max_age_seconds=300,
                clock_skew_seconds=30,
                now=1700000000,
            )


@pytest.mark.parametrize(
    ("max_age", "clock_skew"),
    [(0, 0), (300, -1), (300, 300), (300, 301)],
)
def test_verify_webhook_signature_rejects_invalid_timing_configuration(
    max_age: int, clock_skew: int
) -> None:
    with pytest.raises(WebhookConfigurationError):
        verify_webhook_signature(
            body=b"{}",
            signature="sha256=" + "0" * 64,
            timestamp="1700000000",
            secret="secret",
            max_age_seconds=max_age,
            clock_skew_seconds=clock_skew,
            now=1700000000,
        )


@pytest.mark.parametrize(
    ("max_age", "clock_skew"),
    [(0, 0), (300, -1), (300, 300), (300, 301)],
)
def test_settings_reject_invalid_webhook_timing(max_age: int, clock_skew: int) -> None:
    with pytest.raises(ValueError):
        Settings(
            NCENTRAL_API_URL="https://example.test",
            NCENTRAL_API_KEY="test-key",
            BATCH_CONFIRM_WEBHOOK_MAX_AGE_SECONDS=max_age,
            BATCH_CONFIRM_WEBHOOK_CLOCK_SKEW_SECONDS=clock_skew,
        )


def test_settings_accept_valid_webhook_timing() -> None:
    configured = Settings(
        NCENTRAL_API_URL="https://example.test",
        NCENTRAL_API_KEY="test-key",
        BATCH_CONFIRM_WEBHOOK_MAX_AGE_SECONDS=300,
        BATCH_CONFIRM_WEBHOOK_CLOCK_SKEW_SECONDS=30,
    )

    assert configured.BATCH_CONFIRM_WEBHOOK_CLOCK_SKEW_SECONDS == 30


def test_settings_allow_missing_ncentral_config_when_filter_disabled() -> None:
    configured = Settings(
        ENABLE_WINDOWS_PATCH_FILTER=False,
        NCENTRAL_API_URL="",
        NCENTRAL_API_KEY="",
    )

    assert configured.ENABLE_WINDOWS_PATCH_FILTER is False


@pytest.mark.parametrize(
    ("url", "api_key"),
    [
        ("https://ncentral.example.test", ""),
        ("", "test-key"),
    ],
)
def test_settings_reject_incomplete_ncentral_config(url: str, api_key: str) -> None:
    with pytest.raises(ValueError, match="gemeinsam"):
        Settings(
            ENABLE_WINDOWS_PATCH_FILTER=False,
            NCENTRAL_API_URL=url,
            NCENTRAL_API_KEY=api_key,
        )


def test_settings_require_ncentral_config_when_filter_enabled() -> None:
    with pytest.raises(ValueError, match="ENABLE_WINDOWS_PATCH_FILTER"):
        Settings(
            ENABLE_WINDOWS_PATCH_FILTER=True,
            NCENTRAL_API_URL="",
            NCENTRAL_API_KEY="",
        )


def test_settings_parse_management_credentials_from_environment(monkeypatch) -> None:
    token = "environment-management-token-00000001"
    monkeypatch.setenv(
        "MANAGEMENT_CREDENTIALS",
        (
            '[{"subject":"portfolio-operator","token":"'
            + token
            + '","tenants":["Tenant A"],"operations":["batches:read"]}]'
        ),
    )

    configured = Settings(_env_file=None)

    assert configured.MANAGEMENT_CREDENTIALS[0].subject == "portfolio-operator"
    assert configured.MANAGEMENT_CREDENTIALS[0].tenants == ["Tenant A"]
    assert token not in repr(configured)
    assert token not in repr(configured.model_dump())


def test_management_credential_rejects_short_token() -> None:
    with pytest.raises(ValueError, match="at least 32"):
        ManagementCredential(
            subject="operator",
            token="too-short",
            tenants=["Tenant A"],
            operations=["batches:read"],
        )


@pytest.mark.parametrize("duplicate", ["subject", "token"])
def test_settings_reject_duplicate_management_credentials(duplicate: str) -> None:
    first_token = "first-management-token-000000000001"
    second_token = first_token if duplicate == "token" else "second-management-token-00000000001"
    second_subject = "first" if duplicate == "subject" else "second"

    with pytest.raises(ValueError, match=f"{duplicate}s must be unique"):
        Settings(
            _env_file=None,
            MANAGEMENT_CREDENTIALS=[
                {
                    "subject": "first",
                    "token": first_token,
                    "tenants": ["Tenant A"],
                    "operations": ["batches:read"],
                },
                {
                    "subject": second_subject,
                    "token": second_token,
                    "tenants": ["Tenant B"],
                    "operations": ["batches:read"],
                },
            ],
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("MAX_REQUEST_BYTES", 0),
        ("MAX_IMPORT_BYTES", 0),
        ("MAX_FINDINGS_PER_IMPORT", 0),
        ("MAX_FINDINGS_PER_TICKET_OPERATION", 0),
        ("MAX_CVES_PER_FINDING", 0),
        ("MAX_CVES_PER_TICKET_OPERATION", 0),
        ("MAX_BATCH_CANDIDATES_PER_OPERATION", 0),
        ("MAX_CONCURRENT_MANAGEMENT_OPERATIONS", 0),
        ("NVD_MAX_CONCURRENT_REQUESTS", 0),
        ("NVD_RATE_LIMIT", 0),
        ("NVD_RATE_LIMIT_WITH_KEY", 0),
        ("NCENTRAL_MAX_CUSTOMER_PAGES", 0),
        ("SMTP_TIMEOUT_SECONDS", 0),
        ("COPILOT_TIMEOUT_SECONDS", 0),
        ("COPILOT_CONCURRENT_REQUESTS", 0),
    ],
)
def test_settings_reject_nonpositive_resource_limits(field: str, value: int) -> None:
    with pytest.raises(ValueError):
        Settings(_env_file=None, **{field: value})


def test_settings_reserve_request_space_for_multipart_overhead() -> None:
    with pytest.raises(ValueError, match="MAX_REQUEST_BYTES"):
        Settings(
            _env_file=None,
            MAX_REQUEST_BYTES=1024 + 64 * 1024 - 1,
            MAX_IMPORT_BYTES=1024,
        )


def test_settings_require_operation_cve_limit_to_cover_one_finding() -> None:
    with pytest.raises(ValueError, match="MAX_CVES_PER_TICKET_OPERATION"):
        Settings(
            _env_file=None,
            MAX_CVES_PER_FINDING=21,
            MAX_CVES_PER_TICKET_OPERATION=20,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [("NVD_RATE_LIMIT", 6), ("NVD_RATE_LIMIT_WITH_KEY", 51)],
)
def test_settings_reject_nvd_rates_above_documented_quota(field: str, value: int) -> None:
    with pytest.raises(ValueError):
        Settings(_env_file=None, **{field: value})
