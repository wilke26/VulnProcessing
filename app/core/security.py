"""Security helpers for inbound service-to-service requests."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time

_SIGNATURE_PATTERN = re.compile(r"sha256=([0-9a-f]{64})")
_TIMESTAMP_PATTERN = re.compile(r"[0-9]{1,20}")
_DISPATCH_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")


class WebhookAuthenticationError(ValueError):
    """Raised when a webhook cannot be authenticated."""


class WebhookConfigurationError(RuntimeError):
    """Raised when webhook authentication is not configured."""


def issue_dispatch_confirmation_token() -> tuple[str, str]:
    """Create a high-entropy one-time token and the digest persisted with a batch."""
    token = secrets.token_urlsafe(32)
    return token, hashlib.sha256(token.encode("ascii")).hexdigest()


def verify_dispatch_confirmation_token(token: str | None, expected_digest: str | None) -> bool:
    """Verify a dispatch-bound token without storing the bearer value."""
    if (
        not isinstance(token, str)
        or _DISPATCH_TOKEN_PATTERN.fullmatch(token) is None
        or not isinstance(expected_digest, str)
    ):
        return False
    supplied_digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    return hmac.compare_digest(supplied_digest, expected_digest)


def verify_webhook_signature(
    *,
    body: bytes,
    signature: str | None,
    timestamp: str | None,
    secret: str,
    max_age_seconds: int,
    clock_skew_seconds: int = 0,
    now: int | None = None,
) -> int:
    """Verify an HMAC-SHA256 signature over ``<timestamp>.<raw body>``.

    A timestamp limits replay attempts. The batch state transition provides
    idempotency for otherwise valid requests within the timestamp window.
    """
    if not secret:
        raise WebhookConfigurationError("Webhook secret is not configured")
    if max_age_seconds <= 0:
        raise WebhookConfigurationError("Webhook maximum age must be positive")
    if clock_skew_seconds < 0 or clock_skew_seconds >= max_age_seconds:
        raise WebhookConfigurationError(
            "Webhook clock skew must be non-negative and smaller than maximum age"
        )
    if not isinstance(signature, str) or not isinstance(timestamp, str):
        raise WebhookAuthenticationError("Missing webhook authentication headers")
    if not signature or not timestamp:
        raise WebhookAuthenticationError("Missing webhook authentication headers")

    signature_match = _SIGNATURE_PATTERN.fullmatch(signature)
    if signature_match is None:
        raise WebhookAuthenticationError("Invalid webhook signature format")
    if _TIMESTAMP_PATTERN.fullmatch(timestamp) is None:
        raise WebhookAuthenticationError("Invalid webhook timestamp")

    timestamp_value = int(timestamp)

    current_time = int(time.time()) if now is None else now
    if timestamp_value < current_time - max_age_seconds:
        raise WebhookAuthenticationError("Webhook timestamp is outside the allowed window")
    if timestamp_value > current_time + clock_skew_seconds:
        raise WebhookAuthenticationError("Webhook timestamp is outside the allowed window")

    supplied_signature = bytes.fromhex(signature_match.group(1))
    signed_payload = timestamp.encode("ascii") + b"." + body
    expected_signature = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).digest()
    if not hmac.compare_digest(supplied_signature, expected_signature):
        raise WebhookAuthenticationError("Invalid webhook signature")

    return timestamp_value
