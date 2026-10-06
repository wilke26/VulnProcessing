"""Reference client for signed batch-confirmation webhooks."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Sequence
from typing import Any

_DISPATCH_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")
_MAX_RESPONSE_BYTES = 64 * 1024


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent credentials and dispatch tokens from following redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _confirmation(value: str) -> dict[str, int | str]:
    try:
        finding_id_text, status = value.split("=", 1)
        finding_id = int(finding_id_text)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError(
            "confirmation must use FINDING_ID=confirmed or FINDING_ID=failed"
        ) from exc
    if finding_id <= 0 or status not in {"confirmed", "failed"}:
        raise argparse.ArgumentTypeError(
            "confirmation must use a positive FINDING_ID and confirmed or failed"
        )
    return {"finding_id": finding_id, "status": status}


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("timeout must be positive")
    return parsed


def build_confirmation_body(
    *,
    batch_id: int,
    successful_count: int,
    failed_count: int,
    dispatch_token: str,
    ticket_confirmations: list[dict[str, int | str]] | None = None,
) -> bytes:
    """Serialize the exact compact JSON bytes covered by the HMAC signature."""
    if batch_id <= 0 or successful_count < 0 or failed_count < 0:
        raise ValueError("batch_id must be positive and counts must be non-negative")
    if _DISPATCH_TOKEN_PATTERN.fullmatch(dispatch_token) is None:
        raise ValueError("dispatch token must be a 43-character URL-safe token")

    if ticket_confirmations:
        try:
            finding_ids = [item["finding_id"] for item in ticket_confirmations]
            statuses = [item["status"] for item in ticket_confirmations]
        except KeyError as exc:
            raise ValueError("each ticket confirmation requires finding_id and status") from exc
        if any(
            isinstance(finding_id, bool) or not isinstance(finding_id, int) or finding_id <= 0
            for finding_id in finding_ids
        ):
            raise ValueError("finding IDs must be positive integers")
        if any(status not in {"confirmed", "failed"} for status in statuses):
            raise ValueError("confirmation status must be confirmed or failed")
        if len(set(finding_ids)) != len(finding_ids):
            raise ValueError("ticket confirmations must not contain duplicate finding IDs")
        if statuses.count("confirmed") != successful_count:
            raise ValueError("confirmed findings do not match successful_count")
        if statuses.count("failed") != failed_count:
            raise ValueError("failed findings do not match failed_count")
    elif failed_count:
        raise ValueError("failed confirmations require per-finding confirmation details")

    payload: dict[str, Any] = {
        "batch_id": batch_id,
        "successful_count": successful_count,
        "failed_count": failed_count,
        "dispatch_token": dispatch_token,
    }
    if ticket_confirmations:
        payload["ticket_confirmations"] = ticket_confirmations
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def build_signature_headers(*, body: bytes, secret: str, timestamp: int) -> dict[str, str]:
    """Build the authentication headers for an exact request body."""
    if not secret:
        raise ValueError("webhook secret must not be empty")
    if timestamp < 0:
        raise ValueError("timestamp must not be negative")
    timestamp_text = str(timestamp)
    signed_payload = timestamp_text.encode("ascii") + b"." + body
    digest = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-Webhook-Timestamp": timestamp_text,
        "X-Webhook-Signature": f"sha256={digest}",
    }


def _validate_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("URL must be an absolute HTTP or HTTPS URL")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid port") from exc
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL must not contain credentials")
    if parsed.fragment:
        raise ValueError("URL must not contain a fragment")
    if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("HTTPS is required except for local development")


def send_confirmation(
    *,
    url: str,
    body: bytes,
    headers: dict[str, str],
    timeout: float,
    opener: Any | None = None,
) -> tuple[int, bytes]:
    """Send a signed confirmation without forwarding secrets across redirects."""
    _validate_url(url)
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    active_opener = opener or urllib.request.build_opener(_NoRedirectHandler())
    with active_opener.open(request, timeout=timeout) as response:
        return response.status, response.read(_MAX_RESPONSE_BYTES)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate or send a signed VulnProcessing batch confirmation."
    )
    parser.add_argument("--url", required=True, help="Full /tickets/batch/confirm URL.")
    parser.add_argument("--batch-id", required=True, type=int)
    parser.add_argument("--successful-count", required=True, type=int)
    parser.add_argument("--failed-count", type=int, default=0)
    parser.add_argument(
        "--confirmation",
        action="append",
        default=[],
        type=_confirmation,
        metavar="FINDING_ID=STATUS",
        help="Repeat for every finding when per-finding results are required.",
    )
    parser.add_argument(
        "--secret-env",
        default="BATCH_CONFIRM_WEBHOOK_SECRET",
        help="Environment variable containing the shared webhook secret.",
    )
    parser.add_argument(
        "--dispatch-token-env",
        default="BATCH_CONFIRM_DISPATCH_TOKEN",
        help="Environment variable containing the token returned by dispatch.",
    )
    parser.add_argument("--send", action="store_true", help="Send instead of previewing.")
    parser.add_argument("--timeout", type=_positive_float, default=10.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    secret = os.environ.get(args.secret_env, "")
    dispatch_token = os.environ.get(args.dispatch_token_env, "")
    if not secret:
        parser.error(f"environment variable {args.secret_env} is not set")
    if not dispatch_token:
        parser.error(f"environment variable {args.dispatch_token_env} is not set")

    try:
        _validate_url(args.url)
        body = build_confirmation_body(
            batch_id=args.batch_id,
            successful_count=args.successful_count,
            failed_count=args.failed_count,
            dispatch_token=dispatch_token,
            ticket_confirmations=args.confirmation or None,
        )
        headers = build_signature_headers(body=body, secret=secret, timestamp=int(time.time()))
    except ValueError as exc:
        parser.error(str(exc))

    if not args.send:
        print(f"POST {args.url}")
        for name, value in headers.items():
            print(f"{name}: {value}")
        print()
        print(body.decode("utf-8"))
        return 0

    try:
        status, response_body = send_confirmation(
            url=args.url,
            body=body,
            headers=headers,
            timeout=args.timeout,
        )
    except urllib.error.HTTPError as exc:
        response_body = exc.read(_MAX_RESPONSE_BYTES)
        print(f"HTTP {exc.code}: {response_body.decode('utf-8', errors='replace')}")
        return 1
    except (TimeoutError, urllib.error.URLError) as exc:
        reason = getattr(exc, "reason", str(exc))
        print(f"Request failed: {reason}")
        return 2

    print(f"HTTP {status}: {response_body.decode('utf-8', errors='replace')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
