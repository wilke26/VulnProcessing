from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from scripts.confirm_batch_webhook import (
    build_confirmation_body,
    build_signature_headers,
    main,
    send_confirmation,
)


def test_builds_and_signs_exact_request_bytes() -> None:
    body = build_confirmation_body(
        batch_id=42,
        successful_count=1,
        failed_count=1,
        dispatch_token="A" * 43,
        ticket_confirmations=[
            {"finding_id": 101, "status": "confirmed"},
            {"finding_id": 102, "status": "failed"},
        ],
    )
    timestamp = 1_760_000_000

    headers = build_signature_headers(body=body, secret="test-secret", timestamp=timestamp)

    assert body == (
        b'{"batch_id":42,"successful_count":1,"failed_count":1,'
        b'"dispatch_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",'
        b'"ticket_confirmations":[{"finding_id":101,"status":"confirmed"},'
        b'{"finding_id":102,"status":"failed"}]}'
    )
    expected_digest = hmac.new(
        b"test-secret", str(timestamp).encode("ascii") + b"." + body, hashlib.sha256
    ).hexdigest()
    assert headers == {
        "Content-Type": "application/json",
        "X-Webhook-Timestamp": str(timestamp),
        "X-Webhook-Signature": f"sha256={expected_digest}",
    }


@pytest.mark.parametrize(
    ("confirmations", "error"),
    [
        (None, "failed confirmations require"),
        (
            [
                {"finding_id": 1, "status": "confirmed"},
                {"finding_id": 1, "status": "failed"},
            ],
            "duplicate finding IDs",
        ),
        ([{"finding_id": 1, "status": "unknown"}], "status must be"),
    ],
)
def test_rejects_confirmation_details_that_server_would_reject(
    confirmations: list[dict[str, int | str]] | None, error: str
) -> None:
    with pytest.raises(ValueError, match=error):
        build_confirmation_body(
            batch_id=42,
            successful_count=1,
            failed_count=1,
            dispatch_token="A" * 43,
            ticket_confirmations=confirmations,
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://example.test/tickets/batch/confirm",
        "https://user:password@example.test/tickets/batch/confirm",
        "https://example.test/tickets/batch/confirm#fragment",
    ],
)
def test_sender_rejects_unsafe_urls(url: str) -> None:
    with pytest.raises(ValueError):
        send_confirmation(url=url, body=b"{}", headers={}, timeout=1)


def test_sender_rejects_malformed_port_before_opening_connection() -> None:
    class FailingOpener:
        def open(self, *_args, **_kwargs):
            pytest.fail("connection must not be opened for an invalid URL")

    with pytest.raises(ValueError, match="invalid port"):
        send_confirmation(
            url="https://example.test:bad/tickets/batch/confirm",
            body=b"{}",
            headers={},
            timeout=1,
            opener=FailingOpener(),
        )


def test_cli_previews_a_signed_request_without_sending(monkeypatch, capsys) -> None:
    monkeypatch.setenv("BATCH_CONFIRM_WEBHOOK_SECRET", "test-secret")
    monkeypatch.setenv("BATCH_CONFIRM_DISPATCH_TOKEN", "A" * 43)
    monkeypatch.setattr("scripts.confirm_batch_webhook.time.time", lambda: 1_760_000_000)

    result = main(
        [
            "--url",
            "https://example.test/tickets/batch/confirm",
            "--batch-id",
            "42",
            "--successful-count",
            "2",
        ]
    )

    output = capsys.readouterr().out
    assert result == 0
    assert "X-Webhook-Timestamp: 1760000000" in output
    assert "X-Webhook-Signature: sha256=" in output
    body_text = output.rsplit("\n\n", maxsplit=1)[1].strip()
    assert json.loads(body_text) == {
        "batch_id": 42,
        "successful_count": 2,
        "failed_count": 0,
        "dispatch_token": "A" * 43,
    }
