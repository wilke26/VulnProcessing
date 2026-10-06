from __future__ import annotations

import ssl

import pytest

from app.core.config import settings
from app.services import email_service
from app.services.email_service import EmailService, EmailTicket


def _service() -> EmailService:
    return EmailService(
        smtp_host="smtp.example.test",
        smtp_port=587,
        smtp_user="user",
        smtp_password="password",
        use_tls=True,
        from_address="sender@example.test",
    )


@pytest.mark.parametrize(
    "ticket",
    [
        EmailTicket(
            to="recipient@example.test",
            subject="Finding\r\nBcc: attacker@example.test",
            body_text="details",
        ),
        EmailTicket(
            to="recipient@example.test",
            subject="Finding",
            body_text="details",
            headers={"X-Ticket-Tenant": "Tenant\nBcc: attacker@example.test"},
        ),
    ],
)
def test_build_message_rejects_header_injection(ticket: EmailTicket) -> None:
    with pytest.raises(ValueError):
        _service()._build_message(ticket)


def test_build_message_preserves_legitimate_headers() -> None:
    message = _service()._build_message(
        EmailTicket(
            to="recipient@example.test",
            subject="Kritisches Finding – München",
            body_text="details",
            headers={"X-Ticket-Tenant": "München GmbH"},
        )
    )

    assert str(message["Subject"]) == "Kritisches Finding – München"
    assert str(message["X-Ticket-Tenant"]) == "München GmbH"


class RecordingSMTP:
    def __init__(
        self, host: str, port: int, events: list[object], timeout: float | None = None
    ) -> None:
        self.events = events
        self.events.append(("connect", host, port, timeout))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        return None

    def starttls(self, *, context: ssl.SSLContext) -> None:
        self.events.append(("starttls", context))

    def login(self, user: str, password: str) -> None:
        self.events.append(("login", user, password))

    def send_message(self, message) -> None:
        self.events.append(("send_message", message))


def _configure_smtp(monkeypatch) -> None:
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.example.test")
    monkeypatch.setattr(settings, "SMTP_PORT", 587)
    monkeypatch.setattr(settings, "SMTP_USER", "user")
    monkeypatch.setattr(settings, "SMTP_PASSWORD", "password")


@pytest.mark.asyncio
async def test_send_uses_verifying_tls_context_before_credentials(monkeypatch) -> None:
    events: list[object] = []
    _configure_smtp(monkeypatch)
    monkeypatch.setattr(
        email_service.smtplib,
        "SMTP",
        lambda host, port, timeout: RecordingSMTP(host, port, events, timeout),
    )

    result = await _service().send_ticket_email(
        EmailTicket(to="recipient@example.test", subject="Finding", body_text="details")
    )

    assert result is True
    assert [event[0] for event in events] == [
        "connect",
        "starttls",
        "login",
        "send_message",
    ]
    context = events[1][1]
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert events[0][3] == settings.SMTP_TIMEOUT_SECONDS


@pytest.mark.asyncio
async def test_certificate_rejection_prevents_credentials_and_message(monkeypatch) -> None:
    events: list[object] = []
    _configure_smtp(monkeypatch)

    class RejectingSMTP(RecordingSMTP):
        def starttls(self, *, context: ssl.SSLContext) -> None:
            self.events.append(("starttls", context))
            raise ssl.SSLCertVerificationError("certificate verify failed")

    monkeypatch.setattr(
        email_service.smtplib,
        "SMTP",
        lambda host, port, timeout: RejectingSMTP(host, port, events, timeout),
    )

    result = await _service().send_ticket_email(
        EmailTicket(to="recipient@example.test", subject="Finding", body_text="details")
    )

    assert result is False
    assert [event[0] for event in events] == ["connect", "starttls"]


@pytest.mark.asyncio
async def test_explicit_tls_disable_preserves_legacy_smtp_mode(monkeypatch) -> None:
    events: list[object] = []
    _configure_smtp(monkeypatch)
    monkeypatch.setattr(
        email_service.smtplib,
        "SMTP",
        lambda host, port, timeout: RecordingSMTP(host, port, events, timeout),
    )
    service = EmailService(
        smtp_host="smtp.example.test",
        smtp_port=587,
        smtp_user="user",
        smtp_password="password",
        use_tls=False,
        from_address="sender@example.test",
    )

    result = await service.send_ticket_email(
        EmailTicket(to="recipient@example.test", subject="Finding", body_text="details")
    )

    assert result is True
    assert [event[0] for event in events] == ["connect", "login", "send_message"]
