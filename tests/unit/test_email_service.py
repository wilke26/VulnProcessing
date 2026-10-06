from __future__ import annotations

import pytest

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
