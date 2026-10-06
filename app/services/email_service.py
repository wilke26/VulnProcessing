"""
Dieses Modul stellt den EmailService bereit, der für den Versand von
Schwachstellenberichten und Ticket-Informationen per E-Mail verantwortlich ist.

Er unterstützt:
- Den Versand über SMTP mit optionalem TLS.
- Die Erstellung von mehrteiligen MIME-E-Mails (Text und HTML).
- Die Konfiguration über globale Einstellungen oder direkte Parameter.
"""

from __future__ import annotations

import smtplib
import ssl
from dataclasses import dataclass
from email import policy
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.core.config import settings
from app.core.logging import get_logger

# Logger initialisieren
logger = get_logger(__name__)


@dataclass
class EmailTicket:
    """
    Datenklasse zur Repräsentation einer Ticket-E-Mail.

    Hält alle relevanten Informationen wie Empfänger, Betreff, Textinhalt
    und optionale Header für den E-Mail-Versand bereit.
    """

    to: str
    subject: str
    body_text: str
    body_html: str | None = None
    cc: list[str] | None = None
    reply_to: str | None = None
    headers: dict[str, str] | None = None


class EmailService:
    """
    Service zum Versenden von E-Mails via SMTP.

    Wird primär genutzt, um Tickets an externe Systeme zu senden, die eine
    E-Mail-Schnittstelle besitzen (z.B. DocBee oder MKS).
    """

    def __init__(
        self,
        smtp_host: str | None = None,
        smtp_port: int | None = None,
        smtp_user: str | None = None,
        smtp_password: str | None = None,
        use_tls: bool | None = None,
        from_address: str | None = None,
    ):
        """
        Initialisiert den EmailService. Falls keine Parameter übergeben werden,
        werden die Standardwerte aus den globalen Settings verwendet.
        """
        self.smtp_host = smtp_host or settings.SMTP_HOST
        self.smtp_port = smtp_port or settings.SMTP_PORT
        self.smtp_user = smtp_user or settings.SMTP_USER
        self.smtp_password = smtp_password or settings.SMTP_PASSWORD
        self.use_tls = use_tls if use_tls is not None else settings.SMTP_USE_TLS
        self.from_address = from_address or settings.SMTP_FROM_ADDRESS

        # Prüfung der Konfiguration beim Start
        if not settings.smtp_configured:
            logger.warning(
                "SMTP ist nicht vollständig konfiguriert. Der E-Mail-Versand wird fehlschlagen. "
                "Bitte SMTP_HOST, SMTP_USER und SMTP_PASSWORD in den Einstellungen prüfen."
            )

    async def send_ticket_email(self, ticket: EmailTicket) -> bool:
        """
        Versendet eine E-Mail basierend auf einem EmailTicket-Objekt.

        Args:
            ticket (EmailTicket): Das zu versendende Ticket-Objekt.

        Returns:
            bool: True, wenn der Versand erfolgreich war, sonst False.
        """
        if not settings.smtp_configured:
            logger.error("SMTP-Versand abgebrochen: E-Mail-Dienst ist nicht konfiguriert.")
            return False

        try:
            # MIME-Nachricht generieren
            msg = self._build_message(ticket)
            tls_context = ssl.create_default_context() if self.use_tls else None

            # SMTP-Verbindung aufbauen und Nachricht senden
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if tls_context is not None:
                    server.starttls(context=tls_context)

                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)

            logger.info(
                f"Ticket-E-Mail erfolgreich versendet an {ticket.to} mit Betreff: {ticket.subject}"
            )
            return True

        except Exception as e:
            logger.error(
                f"Fehler beim Versand der Ticket-E-Mail an {ticket.to}: {e}",
                exc_info=True,
            )
            return False

    def _build_message(self, ticket: EmailTicket) -> MIMEMultipart:
        """
        Interne Hilfsmethode zum Aufbau der MIME-Struktur einer E-Mail.
        Unterstützt sowohl Plain-Text als auch HTML (Multipart/Alternative).
        """
        msg = MIMEMultipart("alternative", policy=policy.default)

        msg["From"] = self.from_address
        msg["To"] = ticket.to
        msg["Subject"] = ticket.subject

        if ticket.cc:
            msg["Cc"] = ", ".join(ticket.cc)

        if ticket.reply_to:
            msg["Reply-To"] = ticket.reply_to

        # Zusätzliche benutzerdefinierte Header hinzufügen
        if ticket.headers:
            for key, value in ticket.headers.items():
                msg[key] = value

        # Text-Teil hinzufügen (immer als Fallback vorhanden)
        msg.attach(MIMEText(ticket.body_text, "plain", "utf-8"))

        # Optionalen HTML-Teil hinzufügen
        if ticket.body_html:
            msg.attach(MIMEText(ticket.body_html, "html", "utf-8"))

        return msg
