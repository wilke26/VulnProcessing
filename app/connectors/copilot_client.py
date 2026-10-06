"""
app/connectors/copilot_client.py

Dieses Modul implementiert einen asynchronen Low-Level-Client für die
Kommunikation mit Microsoft Copilot Studio über die Direct Line API. Es
stellt Methoden bereit, um Gespräche zu starten und zu schließen, Nachrichten
zu senden und die Antworten abzurufen, sowie eine Hilfsmethode, um
AI-generierte Remediation-Guides zurückzugeben.

Die Konfiguration wird über ``app.core.config.settings`` eingelesen. Basis-URL,
Secret und HTTP-Timeout stammen aus ``COPILOT_STUDIO_URL``,
``COPILOT_STUDIO_SECRET`` und ``COPILOT_TIMEOUT_SECONDS``.
"""

from __future__ import annotations

from typing import Any

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from app.core.config import settings
from app.core.logging import get_logger
from app.models.remediation import RemediationGuide

logger = get_logger(__name__)


class CopilotStudioClient:
    """Low-Level-Client für Microsoft Copilot Studio."""

    def __init__(self) -> None:
        # Der getattr-Fallback hält den Client gegenüber älteren Settings-Objekten kompatibel.
        endpoint = getattr(settings, "COPILOT_STUDIO_URL", None) or getattr(
            settings, "COPILOT_STUDIO_ENDPOINT", None
        )
        self.endpoint: str | None = endpoint.rstrip("/") if endpoint else None

        # Geheimnis (API‑Token) aus Settings – falls nicht gesetzt None
        self.secret: str | None = getattr(settings, "COPILOT_STUDIO_SECRET", None)

        # Timeout für HTTP‑Aufrufe, Standard 30 s
        self.timeout: int = getattr(settings, "COPILOT_TIMEOUT_SECONDS", 30)

        # Gesprächs‑State
        self.conversation_id: str | None = None
        self.token: str | None = None

    @staticmethod
    def _is_retryable(exc: BaseException) -> bool:
        if isinstance(exc, httpx.TimeoutException):
            return True
        if isinstance(exc, httpx.TransportError):
            return True
        if isinstance(exc, httpx.HTTPStatusError):
            status = exc.response.status_code
            return status == 429 or status >= 500
        return False

    @retry(
        retry=retry_if_exception(_is_retryable),
        stop=stop_after_attempt(getattr(settings, "RETRY_ATTEMPTS", 3)),
        wait=wait_exponential(
            multiplier=1,
            min=getattr(settings, "RETRY_MIN_SECONDS", 1),
            max=getattr(settings, "RETRY_MAX_SECONDS", 8),
        ),
        reraise=True,
    )
    async def _request(
        self, method: str, url: str, headers: dict[str, str], json: dict | None = None
    ) -> httpx.Response:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.request(method, url, headers=headers, json=json)
            response.raise_for_status()
            return response

    async def start_conversation(self) -> str:
        """Neues Gespräch mit Copilot Studio starten und die ID zurückgeben."""
        if not self.endpoint:
            raise RuntimeError("Copilot endpoint is not configured")
        if not self.secret:
            raise RuntimeError("Copilot secret is not configured")

        headers = {
            "Authorization": f"Bearer {self.secret}",
            "Content-Type": "application/json",
        }
        try:
            response = await self._request(
                "POST", f"{self.endpoint}/conversations", headers=headers
            )
            data = response.json()
            self.conversation_id = data.get("conversationId")
            # neues Token (falls geliefert) speichern, sonst Secret weiterverwenden
            self.token = data.get("token", self.secret)
            logger.info("Started Copilot conversation: %s", self.conversation_id)
            return self.conversation_id  # type: ignore[return-value]
        except httpx.HTTPStatusError as e:
            logger.error("Copilot conversation start failed: %s", e.response.status_code)
            raise
        except Exception as e:
            logger.error("Copilot connection error: %s", e)
            raise

    async def send_message(
        self, message: str, conversation_id: str | None = None
    ) -> dict[str, Any]:
        """
        Sendet eine Nachricht an Copilot Studio und gibt die Antwort als Dict zurück.
        Falls noch kein Gespräch existiert, wird automatisch ein neues gestartet.
        """

        if not conversation_id and not self.conversation_id:
            await self.start_conversation()
        conv_id = conversation_id or self.conversation_id
        if not conv_id:
            raise RuntimeError("Conversation ID is not available")

        headers = {
            "Authorization": f"Bearer {self.token or self.secret}",
            "Content-Type": "application/json",
        }
        payload = {
            "type": "message",
            "from": {"id": "user"},
            "text": message,
        }
        try:
            # Nachricht senden
            await self._request(
                "POST",
                f"{self.endpoint}/conversations/{conv_id}/activities",
                headers=headers,
                json=payload,
            )
            # Alle Aktivitäten abrufen und nach Bot-Antworten filtern
            response = await self._request(
                "GET",
                f"{self.endpoint}/conversations/{conv_id}/activities",
                headers=headers,
            )
            activities = response.json().get("activities", [])
            bot_messages = [act for act in activities if act.get("from", {}).get("id") != "user"]
            if bot_messages:
                latest = bot_messages[-1]
                return {
                    "text": latest.get("text", ""),
                    "timestamp": latest.get("timestamp"),
                    "conversation_id": conv_id,
                }
            logger.warning("No bot response received from Copilot")
            return {"text": "", "conversation_id": conv_id}
        except httpx.TimeoutException:
            logger.error("Copilot timeout after %ss", self.timeout)
            raise
        except httpx.HTTPStatusError as e:
            logger.error("Copilot HTTP error: %s", e.response.status_code)
            raise
        except Exception as e:
            logger.error("Copilot message error: %s", e)
            raise

    async def get_remediation(self, prompt: str) -> RemediationGuide:
        """
        Holt einen Remediation Guide von Copilot aus einem Prompt.
        Gibt ein RemediationGuide-Objekt zurück, dessen Anleitungen aus dem
        Bot-Text bestehen. Da Direct Line keinen Confidence Score liefert, wird
        dieser Wert mit 0.0 belegt.
        """

        try:
            resp = await self.send_message(prompt)
            text = resp.get("text", "")
            if not text:
                logger.warning("Copilot returned an empty response for prompt: %s", prompt)
            return RemediationGuide(instructions=text, confidence_score=0.0)
        except Exception as e:
            logger.error("Copilot remediation error: %s", e)
            return RemediationGuide(instructions="", confidence_score=0.0)

    async def close_conversation(self) -> None:
        """
        Setzt die gespeicherte Conversation ID und das Token zurück.

        Copilot bietet derzeit keinen eigenen API-Call zum Schließen eines
        Gesprächs. Beim nächsten Aufruf von start_conversation wird
        automatisch ein neues Gespräch begonnen.
        """

        if self.conversation_id:
            logger.debug("Closing Copilot conversation %s", self.conversation_id)
        self.conversation_id = None
        self.token = None
