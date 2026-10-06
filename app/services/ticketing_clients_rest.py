"""
REST-basierte Ticket-Clients.

Aktuell Platzhalter: REST-Integration ist noch nicht aktiv verdrahtet.
Die Klassen sind separat, damit E-Mail und REST klar getrennt sind.
"""

from __future__ import annotations

import httpx

from app.core.logging import get_logger

logger = get_logger(__name__)


class DocBeeRestClient:
    """DocBee Ticket-Client via REST."""

    name = "DocBee (REST)"

    def __init__(self, base_url: str | None, api_key: str | None):
        self.base_url = (base_url or "").rstrip("/")
        self.api_key = api_key

    async def create_ticket(
        self,
        title: str,
        description: str,
        priority: str,
        tenant: str,
        *,
        batch_id: int | None = None,
        dispatch_token: str | None = None,
    ) -> str:
        if not self.base_url or not self.api_key:
            raise RuntimeError("DocBee REST-Client ist nicht vollständig konfiguriert")

        payload = {
            "title": title,
            "description": description,
            "priority": priority,
            "tenant": tenant,
        }
        if batch_id is not None and dispatch_token is not None:
            payload["batch_id"] = batch_id
            payload["dispatch_token"] = dispatch_token

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{self.base_url}/tickets",
                headers={"X-API-KEY": self.api_key},
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
            return str(data.get("id") or data.get("external_id") or "rest-success")


class MKSRestClient:
    """MKS Ticket-Client via REST."""

    name = "MKS (REST)"

    def __init__(self, base_url: str | None, username: str | None, password: str | None):
        self.base_url = (base_url or "").rstrip("/")
        self.username = username
        self.password = password

    async def create_ticket(
        self,
        title: str,
        description: str,
        priority: str,
        tenant: str,
        *,
        batch_id: int | None = None,
        dispatch_token: str | None = None,
    ) -> str:
        if not self.base_url or not self.username or not self.password:
            raise RuntimeError("MKS REST-Client ist nicht vollständig konfiguriert")

        payload = {
            "subject": title,
            "body": description,
            "priority": priority,
            "customer": tenant,
        }
        if batch_id is not None and dispatch_token is not None:
            payload["batch_id"] = batch_id
            payload["dispatch_token"] = dispatch_token

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{self.base_url}/tickets",
                auth=(self.username, self.password),
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
            return str(data.get("id") or data.get("ticket_no") or "rest-success")
