"""
app/connectors/ncentral_client.py

N-Central REST API Client für Windows-Update-Prüfung.

Dieser Client kommuniziert mit der N-Central REST API, um:
- Kunden (Tenants) zu identifizieren
- Geräte eines Kunden abzurufen
- Installierte Windows-Updates pro Gerät zu prüfen
"""

from __future__ import annotations

from typing import Any

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from app.core.config import Settings, settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class NCentralClient:
    """
    Client für N-Central REST API.

    Konfiguration über Environment-Variablen:
    - NCENTRAL_API_URL: Basis-URL der N-Central API
    - NCENTRAL_API_KEY: JWT-Token oder API-Key
    - NCENTRAL_TIMEOUT: HTTP-Timeout in Sekunden (Standard: 30)
    """

    def __init__(self, settings_obj: Settings = settings) -> None:
        self.settings = settings_obj
        self.base_url = settings_obj.NCENTRAL_API_URL.rstrip("/")
        self.api_key = settings_obj.NCENTRAL_API_KEY
        self.timeout = settings_obj.NCENTRAL_TIMEOUT

        if not self.base_url:
            logger.warning("N-Central API URL nicht konfiguriert")
        if not self.api_key:
            logger.warning("N-Central API Key nicht konfiguriert")

    def _get_headers(self) -> dict[str, str]:
        """Erzeugt HTTP-Headers mit Authentifizierung."""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

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
    async def _get_json(self, url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(url, headers=self._get_headers(), params=params)
            response.raise_for_status()
            return response.json()

    async def find_customer_by_name(self, tenant_name: str) -> dict[str, Any] | None:
        """
        Sucht einen Kunden in N-Central anhand des Namens.

        Args:
            tenant_name: Name des Mandanten (z.B. aus Finding.tenant)

        Returns:
            Customer-Objekt oder None, falls nicht gefunden
        """

        if not self.base_url or not self.api_key:
            logger.error("N-Central API nicht konfiguriert")
            return None

        try:
            exact_matches: list[dict[str, Any]] = []
            page_number = 1
            expected_total_pages: int | None = None
            while True:
                data = await self._get_json(
                    f"{self.base_url}/api/customers",
                    params={"pageNumber": page_number, "pageSize": 1000},
                )
                customers = data.get("items", [])
                total_pages = data.get("totalPages", 1)
                if (
                    not isinstance(customers, list)
                    or not isinstance(total_pages, int)
                    or isinstance(total_pages, bool)
                    or total_pages < 0
                    or (total_pages == 0 and bool(customers))
                    or total_pages > self.settings.NCENTRAL_MAX_CUSTOMER_PAGES
                    or (expected_total_pages is not None and total_pages != expected_total_pages)
                ):
                    logger.warning("Ungültige oder zu große Kundenliste von N-Central erhalten")
                    return None

                expected_total_pages = total_pages

                exact_matches.extend(
                    customer
                    for customer in customers
                    if isinstance(customer, dict) and customer.get("customerName") == tenant_name
                )
                if len(exact_matches) > 1:
                    logger.warning(
                        f"Mehrere exakte Kunden mit Namen '{tenant_name}' gefunden, "
                        "breche Suche ab"
                    )
                    return None
                if page_number >= expected_total_pages:
                    break
                page_number += 1

            if not exact_matches:
                logger.info(f"Kunde '{tenant_name}' nicht in N-Central gefunden")
                return None

            customer = exact_matches[0]
            logger.info(
                f"Kunde gefunden: {customer.get('customerName')} (ID: {customer.get('customerId')})"
            )
            return customer
        except httpx.HTTPStatusError as e:
            logger.error(
                f"N-Central API-Fehler beim Abrufen von Kunde '{tenant_name}': "
                f"{e.response.status_code}"
            )
            return None
        except Exception as e:
            logger.exception(f"Fehler bei N-Central-Abfrage: {e}")
            return None

    async def get_devices_for_customer(
        self, customer_id: int, device_names: list[str] | None = None
    ) -> list[dict[str, Any]]:
        """
        Ruft Geräte eines Kunden ab.

        Args:
            customer_id: N-Central Customer ID
            device_names: Optional: Liste von Gerätenamen zum Filtern

        Returns:
            Liste von Device-Objekten
        """

        if not self.base_url or not self.api_key:
            logger.error("N-Central API nicht konfiguriert")
            return []

        try:
            data = await self._get_json(f"{self.base_url}/api/customers/{customer_id}/devices")
            devices = data.get("items", [])

            # Optional: Nach Gerätenamen filtern
            if device_names:
                devices = [
                    d
                    for d in devices
                    if d.get("deviceName") in device_names or d.get("longName") in device_names
                ]

            logger.info(f"{len(devices)} Gerät(e) für Customer ID {customer_id} gefunden")
            return devices
        except httpx.HTTPStatusError as e:
            logger.error(f"N-Central API-Fehler beim Abrufen von Geräten: {e.response.status_code}")
            return []
        except Exception as e:
            logger.exception(f"Fehler bei Device-Abfrage: {e}")
            return []

    async def get_installed_patches(self, device_id: int) -> list[dict[str, Any]]:
        """
        Ruft installierte Windows-Updates für ein Gerät ab.

        Args:
            device_id: N-Central Device ID

        Returns:
            Liste von Patch-Objekten mit KB-Nummern
        """

        if not self.base_url or not self.api_key:
            logger.error("N-Central API nicht konfiguriert")
            return []

        try:
            data = await self._get_json(
                f"{self.base_url}/api/devices/{device_id}/patches",
                params={"status": "installed"},
            )
            patches = data.get("items", [])

            logger.debug(f"{len(patches)} installierte Patches für Device ID {device_id}")
            return patches
        except httpx.HTTPStatusError as e:
            logger.error(f"N-Central API-Fehler beim Abrufen von Patches: {e.response.status_code}")
            return []
        except Exception as e:
            logger.exception(f"Fehler bei Patch-Abfrage: {e}")
            return []

    async def is_kb_installed(self, device_id: int, kb_numbers: list[str]) -> bool:
        """
        Prüft, ob mindestens eine der angegebenen KB-Nummern installiert ist.

        Args:
            device_id: N-Central Device ID
            kb_numbers: Liste von KB-Nummern (z.B. ["KB5001234", "KB5001235"])

        Returns:
            True, wenn mindestens ein KB installiert ist
        """

        if not kb_numbers:
            return False

        # KB-Nummern normalisieren (mit/ohne "KB"-Präfix)
        normalized_kbs = set()
        for kb in kb_numbers:
            kb_clean = kb.strip().upper()
            normalized_kbs.add(kb_clean)
            # Auch ohne "KB"-Präfix hinzufügen
            if kb_clean.startswith("KB"):
                normalized_kbs.add(kb_clean[2:])
            else:
                normalized_kbs.add(f"KB{kb_clean}")

        patches = await self.get_installed_patches(device_id)

        for patch in patches:
            # N-Central kann KB-Nummern in verschiedenen Feldern speichern
            patch_kb = (
                (patch.get("kb") or patch.get("kbNumber") or patch.get("patchId") or "")
                .strip()
                .upper()
            )

            if patch_kb in normalized_kbs:
                logger.info(f"KB-Nummer {patch_kb} ist auf Device ID {device_id} installiert")
                return True

        return False
