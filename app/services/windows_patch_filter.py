"""
app/services/windows_patch_filter.py

Service zur Filterung von Findings basierend auf installierten Windows-Updates.

Dieser Service prüft vor der Ticketerstellung, ob Windows-Updates bereits
installiert sind und entfernt entsprechende Geräte aus der Ticketing-Liste.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from app.connectors.ncentral_client import NCentralClient
from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class DeviceCheckResult:
    """Ergebnis der Update-Prüfung für ein Gerät."""

    device_name: str
    device_id: int
    kb_installed: bool
    matched_kb: str = ""


class WindowsPatchFilter:
    """
    Filtert Findings basierend auf installierten Windows-Updates in N-Central.

    Workflow:
    1. Extrahiert KB-Nummern aus WindowsVersionHint
    2. Prüft Tenant-Existenz in N-Central
    3. Prüft Device-Existenz für jeden Target
    4. Prüft KB-Installation pro Device
    5. Entfernt bereits gepatchte Devices
    """

    def __init__(self, ncentral_client: NCentralClient):
        self.client = ncentral_client

    @staticmethod
    def extract_kb_numbers(windows_version_hint: str) -> list[str]:
        """
        Extrahiert KB-Nummern aus WindowsVersionHint-String.

        Beispiele:
        - "KB5001234" -> ["KB5001234"]
        - "Install KB5001234 or KB5001235" -> ["KB5001234", "KB5001235"]
        - "5001234, 5001235" -> ["5001234", "5001235"]

        Args:
            windows_version_hint: String mit KB-Nummern

        Returns:
            Liste von KB-Nummern
        """

        if not windows_version_hint:
            return []

        # Regex für KB-Nummern: KB gefolgt von 6-7 Ziffern
        # Auch ohne "KB"-Präfix: 6-7 Ziffern
        kb_pattern = r"\b(?:KB)?(\d{6,7})\b"
        matches = re.findall(kb_pattern, windows_version_hint, re.IGNORECASE)

        # KB-Präfix hinzufügen, falls nicht vorhanden
        kb_numbers = [f"KB{match}" for match in matches]

        logger.debug(f"Extrahierte KB-Nummern aus '{windows_version_hint}': {kb_numbers}")
        return kb_numbers

    async def filter_finding(self, finding: Any) -> tuple[list[str], list[str]]:
        """
        Filtert Targets eines Findings basierend auf installiertem Patch-Status.

        Args:
            finding: Finding-Objekt mit tenant, target, windowsVersionHint

        Returns:
            Tuple (remaining_targets, filtered_targets):
            - remaining_targets: Geräte, die noch gepatcht werden müssen
            - filtered_targets: Geräte, die bereits gepatcht sind
        """

        # Target immer als String behandeln
        target_raw = getattr(finding, "target", "") or ""
        target_str = str(target_raw)

        # 1. Prüfung: KB-Nummer vorhanden?
        kb_numbers = self.extract_kb_numbers(
            getattr(finding, "windowsVersionHint", "")
            or getattr(finding, "windows_version_hint", "")
        )

        if not kb_numbers:
            logger.debug(
                f"Kein WindowsVersionHint für Finding "
                f"'{getattr(finding, 'name', '')}', "
                f"überspringe N-Central-Prüfung"
            )
            # Kein Hint vorhanden -> alle Targets bleiben
            return [target_str], []

        logger.info(
            f"Prüfe Finding '{getattr(finding, 'name', '')}' " f"auf installierte KBs: {kb_numbers}"
        )

        # 2. Tenant in N-Central suchen
        tenant = getattr(finding, "tenant", "")
        tenant_name = str(getattr(tenant, "name", tenant) or "")
        customer = await self.client.find_customer_by_name(tenant_name)

        if not customer:
            logger.info(
                f"Tenant '{tenant_name}' nicht in N-Central gefunden, " f"überspringe Filterung"
            )
            return [target_str], []

        customer_id_raw = customer.get("customerId")
        if not isinstance(customer_id_raw, int):
            logger.warning(
                f"Ungültige oder fehlende customerId für Tenant '{tenant_name}': "
                f"{customer_id_raw!r}"
            )
            return [target_str], []

        customer_id: int = customer_id_raw

        # 3. Target(s) in Liste umwandeln
        # Finding.target kann einzelner String oder kommaseparierte Liste sein
        targets: list[str] = [t.strip() for t in target_str.split(",") if t.strip()]

        if not targets:
            logger.warning(f"Keine Targets für Finding '{getattr(finding, 'name', '')}'")
            return [], []

        # 4. Geräte beim Kunden abrufen
        devices = await self.client.get_devices_for_customer(customer_id, device_names=targets)

        if not devices:
            logger.info(
                f"Keine der Targets {targets} in N-Central für Kunde " f"'{tenant_name}' gefunden"
            )
            return targets, []

        # 5. Für jedes gefundene Gerät KB-Installation prüfen
        check_tasks = []
        device_map: dict[str, Any] = {}
        for d in devices:
            raw_name = d.get("deviceName") or d.get("longName")
            if isinstance(raw_name, str) and raw_name:
                device_map[raw_name] = d
            else:
                logger.warning(f"Gerät ohne gültigen Namen in N-Central gefunden: {d!r}")

        for target in targets:
            if target in device_map:
                device = device_map[target]
                device_id_raw = device.get("deviceId")

                if not isinstance(device_id_raw, int):
                    logger.warning(f"Ungültige deviceId für Gerät '{target}': {device_id_raw!r}")
                    continue

                device_id: int = device_id_raw

                async def check_device(
                    dev_id: int, dev_name: str, kbs: list[str]
                ) -> DeviceCheckResult:
                    is_installed = await self.client.is_kb_installed(dev_id, kbs)
                    matched = kbs[0] if is_installed and kbs else ""
                    return DeviceCheckResult(
                        device_name=dev_name,
                        device_id=dev_id,
                        kb_installed=is_installed,
                        matched_kb=matched,
                    )

                check_tasks.append(check_device(device_id, target, kb_numbers))

        if not check_tasks:
            # Keine passenden Devices gefunden → alle Targets bleiben
            logger.info(
                f"Keine passenden Geräte für Targets {targets} bei Kunde '{tenant_name}' "
                f"gefunden → keine Filterung"
            )
            return targets, []

        results: list[DeviceCheckResult | BaseException] = await asyncio.gather(
            *check_tasks, return_exceptions=True
        )

        # 6. Ergebnisse auswerten
        remaining_targets: list[str] = []
        filtered_targets: list[str] = []

        for result in results:
            if isinstance(result, BaseException):
                logger.error(f"Fehler bei Device-Check: {result}")
                continue

            # Ab hier: result ist DeviceCheckResult
            if result.kb_installed:
                filtered_targets.append(result.device_name)
                logger.info(
                    f"Gerät '{result.device_name}' hat {result.matched_kb} "
                    f"installiert → wird gefiltert"
                )
            else:
                remaining_targets.append(result.device_name)

        # Geräte, die nicht in N-Central gefunden wurden, bleiben erhalten
        for target in targets:
            if target not in device_map and target not in remaining_targets:
                remaining_targets.append(target)
                logger.debug(f"Gerät '{target}' nicht in N-Central gefunden → bleibt in Liste")

        return remaining_targets, filtered_targets

    @staticmethod
    def _set_persisted_ticket_target(finding: Any, target: str | None) -> bool:
        """Set the ORM-only dispatch target without changing the source target."""
        if not hasattr(type(finding), "ticket_target"):
            return False
        finding.ticket_target = target
        return True

    async def filter_findings_batch(self, findings: list[Any]) -> list[Any]:
        """
        Filtert eine Liste von Findings parallel.

        Args:
            findings: Liste von Finding-Objekten

        Returns:
            Liste von Findings, bei denen bereits gepatchte Targets entfernt wurden
        """
        filter_tasks = [self.filter_finding(f) for f in findings]
        results: list[tuple[list[str], list[str]] | BaseException] = await asyncio.gather(
            *filter_tasks, return_exceptions=True
        )

        filtered_findings: list[Any] = []
        total_filtered_devices = 0

        for finding, result in zip(findings, results, strict=False):
            if isinstance(result, BaseException):
                logger.error(
                    f"Fehler beim Filtern von Finding "
                    f"'{getattr(finding, 'name', '')}': {result}"
                )
                # Bei Fehler: Finding unverändert übernehmen
                self._set_persisted_ticket_target(finding, None)
                filtered_findings.append(finding)
                continue

            # Ab hier: result ist Tuple[List[str], List[str]]
            remaining_targets, filtered_targets = result
            total_filtered_devices += len(filtered_targets)

            if not remaining_targets:
                logger.info(
                    f"Finding '{getattr(finding, 'name', '')}' vollständig gefiltert "
                    f"(alle Geräte bereits gepatcht)"
                )
                self._set_persisted_ticket_target(finding, None)
                # Finding komplett überspringen
                continue

            filtered_target = ", ".join(remaining_targets)
            if isinstance(finding, BaseModel):
                # Validierte Eingaben bleiben unverändert; die Pipeline erhält eine Kopie.
                updated_finding = finding.model_copy(update={"target": filtered_target})
                filtered_findings.append(updated_finding)
            else:
                persisted_target = filtered_target if filtered_targets else None
                if filtered_targets and not self._set_persisted_ticket_target(
                    finding, persisted_target
                ):
                    logger.warning(
                        "Gefilterte Target-Liste für Finding '%s' kann nicht persistiert werden",
                        getattr(finding, "name", ""),
                    )
                elif not filtered_targets:
                    self._set_persisted_ticket_target(finding, None)
                filtered_findings.append(finding)

        logger.info(
            f"Filterung abgeschlossen: {len(findings)} → {len(filtered_findings)} "
            f"Findings, {total_filtered_devices} Geräte gefiltert"
        )

        return filtered_findings
