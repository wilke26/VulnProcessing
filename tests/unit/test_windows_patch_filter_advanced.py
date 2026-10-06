"""
Erweiterte Unit-Tests für den WindowsPatchFilter.
Validiert die Integration mit dem N-Central API-Client (gemockt), um Findings
basierend auf dem tatsächlichen Patch-Status der Zielgeräte zu filtern.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.connectors.ncentral_client import NCentralClient
from app.services.windows_patch_filter import WindowsPatchFilter


class TestWindowsPatchFilterIntegration:
    """
    Testklasse für die Integration von Patch-Filter-Logik und API-Client.
    """

    @pytest.mark.asyncio
    async def test_filter_finding_removes_patched_devices(self):
        """
        Stellt sicher, dass Geräte, auf denen der erforderliche Patch bereits
        installiert ist, korrekt aus der Liste der Ziele entfernt werden.
        """
        # Arrange
        mock_client = AsyncMock(spec=NCentralClient)
        mock_client.find_customer_by_name.return_value = {
            "customerId": 123,
            "customerName": "TestCustomer",
        }
        mock_client.get_devices_for_customer.return_value = [
            {"deviceId": 1, "deviceName": "server01"},
            {"deviceId": 2, "deviceName": "server02"},
        ]
        # server01 ist gepatcht (True), server02 nicht (False)
        mock_client.is_kb_installed.side_effect = [True, False]

        filter_service = WindowsPatchFilter(mock_client)

        # Mock Finding mit KB-Hinweis
        finding = MagicMock()
        finding.name = "Test Schwachstelle"
        finding.tenant = "TestCustomer"
        finding.target = "server01, server02"
        finding.windowsVersionHint = "KB5001234"

        # Act: Filterung ausführen
        remaining, filtered = await filter_service.filter_finding(finding)

        # Assert: server02 muss bleiben, server01 muss gefiltert sein
        assert "server02" in remaining
        assert "server01" in filtered

    @pytest.mark.asyncio
    async def test_filter_finding_keeps_all_when_customer_not_found(self):
        """
        Überprüft, dass alle Zielgeräte erhalten bleiben (keine Filterung),
        wenn der Mandant im N-Central System nicht gefunden werden kann.
        """
        # Arrange
        mock_client = AsyncMock(spec=NCentralClient)
        mock_client.find_customer_by_name.return_value = None  # Mandant unbekannt

        filter_service = WindowsPatchFilter(mock_client)

        finding = MagicMock()
        finding.tenant = "UnbekannterMandant"
        finding.target = "server01"
        finding.windowsVersionHint = "KB5001234"

        # Act
        remaining, filtered = await filter_service.filter_finding(finding)

        # Assert: Keine Filterung möglich -> alles bleibt offen (Safety-First)
        assert remaining == ["server01"]
        assert filtered == []

    @pytest.mark.asyncio
    async def test_filter_findings_batch_processes_multiple(self):
        """
        Testet die Batch-Verarbeitung mehrerer Findings und stellt sicher,
        dass alle Findings korrekt verarbeitet werden.
        """
        # Arrange
        mock_client = AsyncMock(spec=NCentralClient)
        mock_client.find_customer_by_name.return_value = {
            "customerId": 123,
            "customerName": "TestCustomer",
        }
        mock_client.get_devices_for_customer.return_value = []

        filter_service = WindowsPatchFilter(mock_client)

        findings = []
        for i in range(5):
            finding = MagicMock()
            finding.name = f"Finding {i}"
            finding.tenant = "TestCustomer"
            finding.target = f"server{i:02d}"
            finding.windowsVersionHint = ""  # Kein KB-Hinweis -> keine Filterung möglich
            findings.append(finding)

        # Act
        result = await filter_service.filter_findings_batch(findings)

        # Assert: Alle 5 Findings müssen unverändert zurückkommen
        assert len(result) == 5
