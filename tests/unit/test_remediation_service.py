"""
Unit-Tests für den RemediationService.
Validiert die KI-gestützte Generierung von Behebungsleitfäden, inklusive
der Caching-Logik und der Robustheit bei unvollständigen Finding-Daten.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.connectors.copilot_client import CopilotStudioClient
from app.core.config import Settings
from app.models.remediation import RemediationGuide
from app.services.remediation_service import RemediationService


class TestRemediationService:
    """
    Testklasse für den RemediationService.
    """

    @pytest.mark.asyncio
    async def test_get_remediation_guides_uses_cache(self):
        """
        Verifiziert, dass der Service ein internes Caching nutzt, um redundante
        Anfragen an die KI-API (Copilot) für identische Findings zu vermeiden.
        """
        # Arrange
        mock_settings = Settings()
        mock_settings.COPILOT_CACHE_TTL = 3600

        mock_client = AsyncMock(spec=CopilotStudioClient)
        mock_client.get_remediation.return_value = RemediationGuide(
            instructions="Test Behebungsanleitung", confidence_score=0.9
        )

        service = RemediationService(mock_settings, mock_client)

        finding = MagicMock()
        finding.cve_id = "CVE-2024-1234"
        finding.product_name = "Windows Server"
        finding.risk = 7.5

        # Act: Den gleichen Guide zweimal anfordern
        result1 = await service.get_remediation_guides([finding])
        result2 = await service.get_remediation_guides([finding])

        # Assert: Die API darf nur einmal aufgerufen worden sein
        assert mock_client.get_remediation.call_count == 1
        assert finding in result1
        assert finding in result2

    @pytest.mark.asyncio
    async def test_get_remediation_guides_handles_missing_attributes(self):
        """
        Stellt sicher, dass der Service robust gegenüber Findings mit fehlenden
        Attributen reagiert und trotzdem einen (ggf. generischen) Guide liefert.
        """
        # Arrange
        mock_settings = Settings()
        mock_client = AsyncMock(spec=CopilotStudioClient)
        mock_client.get_remediation.return_value = RemediationGuide(
            instructions="Generische Anleitung", confidence_score=0.5
        )

        service = RemediationService(mock_settings, mock_client)

        # Finding mit minimalen Attributen (keine CVE-ID, kein Produktname)
        finding = MagicMock()
        finding.name = "Unbekannte Schwachstelle"

        # Act
        result = await service.get_remediation_guides([finding])

        # Assert: Der Aufruf darf nicht fehlschlagen
        assert finding in result
        assert result[finding].instructions == "Generische Anleitung"
