"""
Integrations-Tests für den NVD-API-Client.
Validiert die Kommunikation mit der National Vulnerability Database (NVD) REST API.
Überprüft das Abrufen von CVE-Daten, das Caching von Antworten und die Batch-Verarbeitung.
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from app.connectors.nvd_client import NVDClient


class TestNVDClient:
    """
    Testklasse für den NVDClient zur Abfrage von Schwachstellen-Details.
    """

    @pytest.mark.asyncio
    async def test_get_cve_data_returns_valid_response(self):
        """
        Verifiziert, dass der Client bei einer erfolgreichen API-Antwort
        die CVE-Daten korrekt extrahiert und zurückgibt.
        """
        # Arrange: Definition der gemockten NVD-API-Antwort
        mock_response_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-1234",
                        "descriptions": [
                            {"lang": "en", "value": "A critical vulnerability in example software"}
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                            ]
                        },
                    }
                }
            ]
        }

        client = NVDClient()

        # Mocking des httpx.AsyncClient-Kontexts
        with patch("httpx.AsyncClient") as MockAsyncClient:
            # Vorbereitung der Mock-Response
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json = Mock(return_value=mock_response_data)
            mock_response.raise_for_status = Mock()

            # Mocking der get()-Methode des Clients
            mock_get = AsyncMock(return_value=mock_response)

            # Mocking der AsyncClient-Instanz
            mock_client_instance = Mock()
            mock_client_instance.get = mock_get

            # Simulation des asynchronen Context-Managers (__aenter__ / __aexit__)
            async def async_enter(self):
                return mock_client_instance

            async def async_exit(self, *args):
                pass

            MockAsyncClient.return_value.__aenter__ = async_enter
            MockAsyncClient.return_value.__aexit__ = async_exit

            # Act: Aufruf des Clients
            result = await client.get_cve_data("CVE-2024-1234")

        # Assert: Validierung der zurückgegebenen Daten
        assert result is not None, f"Result is None! Expected data but got: {result}"
        assert result["cve"]["id"] == "CVE-2024-1234"
        assert result["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"] == 9.8

    @pytest.mark.asyncio
    async def test_get_cve_data_handles_not_found(self):
        """
        Stellt sicher, dass der Client korrekt reagiert (None zurückgibt),
        wenn eine CVE-ID in der NVD nicht gefunden wurde.
        """
        # Arrange: Leere Antwort von der API
        mock_response_data = {"vulnerabilities": []}

        client = NVDClient()

        with patch("httpx.AsyncClient") as MockAsyncClient:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json = Mock(return_value=mock_response_data)
            mock_response.raise_for_status = Mock()

            mock_get = AsyncMock(return_value=mock_response)
            mock_client_instance = Mock()
            mock_client_instance.get = mock_get

            async def async_enter(self):
                return mock_client_instance

            async def async_exit(self, *args):
                pass

            MockAsyncClient.return_value.__aenter__ = async_enter
            MockAsyncClient.return_value.__aexit__ = async_exit

            # Act
            result = await client.get_cve_data("CVE-9999-9999")

        # Assert: Ergebnis sollte None sein
        assert result is None

    @pytest.mark.asyncio
    async def test_get_multiple_cves_batch(self):
        """
        Überprüft die Batch-Verarbeitung des Clients beim Abrufen mehrerer CVE-Datensätze.
        """
        # Arrange: Liste von CVE-IDs
        cve_ids = ["CVE-2024-1234", "CVE-2024-5678", "CVE-2024-9999"]

        # Gemockte Antworten für die einzelnen IDs
        mock_responses_data = {
            "CVE-2024-1234": {"vulnerabilities": [{"cve": {"id": "CVE-2024-1234"}}]},
            "CVE-2024-5678": {"vulnerabilities": [{"cve": {"id": "CVE-2024-5678"}}]},
            "CVE-2024-9999": {"vulnerabilities": []},
        }

        client = NVDClient()

        with patch("httpx.AsyncClient") as MockAsyncClient:
            call_count = 0

            # Dynamische Mock-Implementierung basierend auf der cveId im Parameter
            async def mock_get_impl(*args, **kwargs):
                nonlocal call_count
                call_count += 1

                params = kwargs.get("params", {})
                cve_id = params.get("cveId", "")

                mock_response = Mock()
                mock_response.status_code = 200
                mock_response.json = Mock(
                    return_value=mock_responses_data.get(cve_id, {"vulnerabilities": []})
                )
                mock_response.raise_for_status = Mock()

                return mock_response

            mock_client_instance = Mock()
            mock_client_instance.get = AsyncMock(side_effect=mock_get_impl)

            async def async_enter(self):
                return mock_client_instance

            async def async_exit(self, *args):
                pass

            MockAsyncClient.return_value.__aenter__ = async_enter
            MockAsyncClient.return_value.__aexit__ = async_exit

            # Act: Gleichzeitiger Abruf mehrerer CVEs
            results = await client.get_multiple_cves(cve_ids)

        # Assert: Nur die gefundenen CVEs sollten in der Ergebnisliste sein
        assert len(results) == 2, f"Expected 2 results, got {len(results)}: {results}"
        assert results[0]["cve"]["id"] == "CVE-2024-1234"
        assert results[1]["cve"]["id"] == "CVE-2024-5678"

    @pytest.mark.asyncio
    async def test_caches_responses(self):
        """
        Stellt sicher, dass der Client ein internes Caching verwendet,
        um redundante API-Anfragen für dieselbe CVE-ID zu vermeiden.
        """
        # Arrange
        mock_response_data = {"vulnerabilities": [{"cve": {"id": "CVE-2024-1234"}}]}
        client = NVDClient(cache_ttl=3600)
        call_count = 0

        with patch("httpx.AsyncClient") as MockAsyncClient:

            async def mock_get_impl(*args, **kwargs):
                nonlocal call_count
                call_count += 1

                mock_response = Mock()
                mock_response.status_code = 200
                mock_response.json = Mock(return_value=mock_response_data)
                mock_response.raise_for_status = Mock()

                return mock_response

            mock_client_instance = Mock()
            mock_client_instance.get = AsyncMock(side_effect=mock_get_impl)

            async def async_enter(self):
                return mock_client_instance

            async def async_exit(self, *args):
                pass

            MockAsyncClient.return_value.__aenter__ = async_enter
            MockAsyncClient.return_value.__aexit__ = async_exit

            # Act: Zweimaliger Aufruf derselben CVE
            # Erster Request (triggert API-Call)
            result1 = await client.get_cve_data("CVE-2024-1234")

            # Zweiter Request (sollte aus Cache bedient werden)
            result2 = await client.get_cve_data("CVE-2024-1234")

        # Assert: API sollte nur einmal aufgerufen worden sein
        assert call_count == 1, f"Expected 1 API call, but got {call_count}"
        assert result1 == result2
        assert result1 is not None
