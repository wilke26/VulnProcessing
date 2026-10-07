"""
Integrations-Tests für den NVD-API-Client.
Validiert die Kommunikation mit der National Vulnerability Database (NVD) REST API.
Überprüft das Abrufen von CVE-Daten, das Caching von Antworten und die Batch-Verarbeitung.
"""

import asyncio
import time
from unittest.mock import AsyncMock, Mock, patch

import pytest

import app.connectors.nvd_client as nvd_module
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

        client = NVDClient(requests_per_second=1000)

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

        client = NVDClient(requests_per_second=1000)

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

        client = NVDClient(requests_per_second=1000)

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
    async def test_get_multiple_cves_rejects_oversized_batch_before_network(self):
        client = NVDClient(max_cves_per_batch=2)

        with pytest.raises(ValueError, match="maximale Anzahl"):
            await client.get_multiple_cves(["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"])

    @pytest.mark.asyncio
    async def test_get_multiple_cves_bounds_concurrent_requests(self):
        client = NVDClient(
            requests_per_second=100_000,
            max_concurrent_requests=2,
            max_cves_per_batch=10,
        )
        active = 0
        maximum_active = 0

        async def fake_get(self, url, headers=None, params=None, timeout=None):
            nonlocal active, maximum_active
            active += 1
            maximum_active = max(maximum_active, active)
            await asyncio.sleep(0.01)
            active -= 1
            response = Mock()
            response.raise_for_status = Mock()
            response.json = Mock(
                return_value={"vulnerabilities": [{"cve": {"id": params["cveId"]}}]}
            )
            return response

        cve_ids = [f"CVE-2026-{index:04d}" for index in range(1000, 1006)]
        with patch("httpx.AsyncClient.get", new=fake_get):
            results = await client.get_multiple_cves(cve_ids)

        assert maximum_active == 2
        assert [result["cve"]["id"] for result in results] == cve_ids

    @pytest.mark.asyncio
    async def test_rate_limit_serializes_request_starts(self):
        client = NVDClient(
            requests_per_second=100,
            max_concurrent_requests=3,
            max_cves_per_batch=3,
        )
        starts: list[float] = []

        async def fake_get(self, url, headers=None, params=None, timeout=None):
            starts.append(time.monotonic())
            response = Mock()
            response.raise_for_status = Mock()
            response.json = Mock(
                return_value={"vulnerabilities": [{"cve": {"id": params["cveId"]}}]}
            )
            return response

        with patch("httpx.AsyncClient.get", new=fake_get):
            await client.get_multiple_cves(["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"])

        assert len(starts) == 3
        assert all(
            later - earlier >= 0.008 for earlier, later in zip(starts, starts[1:], strict=False)
        )

    @pytest.mark.asyncio
    async def test_default_clients_share_process_concurrency_gate(self, monkeypatch):
        monkeypatch.setattr(nvd_module, "_PROCESS_REQUEST_GATES", {})
        settings_obj = nvd_module.Settings(_env_file=None, NVD_MAX_CONCURRENT_REQUESTS=1)
        first = NVDClient(settings_obj=settings_obj)
        second = NVDClient(settings_obj=settings_obj)
        first._rate_limit_seconds = 0.0001
        second._rate_limit_seconds = 0.0001
        active = 0
        maximum_active = 0

        async def fake_get(self, url, headers=None, params=None, timeout=None):
            nonlocal active, maximum_active
            active += 1
            maximum_active = max(maximum_active, active)
            await asyncio.sleep(0.01)
            active -= 1
            response = Mock()
            response.raise_for_status = Mock()
            response.json = Mock(
                return_value={"vulnerabilities": [{"cve": {"id": params["cveId"]}}]}
            )
            return response

        with patch("httpx.AsyncClient.get", new=fake_get):
            await asyncio.gather(
                first.get_cve_data("CVE-2026-1001"),
                second.get_cve_data("CVE-2026-1002"),
            )

        assert maximum_active == 1

    @pytest.mark.asyncio
    async def test_worker_pool_does_not_block_next_cve_behind_slow_peer(self, monkeypatch):
        client = NVDClient(max_concurrent_requests=2, max_cves_per_batch=3)
        slow_finished = False
        third_started_before_slow_finished = False

        async def fake_get_cve_data(cve_id):
            nonlocal slow_finished, third_started_before_slow_finished
            if cve_id == "CVE-2026-1001":
                await asyncio.sleep(0.03)
                slow_finished = True
            elif cve_id == "CVE-2026-1002":
                await asyncio.sleep(0.001)
            else:
                third_started_before_slow_finished = not slow_finished
            return {"cve": {"id": cve_id}}

        monkeypatch.setattr(client, "get_cve_data", fake_get_cve_data)
        results = await client.get_multiple_cves(
            ["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"]
        )

        assert third_started_before_slow_finished
        assert [result["cve"]["id"] for result in results] == [
            "CVE-2026-1001",
            "CVE-2026-1002",
            "CVE-2026-1003",
        ]

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
