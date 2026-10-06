"""
Integrations-Tests für den N-Central API-Client.
Validiert die Kommunikation mit der N-Central API unter Verwendung von Mocks,
einschließlich Mandantensuche und Überprüfung des Patch-Status (KB-Nummern).
"""

from unittest.mock import patch

import pytest

from app.connectors.ncentral_client import NCentralClient


class FakeResponse:
    """
    Einfache Mock-Klasse für HTTP-Antworten (simuliert httpx.Response).
    """

    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        """Simuliert erfolgreichen HTTP-Status."""
        return None

    def json(self):
        """Gibt den vordefinierten Payload als Dictionary zurück."""
        return self._payload


class TestNCentralClientIntegration:
    """
    Testklasse für Integrations-Tests des NCentralClient.
    """

    @pytest.mark.asyncio
    async def test_find_customer_by_name_with_mock_response(self):
        """
        Verifiziert, dass die Methode 'find_customer_by_name' Mandanten korrekt
        aus der API-Antwort extrahiert.
        """
        # Arrange: Vorbereitung der gemockten API-Antwort
        mock_response = {"items": [{"customerId": 123, "customerName": "Test Customer"}]}

        client = NCentralClient()
        client.base_url = "https://mock-ncentral.example.com"
        client.api_key = "test-key"

        # Async-Funktion, die anstelle von httpx.AsyncClient.get aufgerufen wird
        async def fake_get(self, url, headers=None, params=None, timeout=None):
            return FakeResponse(mock_response)

        # Act: Aufruf der Methode mit gepatchtem httpx-Client
        with patch("httpx.AsyncClient.get", new=fake_get):
            customer = await client.find_customer_by_name("Test Customer")

        # Assert: Validierung des gefundenen Mandanten
        assert customer is not None, "Customer sollte nicht None sein"
        assert customer["customerId"] == 123
        assert customer["customerName"] == "Test Customer"

    @pytest.mark.asyncio
    async def test_is_kb_installed_normalizes_kb_numbers(self):
        """
        Überprüft, ob der Client KB-Nummern in verschiedenen Formaten (mit/ohne Präfix)
        korrekt normalisiert und gegen die Liste installierter Patches abgleicht.
        """
        # Arrange: Vorbereitung einer Liste installierter Patches
        mock_patches = {
            "items": [
                {"kb": "KB5001234"},
                {"kbNumber": "5001235"},
            ]
        }

        client = NCentralClient()
        client.base_url = "https://mock-ncentral.example.com"
        client.api_key = "test-key"

        async def fake_get(self, url, headers=None, params=None, timeout=None):
            # Für alle Aufrufe in diesem Test dieselbe Patch-Liste zurückgeben
            return FakeResponse(mock_patches)

        # Act: Abfrage des Installationsstatus für verschiedene KB-Formate
        with patch("httpx.AsyncClient.get", new=fake_get):
            # Test verschiedene Formate: mit Präfix, ohne Präfix, nicht vorhanden
            is_installed1 = await client.is_kb_installed(1, ["KB5001234"])
            is_installed2 = await client.is_kb_installed(1, ["5001235"])
            is_installed3 = await client.is_kb_installed(1, ["KB9999999"])

        # Assert: Korrekte Erkennung basierend auf Normalisierung
        assert is_installed1 is True  # Mit KB-Präfix
        assert is_installed2 is True  # Ohne KB-Präfix
        assert is_installed3 is False  # Nicht vorhanden
