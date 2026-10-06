import io
import json
from unittest.mock import AsyncMock, patch

import pytest

from scripts.ncentral_check_example import _check_entries, _load_payload, _normalize_targets


def test_normalize_targets():
    assert _normalize_targets(None) == []
    assert _normalize_targets("  SERVER-01  ") == ["SERVER-01"]
    assert _normalize_targets(["  C1 ", "", "C2"]) == ["C1", "C2"]
    assert _normalize_targets(123) == ["123"]


def test_load_payload_valid_list():
    data = [{"tenant": "T1", "target": "S1"}]
    with patch("builtins.open", return_value=io.StringIO(json.dumps(data))):
        payload = _load_payload("dummy.json")
        assert payload == data


def test_load_payload_valid_dict():
    data = {"tenant": "T1", "target": "S1"}
    with patch("builtins.open", return_value=io.StringIO(json.dumps(data))):
        payload = _load_payload("dummy.json")
        assert payload == [data]


@pytest.mark.asyncio
@patch("scripts.ncentral_check_example.NCentralClient")
async def test_check_entries(mock_client_class):
    mock_client = mock_client_class.return_value
    mock_client.__aenter__.return_value = mock_client
    mock_client.find_customer_by_name = AsyncMock(
        return_value={"customerId": 123, "customerName": "T1"}
    )
    mock_client.get_devices_for_customer = AsyncMock(
        return_value=[{"deviceName": "S1", "longName": "S1.local"}]
    )

    entries = [{"tenant": "T1", "target": "S1"}]
    await _check_entries(entries)

    mock_client.find_customer_by_name.assert_called_with("T1")
    mock_client.get_devices_for_customer.assert_called_with(123, device_names=["S1"])
