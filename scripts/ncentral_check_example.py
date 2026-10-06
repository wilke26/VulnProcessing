#!/usr/bin/env python3
"""Beispielskript zur Prüfung von tenant/target in N-Central.

Erwartetes JSON-Format (Datei oder STDIN):
[
  {
    "tenant": "Beispiel GmbH",
    "target": "SERVER-01"
  },
  {
    "tenant": "Beispiel GmbH",
    "target": ["CLIENT-01", "CLIENT-02"]
  }
]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any

from app.connectors.ncentral_client import NCentralClient
from app.core.logging import setup_logging


def _normalize_targets(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()] if str(value).strip() else []


def _load_payload(path: str | None) -> list[dict[str, Any]]:
    try:
        if path:
            with open(path, encoding="utf-8") as handle:
                payload = json.load(handle)
        else:
            payload = json.load(sys.stdin)
    except FileNotFoundError as error:
        raise ValueError(f"Datei nicht gefunden: {path}") from error
    except PermissionError as error:
        raise ValueError(f"Zugriff verweigert: {path}") from error

    if isinstance(payload, dict):
        payload = [payload]

    if not isinstance(payload, list):
        raise ValueError("JSON muss ein Objekt oder eine Liste von Objekten sein.")

    return payload


async def _check_entries(entries: list[dict[str, Any]]) -> None:
    async with NCentralClient() as client:
        for entry in entries:
            tenant = str(entry.get("tenant", "")).strip()
            targets = _normalize_targets(entry.get("target"))

            if not tenant:
                print("Fehlender tenant im JSON-Eintrag.")
                continue

            print(f"\nTenant: {tenant}")
            customer = await client.find_customer_by_name(tenant)
            if not customer:
                print(f"Tenant '{tenant}' existiert nicht in N-Central.")
                continue

            customer_id_raw = customer.get("customerId")
            if not isinstance(customer_id_raw, int):
                print(f"Ungültige customerId für Tenant '{tenant}': {customer_id_raw!r}")
                continue

            print(f"Tenant '{tenant}' existiert in N-Central (ID: {customer_id_raw}).")

            if not targets:
                print("⚠️ Kein target angegeben. Gerätesuche übersprungen.")
                continue

            devices = await client.get_devices_for_customer(customer_id_raw, device_names=targets)
            device_names = {str(device.get("deviceName", "")).strip() for device in devices} | {
                str(device.get("longName", "")).strip() for device in devices
            }

            for target in targets:
                if target in device_names:
                    print(f"Target '{target}' existiert in N-Central.")
                else:
                    print(f"Target '{target}' existiert nicht in N-Central.")


def main() -> int:
    setup_logging(level="WARNING")
    parser = argparse.ArgumentParser(
        description="Prüft tenant/target aus JSON gegen die N-Central API.",
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        help="Pfad zu einer JSON-Datei. Wenn nicht gesetzt, wird von STDIN gelesen.",
    )
    args = parser.parse_args()

    try:
        entries = _load_payload(args.json_path)
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"Ungültiges JSON: {exc}")
        return 1

    asyncio.run(_check_entries(entries))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
