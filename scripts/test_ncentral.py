"""
Beispiel-Skript zur Verifizierung der N-Central Integration und Patch-Filterung.

Dieses Skript demonstriert, wie die WindowsPatchFilter-Logik verwendet wird, um Findings
gegen die in N-Central installierten Patches zu prüfen. Es nutzt Mock-Daten für ein Finding,
um den Filterprozess zu simulieren und das Ergebnis (verbleibende vs. gefilterte Geräte)
auszugeben.
"""

import asyncio

from app.connectors.ncentral_client import NCentralClient
from app.services.windows_patch_filter import WindowsPatchFilter


async def filter_finding_example() -> None:
    """
    Simuliert die Filterung eines Findings basierend auf dem N-Central Patch-Status.

    Workflow:
    1. Erstellt ein Mock-Finding mit typischen Windows-Patch-Informationen.
    2. Initialisiert den N-Central Client und den Filter-Dienst.
    3. Führt die Filterung für die Zielgeräte des Findings aus.
    4. Gibt die Ergebnisse der Filterung auf der Konsole aus.
    """

    # Simulation eines Findings, das fehlende Windows-Updates beschreibt
    class MockFinding:
        name = (
            "The host is missing a security update for Microsoft Windows 10 and "
            "Windows Server 2019 - KB5066586"
        )
        tenant = "Beispiel-Mandant GmbH"
        target = "srv-db-01, srv-dc-01, workspace-01"
        windowsVersionHint = "KB5070883,KB5068791"

    finding = MockFinding()

    # Initialisierung der erforderlichen Komponenten
    client = NCentralClient()
    filter_service = WindowsPatchFilter(client)

    print(f"Prüfe Finding '{finding.name}' für Targets: {finding.target}")

    # Ausführung der Filterlogik
    # remaining: Geräte, auf denen der Patch noch fehlt
    # filtered: Geräte, auf denen der Patch bereits installiert ist (ausgefiltert)
    remaining, filtered = await filter_service.filter_finding(finding)

    print("\n=== Filter-Ergebnis ===")
    print(f"Offen (Ticket erforderlich): {remaining if remaining else 'Keine'}")
    print(f"Bereits gepatcht (Ignoriert):  {filtered if filtered else 'Keine'}")


if __name__ == "__main__":
    # Start des asynchronen Testlaufs
    asyncio.run(filter_finding_example())
