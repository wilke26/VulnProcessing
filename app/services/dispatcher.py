"""
Dieses Modul implementiert den TicketDispatcher, der für die Verteilung von
Sicherheitsfindings an externe Ticketsysteme (z.B. DocBee, MKS) verantwortlich ist.

Der Dispatcher übernimmt:
- Die Zusammenstellung von Ticket-Titeln und -Beschreibungen.
- Die Integration von KI-generierten Behebungsleitfäden.
- Das Mapping von Prioritäts-Scores auf menschlich lesbare Stufen.
- Die Kommunikation mit den jeweiligen API-Connectoren.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from app.core.config import Settings
from app.core.logging import get_logger
from app.services.remediation_service import RemediationService
from app.services.ticketing_clients import (
    TicketClient,
    TicketClientRegistry,
    TicketDispatcherProtocol,
    build_ticket_client_registry,
)

# Logger initialisieren
logger = get_logger(__name__)


class TicketDispatcher(TicketDispatcherProtocol):
    """
    Verteilt Findings an konfigurierte Ticketsysteme.

    Kombiniert Details des Findings mit optionalen KI-Behebungshinweisen und
    erstellt daraus strukturierte Tickets in den Zielsystemen.
    Strategy-Pattern: nutzt austauschbare TicketClient-Strategien.
    """

    def __init__(
        self,
        settings: Settings,
        remediation_service: RemediationService,
        clients: Sequence[TicketClient] | None = None,
        client_registry: TicketClientRegistry | None = None,
    ) -> None:
        """
        Initialisiert den TicketDispatcher.

        Args:
            settings (Settings): Die globalen Anwendungseinstellungen.
            remediation_service (RemediationService): Dienst zur Abfrage von KI-Leitfäden.
            clients (Sequence[TicketClient], optional): Liste aktiver Ticket-Clients.
            client_registry (TicketClientRegistry, optional): Registry fuer Ticket-Clients.
        """
        self.settings = settings
        self.remediation_service = remediation_service
        if client_registry is not None:
            self.clients = client_registry.active()
        elif clients is not None:
            self.clients = list(clients)
        else:
            self.clients = build_ticket_client_registry(settings).active()

    async def dispatch(
        self,
        findings: Iterable[Any],
        *,
        batch_id: int | None = None,
        dispatch_token: str | None = None,
    ) -> None:
        """
        Erstellt Tickets für die übergebenen Findings in allen konfigurierten Systemen.

        Args:
            findings (Iterable[Any]): Eine Liste von Findings (ORM-Modelle oder DTOs).
        """
        findings_list = list(findings)
        if not findings_list:
            logger.info("Keine Findings zum Versenden von Tickets vorhanden.")
            return
        if not self.clients:
            logger.warning("Keine Ticket-Clients konfiguriert, Abbruch des Dispatchings.")
            return

        # 1. Schritt: KI-Behebungsleitfäden abrufen (falls Copilot aktiviert ist)
        remediation_results: dict[Any, Any] = {}
        if getattr(self.settings, "COPILOT_ENABLED", False):
            try:
                remediation_results = await self.remediation_service.get_remediation_guides(
                    findings_list
                )
            except Exception as exc:
                logger.exception("Abruf der Behebungsleitfäden fehlgeschlagen: %s", exc)

        # 2. Schritt: Jedes Finding einzeln verarbeiten und versenden
        for finding in findings_list:
            try:
                title = self._build_title(finding)
                guide = None
                if remediation_results:
                    guide = self._lookup_guide(remediation_results, finding)
                description = self._build_description(finding, guide)
                priority_label = self._get_priority_label(getattr(finding, "priority_score", None))

                tenant = getattr(finding, "tenant", "") or getattr(finding, "tenant_id", "")
                for client in self.clients:
                    try:
                        ext_id = await client.create_ticket(
                            title=title,
                            description=description,
                            priority=priority_label,
                            tenant=tenant,
                            batch_id=batch_id,
                            dispatch_token=dispatch_token,
                        )
                        logger.info(
                            "%s-Ticket %s für Finding '%s' erstellt (Tenant: %s).",
                            client.name,
                            ext_id,
                            title,
                            tenant,
                        )
                    except Exception as exc:
                        logger.exception(
                            "%s-Ticket-Erstellung fehlgeschlagen für '%s': %s",
                            client.name,
                            title,
                            exc,
                        )
            except Exception as exc:
                logger.exception("Unerwarteter Fehler beim Dispatching eines Tickets: %s", exc)

    def _lookup_guide(self, remediation_results: dict[Any, Any], finding: Any) -> Any | None:
        """
        Sucht einen passenden Guide in den Remediation-Ergebnissen, ohne dass das
        Finding hashbar sein muss.
        Bevorzugt wird ein Lookup über eine stabile ID.
        """
        try:
            fid = getattr(finding, "id", None)
        except Exception:
            fid = None

        if fid is not None:
            # Direkter Lookup per ID (int) und als String-Repräsentation
            if fid in remediation_results:
                return remediation_results[fid]
            s_fid = str(fid)
            if s_fid in remediation_results:
                return remediation_results[s_fid]

        # Fallback: lineares Matching über Keys, vergleiche Objektidentität/IDs
        for k, v in remediation_results.items():
            if k is finding:
                return v
            k_id = getattr(k, "id", object())
            if fid is not None and k_id == fid:
                return v
        return None

    def _build_title(self, finding: Any) -> str:
        """
        Erstellt einen aussagekräftigen Ticket-Titel aus einem Finding.

        Beispiel: "Schwachstelle Name | Tenant: Kunde A | Target: Server-01"
        """
        name = getattr(finding, "name", getattr(finding, "product_name", "Unbekanntes Finding"))
        tenant = str(getattr(finding, "tenant", getattr(finding, "tenant_id", ""))).strip()
        target = str(getattr(finding, "target", getattr(finding, "asset", ""))).strip()

        parts = [name]
        if tenant:
            parts.append(f"Tenant: {tenant}")
        if target:
            parts.append(f"Target: {target}")

        return " | ".join(parts)

    def _build_description(self, finding: Any, guide: Any | None) -> str:
        """
        Erstellt die detaillierte Ticket-Beschreibung inklusive Metadaten und KI-Guide.
        """
        lines = []
        severity = str(getattr(finding, "severity", "")).strip()
        cvss = getattr(finding, "cvss_score", getattr(finding, "risk", ""))
        product = str(getattr(finding, "product_name", getattr(finding, "name", ""))).strip()
        version = str(getattr(finding, "product_version", "")).strip()
        hosts = getattr(finding, "affected_hosts", [])
        description = getattr(finding, "description", getattr(finding, "extended_solution", ""))

        if severity:
            lines.append(f"**Schweregrad:** {severity}")
        if cvss:
            lines.append(f"**Score:** {cvss}")
        if product:
            ver_str = f" {version}" if version else ""
            lines.append(f"**Produkt:** {product}{ver_str}")
        if hosts:
            # Nur die ersten 5 Hosts anzeigen, um das Ticket übersichtlich zu halten
            host_list = ", ".join(str(h) for h in hosts[:5])
            lines.append(f"**Betroffene Systeme:** {host_list}")
        if description:
            lines.append(f"**Beschreibung:** {description}")

        # KI-Guide hinzufügen, falls vorhanden
        if guide is not None and getattr(guide, "instructions", None):
            lines.append("\n## Behebungsanleitung (KI-generiert)\n")
            lines.append(guide.instructions)
        else:
            lines.append("\n_Keine KI-Behebungsanleitung für dieses Finding verfügbar._")

        return "\n\n".join(lines)

    def _get_priority_label(self, score: Any) -> str:
        """
        Mappt einen numerischen Prioritäts-Score auf eine textuelle Bezeichnung.
        """
        if score is None:
            return "Niedrig"
        try:
            s = float(score)
        except Exception:
            return "Niedrig"

        if s >= 90:
            return "Sehr Hoch"
        if s >= 70:
            return "Hoch"
        if s >= 50:
            return "Mittel"
        return "Niedrig"
