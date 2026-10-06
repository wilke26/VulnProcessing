"""
Dieses Modul implementiert den EnrichmentService, der Findings um zusätzliche
Informationen aus externen Quellen wie der National Vulnerability Database (NVD) anreichert.

Der Service übernimmt:
- Die Extraktion von CVE-IDs aus Freitextfeldern.
- Den asynchronen Abruf von CVE-Details (Beschreibung, CVSS-Scores, Referenzen).
- Die Normalisierung und Aufbereitung der Daten für die weitere Verarbeitung (z.B. Priorisierung).
- Die Verwaltung des Anreicherungsstatus pro Finding.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from typing import Any, Literal

from app.connectors.nvd_client import NVDClient
from app.core.logging import get_logger
from app.models.enrichment import (
    CVSSVector,
    EnrichedFinding,
    EnrichmentStatus,
    NVDEnrichment,
)
from app.models.findings import Finding

# Logger initialisieren
logger = get_logger(__name__)


class EnrichmentService:
    """
    Service zur Anreicherung von Findings mit externen Metadaten.

    Nutzt den NVDClient, um detaillierte Informationen zu gefundenen CVEs abzurufen
    und diese in einem einheitlichen Format (EnrichedFinding) bereitzustellen.
    """

    # Regulärer Ausdruck zur Erkennung von CVE-Kennungen im Text
    _cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}", flags=re.IGNORECASE)

    def __init__(self, nvd_client: NVDClient | None = None):
        """
        Initialisiert den EnrichmentService.

        Args:
            nvd_client (NVDClient, optional): Client für den Zugriff auf die NVD-API.
        """
        self.nvd_client = nvd_client or NVDClient()

    async def enrich_findings(self, findings: Sequence[Finding]) -> list[EnrichedFinding]:
        """
        Reichert eine Liste von Findings asynchron mit NVD-Daten an.

        Ablauf:
        1. Extraktion aller CVE-IDs aus allen Findings.
        2. Bündelung der eindeutigen CVE-IDs für effiziente API-Abfragen.
        3. Asynchroner Abruf der Daten über den NVDClient.
        4. Zuordnung der Ergebnisse zu den ursprünglichen Findings.

        Args:
            findings (Sequence[Finding]): Die anzureichernden Findings.

        Returns:
            list[EnrichedFinding]: Eine neue Liste mit angereicherten Finding-Objekten.
        """
        if not findings:
            return []

        # Schritt 1: CVE-IDs extrahieren und eindeutige Liste erstellen
        extraction = [self._extract_cve_ids(f) for f in findings]
        unique_cves = sorted({cve for ids, _ in extraction for cve in ids})

        # Schritt 2: Daten von NVD abrufen
        cve_payloads = await self._load_cves(unique_cves)

        enriched_results: list[EnrichedFinding] = []

        # Schritt 3: Ergebnisse mappen
        for finding, (cve_ids, duplicates) in zip(findings, extraction, strict=False):
            enrichments: list[NVDEnrichment] = []

            # Dubletten markieren (interne Konsistenzprüfung)
            for duplicate in duplicates:
                enrichments.append(
                    NVDEnrichment(
                        cve_id=duplicate,
                        status=EnrichmentStatus.DUPLICATE,
                    )
                )

            # Gefundene CVE-Informationen aufbereiten
            for cve_id in cve_ids:
                payload = cve_payloads.get(cve_id)
                try:
                    enrichments.append(self._build_enrichment(cve_id, payload))
                except Exception:
                    logger.exception("Fehler bei der Enrichment-Verarbeitung für %s", cve_id)
                    enrichments.append(
                        NVDEnrichment(
                            cve_id=cve_id,
                            status=EnrichmentStatus.ERROR,
                        )
                    )

            # Neues EnrichedFinding-Objekt erstellen
            # Konvertierung vom DB-Modell zum Pydantic-Modell für das Enrichment
            finding_data = Finding.model_validate(finding).model_dump()
            enriched_results.append(EnrichedFinding(**finding_data, enrichments=enrichments))

        return enriched_results

    async def _load_cves(self, cve_ids: Iterable[str]) -> dict[str, dict[str, Any]]:
        """
        Hilfsmethode zum Laden mehrerer CVE-Datensätze.
        Gibt ein Dictionary zurück, das nach der (normalisierten) CVE-ID indiziert ist.
        """
        if not cve_ids:
            return {}

        payloads = await self.nvd_client.get_multiple_cves(list(cve_ids))
        result: dict[str, dict[str, Any]] = {}
        for payload in payloads:
            cve_id = self.nvd_client.extract_cve_id(payload)
            if not cve_id:
                continue
            result[cve_id.upper()] = payload
        return result

    def _build_enrichment(self, cve_id: str, payload: dict[str, Any] | None) -> NVDEnrichment:
        """
        Erstellt ein NVDEnrichment-Objekt aus einem API-Payload.
        Extrahiert Beschreibung, CVSS-Daten und Referenz-URLs.
        """
        if not payload:
            return NVDEnrichment(cve_id=cve_id, status=EnrichmentStatus.NOT_FOUND)

        description = self.nvd_client.extract_description(payload)
        cvss_data = self.nvd_client.extract_cvss_metrics(payload)
        cvss_vector: CVSSVector | None = None

        if cvss_data and cvss_data.get("baseScore") is not None:
            try:
                # Version normalisieren (z.B. "3.1")
                raw_version = str(cvss_data.get("version", "3.1"))
                cvss_version = self._normalize_cvss_version(raw_version)

                # Basis-Score extrahieren
                base_score_raw = cvss_data.get("baseScore")
                if base_score_raw is None:
                    raise ValueError("baseScore ist nicht vorhanden")

                base_score = float(base_score_raw)

                cvss_vector = CVSSVector(
                    version=cvss_version,
                    base_score=base_score,
                    vector=cvss_data.get("vectorString"),
                )
            except Exception:
                logger.warning("CVSS-Parsing fehlgeschlagen für %s", cve_id)

        references = self._extract_references(payload)

        return NVDEnrichment(
            cve_id=cve_id,
            status=EnrichmentStatus.ENRICHED,
            description=description,
            cvss=cvss_vector,
            references=references,
        )

    def _normalize_cvss_version(self, version_str: str) -> Literal["3.1", "3.0", "2.0"]:
        """
        Normalisiert CVSS-Versionsstrings auf die im Modell unterstützten Werte.
        """
        version_lower = version_str.lower().strip()

        if "3.1" in version_lower:
            return "3.1"
        elif "3.0" in version_lower:
            return "3.0"
        elif "2" in version_lower:
            return "2.0"
        else:
            logger.debug(f"Unbekannte CVSS-Version '{version_str}', Fallback auf 3.1")
            return "3.1"

    def _extract_cve_ids(self, finding: Finding) -> tuple[list[str], list[str]]:
        """
        Extrahiert CVE-IDs aus dem dedizierten Feld 'cve_id' sowie aus dem Namen des Findings.
        Gibt ein Tupel aus (eindeutige IDs, gefundene Duplikate) zurück.
        """
        ids: list[str] = []
        duplicates: list[str] = []

        def _add(candidate: str) -> None:
            normalized = candidate.upper()
            if normalized in ids:
                duplicates.append(normalized)
            else:
                ids.append(normalized)

        # 1. Direktes Feld prüfen
        if finding.cve_id:
            _add(finding.cve_id)

        # 2. Name des Findings per Regex scannen
        for token in self._cve_pattern.findall(finding.name):
            _add(token)

        return ids, duplicates

    def _extract_references(self, payload: dict[str, Any]) -> list[str]:
        """
        Extrahiert alle Referenz-URLs aus dem NVD-Payload.
        """
        refs = payload.get("cve", {}).get("references", [])
        urls: list[str] = []
        for ref in refs:
            if isinstance(ref, dict) and ref.get("url"):
                urls.append(ref["url"])
        return urls
