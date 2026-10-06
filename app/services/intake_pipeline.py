"""
Dieses Modul implementiert eine einfache Intake-Pipeline zur Verarbeitung und
Priorisierung von Findings. Es kombiniert NVD-Anreicherung mit einer
regelbasierten Priorisierung.
"""

from app.connectors.nvd_client import NVDClient
from app.models.findings import FindingsEnvelope
from app.services.prioritizer import Prioritizer

# Globale Instanzen der Dienste (mit Standardkonfiguration)
prioritizer = Prioritizer("config/prioritization_rules.yaml")
nvd_client = NVDClient()


async def process_findings(input_data):
    """
    Verarbeitet eine Liste von Findings oder ein Findings-Envelope.

    Der Prozess umfasst:
    1. Normalisierung der Eingabedaten.
    2. Optionale Anreicherung mit NVD-Daten (CVSS-Score).
    3. Berechnung eines Prioritäts-Scores basierend auf definierten Regeln.
    4. Zusammenstellung der Ergebnisse.

    Args:
        input_data: Entweder ein FindingsEnvelope oder eine Liste von Finding-Objekten.

    Returns:
        list: Eine Liste von Dictionaries mit den verarbeiteten und priorisierten Findings.
    """
    # Schritt 1: Ermittlung des Findings-Arrays je nach Eingabemodell
    if isinstance(input_data, FindingsEnvelope):
        findings = input_data.items
    else:
        # Annahme: Es handelt sich bereits um eine Liste von Finding-Objekten
        findings = input_data

    enriched_results = []

    for finding in findings:
        # Schritt 2: Optionale Anreicherung mit NVD-Daten
        # Falls der Name wie eine CVE-ID aussieht und kein Risk-Score vorhanden ist
        cve_id = getattr(finding, "name", None)
        if cve_id and cve_id.startswith("CVE-"):
            # Asynchroner Abruf
            cve_data = await nvd_client.get_cve_data(cve_id)

            if cve_data:
                # CVSS-Score über die Hilfsmethode des Clients extrahieren
                metrics = nvd_client.extract_cvss_metrics(cve_data)
                cvss_score = metrics.get("baseScore", 0) if metrics else 0

                # Falls das Finding keinen oder einen Risk-Score von 0 hat,
                # wird der CVSS-Score genutzt
                if getattr(finding, "risk", None) in [None, 0]:
                    finding.risk = cvss_score

        # Schritt 3: Prioritäts-Score berechnen
        prio_score = prioritizer.prioritize(finding.model_dump())

        # Schritt 4: Ergebnisstruktur aufbauen
        result = {
            "name": finding.name,
            "risk": finding.risk,
            "prio_score": prio_score,
            "target": finding.target,
        }
        enriched_results.append(result)

    return enriched_results
