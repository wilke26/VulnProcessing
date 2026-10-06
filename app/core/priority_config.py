"""
Dieses Modul definiert die Konfigurationsstrukturen für die Priorisierung von Sicherheitsfunden.
Es ermöglicht die Gewichtung von Risiken basierend auf Schwellenwerten, CVSS-Scores und
produktspezifischen Faktoren.
"""

from pydantic import BaseModel


class RiskRule(BaseModel):
    """
    Repräsentiert eine Regel zur Gewichtung basierend auf einem Risikoschwellenwert.
    """

    threshold: float  # Mindest-Risikowert, ab dem diese Regel greift
    weight: int  # Die zu vergebende Gewichtung


class PriorityConfig(BaseModel):
    """
    Konfigurationseinstellungen für die Berechnung der Priorität von Findings.
    """

    # Liste von Risikoschwellen (absteigend sortiert)
    risk_rules: list[RiskRule] = [
        RiskRule(threshold=9.0, weight=100),  # kritische Schwachstellen
        RiskRule(threshold=7.0, weight=50),  # hohe Schwachstellen
        RiskRule(threshold=5.0, weight=10),  # mittlere Schwachstellen
    ]
    # CVSS-Regeln (werden bevorzugt verwendet, wenn ein expliziter CVSS-Score vorhanden ist)
    cvss_rules: list[RiskRule] = [
        RiskRule(threshold=9.0, weight=150),
        RiskRule(threshold=7.0, weight=80),
        RiskRule(threshold=5.0, weight=20),
    ]
    # Gewichtung pro Produkt (z.B. "Exchange" hat eine höhere Relevanz)
    product_weights: dict[str, int] = {
        "Exchange": 20,
        "IIS": 10,
    }
    # Gewichtung basierend auf dem Anreicherungsstatus (Enrichment)
    enrichment_status_weights: dict[str, int] = {
        "enriched": 5,
        "not_found": -5,
    }
    # Standardgewicht, wenn keine spezifische Regel zutrifft
    default_weight: int = 1
