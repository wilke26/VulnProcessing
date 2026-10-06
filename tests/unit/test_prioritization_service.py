"""
Unit-Tests für den PrioritizationService.
Validiert die Sortierung von Findings basierend auf Risikoregeln und
produktspezifischen Gewichtungen.
"""

from app.core.priority_config import PriorityConfig, RiskRule
from app.models.findings import Finding
from app.services.prioritization_service import PrioritizationService

# Beispiel-Konfiguration für die Tests
config = PriorityConfig(
    risk_rules=[RiskRule(threshold=9.0, weight=100), RiskRule(threshold=5.0, weight=10)],
    product_weights={"Exchange": 3},
    default_weight=0,
)
service = PrioritizationService(config)


def _make_finding(name: str, risk: float, products):
    """
    Hilfsfunktion zum Erstellen eines Finding-Objekts für Tests.
    """
    return Finding(
        name=name,
        tenant="Tenant A",
        risk=risk,
        amount=1,
        target="server",
        extendedSolution=["Fix"],
        products=products,
        windowsVersionHint="",
    )


def test_prioritize_by_risk():
    """
    Stellt sicher, dass Findings basierend auf ihrem Risiko und den definierten
    RiskRules korrekt gewichtet und sortiert werden.
    """
    cfg = PriorityConfig(
        risk_rules=[
            RiskRule(threshold=9.0, weight=100),
            RiskRule(threshold=5.0, weight=10),
        ],
        product_weights={},
        default_weight=0,
    )
    svc = PrioritizationService(cfg)

    high = _make_finding("High", 9.5, ["Produkt1"])  # Gewicht 100
    medium = _make_finding("Medium", 6.0, ["Produkt1"])  # Gewicht 10
    low = _make_finding("Low", 3.0, ["Produkt1"])  # Gewicht 0

    # Act: Liste unsortiert übergeben
    sorted_list = svc.prioritize_findings([low, high, medium])

    # Assert: Korrekte Reihenfolge (absteigend nach Gewicht)
    assert [f.name for f in sorted_list] == ["High", "Medium", "Low"]


def test_prioritize_by_product():
    """
    Prüft, ob produkspezifische Gewichtungen (z.B. für Exchange oder IIS)
    bei der Priorisierung korrekt berücksichtigt werden.
    """
    cfg = PriorityConfig(
        risk_rules=[RiskRule(threshold=0.0, weight=0)],
        product_weights={"Exchange": 50, "IIS": 10},
        default_weight=0,
    )
    svc = PrioritizationService(cfg)

    f1 = _make_finding("f1", 0.0, ["IIS"])  # Gewicht 10
    f2 = _make_finding("f2", 0.0, ["Exchange"])  # Gewicht 50
    f3 = _make_finding("f3", 0.0, ["Unknown"])  # Gewicht 0

    # Act
    sorted_list = svc.prioritize_findings([f1, f3, f2])

    # Assert: Exchange (f2) > IIS (f1) > Unknown (f3)
    assert [f.name for f in sorted_list] == ["f2", "f1", "f3"]
