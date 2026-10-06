"""
Unit-Tests für die Finding-Modelle.
Überprüft die Pydantic-Validierungsregeln für Findings und Envelopes sowie
die Unterstützung polymorpher Eingaben über den UnifiedFindingsInput.
"""

from datetime import UTC, datetime

import pytest
from pydantic import TypeAdapter, ValidationError

from app.models.findings import (
    Finding,
    FindingsEnvelope,
    UnifiedFindingsInput,
)


def test_finding_valid_instance():
    """
    Testet die erfolgreiche Instanziierung eines Findings mit allen erforderlichen Feldern.
    """
    finding = Finding(
        name="Unsichere TLS-Konfiguration",
        tenant="Tenant A",
        risk=7.5,
        amount=3,
        target="server01.local",
        extendedSolution=[
            "TLS auf Version 1.2 oder höher setzen.",
            "Unsichere Cipher Suites deaktivieren.",
        ],
        windowsVersionHint="Windows Server 2019",
        products=["IIS", "Windows Server"],
    )

    assert finding.name == "Unsichere TLS-Konfiguration"
    assert finding.tenant == "Tenant A"
    assert finding.risk == 7.5
    assert finding.amount == 3
    assert finding.target == "server01.local"
    assert finding.windowsVersionHint == "Windows Server 2019"
    assert finding.products == ["IIS", "Windows Server"]


def test_finding_rejects_empty_name():
    """
    Stellt sicher, dass ein leeres Namensfeld zu einem Validierungsfehler führt.
    """
    with pytest.raises(ValidationError):
        Finding(
            name="",  # Ungültig
            tenant="Tenant A",
            risk=5.0,
            amount=1,
            target="server01.local",
            extendedSolution=["Fix"],
            windowsVersionHint="",
            products=["Produkt X"],
        )


def test_finding_rejects_invalid_risk_range():
    """
    Verifiziert, dass Risikowerte außerhalb des Bereichs [0.0, 10.0] abgelehnt werden.
    """
    with pytest.raises(ValidationError):
        Finding(
            name="Test",
            tenant="Tenant A",
            risk=11.0,  # > 10.0 nicht erlaubt
            amount=1,
            target="server01.local",
            extendedSolution=["Fix"],
            windowsVersionHint="",
            products=["Produkt X"],
        )


def test_finding_rejects_amount_less_than_one():
    """
    Prüft, dass die Anzahl (Amount) mindestens 1 betragen muss.
    """
    with pytest.raises(ValidationError):
        Finding(
            name="Test",
            tenant="Tenant A",
            risk=5.0,
            amount=0,  # < 1 nicht erlaubt
            target="server01.local",
            extendedSolution=["Fix"],
            windowsVersionHint="",
            products=["Produkt X"],
        )


def test_findings_envelope_parses_and_exposes_items():
    """
    Validiert das Parsen eines Findings-Envelopes und den Zugriff auf die enthaltenen Findings.
    """
    now = datetime.now(UTC)

    env = FindingsEnvelope(
        schema_version=1,
        source="lywand",
        generated_at=now,
        items=[
            Finding(
                name="Test 1",
                tenant="Tenant A",
                risk=5.0,
                amount=1,
                target="host1",
                extendedSolution=["Fix 1"],
                windowsVersionHint="",
                products=["Produkt A"],
            ),
            Finding(
                name="Test 2",
                tenant="Tenant A",
                risk=3.0,
                amount=2,
                target="host2",
                extendedSolution=["Fix 2"],
                windowsVersionHint="",
                products=["Produkt B"],
            ),
        ],
    )

    assert env.schema_version == 1
    assert env.source == "lywand"
    assert len(env.items) == 2
    assert env.items[0].name == "Test 1"
    assert env.items[1].name == "Test 2"


def test_unified_findings_input_accepts_raw_array():
    """
    Überprüft, ob der UnifiedFindingsInput eine einfache Liste von Findings korrekt verarbeitet.
    """
    adapter = TypeAdapter(UnifiedFindingsInput)

    raw_data = [
        {
            "name": "RawFinding",
            "tenant": "TenantRaw",
            "risk": 4.0,
            "amount": 1,
            "target": "raw-host",
            "extendedSolution": ["Step 1"],
            "windowsVersionHint": "",
            "products": ["RawProduct"],
        }
    ]

    parsed = adapter.validate_python(raw_data)

    # Bei Raw-Array erwarten wir eine Liste von Finding-Instanzen
    assert isinstance(parsed, list)
    assert isinstance(parsed[0], Finding)
    assert parsed[0].tenant == "TenantRaw"


def test_unified_findings_input_accepts_envelope():
    """
    Stellt sicher, dass der UnifiedFindingsInput auch das strukturierte Envelope-Format akzeptiert.
    """
    adapter = TypeAdapter(UnifiedFindingsInput)

    envelope_data = {
        "schema_version": 1,
        "source": "lywand",
        "generated_at": datetime.now(UTC),
        "items": [
            {
                "name": "EnvFinding",
                "tenant": "TenantEnv",
                "risk": 7.0,
                "amount": 1,
                "target": "env-host",
                "extendedSolution": ["Step 1"],
                "windowsVersionHint": "",
                "products": ["EnvProduct"],
            }
        ],
    }

    parsed = adapter.validate_python(envelope_data)

    # In diesem Fall bekommen wir ein FindingsEnvelope zurück
    assert isinstance(parsed, FindingsEnvelope)
    assert parsed.source == "lywand"
    assert len(parsed.items) == 1
    assert parsed.items[0].tenant == "TenantEnv"
