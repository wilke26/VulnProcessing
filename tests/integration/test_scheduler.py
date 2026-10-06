import json
from unittest.mock import patch

import pytest

from app.core.config import settings
from app.db.models import Finding
from app.main import run_scheduled_import


@pytest.fixture
def mock_json_file(tmp_path):
    # Erstelle eine temporäre JSON-Datei
    d = tmp_path / "data"
    d.mkdir()
    f = d / "results.json"

    findings = [
        {
            "name": "Scheduled Finding 1",
            "tenant": "Scheduled_Tenant",
            "risk": 8.0,
            "amount": 1,
            "target": "server01",
            "extendedSolution": ["Update now"],
            "windowsVersionHint": "",
            "products": ["Windows"],
        }
    ]
    f.write_text(json.dumps(findings))
    return str(f)


def test_run_scheduled_import_success(db_session, mock_json_file):
    # Mock settings.LYWAND_JSON_PATH
    with patch.object(settings, "LYWAND_JSON_PATH", mock_json_file):
        # Act
        run_scheduled_import()

        # Assert
        db_session.commit()
        findings = db_session.query(Finding).filter(Finding.name == "Scheduled Finding 1").all()
        assert len(findings) == 1
        assert findings[0].tenant.name == "Scheduled_Tenant"


def test_run_scheduled_import_file_not_found(caplog):
    with patch.object(settings, "LYWAND_JSON_PATH", "/non/existent/path/results.json"):
        run_scheduled_import()
        assert "Import fehlgeschlagen: Datei nicht gefunden" in caplog.text


def test_run_scheduled_import_missing_config(caplog):
    with patch.object(settings, "LYWAND_JSON_PATH", None):
        run_scheduled_import()
        assert "LYWAND_JSON_PATH ist nicht konfiguriert" in caplog.text
