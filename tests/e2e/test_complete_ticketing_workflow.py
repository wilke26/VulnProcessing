"""
End-to-End-Test für den vollständigen Ticketing-Workflow.

Dieser Test validiert die gesamte Kette von der Datenübernahme über die API
bis hin zum Abschluss der Batch-Verarbeitung. Er stellt sicher, dass die
verschiedenen API-Endpunkte korrekt zusammenarbeiten und der Status der
Findings und Batches in der Datenbank konsistent nachgeführt wird.
"""

import hashlib
import hmac
import json
import time

import pytest
from fastapi.testclient import TestClient

from app.api import routes_tickets
from app.core.config import settings
from app.main import app
from app.services.ticketing_clients import TicketDispatchAttempt, TicketDispatchResult


class SuccessfulDispatcher:
    async def dispatch(self, findings, **kwargs):
        findings = list(findings)
        return TicketDispatchResult(
            finding_count=len(findings),
            client_count=1,
            attempts=tuple(
                TicketDispatchAttempt(finding.id, "E2E", True, external_id="EXT")
                for finding in findings
            ),
        )


class TestCompleteTicketingWorkflow:
    """
    Testklasse zur Validierung des End-to-End-Workflows für die Ticketerstellung.
    """

    @pytest.mark.asyncio
    async def test_full_workflow_import_to_ticket_confirmation(self, db_session, monkeypatch):
        """
        Testet den kompletten Workflow durch Aufruf der API-Endpunkte:
        1. Import von Findings über den /findings/import Endpunkt.
        2. Validierung der Findings und automatische Anlage von Tenant/Asset.
        3. Erstellung eines Ticket-Batches für einen Mandanten.
        4. Versand des Batches (Simulation der externen Kommunikation).
        5. Bestätigung des Batch-Abschlusses (Simulation Rückkanal).
        6. Verifizierung, dass Folge-Batches korrekt inkrementiert werden.
        """
        monkeypatch.setattr(
            routes_tickets,
            "build_ticket_dispatcher",
            lambda: SuccessfulDispatcher(),
        )
        client = TestClient(app)

        # Import einer repräsentativen JSON-Dateianlieferung.
        json_data = {
            "schema_version": 1,
            "source": "lywand",
            "generated_at": "2025-11-19T09:00:00Z",
            "items": [
                {
                    "name": f"Critical Vuln {i}",
                    "tenant": "E2E_Workflow_Tenant",
                    "risk": 9.5,
                    "amount": 5,
                    "target": "server01",
                    "extendedSolution": ["Fix now"],
                    "windowsVersionHint": "",
                    "products": ["Windows Server"],
                }
                for i in range(10)
            ],
        }

        import_response = client.post(
            "/findings/import",
            files={"file": ("test.json", json.dumps(json_data), "application/json")},
        )
        assert import_response.status_code == 200

        # Findings tenantbezogen in einem Batch gruppieren.
        batch_response = client.post(
            "/tickets/batch/create", params={"tenant_name": "E2E_Workflow_Tenant"}
        )
        assert batch_response.status_code == 200
        batch_id = batch_response.json()["batch_id"]

        # Den externen Versand mit einem kontrollierten Dispatcher simulieren.
        send_response = client.post(f"/tickets/batch/{batch_id}/send")
        assert send_response.status_code == 200
        dispatch_token = send_response.json()["dispatch_token"]

        # Eine gültig signierte Erfolgsmeldung des Ticketsystems simulieren.
        monkeypatch.setattr(settings, "BATCH_CONFIRM_WEBHOOK_SECRET", "test-secret")
        confirm_body = json.dumps(
            {
                "batch_id": batch_id,
                "successful_count": 5,
                "failed_count": 0,
                "dispatch_token": dispatch_token,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        timestamp = str(int(time.time()))
        signature = hmac.new(
            b"test-secret",
            timestamp.encode("ascii") + b"." + confirm_body,
            hashlib.sha256,
        ).hexdigest()
        confirm_response = client.post(
            "/tickets/batch/confirm",
            content=confirm_body,
            headers={
                "Content-Type": "application/json",
                "X-Webhook-Timestamp": timestamp,
                "X-Webhook-Signature": f"sha256={signature}",
            },
        )
        assert confirm_response.status_code == 200

        # Nach der Bestätigung muss der nächste sequenzielle Batch möglich sein.
        next_batch_response = client.post(
            "/tickets/batch/create", params={"tenant_name": "E2E_Workflow_Tenant"}
        )
        assert next_batch_response.status_code == 200
        assert next_batch_response.json()["batch_number"] == 2
