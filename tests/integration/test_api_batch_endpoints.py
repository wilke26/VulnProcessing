"""
Integrations-Tests für die Batch-API-Endpunkte.
Validiert das Erstellen, Abrufen und die Statusverwaltung von Ticket-Batches über
die REST-Schnittstelle.
"""

from fastapi.testclient import TestClient

from app.db.models import (
    Asset,
    Finding,
    FindingStatus,
    Tenant,
    TicketBatch,
    TicketBatchStatus,
)
from app.main import app


class TestBatchAPIEndpoints:
    """
    Testet die Funktionalität der API-Endpunkte zur Batch-Verarbeitung.
    """

    def test_create_batch_endpoint_returns_batch_info(self, db_session):
        """
        Prüft, ob der Endpunkt POST /tickets/batch/create erfolgreich einen Batch erstellt
        und die korrekten Metadaten zurückgibt.
        """
        # Arrange: Eigene Testdaten mit eindeutigem Tenant
        tenant = Tenant(name="TestTenant_BatchInfo")
        db_session.add(tenant)
        db_session.flush()

        asset = Asset(tenant_id=tenant.id, name="test-server")
        db_session.add(asset)
        db_session.flush()

        # 5 Findings erstellen
        for i in range(5):
            finding = Finding(
                tenant_id=tenant.id,
                asset_id=asset.id,
                name=f"Test Finding {i}",
                target=f"host{i:02d}.local",
                risk=5.0 + i * 0.5,
                amount=i + 1,
                extended_solution_json='["Fix step 1", "Fix step 2"]',
                status=FindingStatus.NEW.value,
            )
            db_session.add(finding)
            db_session.flush()
        db_session.commit()

        client = TestClient(app)

        # Act: Aufruf des Batch-Erstellungs-Endpunkts
        response = client.post(
            "/tickets/batch/create", params={"tenant_name": "TestTenant_BatchInfo"}
        )

        # Assert: Validierung der Antwort
        assert response.status_code == 200
        assert response.json().get("error") is None
        assert response.json().get("code") is None
        data = response.json()
        assert data["status"] == "created"
        assert data["findings_count"] == 5
        assert "batch_id" in data
        assert data["batch_number"] == 1

    def test_create_batch_endpoint_limits_to_5_findings(self, db_session):
        """
        Stellt sicher, dass die Anzahl der Findings in einem Batch auf 5 begrenzt ist,
        auch wenn mehr offene Findings für den Mandanten vorhanden sind.
        """
        # Arrange: Eigene Testdaten
        tenant = Tenant(name="TestTenant_Limit5")
        db_session.add(tenant)
        db_session.flush()

        asset = Asset(tenant_id=tenant.id, name="test-server")
        db_session.add(asset)
        db_session.flush()

        # 10 Findings erstellen
        for i in range(10):
            finding = Finding(
                tenant_id=tenant.id,
                asset_id=asset.id,
                name=f"Finding {i}",
                target=f"host{i}",
                risk=5.0,
                amount=1,
                extended_solution_json='["Fix"]',
                status=FindingStatus.NEW.value,
            )
            db_session.add(finding)
            db_session.flush()
        db_session.commit()

        client = TestClient(app)

        # Act
        response = client.post("/tickets/batch/create", params={"tenant_name": "TestTenant_Limit5"})

        # Assert: Nur 5 Findings sollten im Batch sein
        assert response.status_code == 200
        assert response.json().get("error") is None
        assert response.json().get("code") is None
        data = response.json()
        assert data["status"] == "created"
        assert data["findings_count"] == 5  # Maximal 5!

    def test_create_batch_endpoint_blocks_when_batch_pending(self, db_session):
        """
        Verifiziert, dass kein neuer Batch erstellt werden kann, solange ein
        vorheriger Batch noch im Status 'pending' (wartend auf Bestätigung) ist.
        """
        # Arrange: Vorbereitung eines bereits existierenden pending Batches
        tenant = Tenant(name="TestTenant_Pending")
        db_session.add(tenant)
        db_session.flush()

        # Pending Batch erstellen
        pending_batch = TicketBatch(
            tenant_id=tenant.id,
            batch_number=1,
            status=TicketBatchStatus.PENDING.value,
            total_findings=3,
        )
        db_session.add(pending_batch)
        db_session.commit()

        client = TestClient(app)

        # Act: Versuch, einen neuen Batch zu erstellen
        response = client.post(
            "/tickets/batch/create", params={"tenant_name": "TestTenant_Pending"}
        )

        # Assert: Antwort sollte auf den ausstehenden Batch hinweisen
        assert response.status_code == 200
        assert response.json().get("error") is None
        assert response.json().get("code") is None
        data = response.json()
        assert data["status"] == "pending"
        assert data["pending_batch_number"] == 1

    def test_create_batch_endpoint_returns_no_findings_message(self, db_session):
        """
        Überprüft die Rückgabe des Endpunkts, wenn keine offenen Findings
        für den angegebenen Mandanten gefunden wurden.
        """
        # Arrange: Tenant ohne Findings
        tenant = Tenant(name="TestTenant_NoFindings")
        db_session.add(tenant)
        db_session.commit()

        client = TestClient(app)

        # Act
        response = client.post(
            "/tickets/batch/create", params={"tenant_name": "TestTenant_NoFindings"}
        )

        # Assert
        assert response.status_code == 200
        assert response.json().get("error") is None
        assert response.json().get("code") is None
        data = response.json()
        assert data["status"] == "no_findings"

    def test_get_batch_status_endpoint_returns_details(self, db_session):
        """
        Testet den Endpunkt GET /tickets/batch/status/{batch_id} auf die
        korrekte Rückgabe aller Batch-Details und verknüpften Findings.
        """
        # Arrange: Batch mit verknüpften Findings anlegen
        tenant = Tenant(name="TestTenant_Status")
        db_session.add(tenant)
        db_session.flush()

        asset = Asset(tenant_id=tenant.id, name="test-server")
        db_session.add(asset)
        db_session.flush()

        batch = TicketBatch(
            tenant_id=tenant.id,
            batch_number=1,
            status="created",
            total_findings=3,
            target_system="mks",
        )
        db_session.add(batch)
        db_session.flush()

        # Findings mit Batch verknüpfen
        for i in range(3):
            finding = Finding(
                tenant_id=tenant.id,
                asset_id=asset.id,
                batch_id=batch.id,
                name=f"Finding {i}",
                target=f"host{i}",
                risk=5.0 + i,
                amount=1,
                extended_solution_json='["Fix"]',
                status="queued",
            )
            db_session.add(finding)
        db_session.commit()

        client = TestClient(app)

        # Act: Abfrage des Batch-Status
        response = client.get(f"/tickets/batch/status/{batch.id}")

        # Assert: Validierung der Detailinformationen
        assert response.status_code == 200
        assert response.json().get("error") is None
        assert response.json().get("code") is None
        data = response.json()
        assert data["batch_id"] == batch.id
        assert data["batch_number"] == 1
        assert data["status"] == "created"
        assert data["total_findings"] == 3
        assert len(data["findings"]) == 3

        # Prüfe Finding-Details innerhalb des Batches
        for i, finding_data in enumerate(data["findings"]):
            assert finding_data["name"] == f"Finding {i}"
            assert finding_data["target"] == f"host{i}"
            assert finding_data["status"] == "queued"

    def test_get_batch_status_endpoint_returns_404_for_invalid_id(self, db_session):
        """
        Stellt sicher, dass bei einer nicht existierenden Batch-ID ein 404-Fehler
        zurückgegeben wird.
        """
        client = TestClient(app)

        # Act
        response = client.get("/tickets/batch/status/99999")

        # Assert
        assert response.status_code == 404
