"""
Unit-Tests für das TicketBatchRepository.
Validiert die Geschäftslogik zur Verwaltung von Ticket-Batches, inklusive der
Nummernvergabe, der Statusverwaltung und der Fehlerbehandlung.
"""

from app.db.models import Finding, Tenant, TicketBatch, TicketBatchStatus
from app.db.repository import TicketBatchRepository


class TestTicketBatchRepository:
    """
    Testklasse für das TicketBatchRepository.
    """

    def test_create_batch_assigns_sequential_batch_numbers(self, db_session):
        """
        Prüft, dass Batch-Nummern innerhalb eines Tenants sequenziell vergeben werden.
        """
        # Arrange
        tenant = Tenant(name="TestTenant")
        db_session.add(tenant)
        db_session.flush()

        repo = TicketBatchRepository(db_session)

        # Act: 3 Batches nacheinander erstellen
        batch1 = repo.create_batch(tenant.id, [], "mks")
        db_session.commit()
        batch2 = repo.create_batch(tenant.id, [], "mks")
        db_session.commit()
        batch3 = repo.create_batch(tenant.id, [], "mks")
        db_session.commit()

        # Assert: Batch-Nummern müssen 1, 2 und 3 sein
        assert batch1.batch_number == 1
        assert batch2.batch_number == 2
        assert batch3.batch_number == 3

    def test_get_next_pending_batch_returns_oldest_pending(self, db_session):
        """
        Stellt sicher, dass der älteste Batch mit dem Status 'pending' oder
        'created' zurückgegeben wird.
        """
        # Arrange
        tenant = Tenant(name="TestTenant")
        db_session.add(tenant)
        db_session.flush()

        # Verschiedene Batches mit unterschiedlichen Stati anlegen
        batch1 = TicketBatch(
            tenant_id=tenant.id, batch_number=1, status=TicketBatchStatus.COMPLETED.value
        )
        batch2 = TicketBatch(
            tenant_id=tenant.id, batch_number=2, status=TicketBatchStatus.PENDING.value
        )
        batch3 = TicketBatch(
            tenant_id=tenant.id, batch_number=3, status=TicketBatchStatus.CREATED.value
        )
        db_session.add_all([batch1, batch2, batch3])
        db_session.commit()

        repo = TicketBatchRepository(db_session)

        # Act: Den nächsten zu verarbeitenden Batch abrufen
        next_batch = repo.get_next_pending_batch(tenant.id)

        # Assert: Es sollte batch2 (der älteste nicht-abgeschlossene Batch) sein
        assert next_batch is not None, "Es wurde kein pending/created Batch gefunden."
        assert next_batch.batch_number == 2

    def test_mark_batch_failed_resets_findings(self, db_session):
        """
        Verifiziert, dass beim Scheitern eines Batches alle darin enthaltenen Findings
        wieder auf den Status 'new' gesetzt werden und die Batch-ID entfernt wird.
        """
        # Arrange
        tenant = Tenant(name="TestTenant")
        db_session.add(tenant)
        db_session.flush()

        batch = TicketBatch(
            tenant_id=tenant.id, batch_number=1, status=TicketBatchStatus.PENDING.value
        )
        db_session.add(batch)
        db_session.flush()

        # Ein Finding mit dem Batch verknüpfen
        finding = Finding(
            tenant_id=tenant.id,
            asset_id=1,  # Vereinfacht für Unit-Test
            batch_id=batch.id,
            name="Test Finding",
            target="host1",
            risk=5.0,
            amount=1,
            extended_solution_json='["Fix"]',
            status="ticketing_in_progress",
        )
        db_session.add(finding)
        db_session.commit()

        repo = TicketBatchRepository(db_session)

        # Act: Batch als fehlgeschlagen markieren
        repo.mark_batch_failed(batch, "Connection timeout")
        db_session.commit()

        # Assert: Batch-Status prüfen
        assert batch.status == TicketBatchStatus.FAILED.value
        assert batch.retry_count == 1
        # Finding-Status prüfen (muss zurückgesetzt sein)
        assert finding.status == "new"
        assert finding.batch_id is None
