"""
Unit-Tests für den BatchTicketingService.
Validiert die Orchestrierung der Batch-weisen Ticketerstellung, inklusive
der Limitierung der Batch-Größe, der Sequentialitätsprüfung und der Filterlogik.
"""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest

from app.core.security import issue_dispatch_confirmation_token
from app.db.models import Asset, Finding, FindingStatus, Tenant, TicketBatch, TicketBatchStatus
from app.services.batch_ticketing_service import BatchTicketingService
from app.services.composition_root import build_batch_ticketing_service


class TestBatchTicketingService:
    """
    Testklasse für den BatchTicketingService.
    """

    @pytest.mark.asyncio
    async def test_create_next_batch_identifies_unknown_tenant(self, db_session):
        service = build_batch_ticketing_service(batch_size=5, db_session=db_session)

        result = await service.create_next_batch(tenant_name="MissingTenant")

        assert result == {
            "status": "error",
            "code": "tenant_not_found",
            "message": "Tenant not found",
        }

    @pytest.mark.asyncio
    async def test_create_next_batch_creates_batch_with_max_5_findings(self, db_session):
        """
        Stellt sicher, dass bei der Batch-Erstellung maximal 5 Findings berücksichtigt werden.
        """
        # Arrange: 10 unverarbeitete Findings für einen Mandanten erstellen
        tenant = Tenant(name="TestTenant")
        asset = Asset(tenant=tenant, name="server01")
        db_session.add_all([tenant, asset])
        db_session.flush()

        for i in range(10):
            finding = Finding(
                tenant_id=tenant.id,
                asset_id=asset.id,
                name=f"Finding {i}",
                target=f"host{i}",
                risk=1.0 + (i / 10.0),
                amount=1,
                extended_solution_json='["Fix"]',
                status=FindingStatus.NEW.value,
            )
            db_session.add(finding)
        db_session.commit()

        # Act: Batch-Erstellung anstoßen (batch_size auf 5 begrenzt)
        service = build_batch_ticketing_service(batch_size=5, db_session=db_session)
        # Mocking des Vorbereitungs-Services (keine Filterung)
        with patch.object(
            service.prep_service, "prepare_for_ticketing", new=AsyncMock(side_effect=lambda x: x)
        ):
            result = await service.create_next_batch(tenant_name="TestTenant")

        # Assert: Ergebnis prüfen
        assert result["status"] == "created"
        findings_count = result.get("findings_count")
        batch_number = result.get("batch_number")
        assert findings_count == 5
        assert batch_number == 1

    @pytest.mark.asyncio
    async def test_create_next_batch_blocks_when_pending_batch_exists(self, db_session):
        """
        Verifiziert, dass kein neuer Batch erstellt wird,
        wenn noch ein Batch aussteht (Sequentialität).
        """
        # Arrange
        tenant = Tenant(name="TestTenant")
        db_session.add(tenant)
        db_session.flush()

        # Einen bereits existierenden Batch im Status 'pending' anlegen
        pending_batch = TicketBatch(
            tenant_id=tenant.id, batch_number=1, status="pending", total_findings=5
        )
        db_session.add(pending_batch)
        db_session.commit()

        # Act: Versuch, einen neuen Batch zu erstellen
        service = build_batch_ticketing_service(batch_size=5, db_session=db_session)
        result = await service.create_next_batch(tenant_name="TestTenant")

        # Assert: Status muss 'pending' sein, da blockiert
        assert result["status"] == "pending"
        assert result.get("pending_batch_number") == 1

    @pytest.mark.asyncio
    async def test_create_next_batch_filters_already_patched_findings(self, db_session):
        """
        Prüft, ob Findings, die bereits gepatcht wurden, korrekt aus dem Batch gefiltert werden.
        """
        # Arrange
        tenant = Tenant(name="TestTenant")
        asset = Asset(tenant=tenant, name="server01")
        db_session.add_all([tenant, asset])
        db_session.flush()

        # 3 Findings anlegen
        for i in range(3):
            finding = Finding(
                tenant_id=tenant.id,
                asset_id=asset.id,
                name=f"Finding {i}",
                target="server01",
                risk=5.0,
                amount=1,
                extended_solution_json='["Fix"]',
                windows_version_hint="KB5001234",
                status=FindingStatus.NEW.value,
            )
            db_session.add(finding)
        db_session.commit()

        # Mock: Simulation, dass 2 Findings bereits gepatcht sind (nur eines bleibt übrig)
        async def mock_prep(findings):
            return findings[:1]

        # Act
        service = build_batch_ticketing_service(batch_size=5, db_session=db_session)
        with patch.object(
            service.prep_service, "prepare_for_ticketing", new=AsyncMock(side_effect=mock_prep)
        ):
            result = await service.create_next_batch(tenant_name="TestTenant")

        # Assert: 1 Finding im Batch, 2 wurden gefiltert
        assert result.get("findings_count") == 1
        assert result.get("filtered_count") == 2

    @pytest.mark.asyncio
    async def test_create_next_batch_stops_at_candidate_budget(self, db_session):
        tenant = Tenant(name="CandidateBudgetTenant")
        asset = Asset(tenant=tenant, name="server01")
        db_session.add_all([tenant, asset])
        db_session.flush()
        findings = []
        for index in range(3):
            finding = Finding(
                tenant_id=tenant.id,
                asset_id=asset.id,
                name=f"Finding {index}",
                target="server01",
                risk=5.0,
                amount=1,
                extended_solution_json='["Fix"]',
                status=FindingStatus.NEW.value,
            )
            findings.append(finding)
            db_session.add(finding)
        db_session.commit()

        prep_service = AsyncMock()
        prep_service.prepare_for_ticketing.return_value = []
        service = BatchTicketingService(
            batch_size=2,
            max_candidates_per_operation=2,
            db_session=db_session,
            prep_service=prep_service,
        )

        result = await service.create_next_batch(tenant_name=tenant.name)

        assert result["status"] == "limit_reached"
        assert prep_service.prepare_for_ticketing.await_count == 1
        assert [finding.status for finding in findings].count(FindingStatus.FILTERED.value) == 2
        assert [finding.status for finding in findings].count(FindingStatus.NEW.value) == 1

    def test_confirm_batch_completion_updates_status(self, db_session):
        """
        Validiert, dass die Bestätigung des Batches den Status in der Datenbank
        korrekt aktualisiert.
        """
        # Arrange
        tenant = Tenant(name="TestTenant")
        asset = Asset(tenant=tenant, name="server01")
        db_session.add_all([tenant, asset])
        db_session.flush()

        batch = TicketBatch(tenant_id=tenant.id, batch_number=1, status="pending", total_findings=3)
        dispatch_token, token_hash = issue_dispatch_confirmation_token()
        batch.sent_at = datetime.now(UTC)
        batch.confirmation_token_hash = token_hash
        db_session.add(batch)
        db_session.flush()

        # Findings im Status 'ticketing_in_progress' anlegen
        findings = []
        for i in range(3):
            finding = Finding(
                tenant_id=tenant.id,
                asset_id=asset.id,
                batch_id=batch.id,
                name=f"Finding {i}",
                target="server01",
                risk=5.0,
                amount=1,
                extended_solution_json='["Fix"]',
                status=FindingStatus.TICKETING_IN_PROGRESS.value,
            )
            db_session.add(finding)
            findings.append(finding)
        db_session.commit()

        # Act: Batch-Abschluss bestätigen
        service = build_batch_ticketing_service(db_session=db_session)
        result = service.confirm_batch_completion(
            batch_id=batch.id,
            successful_count=3,
            failed_count=0,
            dispatch_token=dispatch_token,
        )

        # Assert: Status-Updates verifizieren
        assert result["success"] is True
        assert batch.status == "completed"
        assert batch.successful_tickets == 3
        for finding in findings:
            assert finding.status == FindingStatus.TICKET_CONFIRMED.value

    def test_confirm_batch_rejects_inconsistent_per_finding_results(self, db_session):
        tenant = Tenant(name="ConfirmationDetailsTenant")
        asset = Asset(tenant=tenant, name="server01")
        db_session.add_all([tenant, asset])
        db_session.flush()
        batch = TicketBatch(
            tenant_id=tenant.id,
            batch_number=1,
            status=TicketBatchStatus.PENDING.value,
            total_findings=2,
        )
        dispatch_token, token_hash = issue_dispatch_confirmation_token()
        batch.sent_at = datetime.now(UTC)
        batch.confirmation_token_hash = token_hash
        db_session.add(batch)
        db_session.flush()
        for i in range(2):
            db_session.add(
                Finding(
                    tenant_id=tenant.id,
                    asset_id=asset.id,
                    batch_id=batch.id,
                    name=f"Finding {i}",
                    target="server01",
                    risk=5.0,
                    amount=1,
                    extended_solution_json='["Fix"]',
                    status=FindingStatus.TICKETING_IN_PROGRESS.value,
                )
            )
        db_session.commit()

        service = build_batch_ticketing_service(db_session=db_session)
        result = service.confirm_batch_completion(
            batch_id=batch.id,
            successful_count=0,
            failed_count=2,
            ticket_confirmations=[],
            dispatch_token=dispatch_token,
        )

        assert result == {
            "success": False,
            "error": "Per-finding confirmations do not match the batch result",
            "code": "invalid_confirmation_details",
        }
        assert batch.status == TicketBatchStatus.PENDING.value

    def test_confirm_batch_rejects_direct_call_without_dispatch_token(self, db_session):
        tenant = Tenant(name="TokenlessDirectConfirmationTenant")
        db_session.add(tenant)
        db_session.flush()
        batch = TicketBatch(
            tenant_id=tenant.id,
            batch_number=1,
            status=TicketBatchStatus.PENDING.value,
            total_findings=0,
            sent_at=datetime.now(UTC),
        )
        db_session.add(batch)
        db_session.commit()

        result = build_batch_ticketing_service(db_session=db_session).confirm_batch_completion(
            batch_id=batch.id,
            successful_count=0,
        )

        assert result["code"] == "invalid_batch_state"
        assert batch.status == TicketBatchStatus.PENDING.value
