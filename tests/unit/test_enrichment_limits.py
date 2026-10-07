from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.config import Settings
from app.services.enrichment_service import CVEQueryLimitExceeded, EnrichmentService

pytestmark = pytest.mark.no_db


def _settings(**overrides) -> Settings:
    return Settings(
        _env_file=None,
        MAX_CVES_PER_FINDING=overrides.get("MAX_CVES_PER_FINDING", 20),
        MAX_CVES_PER_TICKET_OPERATION=overrides.get("MAX_CVES_PER_TICKET_OPERATION", 500),
    )


@pytest.mark.asyncio
async def test_enrichment_rejects_legacy_finding_above_per_finding_limit():
    nvd_client = MagicMock()
    nvd_client.get_multiple_cves = AsyncMock()
    finding = SimpleNamespace(
        name="CVE-2026-1001 CVE-2026-1002 CVE-2026-1003",
        cve_id=None,
    )
    service = EnrichmentService(
        nvd_client=nvd_client,
        settings_obj=_settings(MAX_CVES_PER_FINDING=2),
    )

    with pytest.raises(CVEQueryLimitExceeded, match="Finding"):
        await service.enrich_findings([finding])

    nvd_client.get_multiple_cves.assert_not_awaited()


@pytest.mark.asyncio
async def test_enrichment_rejects_aggregate_cves_before_nvd_call():
    nvd_client = MagicMock()
    nvd_client.get_multiple_cves = AsyncMock()
    findings = [
        SimpleNamespace(name="CVE-2026-1001 CVE-2026-1002", cve_id=None),
        SimpleNamespace(name="CVE-2026-1003 CVE-2026-1004", cve_id=None),
    ]
    service = EnrichmentService(
        nvd_client=nvd_client,
        settings_obj=_settings(
            MAX_CVES_PER_FINDING=2,
            MAX_CVES_PER_TICKET_OPERATION=3,
        ),
    )

    with pytest.raises(CVEQueryLimitExceeded, match="Ticket-Operation"):
        await service.enrich_findings(findings)

    nvd_client.get_multiple_cves.assert_not_awaited()


@pytest.mark.asyncio
async def test_enrichment_rejects_duplicate_occurrence_amplification():
    nvd_client = MagicMock()
    nvd_client.get_multiple_cves = AsyncMock()
    finding = SimpleNamespace(
        name="CVE-2026-1001 CVE-2026-1001 CVE-2026-1001",
        cve_id=None,
    )
    service = EnrichmentService(
        nvd_client=nvd_client,
        settings_obj=_settings(MAX_CVES_PER_FINDING=2),
    )

    with pytest.raises(CVEQueryLimitExceeded, match="Finding"):
        await service.enrich_findings([finding])

    nvd_client.get_multiple_cves.assert_not_awaited()
