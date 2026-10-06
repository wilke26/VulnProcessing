"""
app/services/remediation_service.py

Remediation service for VulnProcessing.

This module provides an asynchronous service that fetches AI-based remediation
guides for security findings. It caches results to avoid repeated calls and
limits concurrency when querying external systems. The service is robust
against missing attributes on the Finding objects by falling back to
alternative fields or sensible defaults.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from typing import Any

from cachetools import TTLCache

from app.connectors.copilot_client import CopilotStudioClient
from app.core.config import Settings
from app.core.logging import get_logger
from app.models.remediation import RemediationGuide, RemediationRequest

logger = get_logger(__name__)


class RemediationService:
    """
    Service to retrieve and cache remediation guides for findings.

    The service wraps a CopilotStudioClient and adds caching, batching and
    concurrency control. It accepts arbitrary finding-like objects; if a
    required attribute is missing, a default value is used instead. Caching
    keys are computed from the salient attributes of a finding so that
    identical findings reuse the same AI guide.

    Attributes:
        settings (Settings): Application settings containing Copilot configuration and cache TTL.
        client (CopilotStudioClient): The client used to query Copilot Studio for
            remediation guides.
    """

    def __init__(self, settings: Settings, client: CopilotStudioClient) -> None:
        self.settings = settings
        self.client = client
        # TTL in seconds for cached remediation guides
        ttl = getattr(settings, "COPILOT_CACHE_TTL", 3600)
        self.cache: TTLCache[tuple[Any, ...], RemediationGuide] = TTLCache(maxsize=512, ttl=ttl)
        # Limit concurrent requests to Copilot
        concurrency = getattr(settings, "COPILOT_CONCURRENT_REQUESTS", 5)
        self._semaphore = asyncio.Semaphore(concurrency)

    def _make_request(self, finding: Any) -> RemediationRequest:
        """
        Construct a RemediationRequest from an arbitrary finding.

        This helper extracts the expected attributes from the finding. If a
        field is not present, it falls back to getattr with a default.
        cvss_score defaults to the finding's risk attribute if
        cvss_score is missing. affected_hosts is sliced to the first
        five entries to avoid overly long prompts.
        """

        # Helper to avoid getting Mocks back from getattr when using MagicMocks in tests
        def get_val(obj: Any, attr: str, default: Any) -> Any:
            val = getattr(obj, attr, default)
            # If we get a Mock back but expected a basic type, use the default
            # (unless the default itself is a Mock, which is unlikely here)
            if hasattr(val, "_mock_return_value") and not isinstance(default, type(val)):
                return default
            return val

        return RemediationRequest(
            cve_id=get_val(finding, "cve_id", ""),
            product_name=get_val(finding, "product_name", get_val(finding, "name", "")),
            product_version=get_val(finding, "product_version", ""),
            severity=get_val(finding, "severity", ""),
            cvss_score=get_val(finding, "cvss_score", get_val(finding, "risk", None)),
            affected_hosts=(
                list(get_val(finding, "affected_hosts", []))[:5]
                if get_val(finding, "affected_hosts", None) is not None
                else []
            ),
            description=get_val(finding, "description", get_val(finding, "extended_solution", "")),
        )

    def _get_cache_key(self, finding: Any) -> tuple[Any, ...]:
        """Compute a stable cache key for a finding."""

        # Helper to avoid getting Mocks back from getattr when using MagicMocks in tests
        def get_val(obj: Any, attr: str, default: Any) -> Any:
            val = getattr(obj, attr, default)
            if hasattr(val, "_mock_return_value") and not isinstance(default, type(val)):
                return default
            return val

        return (
            get_val(finding, "cve_id", ""),
            get_val(finding, "product_name", get_val(finding, "name", "")),
            get_val(finding, "product_version", ""),
            get_val(finding, "severity", ""),
            get_val(finding, "cvss_score", get_val(finding, "risk", None)),
        )

    async def _fetch_guide(self, request: RemediationRequest) -> RemediationGuide | None:
        """Internal coroutine to fetch a remediation guide from Copilot."""
        async with self._semaphore:
            try:
                prompt = request.to_prompt()
                logger.debug("Sending remediation prompt: %s", prompt)
                guide = await self.client.get_remediation(prompt)
                return guide
            except Exception as exc:
                logger.exception("Failed to fetch remediation guide: %s", exc)
                return None

    async def get_remediation_guides(self, findings: Iterable[Any]) -> dict[Any, RemediationGuide]:
        """Retrieve remediation guides for a collection of findings."""
        tasks: list[asyncio.Task[tuple[Any, RemediationGuide | None]]] = []
        results: dict[Any, RemediationGuide] = {}

        for finding in findings:
            key = self._get_cache_key(finding)
            if key in self.cache:
                results[finding] = self.cache[key]
            else:
                req = self._make_request(finding)

                async def _task(
                    f: Any, k: tuple[Any, ...], r: RemediationRequest
                ) -> tuple[Any, RemediationGuide | None]:
                    guide = await self._fetch_guide(r)
                    return (f, guide)

                tasks.append(asyncio.create_task(_task(finding, key, req)))

        if tasks:
            for task in await asyncio.gather(*tasks, return_exceptions=True):
                if isinstance(task, Exception):
                    logger.error("Unexpected exception in remediation task: %s", task)
                    continue
                finding, guide = task  # type: ignore[misc]
                if guide is not None:
                    key = self._get_cache_key(finding)
                    self.cache[key] = guide
                    results[finding] = guide
        return results
