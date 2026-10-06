"""
app/connectors/nvd_client.py

Client für die NVD (National Vulnerability Database) API v2.0.
Dokumentation: https://nvd.nist.gov/developers/vulnerabilities

Zusammenführung aus:
- Struktur/Ablage: connectors/-Konsolidierung (origin/main).
- Verbesserungen (e467dd1): config-driven Retry/TTL/Rate-Limit, internes
  NOT_FOUND-Caching, Tenacity AsyncRetrying (v9+), Safe-HTTPStatusError-Zugriff.

Öffentlicher Vertrag (bewusst kompatibel zu den bestehenden Aufrufern):
- get_cve_data(cve_id) -> dict | None
    dict      = CVE-Payload bei Erfolg
    None      = CVE nicht gefunden ODER API-Fehler
  Die Unterscheidung "nicht gefunden" vs. "Fehler" wird intern nur fürs
  Caching genutzt (nicht-gefundene CVEs werden gecacht, Fehler nicht), aber
  NICHT als String-Sentinel nach außen gegeben – das würde intake_pipeline
  (prüft nur `if cve_data:`) zum Absturz bringen.
- get_multiple_cves(ids) -> list[dict]   (nur Treffer, ohne None/Fehler)
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
from cachetools import TTLCache
from tenacity import (
    AsyncRetrying,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from app.core.config import settings as cfg
from app.core.logging import get_logger

logger = get_logger(__name__)

# Eindeutiger Marker, um "CVE existiert nicht" im Cache von echten Treffern zu
# unterscheiden. Verlässt diese Datei NICHT (rein internes Caching-Detail).
_NOT_FOUND = object()


class NVDClient:
    """Async-first Client für die NVD REST API v2.0.

    Features:
    - Rate-Limiting dynamisch nach API-Key-Status (NVD-Limit: 5 bzw. 50 Requests
      pro 30-Sekunden-Fenster).
    - TTL-Caching von Treffern und Negativ-Ergebnissen.
    - Retry mit Exponential-Backoff bei Timeout/Netzwerkfehlern sowie HTTP 429/5xx.
    """

    # Defaults, falls Settings einmal fehlen sollten.
    _DEFAULT_CACHE_TTL: int = 86_400
    _DEFAULT_MAX_RETRIES: int = 3
    _DEFAULT_RETRY_MIN_SEC: float = 1.0
    _DEFAULT_RETRY_MAX_SEC: float = 8.0
    # NVD zählt Requests in einem rollierenden 30-Sekunden-Fenster.
    _RATE_WINDOW_SECONDS: float = 30.0

    def __init__(
        self,
        api_key: str | None = None,
        cache_ttl: int | None = None,
        requests_per_second: float | None = None,
    ) -> None:
        """Initialisiert den NVD-Client.

        Args:
            api_key: Optionaler NVD-API-Key. Ohne Angabe wird Settings.NVD_API_KEY
                genutzt. Ein Key erhöht das Rate-Limit (5 -> 50 / 30 s).
            cache_ttl: Optionaler Override der Cache-Dauer (Sekunden). Ohne Angabe
                wird Settings.NVD_CACHE_TTL genutzt.
            requests_per_second: Optionaler Override des Rate-Limits. Ohne Angabe
                wird dynamisch aus Settings.NVD_RATE_LIMIT(_WITH_KEY) berechnet.
        """
        config_api_key: str | None = getattr(cfg, "NVD_API_KEY", None)
        self.api_key: str | None = api_key or config_api_key

        self._base_url: str = getattr(
            cfg, "NVD_BASE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0"
        )
        self._timeout: int = int(getattr(cfg, "NVD_TIMEOUT", 30) or 30)

        # --- Cache-TTL: expliziter Override > Settings > Default ---
        ttl_candidate: int | None = (
            cache_ttl
            if isinstance(cache_ttl, int) and cache_ttl > 0
            else getattr(cfg, "NVD_CACHE_TTL", None)
        )
        cache_ttl_effective: int = (
            ttl_candidate
            if isinstance(ttl_candidate, int) and ttl_candidate > 0
            else self._DEFAULT_CACHE_TTL
        )
        self.cache: TTLCache = TTLCache(maxsize=1000, ttl=cache_ttl_effective)

        # --- Rate-Limit: Mindestabstand zwischen zwei Requests (Sekunden) ---
        if requests_per_second is not None and requests_per_second > 0:
            self._rate_limit_seconds: float = round(1.0 / requests_per_second, 4)
        else:
            effective_rate: int = self._effective_rate_limit()
            self._rate_limit_seconds = round(self._RATE_WINDOW_SECONDS / effective_rate, 4)
        self._last_request_time: float = 0.0

        # --- Retry-Konfiguration aus Settings ---
        retries: int = self._normalize_int(
            getattr(cfg, "MAX_RETRIES", None), self._DEFAULT_MAX_RETRIES
        )
        retry_min: float = self._normalize_float(
            getattr(cfg, "RETRY_MIN_SECONDS", None), self._DEFAULT_RETRY_MIN_SEC
        )
        retry_max: float = self._normalize_float(
            getattr(cfg, "RETRY_MAX_SECONDS", None), self._DEFAULT_RETRY_MAX_SEC
        )
        self._retry_ctx: AsyncRetrying = AsyncRetrying(
            retry=retry_if_exception(self._is_retryable_exc),
            stop=stop_after_attempt(retries),
            wait=wait_exponential(multiplier=1.0, min=retry_min, max=retry_max),
            reraise=True,
        )

    # ------------------------------------------------------------------ #
    # Hilfsfunktionen
    # ------------------------------------------------------------------ #
    def _effective_rate_limit(self) -> int:
        """Requests pro 30-s-Fenster, abhängig vom Key-Status."""
        # Property aus Settings bevorzugen, sonst manuell ableiten.
        prop = getattr(cfg, "nvd_rate_limit_effective", None)
        if isinstance(prop, int) and prop > 0:
            return prop
        if self.api_key:
            return int(getattr(cfg, "NVD_RATE_LIMIT_WITH_KEY", 50) or 50)
        return int(getattr(cfg, "NVD_RATE_LIMIT", 5) or 5)

    @staticmethod
    def _normalize_int(value: Any | None, default: int) -> int:
        return value if isinstance(value, int) and value > 0 else default

    @staticmethod
    def _normalize_float(value: Any | None, default: float) -> float:
        return float(value) if isinstance(value, (int, float)) and value > 0 else default

    @staticmethod
    def _is_retryable_exc(exc: BaseException) -> bool:
        """True für transiente Fehler: Timeout, Netzwerk, HTTP 429/5xx."""
        if isinstance(exc, (httpx.TimeoutException, httpx.TransportError)):
            return True
        if isinstance(exc, httpx.HTTPStatusError):
            sc = exc.response.status_code if exc.response is not None else 0
            return sc == 429 or sc >= 500
        return False

    async def _rate_limit(self) -> None:
        """Erzwingt den Mindestabstand zwischen zwei Requests."""
        now: float = time.time()
        elapsed: float = now - self._last_request_time
        if elapsed < self._rate_limit_seconds:
            await asyncio.sleep(self._rate_limit_seconds - elapsed)
        self._last_request_time = time.time()

    async def _fetch_json(self, params: dict[str, str], headers: dict[str, str]) -> dict[str, Any]:
        """Führt den HTTP-GET mit Tenacity-Retry aus.

        Retryt transiente Fehler (Timeout/Netzwerk/429/5xx) gemäß
        _is_retryable_exc; nicht-retrybare Fehler (übrige 4xx) werden sofort
        durchgereicht. Nach erschöpften Retries wird die letzte Exception
        erneut geworfen (reraise=True) und vom Aufrufer behandelt.
        """

        async def _request() -> dict[str, Any]:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(self._base_url, params=params, headers=headers)
                response.raise_for_status()
                return response.json()

        return await self._retry_ctx(_request)

    # ------------------------------------------------------------------ #
    # Öffentliche API
    # ------------------------------------------------------------------ #
    async def get_cve_data(self, cve_id: str) -> dict[str, Any] | None:
        """Holt CVE-Daten von NVD.

        Returns:
            dict mit CVE-Payload bei Erfolg, sonst None (nicht gefunden ODER
            API-Fehler nach allen Retries).
        """
        if cve_id in self.cache:
            cached = self.cache[cve_id]
            if cached is _NOT_FOUND:
                logger.debug("Cache-Hit (NOT_FOUND) für %s", cve_id)
                return None
            logger.debug("Cache-Hit für %s", cve_id)
            return cached  # type: ignore[return-value]

        await self._rate_limit()

        headers: dict[str, str] = {"apiKey": self.api_key} if self.api_key else {}

        try:
            data = await self._fetch_json({"cveId": cve_id}, headers)
        except httpx.HTTPStatusError as exc:
            sc = exc.response.status_code if exc.response is not None else 502
            logger.warning("NVD API HTTP %d für %s", sc, cve_id)
            return None
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            logger.warning("NVD Netzwerkfehler für %s: %s", cve_id, type(exc).__name__)
            return None
        except Exception:  # pragma: no cover - defensive
            logger.exception("Unerwarteter Fehler bei NVD-Abfrage für %s", cve_id)
            return None

        vulnerabilities = data.get("vulnerabilities")
        if not vulnerabilities:
            # CVE existiert nicht -> negativ cachen, damit nicht erneut abgefragt wird.
            logger.debug("CVE %s nicht gefunden", cve_id)
            self.cache[cve_id] = _NOT_FOUND
            return None

        cve_data: dict[str, Any] = vulnerabilities[0]
        self.cache[cve_id] = cve_data
        return cve_data

    async def get_multiple_cves(self, cve_ids: list[str]) -> list[dict[str, Any]]:
        """Holt mehrere CVEs nebenläufig.

        Das Rate-Limit greift pro Einzelabruf in get_cve_data. Rückgabe enthält
        ausschließlich erfolgreiche Treffer (keine None/Fehler).
        """
        if not cve_ids:
            return []

        tasks = [self.get_cve_data(cve_id) for cve_id in cve_ids]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        filtered: list[dict[str, Any]] = []
        for idx, result in enumerate(results):
            if isinstance(result, dict):
                filtered.append(result)
            elif isinstance(result, Exception):
                logger.warning(
                    "Fehler bei CVE-Abfrage für %s: %s",
                    cve_ids[idx],
                    type(result).__name__,
                )
            else:  # None -> nicht gefunden oder Fehler (bereits geloggt)
                logger.debug("Kein Treffer für %s", cve_ids[idx])

        logger.info("%d/%d CVEs erfolgreich abgerufen", len(filtered), len(cve_ids))
        return filtered

    # ------------------------------------------------------------------ #
    # Extraktions-Helfer (unverändert gegenüber beiden Vorlagen)
    # ------------------------------------------------------------------ #
    def extract_cvss_metrics(self, cve_data: dict[str, Any]) -> dict[str, Any] | None:
        """Liefert CVSS-Metriken (version, baseScore, vectorString), v3.1 bevorzugt."""
        metrics = cve_data.get("cve", {}).get("metrics", {})

        if metrics.get("cvssMetricV31"):
            data = metrics["cvssMetricV31"][0].get("cvssData", {})
            return {
                "version": "3.1",
                "baseScore": data.get("baseScore"),
                "vectorString": data.get("vectorString"),
            }

        if metrics.get("cvssMetricV2"):
            data = metrics["cvssMetricV2"][0].get("cvssData", {})
            return {
                "version": "2.0",
                "baseScore": data.get("baseScore"),
                "vectorString": data.get("vectorString"),
            }

        return None

    def extract_description(self, cve_data: dict[str, Any], lang: str = "en") -> str | None:
        """Extrahiert die CVE-Beschreibung in der gewünschten Sprache (Fallback: erste)."""
        descriptions = cve_data.get("cve", {}).get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == lang:
                return desc.get("value")
        if descriptions:
            return descriptions[0].get("value")
        return None

    def extract_cve_id(self, cve_data: dict[str, Any]) -> str | None:
        """Liefert die CVE-Kennung aus dem Payload, falls vorhanden."""
        cve = cve_data.get("cve", {})
        if isinstance(cve, dict):
            if cve.get("id"):
                return str(cve.get("id"))
            meta = cve.get("CVE_data_meta", {})
            if isinstance(meta, dict) and meta.get("ID"):
                return str(meta.get("ID"))
        return None
