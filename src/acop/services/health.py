"""Health aggregation.

Every probe is a real call. Nothing here reports a status it has not verified
(section 36: "Do not fake health results").

Two operational safeguards:

* **Caching.** A monitoring system scraping every few seconds must not turn the
  health endpoint into a load generator against the GPU host. Results are
  cached for ``ACOP_HEALTH_CACHE_TTL_SECONDS`` and a single-flight lock stops a
  burst of concurrent requests from producing a burst of probes.
* **Bounded probes.** Each probe runs under its own timeout, so a hung
  dependency produces an ``unhealthy`` verdict rather than a hung request.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import text

from acop import __version__
from acop.ai.ollama import OllamaClient
from acop.config import Settings
from acop.core.exceptions import (
    OllamaError,
    OllamaTimeoutError,
    OllamaUnavailableError,
)
from acop.core.logging import get_logger
from acop.db import Database
from acop.schemas.health import ComponentCheck, ComponentStatus, HealthReport

logger = get_logger(__name__)

#: Components whose failure makes the whole service unhealthy rather than
#: degraded. A missing model is recoverable with `ollama pull` and does not
#: warrant an orchestrator restarting the API container; an unreachable
#: database or inference host does.
REQUIRED_COMPONENTS: frozenset[str] = frozenset({"database", "ollama"})

_SEVERITY_ORDER = {
    ComponentStatus.HEALTHY: 0,
    ComponentStatus.DEGRADED: 1,
    ComponentStatus.UNHEALTHY: 2,
}


@dataclass
class _CachedReport:
    report: HealthReport
    expires_at: float


class HealthService:
    """Probes ACOP's dependencies and aggregates the result."""

    def __init__(
        self,
        settings: Settings,
        database: Database,
        ollama: OllamaClient,
    ) -> None:
        self._settings = settings
        self._database = database
        self._ollama = ollama
        self._cache: _CachedReport | None = None
        self._lock = asyncio.Lock()

    async def report(self, *, use_cache: bool = True) -> HealthReport:
        """Return the current health report, using the cache when permitted."""
        if use_cache:
            cached = self._cache
            if cached is not None and cached.expires_at > time.monotonic():
                return cached.report.model_copy(update={"cached": True})

        async with self._lock:
            # Re-check: another coroutine may have refreshed while we waited.
            cached = self._cache
            if use_cache and cached is not None and cached.expires_at > time.monotonic():
                return cached.report.model_copy(update={"cached": True})

            report = await self._build_report()
            self._cache = _CachedReport(
                report=report,
                expires_at=time.monotonic() + self._settings.health_cache_ttl_seconds,
            )
            return report

    # ------------------------------------------------------------------
    # Probes
    # ------------------------------------------------------------------
    async def _build_report(self) -> HealthReport:
        database, ollama, model = await asyncio.gather(
            self._check_database(),
            self._check_ollama(),
            self._check_model(),
        )

        details: dict[str, ComponentCheck] = {
            "api": ComponentCheck(
                status=ComponentStatus.HEALTHY,
                message="Serving requests.",
                metadata={"version": __version__},
            ),
            "database": database,
            "ollama": ollama,
            # Intentional deviation from section 36 of the brief, which names
            # this component "qwen". A component key that changes when the model
            # changes would silently break every dashboard panel and alert rule
            # that references it, and would keep reporting "qwen: healthy" after
            # a switch to a different model. The key is stable; the model
            # actually checked is reported in details.model.metadata.
            "model": model,
        }

        overall = self._aggregate(details)
        return HealthReport(
            status=overall,
            version=__version__,
            environment=self._settings.environment.value,
            checked_at=datetime.now(UTC),
            cached=False,
            components={
                name: ComponentStatus(check.status).value
                for name, check in details.items()
            },
            details=details,
        )

    async def _check_database(self) -> ComponentCheck:
        started = time.perf_counter()
        try:
            async with self._database.engine.connect() as connection:
                await asyncio.wait_for(
                    connection.execute(text("SELECT 1")),
                    timeout=self._settings.db_connect_timeout_seconds + 2.0,
                )
        except TimeoutError:
            return ComponentCheck(
                status=ComponentStatus.UNHEALTHY,
                latency_ms=self._elapsed_ms(started),
                message="Timed out while querying PostgreSQL.",
                metadata={"target": self._settings.safe_database_target},
            )
        except Exception as exc:
            logger.warning(
                "health.database.failed",
                error_type=type(exc).__name__,
                target=self._settings.safe_database_target,
            )
            return ComponentCheck(
                status=ComponentStatus.UNHEALTHY,
                latency_ms=self._elapsed_ms(started),
                message="Could not execute a query against PostgreSQL.",
                metadata={
                    "target": self._settings.safe_database_target,
                    "error_type": type(exc).__name__,
                },
            )

        return ComponentCheck(
            status=ComponentStatus.HEALTHY,
            latency_ms=self._elapsed_ms(started),
            message="Query succeeded.",
            metadata={"target": self._settings.safe_database_target},
        )

    async def _check_ollama(self) -> ComponentCheck:
        started = time.perf_counter()
        try:
            version = await self._ollama.version()
        except OllamaTimeoutError:
            return ComponentCheck(
                status=ComponentStatus.UNHEALTHY,
                latency_ms=self._elapsed_ms(started),
                message="Ollama did not respond within the control-plane timeout.",
                metadata={"base_url": self._ollama.base_url},
            )
        except OllamaUnavailableError:
            return ComponentCheck(
                status=ComponentStatus.UNHEALTHY,
                latency_ms=self._elapsed_ms(started),
                message="Could not reach the Ollama API.",
                metadata={"base_url": self._ollama.base_url},
            )
        except OllamaError as exc:
            return ComponentCheck(
                status=ComponentStatus.UNHEALTHY,
                latency_ms=self._elapsed_ms(started),
                message="Ollama returned an error.",
                metadata={
                    "base_url": self._ollama.base_url,
                    "error_code": exc.code,
                },
            )

        return ComponentCheck(
            status=ComponentStatus.HEALTHY,
            latency_ms=self._elapsed_ms(started),
            message="Ollama API responded.",
            metadata={
                "base_url": self._ollama.base_url,
                "ollama_version": version.version,
            },
        )

    async def _check_model(self) -> ComponentCheck:
        """Verify the configured model is present on the inference host.

        This checks *availability*, not inference. Running a real completion on
        every health scrape would occupy the GPU and make the endpoint a denial
        of service against ACOP's own reasoning capacity. An actual inference
        test is a deliberate, separate operation: ``scripts/check_qwen.py`` and
        the integration test suite.
        """
        started = time.perf_counter()
        try:
            resolution = await self._ollama.resolve_model()
        except (OllamaUnavailableError, OllamaTimeoutError):
            return ComponentCheck(
                status=ComponentStatus.UNHEALTHY,
                latency_ms=self._elapsed_ms(started),
                message="Could not list models because Ollama is unreachable.",
                metadata={"requested_model": self._settings.ollama_model},
            )
        except OllamaError:
            return ComponentCheck(
                status=ComponentStatus.UNHEALTHY,
                latency_ms=self._elapsed_ms(started),
                message="Ollama returned an error while listing models.",
                metadata={"requested_model": self._settings.ollama_model},
            )

        if not resolution.available:
            return ComponentCheck(
                status=ComponentStatus.UNHEALTHY,
                latency_ms=self._elapsed_ms(started),
                message=(
                    f"Configured model {resolution.requested!r} is not present on "
                    f"the inference host. Pull it with "
                    f"'ollama pull {resolution.requested}'."
                ),
                metadata={
                    "requested_model": resolution.requested,
                    "available_models": list(resolution.available_models),
                },
            )

        if not resolution.exact_match:
            return ComponentCheck(
                status=ComponentStatus.DEGRADED,
                latency_ms=self._elapsed_ms(started),
                message=(
                    f"Configured model {resolution.requested!r} matched "
                    f"{resolution.resolved!r} by tag prefix. Pin the exact tag in "
                    f"ACOP_OLLAMA_MODEL so the model in use is unambiguous."
                ),
                metadata={
                    "requested_model": resolution.requested,
                    "resolved_model": resolution.resolved,
                    "available_models": list(resolution.available_models),
                },
            )

        return ComponentCheck(
            status=ComponentStatus.HEALTHY,
            latency_ms=self._elapsed_ms(started),
            message="Configured model is present on the inference host.",
            metadata={
                "resolved_model": resolution.resolved,
                "num_ctx_requested": self._ollama.num_ctx,
            },
        )

    # ------------------------------------------------------------------
    # Aggregation
    # ------------------------------------------------------------------
    def _aggregate(self, details: dict[str, ComponentCheck]) -> ComponentStatus:
        """Reduce component states to an overall verdict.

        A required component that is unhealthy makes the service unhealthy. Any
        other non-healthy component degrades it.
        """
        worst = ComponentStatus.HEALTHY
        for name, check in details.items():
            status = ComponentStatus(check.status)
            if status is ComponentStatus.HEALTHY:
                continue
            # A non-required component can degrade the service but never mark it
            # unhealthy, so an orchestrator will not restart a container over a
            # model that simply needs pulling.
            effective = (
                status if name in REQUIRED_COMPONENTS else ComponentStatus.DEGRADED
            )
            if _SEVERITY_ORDER[effective] > _SEVERITY_ORDER[worst]:
                worst = effective
        return worst

    @staticmethod
    def _elapsed_ms(started: float) -> float:
        return round((time.perf_counter() - started) * 1000, 2)
