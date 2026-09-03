"""Health aggregation and endpoint semantics."""

from __future__ import annotations

from typing import Any

import httpx
import respx

from acop.schemas.health import ComponentCheck, ComponentStatus
from acop.services.health import REQUIRED_COMPONENTS, HealthService
from tests.conftest import OLLAMA_BASE_URL

TAGS_PAYLOAD = {"models": [{"name": "qwen3:32b"}]}


def check(status: ComponentStatus) -> ComponentCheck:
    return ComponentCheck(status=status)


def aggregate(**components: ComponentStatus) -> ComponentStatus:
    service = HealthService.__new__(HealthService)  # aggregation is pure
    return service._aggregate({name: check(s) for name, s in components.items()})


class TestAggregation:
    def test_all_healthy(self) -> None:
        assert (
            aggregate(
                api=ComponentStatus.HEALTHY,
                database=ComponentStatus.HEALTHY,
                ollama=ComponentStatus.HEALTHY,
                model=ComponentStatus.HEALTHY,
            )
            is ComponentStatus.HEALTHY
        )

    def test_required_component_failure_is_unhealthy(self) -> None:
        for required in REQUIRED_COMPONENTS:
            components = {
                "api": ComponentStatus.HEALTHY,
                "database": ComponentStatus.HEALTHY,
                "ollama": ComponentStatus.HEALTHY,
                "model": ComponentStatus.HEALTHY,
            }
            components[required] = ComponentStatus.UNHEALTHY
            assert aggregate(**components) is ComponentStatus.UNHEALTHY, required

    def test_missing_model_degrades_but_does_not_fail_the_service(self) -> None:
        # The behaviour that stops an orchestrator restarting a working
        # container over a model that simply needs pulling.
        assert (
            aggregate(
                api=ComponentStatus.HEALTHY,
                database=ComponentStatus.HEALTHY,
                ollama=ComponentStatus.HEALTHY,
                model=ComponentStatus.UNHEALTHY,
            )
            is ComponentStatus.DEGRADED
        )

    def test_worst_required_status_wins(self) -> None:
        assert (
            aggregate(
                api=ComponentStatus.HEALTHY,
                database=ComponentStatus.UNHEALTHY,
                ollama=ComponentStatus.HEALTHY,
                model=ComponentStatus.DEGRADED,
            )
            is ComponentStatus.UNHEALTHY
        )


class TestLiveness:
    async def test_liveness_performs_no_dependency_checks(
        self, client: httpx.AsyncClient
    ) -> None:
        # No respx routes are registered and no database is running, yet
        # liveness must still return 200. A liveness probe that depends on
        # PostgreSQL restarts a healthy API during a database blip.
        response = await client.get("/health/live")
        assert response.status_code == 200
        assert response.json()["status"] == "alive"

    async def test_correlation_header_is_returned(
        self, client: httpx.AsyncClient
    ) -> None:
        response = await client.get("/health/live")
        assert response.headers.get("X-Request-ID")

    async def test_supplied_correlation_id_is_propagated(
        self, client: httpx.AsyncClient
    ) -> None:
        response = await client.get(
            "/health/live", headers={"X-Request-ID": "upstream-trace-1"}
        )
        assert response.headers["X-Request-ID"] == "upstream-trace-1"

    async def test_oversized_correlation_id_is_truncated(
        self, client: httpx.AsyncClient
    ) -> None:
        response = await client.get("/health/live", headers={"X-Request-ID": "a" * 5000})
        assert len(response.headers["X-Request-ID"]) <= 128

    async def test_security_headers_are_applied(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/health/live")
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"


class TestHealthReportWithDependenciesDown:
    """Both dependencies are deliberately unreachable in the unit fixture.

    The database points at a refused port and Ollama's HTTP calls are mocked to
    fail, so these assertions hold regardless of what happens to be running on
    the developer's machine.
    """

    @respx.mock
    async def test_report_is_returned_with_real_failures(
        self, client: httpx.AsyncClient
    ) -> None:
        respx.get(f"{OLLAMA_BASE_URL}/api/version").mock(
            side_effect=httpx.ConnectError("refused")
        )
        respx.get(f"{OLLAMA_BASE_URL}/api/tags").mock(
            side_effect=httpx.ConnectError("refused")
        )

        response = await client.get("/health")
        assert response.status_code == 200

        body: dict[str, Any] = response.json()
        assert body["status"] == "unhealthy"
        assert set(body["components"]) == {"api", "database", "ollama", "model"}
        assert body["components"]["api"] == "healthy"
        assert body["components"]["database"] == "unhealthy"
        assert body["components"]["ollama"] == "unhealthy"

    @respx.mock
    async def test_readiness_returns_503_when_unhealthy(
        self, client: httpx.AsyncClient
    ) -> None:
        respx.get(f"{OLLAMA_BASE_URL}/api/version").mock(
            side_effect=httpx.ConnectError("refused")
        )
        respx.get(f"{OLLAMA_BASE_URL}/api/tags").mock(
            side_effect=httpx.ConnectError("refused")
        )
        response = await client.get("/health/ready")
        assert response.status_code == 503

    @respx.mock
    async def test_report_does_not_leak_credentials(self, make_settings: Any) -> None:
        from acop.main import create_app

        respx.get(f"{OLLAMA_BASE_URL}/api/version").mock(
            side_effect=httpx.ConnectError("refused")
        )
        respx.get(f"{OLLAMA_BASE_URL}/api/tags").mock(
            side_effect=httpx.ConnectError("refused")
        )

        # A canary value that cannot appear anywhere else in the response, so
        # the assertion cannot pass by coincidence or fail because the ambient
        # test password happens to match a hostname or database name.
        canary = "LEAK-CANARY-9f2b1c7e"
        app = create_app(make_settings(postgres_port=1, postgres_password=canary))
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://acop.test"
            ) as leak_client:
                raw = (await leak_client.get("/health")).text

        assert canary not in raw
        # The health endpoint is unauthenticated; a raw driver error string is
        # not an acceptable payload for an anonymous caller.
        assert "asyncpg" not in raw.lower()

    @respx.mock
    async def test_ollama_error_status_is_reported_as_unhealthy(
        self, client: httpx.AsyncClient
    ) -> None:
        respx.get(f"{OLLAMA_BASE_URL}/api/version").mock(
            return_value=httpx.Response(502, text="bad gateway")
        )
        respx.get(f"{OLLAMA_BASE_URL}/api/tags").mock(
            return_value=httpx.Response(502, text="bad gateway")
        )
        body = (await client.get("/health")).json()
        assert body["components"]["ollama"] == "unhealthy"
        assert "bad gateway" not in body["details"]["ollama"]["message"]


class TestModelComponent:
    @respx.mock
    async def test_missing_model_is_reported_with_a_remedy(
        self, client: httpx.AsyncClient
    ) -> None:
        respx.get(f"{OLLAMA_BASE_URL}/api/version").mock(
            return_value=httpx.Response(200, json={"version": "0.5.7"})
        )
        respx.get(f"{OLLAMA_BASE_URL}/api/tags").mock(
            return_value=httpx.Response(200, json={"models": [{"name": "llama3:8b"}]})
        )
        body = (await client.get("/health")).json()
        assert body["components"]["model"] == "unhealthy"
        assert "ollama pull" in body["details"]["model"]["message"]
        assert body["details"]["model"]["metadata"]["available_models"] == ["llama3:8b"]

    @respx.mock
    async def test_present_model_is_healthy(self, client: httpx.AsyncClient) -> None:
        respx.get(f"{OLLAMA_BASE_URL}/api/version").mock(
            return_value=httpx.Response(200, json={"version": "0.5.7"})
        )
        respx.get(f"{OLLAMA_BASE_URL}/api/tags").mock(
            return_value=httpx.Response(200, json=TAGS_PAYLOAD)
        )
        body = (await client.get("/health")).json()
        assert body["components"]["model"] == "healthy"
        assert body["details"]["model"]["metadata"]["resolved_model"] == "qwen3:32b"

    @respx.mock
    async def test_health_check_never_runs_inference(
        self, client: httpx.AsyncClient
    ) -> None:
        # A health check that generates would put ACOP's monitoring in
        # competition with ACOP's reasoning for the GPU.
        respx.get(f"{OLLAMA_BASE_URL}/api/version").mock(
            return_value=httpx.Response(200, json={"version": "0.5.7"})
        )
        respx.get(f"{OLLAMA_BASE_URL}/api/tags").mock(
            return_value=httpx.Response(200, json=TAGS_PAYLOAD)
        )
        generate = respx.post(f"{OLLAMA_BASE_URL}/api/generate")
        chat = respx.post(f"{OLLAMA_BASE_URL}/api/chat")

        await client.get("/health")

        assert not generate.called
        assert not chat.called


class TestHealthCaching:
    @respx.mock
    async def test_results_are_cached_between_calls(
        self, client: httpx.AsyncClient, make_settings: Any
    ) -> None:
        from acop.main import create_app

        version_route = respx.get(f"{OLLAMA_BASE_URL}/api/version").mock(
            return_value=httpx.Response(200, json={"version": "0.5.7"})
        )
        respx.get(f"{OLLAMA_BASE_URL}/api/tags").mock(
            return_value=httpx.Response(200, json=TAGS_PAYLOAD)
        )

        app = create_app(make_settings(health_cache_ttl_seconds=60.0, postgres_port=1))
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://acop.test"
            ) as cached_client:
                first = await cached_client.get("/health")
                second = await cached_client.get("/health")
                third = await cached_client.get("/health", params={"fresh": "true"})

        assert first.json()["cached"] is False
        assert second.json()["cached"] is True
        assert third.json()["cached"] is False
        # Two probe rounds: the first request and the explicit refresh.
        assert version_route.call_count == 2
