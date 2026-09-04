"""Authentication behaviour at the HTTP boundary.

/whoami touches the database (it writes an audit record), so the success path
lives in the integration suite. These tests cover what can be verified without
a database: that the endpoint is guarded, and that failures do not disclose
internals.
"""

from __future__ import annotations

import functools
import importlib.util
from pathlib import Path
from types import ModuleType

import httpx

from acop.schemas.fact import AttestationRead
from tests.conftest import TEST_API_SECRET


class TestAuthenticationGuard:
    async def test_unauthenticated_request_is_rejected(
        self, client: httpx.AsyncClient
    ) -> None:
        response = await client.get("/whoami")
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "authentication_failed"

    async def test_invalid_key_is_rejected(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/whoami", headers={"X-ACOP-API-Key": "not-the-key"})
        assert response.status_code == 401

    async def test_error_response_carries_the_correlation_id(
        self, client: httpx.AsyncClient
    ) -> None:
        response = await client.get("/whoami")
        body = response.json()["error"]
        assert body["request_id"]
        assert body["request_id"] == response.headers["X-Request-ID"]

    async def test_error_response_does_not_enumerate_backends(
        self, client: httpx.AsyncClient
    ) -> None:
        # Which credential types a deployment accepts is not information an
        # unauthenticated caller needs.
        raw = (await client.get("/whoami")).text.lower()
        assert "api_key" not in raw
        assert "backend" not in raw

    async def test_error_response_does_not_echo_the_presented_credential(
        self, client: httpx.AsyncClient
    ) -> None:
        raw = (
            await client.get("/whoami", headers={"X-ACOP-API-Key": "leaked-value"})
        ).text
        assert "leaked-value" not in raw

    async def test_www_authenticate_header_is_set(
        self, client: httpx.AsyncClient
    ) -> None:
        response = await client.get("/whoami")
        assert response.headers.get("WWW-Authenticate") == "Bearer"


@functools.cache
def _verifier() -> ModuleType:
    """Load scripts/verify_milestone2.py as a module.

    Loaded by path rather than duplicated here on purpose: the acceptance
    contract must exist exactly once, or the guard guards a copy.
    """
    path = Path(__file__).resolve().parents[2] / "scripts" / "verify_milestone2.py"
    spec = importlib.util.spec_from_file_location("acop_verify_milestone2", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestMilestoneScope:
    async def test_only_milestone_3_endpoints_are_exposed(
        self, client: httpx.AsyncClient
    ) -> None:
        """Guard against scope creep.

        Milestones 1-3 expose health, identity, the CMDB and knowledge. Nothing
        that reads or changes infrastructure exists yet, and this test fails if
        an endpoint appears without the milestone that justifies it.
        """
        schema = (await client.get("/openapi.json")).json()
        assert set(schema["paths"]) == {
            "/health",
            "/health/live",
            "/health/ready",
            "/whoami",
            "/cmdb/assets",
            "/cmdb/assets/resolve",
            "/cmdb/assets/{asset_id}",
            "/cmdb/assets/{asset_id}/conflicts",
            "/cmdb/assets/{asset_id}/desired-facts",
            "/cmdb/assets/{asset_id}/facts",
            "/cmdb/assets/{asset_id}/facts/{predicate}/effective",
            "/cmdb/assets/{asset_id}/facts/{predicate}/history",
            "/cmdb/assets/{asset_id}/identifiers",
            "/cmdb/assets/{asset_id}/related",
            "/cmdb/assets/{asset_id}/retire",
            "/cmdb/facts/{fact_id}/attestations",
            "/cmdb/facts/{fact_id}/revoke",
            "/cmdb/facts/{fact_id}/verify",
            "/cmdb/identifiers/{identifier_id}/retire",
            "/cmdb/relationships",
            "/cmdb/relationships/{relationship_id}/retire",
            "/knowledge/attempts",
            "/knowledge/attempts/{attempt_id}",
            "/knowledge/chunks/{chunk_id}/mentions",
            "/knowledge/documents",
            "/knowledge/documents/{document_id}",
            "/knowledge/documents/{document_id}/retire",
            "/knowledge/documents/{document_id}/versions",
            "/knowledge/embedding-spaces",
            "/knowledge/embedding-spaces/{space_id}/verify-prefixes",
            "/knowledge/evidence",
            "/knowledge/findings/{finding_id}/dispositions",
            "/knowledge/search",
            "/knowledge/sources",
            "/knowledge/sources/{source_id}",
            "/knowledge/sources/{source_id}/reclassify",
            "/knowledge/sources/{source_id}/retire",
            "/knowledge/versions/{version_id}/chunks",
            "/knowledge/versions/{version_id}/mentions/scan",
        }

    async def test_verifier_required_route_contract_matches_the_api(
        self, client: httpx.AsyncClient
    ) -> None:
        """The acceptance verifier's contract and the API cannot drift apart.

        The verifier previously asserted a raw count of CMDB paths against a
        number that had silently included /health and /whoami, so it failed on
        a correct deployment and advised running a database migration - which
        cannot create a FastAPI route. It now asserts an explicit set of
        (method, path) pairs, and this test pins that set to what the
        application actually registers, in both directions.
        """
        schema = (await client.get("/openapi.json")).json()
        registered = {
            (method.upper(), path)
            for path, operations in schema["paths"].items()
            for method in operations
            if path.startswith("/cmdb")
        }
        required = _verifier().REQUIRED_ROUTES
        assert not required - registered, "verifier requires routes the API lacks"
        assert not registered - required, "API exposes CMDB routes the contract omits"

    async def test_verifier_reads_the_provider_neutral_attestation_field(
        self,
    ) -> None:
        """The verifier must use the Principal vocabulary, not invent its own.

        It previously read ``actor_subject``, which exists nowhere in ACOP, and
        crashed with a KeyError on a correct response. The field it reads is
        pinned to a real field of the response model.
        """
        field = _verifier().ATTESTATION_SUBJECT_FIELD
        assert field == "principal_subject"
        assert field in AttestationRead.model_fields

    async def test_no_delete_verb_anywhere(self, client: httpx.AsyncClient) -> None:
        """Retirement is a POST. Nothing in the CMDB is destructive, so an
        accidental DELETE has nothing to hit."""
        schema = (await client.get("/openapi.json")).json()
        for path, operations in schema["paths"].items():
            assert "delete" not in operations, path

    async def test_no_endpoint_accepts_a_verification_status(
        self, client: httpx.AsyncClient
    ) -> None:
        """Trust is derived from source_type or set by an explicit transition;
        a client can never assert its own trustworthiness."""
        schema = (await client.get("/openapi.json")).json()
        for name, model in schema.get("components", {}).get("schemas", {}).items():
            if not name.endswith(("Assert", "Create", "Input", "Request")):
                continue
            assert "verification_status" not in model.get("properties", {}), name
            assert "statement_class" not in model.get("properties", {}), name

    async def test_no_tool_execution_surface_exists(
        self, client: httpx.AsyncClient
    ) -> None:
        schema = (await client.get("/openapi.json")).json()
        forbidden = ("tool", "execute", "command", "ssh", "remediat", "discover")
        for path in schema["paths"]:
            assert not any(word in path.lower() for word in forbidden), path


class TestValidKeyReachesTheDatabase:
    async def test_valid_key_fails_at_the_datastore_not_at_authentication(
        self, app
    ) -> None:
        """A correct key must fail at the database, not at authentication.

        The unit fixture points the database at a refused port, so the audit
        write cannot succeed. What matters is the shape of the failure: 503
        with a ``database_unavailable`` code means authentication succeeded and
        the request reached the datastore. A 401 here would mean the credential
        was rejected, and a bare 500 would mean the failure was unclassified.
        """
        # raise_app_exceptions=False so the transport returns the handler's
        # response instead of re-raising, which is what a real server does.
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=transport, base_url="http://acop.test"
            ) as client:
                response = await client.get(
                    "/whoami", headers={"X-ACOP-API-Key": TEST_API_SECRET}
                )

        assert response.status_code == 503
        assert response.json()["error"]["code"] == "database_unavailable"

    async def test_datastore_failure_does_not_leak_driver_internals(self, app) -> None:
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=transport, base_url="http://acop.test"
            ) as client:
                raw = (
                    await client.get(
                        "/whoami", headers={"X-ACOP-API-Key": TEST_API_SECRET}
                    )
                ).text
        assert "asyncpg" not in raw.lower()
        assert "traceback" not in raw.lower()
