"""The Milestone 3 HTTP contract, pinned so it cannot drift.

Two kinds of assertion live here. The first is bookkeeping: the acceptance
verifier's route set and the application's registered routes must be the same
set, in both directions, or the verifier is checking a contract nobody
implements.

The second is the interesting one. Several of Milestone 3's guarantees are
properties of the *schema* rather than of any code path - there is no field a
retrieved document could use to request a tool, no field a response could use
to return a query verbatim, no DELETE for an accident to hit. Those are worth
asserting against the generated OpenAPI document, because that is the thing an
outside caller actually sees.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import httpx

from acop.schemas.knowledge import (
    DocumentIngest,
    EvidenceResponse,
    SearchRequest,
    SearchResponse,
)


def _verifier() -> ModuleType:
    """Load scripts/verify_milestone3.py by path.

    By path rather than duplicated here, so the acceptance contract exists
    exactly once - otherwise this test guards a copy of it.
    """
    path = Path(__file__).resolve().parents[2] / "scripts" / "verify_milestone3.py"
    spec = importlib.util.spec_from_file_location("acop_verify_milestone3", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestRouteContract:
    async def test_verifier_contract_matches_the_api_in_both_directions(
        self, client: httpx.AsyncClient
    ) -> None:
        schema = (await client.get("/openapi.json")).json()
        registered = {
            (method.upper(), path)
            for path, operations in schema["paths"].items()
            for method in operations
            if path.startswith("/knowledge")
        }
        required = _verifier().REQUIRED_ROUTES
        assert not required - registered, "verifier requires routes the API lacks"
        assert not registered - required, (
            "API exposes knowledge routes the acceptance contract omits"
        )

    async def test_no_delete_anywhere_in_knowledge(
        self, client: httpx.AsyncClient
    ) -> None:
        """Retirement is a POST.

        Deleting a document would strand every citation that already pointed at
        it, turning a previously auditable answer into an unverifiable one. The
        verb simply does not exist, so an accidental DELETE has nothing to hit.
        """
        schema = (await client.get("/openapi.json")).json()
        for path, operations in schema["paths"].items():
            if path.startswith("/knowledge"):
                assert "delete" not in operations, path


class TestSchemaGuarantees:
    async def test_no_request_schema_can_express_an_instruction(
        self, client: httpx.AsyncClient
    ) -> None:
        """Milestone 3 executes nothing, and the schema is where that is true.

        An injected instruction that a model faithfully obeyed would have
        nowhere to put the result. That is a stronger control than any wording
        in a system prompt, because it does not depend on the model's
        cooperation - so it is asserted against the published contract.
        """
        schema = (await client.get("/openapi.json")).json()
        forbidden = (
            "tool_call",
            "command",
            "execute",
            "shell",
            "ssh",
            "remediat",
            "grant",
            "permission",
        )
        for name, model in schema.get("components", {}).get("schemas", {}).items():
            if "nowledge" not in name and name not in {
                "SearchRequest",
                "EvidenceRequest",
                "SearchResponse",
                "EvidenceResponse",
                "DocumentIngest",
                "SourceCreate",
            }:
                continue
            for field in model.get("properties", {}):
                assert not any(bad in field.lower() for bad in forbidden), (
                    f"{name}.{field}"
                )

    def test_a_search_response_cannot_carry_the_query_text(self) -> None:
        """Hash and length, never the text.

        A search query is frequently the most sensitive thing about a search -
        it describes what an operator was worried about - and the same rule
        applies to the response as to the immutable audit record.
        """
        for model in (SearchResponse, EvidenceResponse):
            assert "query" not in model.model_fields
            assert "query_hash" in model.model_fields
            assert "query_length" in model.model_fields

    def test_a_caller_cannot_assert_its_own_retrieval_reach(self) -> None:
        """Authorization is derived from the principal, never from the payload.

        A request that could name its own sensitivity ceiling would make the
        classification policy client-supplied.
        """
        forbidden = {
            "sensitivity",
            "sensitivities",
            "allowed_sensitivities",
            "roles",
            "principal",
            "subject",
        }
        assert forbidden.isdisjoint(SearchRequest.model_fields)

    def test_ingest_cannot_assert_a_screening_outcome(self) -> None:
        """A submitter does not get to declare its own content clean."""
        forbidden = {
            "screening_outcome",
            "findings",
            "trust_class",
            "sensitivity",
            "prefix_verified_at",
        }
        assert forbidden.isdisjoint(DocumentIngest.model_fields)

    async def test_a_finding_is_never_described_by_what_it_matched(
        self, client: httpx.AsyncClient
    ) -> None:
        """The finding schema has a locator and a fingerprint, and no value.

        Knowledge history is immutable and secrets must never be stored, which
        together leave no remediation path - so the schema is built so the
        value cannot be represented in the first place.
        """
        schema = (await client.get("/openapi.json")).json()
        finding = schema["components"]["schemas"]["FindingRead"]["properties"]
        assert "locator" in finding
        assert "match_fingerprint" in finding
        for field in finding:
            assert field not in {"value", "matched", "matched_text", "secret", "content"}


class TestDiagnosticsAreNotOptional:
    async def test_every_search_response_reports_completeness(
        self, client: httpx.AsyncClient
    ) -> None:
        """Degradation is part of the answer, not a debug flag.

        Three results when ten were asked for is either a complete answer or a
        degraded one, and a caller that cannot tell the difference will read
        both as "there is nothing else".
        """
        schema = (await client.get("/openapi.json")).json()
        diagnostics = schema["components"]["schemas"]["RetrievalDiagnosticsRead"]
        properties = diagnostics["properties"]
        for field in (
            "strategy",
            "degraded",
            "degradation_reason",
            "eligible_population",
            "eligible_population_capped",
            "returned_count",
        ):
            assert field in properties, field
        assert set(diagnostics["required"]) >= {"strategy", "degraded"}
