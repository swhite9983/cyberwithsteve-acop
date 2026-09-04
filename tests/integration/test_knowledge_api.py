"""The knowledge API end to end, over a real uvicorn server on a real socket.

**Not ASGITransport.** Every property proved here is about what is *committed*
when the client reads a status code, and ``httpx.ASGITransport`` cannot observe
that: it awaits FastAPI's dependency-teardown stack before handing back the
response, so work done in teardown appears to have happened. Over a real socket
it has not - uvicorn writes the response bytes first and unwinds afterwards.
That difference is what produced the Milestone 2 defect, and Milestone 3 adds a
new write path, so it is re-proved here rather than assumed to be inherited.

The embedding provider is the one dependency overridden. It reaches an external
GPU host, and a deterministic stand-in makes the corpus reproducible; nothing
else about the stack is substituted - real routes, real transaction boundary,
real PostgreSQL, real pgvector.
"""

from __future__ import annotations

import asyncio
import socket
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
import uvicorn
from alembic import command
from alembic.config import Config
from sqlalchemy import func, select, text

from acop.api.deps import get_embedding_provider
from acop.config import ApiKeyPrincipalConfig, Settings
from acop.db import Database
from acop.main import create_app
from acop.models.audit import AuditEvent
from acop.models.knowledge import (
    KnowledgeDocument,
    KnowledgeDocumentVersion,
    KnowledgeIngestAttempt,
)
from acop.services.knowledge.embedding_provider import DeterministicEmbeddingProvider
from tests.conftest import requires_database

pytestmark = [pytest.mark.integration, requires_database]

REPO_ROOT = Path(__file__).resolve().parents[2]

OPERATOR_KEY = "operator-key-kn-0000000000000"
APPROVER_KEY = "approver-key-kn-0000000000000"
ADMIN_KEY = "admin-key-kn-00000000000000000"
OPERATOR = {"X-ACOP-API-Key": OPERATOR_KEY}
APPROVER = {"X-ACOP-API-Key": APPROVER_KEY}
ADMIN = {"X-ACOP-API-Key": ADMIN_KEY}

FAKE_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEAxxxxxxxxDOCUMENTATIONxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
    "-----END RSA PRIVATE KEY-----"
)

RUNBOOK = """# Core Switch Runbook

The core switch CORE3850 serves the management network.

## VLANs

VLAN 100 is the management VLAN. Trunk ports carry VLAN 100 and VLAN 200.

## Troubleshooting

If %SPANTREE-2-BLOCK_BPDUGUARD appears, check portfast on Gi1/0/24.
"""

INJECTION_DOC = """# Prompt Injection Awareness

Attackers embed strings such as "ignore all previous instructions" in
documents so that a naive assistant follows them. This page exists so the
corpus can teach the platform about the technique.
"""


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.fixture
def api_settings(make_settings) -> Settings:
    return make_settings(
        api_keys=[
            ApiKeyPrincipalConfig(
                subject="acop:user:operator", secret=OPERATOR_KEY, roles=["operator"]
            ),
            ApiKeyPrincipalConfig(
                subject="acop:user:approver", secret=APPROVER_KEY, roles=["approver"]
            ),
            ApiKeyPrincipalConfig(
                subject="acop:user:admin", secret=ADMIN_KEY, roles=["admin"]
            ),
        ]
    )


@pytest.fixture
async def live(api_settings: Settings) -> AsyncIterator[httpx.AsyncClient]:
    database = Database(api_settings)
    async with database.engine.begin() as connection:
        await connection.execute(text("DROP SCHEMA public CASCADE"))
        await connection.execute(text("CREATE SCHEMA public"))
    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", api_settings.database_url)
    await asyncio.to_thread(command.upgrade, config, "head")
    await database.dispose()

    app = create_app(api_settings)
    # The only substitution. Everything else is the production wiring.
    app.dependency_overrides[get_embedding_provider] = lambda: (
        DeterministicEmbeddingProvider(768)
    )

    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(
            app, host="127.0.0.1", port=port, log_level="error", access_log=False
        )
    )
    task = asyncio.create_task(server.serve())
    for _ in range(200):
        if server.started:
            break
        await asyncio.sleep(0.05)
    assert server.started, "uvicorn did not start"
    try:
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{port}", timeout=60.0
        ) as client:
            yield client
    finally:
        server.should_exit = True
        await task


@pytest.fixture
async def observer(api_settings: Settings) -> AsyncIterator[Database]:
    """An independent connection, for seeing what the server actually committed."""
    database = Database(api_settings)
    try:
        yield database
    finally:
        await database.dispose()


async def _count(database: Database, model: type, *where: object) -> int:
    async with database.session() as session:
        statement = select(func.count()).select_from(model)
        for clause in where:
            statement = statement.where(clause)  # type: ignore[arg-type]
        return int((await session.execute(statement)).scalar_one())


async def _bootstrap(client: httpx.AsyncClient) -> tuple[str, str]:
    """Register and verify a space, then register an INTERNAL source."""
    space = await client.post(
        "/knowledge/embedding-spaces",
        headers=ADMIN,
        json={
            "space_key": "api_768",
            "provider": "deterministic",
            "model": "deterministic-test",
            "model_digest": "deterministic",
            "dimensions": 768,
            "document_prefix": "title: none | text: ",
            "query_prefix": "task: search result | query: ",
            "make_default": True,
        },
    )
    assert space.status_code == 201, space.text
    space_id = space.json()["id"]
    verified = await client.post(
        f"/knowledge/embedding-spaces/{space_id}/verify-prefixes",
        headers=ADMIN,
        json={
            "observed_document_prefix": "title: none | text: ",
            "observed_query_prefix": "task: search result | query: ",
            "prefix_changes_vector": True,
            "note": "deterministic provider, observed in test",
        },
    )
    assert verified.status_code == 200, verified.text

    source = await client.post(
        "/knowledge/sources",
        headers=OPERATOR,
        json={
            "source_kind": "RUNBOOK",
            "title": "Network runbooks",
            "origin": "steve",
            "trust_class": "INTERNAL_VERIFIED",
            "sensitivity": "INTERNAL",
        },
    )
    assert source.status_code == 201, source.text
    return space_id, source.json()["id"]


async def _ingest(
    client: httpx.AsyncClient, source_id: str, ref: str, content: str
) -> httpx.Response:
    return await client.post(
        "/knowledge/documents",
        headers=OPERATOR,
        json={
            "source_id": source_id,
            "external_ref": ref,
            "title": ref,
            "content": content,
        },
    )


class TestCommitBoundary:
    async def test_a_201_means_the_document_is_already_committed(
        self, live: httpx.AsyncClient, observer: Database
    ) -> None:
        """The Milestone 2 invariant, re-proved for Milestone 3's write path.

        Ingestion writes an attempt, a document, a version, chunks and vectors
        across two transactions. When the client reads 201, every one of them
        must already be visible on an independent connection.
        """
        _, source_id = await _bootstrap(live)
        response = await _ingest(live, source_id, "runbook.md", RUNBOOK)
        assert response.status_code == 201, response.text
        body = response.json()

        # No sleep, no retry: the assertion is that it is visible *now*.
        assert (
            await _count(
                observer,
                KnowledgeDocument,
                KnowledgeDocument.id == uuid.UUID(body["document_id"]),
            )
            == 1
        )
        assert (
            await _count(
                observer,
                KnowledgeDocumentVersion,
                KnowledgeDocumentVersion.id == uuid.UUID(body["version_id"]),
            )
            == 1
        )

    async def test_repeated_ingest_is_committed_every_time(
        self, live: httpx.AsyncClient, observer: Database
    ) -> None:
        """Repeated over many requests, because the defect was intermittent.

        The Milestone 2 failure appeared in 116 of 150 requests, not in one. A
        single-shot check would have passed against the broken code.
        """
        _, source_id = await _bootstrap(live)
        for index in range(25):
            response = await _ingest(
                live, source_id, f"doc-{index}.md", f"# Doc {index}\n\nBody {index}.\n"
            )
            assert response.status_code == 201
            document_id = uuid.UUID(response.json()["document_id"])
            assert (
                await _count(
                    observer, KnowledgeDocument, KnowledgeDocument.id == document_id
                )
                == 1
            ), f"document from request {index} was not committed when 201 was read"

    async def test_a_refused_ingest_still_commits_its_attempt(
        self, live: httpx.AsyncClient, observer: Database
    ) -> None:
        """The failure path's transaction discipline.

        The request transaction is rolled back, so the attempt has to be
        written out of band or the record of the refusal disappears with it -
        the same mechanism as ``AuditService.record_denial``. And no canonical
        row may survive.
        """
        _, source_id = await _bootstrap(live)
        refused = await _ingest(
            live, source_id, "secret.md", RUNBOOK + "\n```\n" + FAKE_PEM + "\n```\n"
        )
        assert refused.status_code in (400, 422), refused.text

        assert (
            await _count(
                observer,
                KnowledgeIngestAttempt,
                KnowledgeIngestAttempt.external_ref == "secret.md",
            )
            == 1
        )
        assert (
            await _count(
                observer,
                KnowledgeDocument,
                KnowledgeDocument.external_ref == "secret.md",
            )
            == 0
        )


class TestSecretHandlingOverTheWire:
    async def test_the_refusal_body_never_carries_the_matched_material(
        self, live: httpx.AsyncClient, observer: Database
    ) -> None:
        _, source_id = await _bootstrap(live)
        refused = await _ingest(
            live, source_id, "secret.md", RUNBOOK + "\n```\n" + FAKE_PEM + "\n```\n"
        )
        raw = refused.text
        assert "BEGIN RSA PRIVATE KEY" not in raw
        assert "MIIEowIBAAKCAQEA" not in raw
        # What it does carry is enough to act on without disclosing anything:
        # the detector's name, a position in the submitter's own document, and
        # the attempt id an approver can review.
        assert "pem_private_key" in raw
        assert "line " in raw
        assert "cols " in raw

    async def test_no_audit_row_contains_the_matched_material(
        self, live: httpx.AsyncClient, observer: Database
    ) -> None:
        """The audit trail is immutable, so a leak into it cannot be redacted."""
        _, source_id = await _bootstrap(live)
        await _ingest(
            live, source_id, "secret.md", RUNBOOK + "\n```\n" + FAKE_PEM + "\n```\n"
        )
        async with observer.session() as session:
            rows = (await session.execute(select(AuditEvent))).scalars()
            for row in rows:
                serialised = str(row.context)
                assert "BEGIN RSA PRIVATE KEY" not in serialised
                assert "MIIEowIBAAKCAQEA" not in serialised


class TestRetrievalOverTheWire:
    async def test_search_returns_results_and_never_echoes_the_query(
        self, live: httpx.AsyncClient
    ) -> None:
        _, source_id = await _bootstrap(live)
        assert (await _ingest(live, source_id, "runbook.md", RUNBOOK)).status_code == 201

        response = await live.post(
            "/knowledge/search",
            headers=OPERATOR,
            json={
                "query": "which VLAN is used for management?",
                "mode": "HYBRID",
                "k": 5,
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["results"]
        assert "query" not in body
        assert body["query_hash"] and body["query_length"] > 0
        assert body["diagnostics"]["degraded"] is False

    async def test_the_audit_record_stores_a_hash_not_the_query(
        self, live: httpx.AsyncClient, observer: Database
    ) -> None:
        """What an investigation needs, without what it must not keep.

        The hash still makes repeated queries correlatable. The text - which
        describes what an operator was worried about - is not written to an
        immutable table that cannot later be redacted.
        """
        _, source_id = await _bootstrap(live)
        await _ingest(live, source_id, "runbook.md", RUNBOOK)
        secret_query = "does CORE3850 expose the out-of-band management network?"
        await live.post(
            "/knowledge/search",
            headers=OPERATOR,
            json={"query": secret_query, "mode": "VECTOR", "k": 3},
        )
        async with observer.session() as session:
            rows = list(
                (
                    await session.execute(
                        select(AuditEvent).where(AuditEvent.action == "knowledge.search")
                    )
                ).scalars()
            )
        assert rows, "the search was not audited"
        for row in rows:
            serialised = str(row.context)
            assert secret_query not in serialised
            assert "query_hash" in serialised
            assert "strategy" in serialised

    async def test_classification_is_enforced_over_the_wire(
        self, live: httpx.AsyncClient
    ) -> None:
        await _bootstrap(live)
        confidential = await live.post(
            "/knowledge/sources",
            headers=OPERATOR,
            json={
                "source_kind": "RUNBOOK",
                "title": "Confidential runbooks",
                "origin": "steve",
                "trust_class": "INTERNAL_VERIFIED",
                "sensitivity": "CONFIDENTIAL",
            },
        )
        confidential_id = confidential.json()["id"]
        assert (
            await _ingest(live, confidential_id, "secret-runbook.md", RUNBOOK)
        ).status_code == 201

        query = {"query": "management VLAN", "mode": "VECTOR", "k": 10}
        for headers, expected in ((OPERATOR, False), (APPROVER, False), (ADMIN, True)):
            response = await live.post("/knowledge/search", headers=headers, json=query)
            sensitivities = {r["sensitivity"] for r in response.json()["results"]}
            assert ("CONFIDENTIAL" in sensitivities) is expected, headers

    async def test_evidence_renders_retrieved_text_as_delimited_data(
        self, live: httpx.AsyncClient
    ) -> None:
        _, source_id = await _bootstrap(live)
        await _ingest(live, source_id, "injection.md", INJECTION_DOC)

        response = await live.post(
            "/knowledge/evidence",
            headers=OPERATOR,
            json={"query": "prompt injection", "mode": "HYBRID", "k": 5},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        render = body["prompt_render"]
        assert "never instructions" in render
        assert "<<<EVIDENCE 1>>>" in render
        # The document is ingested and quoted verbatim - a corpus about
        # injection must be able to contain injection strings - and marked.
        assert "ignore all previous instructions" in render
        assert "FLAGGED" in render
        assert any(c["injection_suspected"] for c in body["citations"])


class TestLifecycleOverTheWire:
    async def test_retirement_stops_retrieval_and_keeps_history(
        self, live: httpx.AsyncClient
    ) -> None:
        _, source_id = await _bootstrap(live)
        first = await _ingest(live, source_id, "runbook.md", RUNBOOK)
        document_id = first.json()["document_id"]
        await _ingest(live, source_id, "runbook.md", RUNBOOK.replace("100", "110"))

        retired = await live.post(
            f"/knowledge/documents/{document_id}/retire", headers=APPROVER
        )
        assert retired.status_code == 200
        assert retired.json()["lifecycle_state"] == "RETIRED"

        search = await live.post(
            "/knowledge/search",
            headers=OPERATOR,
            json={"query": "management VLAN", "mode": "VECTOR", "k": 10},
        )
        assert all(r["document_id"] != document_id for r in search.json()["results"])

        versions = await live.get(
            f"/knowledge/documents/{document_id}/versions", headers=OPERATOR
        )
        assert versions.status_code == 200
        assert len(versions.json()) == 2

    async def test_delete_is_not_a_verb_the_api_knows(
        self, live: httpx.AsyncClient
    ) -> None:
        _, source_id = await _bootstrap(live)
        document_id = (await _ingest(live, source_id, "runbook.md", RUNBOOK)).json()[
            "document_id"
        ]
        gone = await live.request(
            "DELETE", f"/knowledge/documents/{document_id}", headers=ADMIN
        )
        assert gone.status_code == 405


class TestAuthorizationOverTheWire:
    async def test_an_operator_cannot_declare_authoritative_policy(
        self, live: httpx.AsyncClient
    ) -> None:
        response = await live.post(
            "/knowledge/sources",
            headers=OPERATOR,
            json={
                "source_kind": "POLICY",
                "title": "Our policy",
                "origin": "steve",
                "trust_class": "AUTHORITATIVE_POLICY",
                "sensitivity": "INTERNAL",
            },
        )
        assert response.status_code == 403

    async def test_the_attempt_log_is_approver_scoped(
        self, live: httpx.AsyncClient
    ) -> None:
        """What was blocked, by which detector and where, is a review surface."""
        await _bootstrap(live)
        assert (
            await live.get("/knowledge/attempts", headers=OPERATOR)
        ).status_code == 403
        assert (
            await live.get("/knowledge/attempts", headers=APPROVER)
        ).status_code == 200

    async def test_registering_an_embedding_space_requires_admin(
        self, live: httpx.AsyncClient
    ) -> None:
        response = await live.post(
            "/knowledge/embedding-spaces",
            headers=APPROVER,
            json={
                "space_key": "sneaky_768",
                "provider": "deterministic",
                "model": "deterministic-test",
                "dimensions": 768,
            },
        )
        assert response.status_code == 403


class TestDispositionOverTheWire:
    async def test_only_false_positive_unblocks_and_only_those_bytes(
        self, live: httpx.AsyncClient
    ) -> None:
        """The whole disposition rule, exercised through the API.

        ``REMEDIATED_AT_SOURCE`` records that a real secret was dealt with and
        must not make the original bytes ingestable - the submitter has to edit
        the document, and edited content has a different hash. Only
        ``FALSE_POSITIVE`` clears the block, and only for exactly what was
        reviewed.
        """
        _, source_id = await _bootstrap(live)
        content = RUNBOOK + "\n```\n" + FAKE_PEM + "\n```\n"
        refused = await _ingest(live, source_id, "secret.md", content)
        assert refused.status_code in (400, 422)

        attempts = await live.get(
            "/knowledge/attempts",
            headers=APPROVER,
            params={"source_id": source_id, "external_ref": "secret.md"},
        )
        attempt_id = attempts.json()[0]["id"]
        detail = await live.get(f"/knowledge/attempts/{attempt_id}", headers=APPROVER)
        blocking = [f for f in detail.json()["findings"] if f["severity"] == "BLOCKING"]
        assert blocking
        finding_id = blocking[0]["id"]
        assert "BEGIN" not in str(blocking[0])

        by_operator = await live.post(
            f"/knowledge/findings/{finding_id}/dispositions",
            headers=OPERATOR,
            json={"disposition": "FALSE_POSITIVE", "reason": "let me in"},
        )
        assert by_operator.status_code == 403

        remediated = await live.post(
            f"/knowledge/findings/{finding_id}/dispositions",
            headers=APPROVER,
            json={"disposition": "REMEDIATED_AT_SOURCE", "reason": "key rotated"},
        )
        assert remediated.status_code == 201
        assert (await _ingest(live, source_id, "secret.md", content)).status_code in (
            400,
            422,
        )

        cleared = await live.post(
            f"/knowledge/findings/{finding_id}/dispositions",
            headers=APPROVER,
            json={"disposition": "FALSE_POSITIVE", "reason": "documentation sample"},
        )
        assert cleared.status_code == 201
        allowed = await _ingest(live, source_id, "secret.md", content)
        assert allowed.status_code == 201, allowed.text

        # Scoped: the same fingerprint under a different external_ref is still
        # blocked, because the disposition named one target.
        elsewhere = await _ingest(live, source_id, "other.md", content)
        assert elsewhere.status_code in (400, 422)


class TestUnverifiedSpaceGate:
    async def test_ingest_into_an_unverified_space_is_refused(
        self, live: httpx.AsyncClient, observer: Database
    ) -> None:
        """The blocker that stands between a fresh install and a poisoned corpus.

        A registered space is unusable until a human has observed what the
        provider does with task prefixes. This is that gate, over the wire.
        """
        space = await live.post(
            "/knowledge/embedding-spaces",
            headers=ADMIN,
            json={
                "space_key": "unverified_768",
                "provider": "deterministic",
                "model": "deterministic-test",
                "dimensions": 768,
                "make_default": True,
            },
        )
        assert space.status_code == 201
        source = await live.post(
            "/knowledge/sources",
            headers=OPERATOR,
            json={
                "source_kind": "RUNBOOK",
                "title": "Runbooks",
                "origin": "steve",
                "trust_class": "INTERNAL_VERIFIED",
                "sensitivity": "INTERNAL",
            },
        )
        refused = await _ingest(live, source.json()["id"], "runbook.md", RUNBOOK)
        assert refused.status_code == 409, refused.text
        # The refusal has to name the space and the remedy: a bare "conflict"
        # leaves an operator with no way to find out what is wrong.
        assert "prefix" in refused.text.lower()
        assert "unverified_768" in refused.text
        assert "probe_embedding_prefixes" in refused.text
        assert await _count(observer, KnowledgeDocument) == 0
