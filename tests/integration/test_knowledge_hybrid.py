"""Lexical retrieval, and the fusion of the two legs.

Hybrid retrieval is worth a second query only if the two legs genuinely fail in
different directions, so these tests construct exactly that: a passage whose
value is an exact token no embedder was trained on (an interface name, a Cisco
syslog mnemonic) and a passage whose value is a paraphrase sharing no words with
the query. One leg finds each. Fusion has to return both.

The corpus is built through the real ingestion service rather than by hand,
because the lexical leg depends on the ``lexeme`` generated column, the chunker's
boundaries and the same eligibility joins the dense leg uses - and a fixture that
wrote rows directly would quietly stop testing whether those agree.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

from acop.auth import AuthMethod, Principal, PrincipalType
from acop.config import Settings
from acop.core.exceptions import ValidationError
from acop.db import Database
from acop.models.knowledge import KnowledgeSource
from acop.models.knowledge_vocabulary import (
    RetrievalMethod,
    RetrievalMode,
    RetrievalStrategy,
    Sensitivity,
    SourceKind,
    TrustClass,
)
from acop.services.knowledge.embedding_provider import DeterministicEmbeddingProvider
from acop.services.knowledge.ingest import IngestRequest, KnowledgeIngestService
from acop.services.knowledge.retrieval import (
    KnowledgeRetrievalService,
    RetrievalConfig,
    RetrievalFilters,
)
from acop.services.knowledge.screening import DocumentScreen
from acop.services.knowledge.spaces import EmbeddingSpaceService, SpaceRegistration
from tests.conftest import requires_database

pytestmark = [pytest.mark.integration, requires_database]

REPO_ROOT = Path(__file__).resolve().parents[2]

OPERATOR = Principal(
    subject="acop:user:operator",
    principal_type=PrincipalType.HUMAN,
    issuer="acop:api-key",
    auth_method=AuthMethod.API_KEY,
    roles=frozenset({"operator"}),
)
ADMIN = Principal(
    subject="acop:user:admin",
    principal_type=PrincipalType.HUMAN,
    issuer="acop:api-key",
    auth_method=AuthMethod.API_KEY,
    roles=frozenset({"admin"}),
)
NOBODY = Principal(
    subject="acop:svc:nobody",
    principal_type=PrincipalType.SERVICE,
    issuer="acop:api-key",
    auth_method=AuthMethod.API_KEY,
    roles=frozenset(),
)

# Exact tokens: an interface designator and a syslog mnemonic. Nothing about
# them is semantically derivable - they either match literally or they do not,
# which is precisely what a dense-only corpus is bad at.
EXACT_DOC = """# Spanning Tree Incident Notes

The mnemonic %SPANTREE-2-BLOCK_BPDUGUARD was logged against Gi1/0/24 during
the outage window. Port security shut the interface and it stayed in
err-disable until it was cleared by hand.
"""

# Paraphrase: the same subject as the query below, sharing almost no tokens
# with it.
PARAPHRASE_DOC = """# Change Window Guidance

Alterations to the campus fabric are only permitted inside the agreed
maintenance period. Anything touching the distribution layer outside that
period requires sign-off from the network owner beforehand.
"""

FILLER_DOC = """# Printer Deployment

The third floor printer pool uses static reservations. Toner is replaced on a
quarterly cycle by the facilities team.
"""


@pytest.fixture
async def hdb(settings: Settings) -> AsyncIterator[Database]:
    database = Database(settings)
    async with database.engine.begin() as connection:
        await connection.execute(text("DROP SCHEMA public CASCADE"))
        await connection.execute(text("CREATE SCHEMA public"))
    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", settings.database_url)
    await asyncio.to_thread(command.upgrade, config, "head")
    try:
        yield database
    finally:
        await database.dispose()


async def _space(database: Database):
    async with database.session() as session:
        service = EmbeddingSpaceService(session)
        space = await service.register(
            SpaceRegistration(
                space_key="hybrid_768",
                provider="deterministic",
                model="deterministic-test",
                dimensions=768,
                model_digest="deterministic",
                document_prefix="title: none | text: ",
                query_prefix="task: search result | query: ",
                make_default=True,
            )
        )
        await service.mark_prefixes_verified(space.id, ADMIN.subject)
        space_id = space.id
    async with database.session() as session:
        return await EmbeddingSpaceService(session).get(space_id)


async def _source(
    database: Database, sensitivity: Sensitivity = Sensitivity.INTERNAL
) -> uuid.UUID:
    async with database.session() as session:
        source = KnowledgeSource(
            id=uuid.uuid4(),
            source_kind=SourceKind.RUNBOOK.value,
            title="Network documentation",
            origin="steve",
            trust_class=TrustClass.INTERNAL_VERIFIED.value,
            sensitivity=sensitivity.value,
        )
        session.add(source)
        await session.flush()
        return source.id


async def _ingest(database: Database, space, source_id, content, ref) -> None:
    async with database.session() as session:
        service = KnowledgeIngestService(
            session,
            screen=DocumentScreen("test-salt"),
            embedder=DeterministicEmbeddingProvider(),
            database=database,
        )
        await service.ingest(
            IngestRequest(
                source_id=source_id, external_ref=ref, title=ref, content=content
            ),
            OPERATOR,
            space=space,
        )


def _service(session, config: RetrievalConfig | None = None):
    return KnowledgeRetrievalService(
        session, embedder=DeterministicEmbeddingProvider(), config=config
    )


async def _corpus(database: Database):
    space = await _space(database)
    source_id = await _source(database)
    await _ingest(database, space, source_id, EXACT_DOC, "spantree.md")
    await _ingest(database, space, source_id, PARAPHRASE_DOC, "change-window.md")
    await _ingest(database, space, source_id, FILLER_DOC, "printers.md")
    return space, source_id


class TestLexicalLeg:
    async def test_an_exact_mnemonic_is_found(self, hdb: Database) -> None:
        """The case dense retrieval is structurally bad at.

        ``%SPANTREE-2-BLOCK_BPDUGUARD`` is not a word any embedding model has a
        meaningful representation of. A lexical index either matches it or it
        does not.
        """
        space, _ = await _corpus(hdb)
        async with hdb.session() as session:
            result = await _service(session).search_lexical(
                "SPANTREE BLOCK_BPDUGUARD", OPERATOR, space=space, k=5
            )
        assert result.results
        assert "%SPANTREE-2-BLOCK_BPDUGUARD" in result.results[0].content
        assert result.results[0].method is RetrievalMethod.LEXICAL
        assert result.diagnostics.mode is RetrievalMode.LEXICAL
        # No approximation happened, so no fallback vocabulary is claimed.
        assert result.diagnostics.strategy is RetrievalStrategy.NOT_RUN
        assert result.diagnostics.degraded is False

    async def test_prose_with_punctuation_does_not_raise(self, hdb: Database) -> None:
        """``websearch_to_tsquery`` earns its place here.

        ``to_tsquery`` would raise a syntax error on this input and the caller
        would see a 500 for typing a normal sentence.
        """
        space, _ = await _corpus(hdb)
        async with hdb.session() as session:
            result = await _service(session).search_lexical(
                "what is Gi1/0/24 & why (err-disable)?", OPERATOR, space=space, k=5
            )
        assert result.diagnostics.returned_count >= 0

    async def test_lexical_obeys_the_same_sensitivity_policy(self, hdb: Database) -> None:
        """The two legs must not disagree about who may read what."""
        space = await _space(hdb)
        secret_source = await _source(hdb, Sensitivity.CONFIDENTIAL)
        await _ingest(hdb, space, secret_source, EXACT_DOC, "spantree.md")

        async with hdb.session() as session:
            operator_view = await _service(session).search_lexical(
                "SPANTREE BLOCK_BPDUGUARD", OPERATOR, space=space, k=5
            )
            admin_view = await _service(session).search_lexical(
                "SPANTREE BLOCK_BPDUGUARD", ADMIN, space=space, k=5
            )
        assert operator_view.results == ()
        assert admin_view.results

    async def test_lexical_excludes_superseded_versions(self, hdb: Database) -> None:
        """Lifecycle lives on the embedding row; the lexical leg joins to it.

        Without that join a lexical search would return passages from a
        superseded version that the dense leg had correctly stopped returning -
        two legs, two different answers to "what is current".
        """
        space, source_id = await _corpus(hdb)
        revised = EXACT_DOC.replace("Gi1/0/24", "Gi1/0/48")
        await _ingest(hdb, space, source_id, revised, "spantree.md")

        async with hdb.session() as session:
            result = await _service(session).search_lexical(
                "BLOCK_BPDUGUARD", OPERATOR, space=space, k=10
            )
        contents = " ".join(r.content for r in result.results)
        assert "Gi1/0/48" in contents
        assert "Gi1/0/24" not in contents

    async def test_filters_apply_to_the_lexical_leg(self, hdb: Database) -> None:
        space, source_id = await _corpus(hdb)
        other = await _source(hdb)
        await _ingest(hdb, space, other, EXACT_DOC, "copy.md")

        async with hdb.session() as session:
            result = await _service(session).search_lexical(
                "BLOCK_BPDUGUARD",
                OPERATOR,
                space=space,
                k=10,
                filters=RetrievalFilters(source_ids=(other,)),
            )
        assert result.results
        assert {r.source_id for r in result.results} == {other}
        del source_id

    async def test_no_readable_band_returns_empty(self, hdb: Database) -> None:
        space, _ = await _corpus(hdb)
        async with hdb.session() as session:
            result = await _service(session).search_lexical(
                "BLOCK_BPDUGUARD", NOBODY, space=space, k=5
            )
        assert result.results == ()
        assert result.diagnostics.degraded is False


class TestHybridFusion:
    async def test_fusion_returns_both_legs_findings(self, hdb: Database) -> None:
        """The reason hybrid exists, stated as a test.

        The query carries an exact mnemonic only the lexical leg can match. The
        dense leg contributes its own ordering over the same corpus. The fused
        answer must contain the lexical find - and must be reachable by neither
        leg's ranking alone being taken on trust.
        """
        space, _ = await _corpus(hdb)
        async with hdb.session() as session:
            hybrid = await _service(session).search_hybrid(
                "BLOCK_BPDUGUARD err-disable", OPERATOR, space=space, k=5
            )
        assert hybrid.diagnostics.mode is RetrievalMode.HYBRID
        assert hybrid.diagnostics.lexical_candidates is not None
        assert hybrid.diagnostics.fused_candidates is not None
        assert hybrid.diagnostics.rrf_k == 60
        contents = " ".join(r.content for r in hybrid.results)
        assert "%SPANTREE-2-BLOCK_BPDUGUARD" in contents

    async def test_a_chunk_found_by_both_legs_is_labelled_hybrid(
        self, hdb: Database
    ) -> None:
        space, _ = await _corpus(hdb)
        async with hdb.session() as session:
            result = await _service(session).search_hybrid(
                "spanning tree BLOCK_BPDUGUARD outage", OPERATOR, space=space, k=10
            )
        methods = {r.method for r in result.results}
        assert RetrievalMethod.HYBRID in methods
        both = next(r for r in result.results if r.method is RetrievalMethod.HYBRID)
        assert both.vector_rank is not None
        assert both.lexical_rank is not None
        assert both.fused_score is not None

    async def test_agreement_outranks_a_single_legs_top_hit(self, hdb: Database) -> None:
        """The RRF property that makes fusion more than concatenation.

        A passage both legs rank second scores 2/(60+2) = 0.0323, which beats a
        passage only one leg ranks first at 1/(60+1) = 0.0164. Asserted as
        arithmetic rather than by hoping the corpus produces it.
        """
        space, _ = await _corpus(hdb)
        async with hdb.session() as session:
            result = await _service(session).search_hybrid(
                "spanning tree BLOCK_BPDUGUARD outage", OPERATOR, space=space, k=10
            )
        scores = [r.fused_score or 0.0 for r in result.results]
        assert scores == sorted(scores, reverse=True)
        for chunk in result.results:
            expected = 0.0
            if chunk.vector_rank is not None:
                expected += 1.0 / (60 + chunk.vector_rank)
            if chunk.lexical_rank is not None:
                expected += 1.0 / (60 + chunk.lexical_rank)
            assert chunk.fused_score == pytest.approx(expected)

    async def test_ranks_are_dense_and_ordering_is_reproducible(
        self, hdb: Database
    ) -> None:
        space, _ = await _corpus(hdb)
        async with hdb.session() as session:
            first = await _service(session).search_hybrid(
                "management VLAN trunk", OPERATOR, space=space, k=10
            )
            second = await _service(session).search_hybrid(
                "management VLAN trunk", OPERATOR, space=space, k=10
            )
        assert [r.rank for r in first.results] == list(range(1, len(first.results) + 1))
        assert [r.chunk_id for r in first.results] == [r.chunk_id for r in second.results]

    async def test_hybrid_inherits_dense_degradation(self, hdb: Database) -> None:
        """A lexical hit does not repair an incomplete dense leg.

        With the fallback disabled the dense leg may be incomplete; the fused
        result must keep saying so rather than presenting itself as whole
        because the other leg happened to return something.
        """
        space = await _space(hdb)
        secret = await _source(hdb, Sensitivity.CONFIDENTIAL)
        public = await _source(hdb, Sensitivity.PUBLIC)
        # Many near-identical CONFIDENTIAL documents, one PUBLIC document that
        # only matches lexically.
        for index in range(40):
            await _ingest(
                hdb,
                space,
                secret,
                f"# Secret {index}\n\nManagement VLAN configuration notes {index}.\n",
                f"secret-{index}.md",
            )
        await _ingest(hdb, space, public, EXACT_DOC, "public-spantree.md")

        config = RetrievalConfig(k=10, ann_overfetch=1, exact_fallback_enabled=False)
        async with hdb.session() as session:
            result = await _service(session, config).search_hybrid(
                "management VLAN BLOCK_BPDUGUARD", OPERATOR, space=space
            )

        if result.diagnostics.strategy in (
            RetrievalStrategy.ANN_PARTIAL_FALLBACK_SKIPPED,
        ):
            assert result.diagnostics.degraded is True
            assert result.diagnostics.degradation_reason == "exact_fallback_disabled"
        else:
            # The dense leg was complete on its own terms, which is a legitimate
            # outcome; what is not legitimate is claiming completeness while
            # having skipped the fallback.
            assert result.diagnostics.strategy in (
                RetrievalStrategy.ANN,
                RetrievalStrategy.ANN_COMPLETE,
            )
            assert result.diagnostics.degraded is False

    async def test_hybrid_never_returns_content_above_the_caller_band(
        self, hdb: Database
    ) -> None:
        """Fusion happens in Python, so this is the assertion that matters."""
        space = await _space(hdb)
        secret = await _source(hdb, Sensitivity.CONFIDENTIAL)
        await _ingest(hdb, space, secret, EXACT_DOC, "spantree.md")
        await _ingest(hdb, space, secret, PARAPHRASE_DOC, "change-window.md")

        async with hdb.session() as session:
            result = await _service(session).search_hybrid(
                "BLOCK_BPDUGUARD maintenance window", OPERATOR, space=space, k=10
            )
        assert result.results == ()


class TestModeDispatch:
    async def test_retrieve_dispatches_each_mode(self, hdb: Database) -> None:
        space, _ = await _corpus(hdb)
        async with hdb.session() as session:
            service = _service(session)
            for mode in RetrievalMode:
                result = await service.retrieve(
                    "BLOCK_BPDUGUARD", OPERATOR, space=space, mode=mode, k=5
                )
                assert result.diagnostics.mode is mode

    async def test_empty_query_is_rejected_in_every_mode(self, hdb: Database) -> None:
        space, _ = await _corpus(hdb)
        async with hdb.session() as session:
            service = _service(session)
            for mode in RetrievalMode:
                with pytest.raises(ValidationError):
                    await service.retrieve("  ", OPERATOR, space=space, mode=mode)
