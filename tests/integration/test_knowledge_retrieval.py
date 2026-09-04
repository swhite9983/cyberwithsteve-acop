"""Dense retrieval, the exact fallback, and the two ways it can be wrong.

The centrepiece is the adversarial corpus from R3 §1: thousands of CONFIDENTIAL
chunks clustered tightly around the query, and a single PUBLIC chunk further
away. An operator asking that query gets nothing from the ANN alone, no matter
how generous the over-fetch. It is run twice - once with the fallback enabled
and once with it disabled - because a fallback test that only ever passes proves
nothing about whether the fallback is what made it pass.

The second is the generic-plan regression. SQLAlchemy with asyncpg uses prepared
statements, so PostgreSQL will eventually switch to a generic plan for a query
it has seen enough times. A partial HNSW index whose predicate depends on a bind
parameter is unusable under a generic plan and silently degrades to a
sequential scan; LIST partitioning survives it via runtime pruning. That is the
measurement the physical layout was chosen on, so it is pinned by a test.
"""

from __future__ import annotations

import asyncio
import math
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

from acop.auth import AuthMethod, Principal, PrincipalType
from acop.config import Settings
from acop.core.exceptions import ConflictError, ValidationError
from acop.db import Database
from acop.models.knowledge import KnowledgeChunk, KnowledgeDocument, KnowledgeSource
from acop.models.knowledge_vocabulary import (
    KnowledgeLifecycle,
    RetrievalMethod,
    RetrievalStrategy,
    Sensitivity,
    SourceKind,
    TrustClass,
    parent_relation,
)
from acop.services.knowledge.embedding_provider import (
    DeterministicEmbeddingProvider,
    EmbeddingDimensionError,
    l2_normalise,
)
from acop.services.knowledge.retrieval import (
    KnowledgeRetrievalService,
    RetrievalConfig,
    RetrievalFilters,
    policy_for,
)
from acop.services.knowledge.spaces import EmbeddingSpaceService, SpaceRegistration
from tests.conftest import requires_database

pytestmark = [pytest.mark.integration, requires_database]

REPO_ROOT = Path(__file__).resolve().parents[2]
DIMENSIONS = 768

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
APPROVER = Principal(
    subject="acop:user:approver",
    principal_type=PrincipalType.HUMAN,
    issuer="acop:api-key",
    auth_method=AuthMethod.API_KEY,
    roles=frozenset({"approver"}),
)
NOBODY = Principal(
    subject="acop:svc:nobody",
    principal_type=PrincipalType.SERVICE,
    issuer="acop:api-key",
    auth_method=AuthMethod.API_KEY,
    roles=frozenset(),
)


@pytest.fixture
async def rdb(settings: Settings) -> AsyncIterator[Database]:
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


# ---------------------------------------------------------------------------
# Corpus construction
#
# Vectors are placed by hand rather than embedded from prose. The properties
# under test are geometric - "these thousands of rows are nearer to the query
# than that one" - and constructing them directly makes the adversarial layout
# exact and reproducible instead of hoping a hash-based embedder happens to
# produce it.
# ---------------------------------------------------------------------------


def _unit(*, angle: float, seed: int) -> list[float]:
    """A unit vector at a chosen angle from the query axis.

    The query axis is e0. A vector at angle t is cos(t)*e0 plus sin(t) spread
    over the remaining dimensions, jittered by ``seed`` so no two rows collide
    and ties are not what any assertion depends on.
    """
    vector = [0.0] * DIMENSIONS
    vector[0] = math.cos(angle)
    tail = math.sin(angle)
    rng = seed * 2654435761 % 2147483647
    for index in range(1, 9):
        rng = (rng * 1103515245 + 12345) % 2147483648
        vector[index] = tail * ((rng / 2147483648.0) - 0.5)
    return l2_normalise(vector)


QUERY_VECTOR = [1.0] + [0.0] * (DIMENSIONS - 1)


async def _register_space(database: Database):
    async with database.session() as session:
        service = EmbeddingSpaceService(session)
        space = await service.register(
            SpaceRegistration(
                space_key="retrieval_768",
                provider="deterministic",
                model="deterministic-test",
                dimensions=DIMENSIONS,
                model_digest="deterministic",
                document_prefix="title: none | text: ",
                query_prefix="task: search result | query: ",
                make_default=True,
            )
        )
        await service.mark_prefixes_verified(space.id, APPROVER.subject)
        space_id = space.id
    async with database.session() as session:
        return await EmbeddingSpaceService(session).get(space_id)


async def _seed_source(
    session,
    *,
    sensitivity: Sensitivity,
    trust: TrustClass = TrustClass.INTERNAL_VERIFIED,
    kind: SourceKind = SourceKind.RUNBOOK,
    lifecycle: KnowledgeLifecycle = KnowledgeLifecycle.ACTIVE,
) -> KnowledgeSource:
    from datetime import UTC, datetime

    source = KnowledgeSource(
        id=uuid.uuid4(),
        source_kind=kind.value,
        title=f"{sensitivity.value} source",
        origin="test",
        trust_class=trust.value,
        sensitivity=sensitivity.value,
        lifecycle_state=lifecycle.value,
        retired_at=(
            datetime.now(UTC) if lifecycle is KnowledgeLifecycle.RETIRED else None
        ),
    )
    session.add(source)
    await session.flush()
    return source


async def _seed_chunks(
    session,
    space,
    source: KnowledgeSource,
    vectors: list[list[float]],
    *,
    label: str,
    retrievable: bool = True,
    current_version: bool = True,
) -> list[uuid.UUID]:
    """Create a document, one version and N chunks with the given vectors.

    Written against the tables directly rather than through the ingest service:
    ingestion is proved elsewhere, and these tests need control over the
    geometry that a real embedder cannot give.
    """
    from datetime import UTC, datetime

    from acop.models.embedding import embedding_model_for
    from acop.models.knowledge import KnowledgeDocumentVersion, KnowledgeIngestAttempt
    from acop.models.knowledge_vocabulary import IngestOutcome, ScreeningOutcome

    raw_hash = uuid.uuid4().hex * 2

    document = KnowledgeDocument(
        id=uuid.uuid4(),
        source_id=source.id,
        external_ref=f"{label}.md",
        title=f"{label} document",
        media_type="text/markdown",
        lifecycle_state=KnowledgeLifecycle.ACTIVE.value,
    )
    session.add(document)
    await session.flush()

    # Every canonical version names the attempt that earned it, so the seed has
    # to produce one too. Constructing it by hand rather than skipping it keeps
    # the fixture honest: a version with no attempt is a state the schema
    # forbids, and a test corpus that could not have been ingested proves
    # nothing about retrieval over one that was.
    attempt = KnowledgeIngestAttempt(
        id=uuid.uuid4(),
        source_id=source.id,
        external_ref=document.external_ref,
        document_id=document.id,
        raw_content_hash=raw_hash,
        text_content_hash=raw_hash,
        byte_size=1,
        media_type="text/markdown",
        outcome=IngestOutcome.PENDING.value,
        requested_by_subject="test",
        principal_type="human",
        principal_issuer="acop:api-key",
        auth_method="api_key",
    )
    session.add(attempt)
    await session.flush()

    version = KnowledgeDocumentVersion(
        id=uuid.uuid4(),
        document_id=document.id,
        version_no=1,
        raw_content_hash=raw_hash,
        text_content_hash=raw_hash,
        byte_size=1,
        char_count=1,
        parser_name="markdown-plain",
        parser_version="1",
        chunker_name="heading-recursive",
        chunker_version="1",
        chunker_params={},
        ingested_at=datetime.now(UTC),
        ingested_by_subject="test",
        screening_outcome=ScreeningOutcome.CLEAN.value,
        created_by_attempt_id=attempt.id,
    )
    session.add(version)
    await session.flush()

    attempt.outcome = IngestOutcome.CREATED.value
    attempt.version_id = version.id
    attempt.finished_at = datetime.now(UTC)

    if current_version:
        document.current_version_id = version.id

    chunks: list[KnowledgeChunk] = []
    for ordinal, _vector in enumerate(vectors):
        chunk = KnowledgeChunk(
            id=uuid.uuid4(),
            version_id=version.id,
            document_id=document.id,
            source_id=source.id,
            ordinal=ordinal,
            content=f"{label} passage {ordinal}",
            content_hash=uuid.uuid4().hex * 2,
            char_start=0,
            char_end=32,
            token_estimate=8,
            heading_path=["Section"],
            section_label="Section",
            flags=[],
        )
        session.add(chunk)
        chunks.append(chunk)
    await session.flush()

    model = embedding_model_for(space.dimensions)
    for chunk, vector in zip(chunks, vectors, strict=True):
        session.add(
            model(
                id=uuid.uuid4(),
                embedding_space_id=space.id,
                chunk_id=chunk.id,
                source_id=source.id,
                document_id=document.id,
                embedding=vector,
                is_current_embedding=True,
                is_retrievable=retrievable,
                sensitivity=source.sensitivity,
                input_token_estimate=8,
                was_truncated=False,
            )
        )
    await session.flush()
    return [chunk.id for chunk in chunks]


def _service(session, config: RetrievalConfig | None = None):
    return KnowledgeRetrievalService(
        session, embedder=DeterministicEmbeddingProvider(DIMENSIONS), config=config
    )


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


class TestPolicy:
    def test_approver_is_not_a_clearance(self) -> None:
        assert (
            policy_for(APPROVER).allowed_sensitivities
            == policy_for(OPERATOR).allowed_sensitivities
        )
        assert Sensitivity.CONFIDENTIAL not in policy_for(APPROVER).allowed_sensitivities

    def test_only_admin_reads_confidential(self) -> None:
        assert Sensitivity.CONFIDENTIAL in policy_for(ADMIN).allowed_sensitivities

    def test_quarantined_is_excluded_for_everyone(self) -> None:
        for principal in (OPERATOR, APPROVER, ADMIN):
            assert TrustClass.QUARANTINED in policy_for(principal).excluded_trust


# ---------------------------------------------------------------------------
# Basic dense retrieval
# ---------------------------------------------------------------------------


class TestDenseRetrieval:
    async def test_nearest_first_and_ranked(self, rdb: Database) -> None:
        space = await _register_space(rdb)
        async with rdb.session() as session:
            source = await _seed_source(session, sensitivity=Sensitivity.INTERNAL)
            await _seed_chunks(
                session,
                space,
                source,
                [_unit(angle=a, seed=i) for i, a in enumerate([0.05, 0.4, 0.9, 1.3])],
                label="near",
            )

        async with rdb.session() as session:
            result = await _service(session).search_vector(
                QUERY_VECTOR, OPERATOR, space=space, k=4
            )

        assert result.diagnostics.strategy is RetrievalStrategy.ANN
        assert [r.rank for r in result.results] == [1, 2, 3, 4]
        distances = [r.distance for r in result.results]
        assert distances == sorted(distances)
        assert all(r.method is RetrievalMethod.VECTOR for r in result.results)
        # score is a similarity; distance is what the database ranked on.
        assert result.results[0].score > result.results[-1].score

    async def test_confidential_is_invisible_to_an_operator(self, rdb: Database) -> None:
        space = await _register_space(rdb)
        async with rdb.session() as session:
            secret = await _seed_source(session, sensitivity=Sensitivity.CONFIDENTIAL)
            await _seed_chunks(
                session, space, secret, [_unit(angle=0.01, seed=1)], label="secret"
            )
            public = await _seed_source(session, sensitivity=Sensitivity.PUBLIC)
            await _seed_chunks(
                session, space, public, [_unit(angle=1.0, seed=2)], label="public"
            )

        async with rdb.session() as session:
            operator_view = await _service(session).search_vector(
                QUERY_VECTOR, OPERATOR, space=space, k=5
            )
            admin_view = await _service(session).search_vector(
                QUERY_VECTOR, ADMIN, space=space, k=5
            )

        assert [r.sensitivity for r in operator_view.results] == [Sensitivity.PUBLIC]
        assert Sensitivity.CONFIDENTIAL in {r.sensitivity for r in admin_view.results}
        # The nearest chunk overall is the CONFIDENTIAL one; the operator's
        # answer must not merely omit its content, it must not reference it.
        assert all("secret" not in r.content for r in operator_view.results)

    async def test_a_principal_with_no_readable_band_gets_a_complete_empty_answer(
        self, rdb: Database
    ) -> None:
        space = await _register_space(rdb)
        async with rdb.session() as session:
            source = await _seed_source(session, sensitivity=Sensitivity.PUBLIC)
            await _seed_chunks(
                session, space, source, [_unit(angle=0.1, seed=1)], label="public"
            )

        async with rdb.session() as session:
            result = await _service(session).search_vector(
                QUERY_VECTOR, NOBODY, space=space, k=5
            )
        assert result.results == ()
        assert result.diagnostics.degraded is False
        assert result.diagnostics.returned_count == 0

    async def test_quarantined_trust_is_never_returned(self, rdb: Database) -> None:
        space = await _register_space(rdb)
        async with rdb.session() as session:
            source = await _seed_source(
                session,
                sensitivity=Sensitivity.PUBLIC,
                trust=TrustClass.QUARANTINED,
            )
            await _seed_chunks(
                session, space, source, [_unit(angle=0.01, seed=1)], label="quarantined"
            )

        async with rdb.session() as session:
            for principal in (OPERATOR, ADMIN):
                result = await _service(session).search_vector(
                    QUERY_VECTOR, principal, space=space, k=5
                )
                assert result.results == ()

    async def test_retired_source_and_superseded_vectors_are_excluded(
        self, rdb: Database
    ) -> None:
        space = await _register_space(rdb)
        async with rdb.session() as session:
            retired = await _seed_source(
                session,
                sensitivity=Sensitivity.PUBLIC,
                lifecycle=KnowledgeLifecycle.RETIRED,
            )
            await _seed_chunks(
                session, space, retired, [_unit(angle=0.01, seed=1)], label="retired"
            )
            superseded = await _seed_source(session, sensitivity=Sensitivity.PUBLIC)
            await _seed_chunks(
                session,
                space,
                superseded,
                [_unit(angle=0.02, seed=2)],
                label="superseded",
                retrievable=False,
            )
            orphan = await _seed_source(session, sensitivity=Sensitivity.PUBLIC)
            await _seed_chunks(
                session,
                space,
                orphan,
                [_unit(angle=0.03, seed=3)],
                label="orphan",
                current_version=False,
            )

        async with rdb.session() as session:
            result = await _service(session).search_vector(
                QUERY_VECTOR, ADMIN, space=space, k=10
            )
        assert result.results == ()

    async def test_filters_narrow_and_cannot_widen(self, rdb: Database) -> None:
        space = await _register_space(rdb)
        async with rdb.session() as session:
            wanted = await _seed_source(session, sensitivity=Sensitivity.PUBLIC)
            await _seed_chunks(
                session, space, wanted, [_unit(angle=0.2, seed=1)], label="wanted"
            )
            other = await _seed_source(session, sensitivity=Sensitivity.PUBLIC)
            await _seed_chunks(
                session, space, other, [_unit(angle=0.1, seed=2)], label="other"
            )
            confidential = await _seed_source(
                session, sensitivity=Sensitivity.CONFIDENTIAL
            )
            await _seed_chunks(
                session,
                space,
                confidential,
                [_unit(angle=0.01, seed=3)],
                label="confidential",
            )
            wanted_id, confidential_id = wanted.id, confidential.id

        async with rdb.session() as session:
            narrowed = await _service(session).search_vector(
                QUERY_VECTOR,
                OPERATOR,
                space=space,
                k=10,
                filters=RetrievalFilters(source_ids=(wanted_id,)),
            )
            assert {r.source_id for r in narrowed.results} == {wanted_id}

            # Asking explicitly for a source above the caller's band returns
            # nothing: a filter restricts, it never grants.
            attempted = await _service(session).search_vector(
                QUERY_VECTOR,
                OPERATOR,
                space=space,
                k=10,
                filters=RetrievalFilters(source_ids=(confidential_id,)),
            )
            assert attempted.results == ()


# ---------------------------------------------------------------------------
# The adversarial corpus - R3 §1
# ---------------------------------------------------------------------------


CONFIDENTIAL_COUNT = 3000


async def _seed_adversarial(
    rdb: Database, space, *, public_count: int = 1
) -> list[uuid.UUID]:
    """Thousands of CONFIDENTIAL vectors hugging the query; one PUBLIC further out.

    Deliberately hostile to over-fetch: the PUBLIC chunk is further from the
    query than every one of the CONFIDENTIAL chunks, so no multiplier short of
    "fetch everything" reaches it.
    """
    async with rdb.session() as session:
        confidential = await _seed_source(session, sensitivity=Sensitivity.CONFIDENTIAL)
        # Chunked into batches so one INSERT statement does not carry 3000 rows.
        for batch in range(0, CONFIDENTIAL_COUNT, 500):
            await _seed_chunks(
                session,
                space,
                confidential,
                [
                    _unit(angle=0.001 + (index % 500) * 1e-6, seed=index + 1)
                    for index in range(batch, min(batch + 500, CONFIDENTIAL_COUNT))
                ],
                label=f"confidential-{batch}",
            )
        public = await _seed_source(session, sensitivity=Sensitivity.PUBLIC)
        return await _seed_chunks(
            session,
            space,
            public,
            [
                _unit(angle=1.2 + index * 1e-4, seed=99991 + index)
                for index in range(public_count)
            ],
            label="public",
        )


class TestAdversarialCorpus:
    """The measurement that killed 'over-fetch is the correctness floor'."""

    async def test_exact_fallback_finds_the_far_public_chunk(self, rdb: Database) -> None:
        space = await _register_space(rdb)
        target = (await _seed_adversarial(rdb, space))[0]

        config = RetrievalConfig(k=5, ann_overfetch=8, exact_fallback_enabled=True)
        async with rdb.session() as session:
            result = await _service(session, config).search_vector(
                QUERY_VECTOR, OPERATOR, space=space
            )

        diagnostics = result.diagnostics
        assert diagnostics.strategy is RetrievalStrategy.EXACT_FALLBACK
        assert diagnostics.degraded is False
        # The ANN alone found nothing eligible: every candidate it proposed was
        # CONFIDENTIAL. This is the assertion that makes the test adversarial
        # rather than merely large.
        assert diagnostics.ann_eligible_count == 0
        assert diagnostics.eligible_population == 1
        assert [r.chunk_id for r in result.results] == [target]
        assert result.results[0].method is RetrievalMethod.VECTOR_EXACT
        assert result.results[0].sensitivity is Sensitivity.PUBLIC

    async def test_negative_control_with_the_fallback_disabled(
        self, rdb: Database
    ) -> None:
        """The same corpus, the same query, the fallback switched off.

        Without this the positive test proves only that *something* returned
        the right row. With it, the fallback is shown to be the thing that did.
        """
        space = await _register_space(rdb)
        await _seed_adversarial(rdb, space)

        config = RetrievalConfig(k=5, ann_overfetch=8, exact_fallback_enabled=False)
        async with rdb.session() as session:
            result = await _service(session, config).search_vector(
                QUERY_VECTOR, OPERATOR, space=space
            )

        diagnostics = result.diagnostics
        assert result.results == ()
        assert diagnostics.strategy is RetrievalStrategy.ANN_PARTIAL_FALLBACK_SKIPPED
        assert diagnostics.degraded is True
        assert diagnostics.degradation_reason == "exact_fallback_disabled"
        # And crucially: it did not claim completeness. An empty answer marked
        # degraded is a different statement from an empty answer marked ANN.
        assert diagnostics.eligible_population == 1

    async def test_admin_needs_no_fallback_on_the_same_corpus(
        self, rdb: Database
    ) -> None:
        """A control in the other direction: same data, different principal.

        For an admin every candidate is eligible, so the ANN satisfies k on its
        own. That the strategy differs by principal on identical data is the
        point - the fallback is driven by eligibility, not by corpus size.
        """
        space = await _register_space(rdb)
        await _seed_adversarial(rdb, space)

        config = RetrievalConfig(k=5, ann_overfetch=8)
        async with rdb.session() as session:
            result = await _service(session, config).search_vector(
                QUERY_VECTOR, ADMIN, space=space
            )
        assert result.diagnostics.strategy is RetrievalStrategy.ANN
        assert len(result.results) == 5

    async def test_exact_max_rows_degrades_instead_of_scanning(
        self, rdb: Database
    ) -> None:
        """The bound is honoured, and its being honoured is visible.

        Constructed so both fallback preconditions hold: the ANN returns no
        eligible rows *and* more eligible rows exist than the bound permits
        ranking. Without the second, this would only re-test cause (B).
        """
        space = await _register_space(rdb)
        await _seed_adversarial(rdb, space, public_count=100)

        config = RetrievalConfig(k=50, ann_overfetch=1, exact_max_rows=10)
        async with rdb.session() as session:
            result = await _service(session, config).search_vector(
                QUERY_VECTOR, OPERATOR, space=space
            )

        diagnostics = result.diagnostics
        assert diagnostics.strategy is RetrievalStrategy.ANN_PARTIAL_FALLBACK_SKIPPED
        assert diagnostics.degraded is True
        assert (
            diagnostics.degradation_reason == "eligible_population_exceeds_exact_max_rows"
        )
        assert diagnostics.eligible_population_capped is True


# ---------------------------------------------------------------------------
# The trigger rule: (A) ANN missed rows vs (B) no more rows exist
# ---------------------------------------------------------------------------


class TestFallbackTrigger:
    async def test_short_answer_with_nothing_left_is_complete_not_degraded(
        self, rdb: Database
    ) -> None:
        """Cause (B). Two eligible rows, k of ten: the answer is already whole.

        The failure this pins down is the tempting one - treating "fewer than k"
        as sufficient reason to run an exhaustive scan. On a small corpus it is
        merely wasteful; on a large one with a narrow filter it is a full scan
        on every request that happens to be selective.
        """
        space = await _register_space(rdb)
        async with rdb.session() as session:
            source = await _seed_source(session, sensitivity=Sensitivity.PUBLIC)
            await _seed_chunks(
                session,
                space,
                source,
                [_unit(angle=0.1, seed=1), _unit(angle=0.2, seed=2)],
                label="small",
            )

        async with rdb.session() as session:
            result = await _service(session).search_vector(
                QUERY_VECTOR, OPERATOR, space=space, k=10
            )

        diagnostics = result.diagnostics
        assert diagnostics.strategy is RetrievalStrategy.ANN_COMPLETE
        assert diagnostics.degraded is False
        assert diagnostics.exact_rows_ranked is None
        assert diagnostics.eligible_population == 2
        assert len(result.results) == 2

    async def test_exact_fallback_reports_what_it_ranked(self, rdb: Database) -> None:
        space = await _register_space(rdb)
        async with rdb.session() as session:
            confidential = await _seed_source(
                session, sensitivity=Sensitivity.CONFIDENTIAL
            )
            await _seed_chunks(
                session,
                space,
                confidential,
                [_unit(angle=0.001, seed=i) for i in range(1, 60)],
                label="confidential",
            )
            public = await _seed_source(session, sensitivity=Sensitivity.PUBLIC)
            await _seed_chunks(
                session,
                space,
                public,
                [_unit(angle=1.1, seed=500 + i) for i in range(3)],
                label="public",
            )

        config = RetrievalConfig(k=10, ann_overfetch=2)
        async with rdb.session() as session:
            result = await _service(session, config).search_vector(
                QUERY_VECTOR, OPERATOR, space=space
            )

        diagnostics = result.diagnostics
        assert diagnostics.strategy is RetrievalStrategy.EXACT_FALLBACK
        assert diagnostics.eligible_population == 3
        assert diagnostics.exact_rows_ranked == 3
        assert len(result.results) == 3
        assert all(r.method is RetrievalMethod.VECTOR_EXACT for r in result.results)


# ---------------------------------------------------------------------------
# Isolation of the exact stage
# ---------------------------------------------------------------------------


class TestExactStageIsolation:
    async def test_settings_are_restored_and_the_transaction_survives(
        self, rdb: Database
    ) -> None:
        """``SET LOCAL`` must not leak into the rest of the request.

        A retrieval call shares its transaction with CMDB reads and audit
        writes. If it left ``hnsw.ef_search`` - or, in the rejected design,
        ``enable_indexscan`` - altered behind it, unrelated statements would be
        planned differently for the remainder of the request.
        """
        space = await _register_space(rdb)
        async with rdb.session() as session:
            source = await _seed_source(session, sensitivity=Sensitivity.PUBLIC)
            await _seed_chunks(
                session, space, source, [_unit(angle=0.1, seed=1)], label="a"
            )

        async with rdb.session() as session:
            before = (await session.execute(text("SHOW hnsw.ef_search"))).scalar_one()
            await _service(
                session, RetrievalConfig(k=3, hnsw_ef_search=250)
            ).search_vector(QUERY_VECTOR, OPERATOR, space=space)
            after = (await session.execute(text("SHOW hnsw.ef_search"))).scalar_one()
            assert after == before
            # And the session is still usable, which a leaked abort would break.
            assert (await session.execute(text("SELECT 1"))).scalar_one() == 1

    async def test_exact_timeout_degrades_without_killing_the_transaction(
        self, rdb: Database
    ) -> None:
        """A timeout in the fallback must abort the fallback and nothing else.

        Forced with a one-millisecond budget rather than a huge corpus, so the
        test proves the SAVEPOINT containment rather than exercising the
        machine.
        """
        space = await _register_space(rdb)
        async with rdb.session() as session:
            confidential = await _seed_source(
                session, sensitivity=Sensitivity.CONFIDENTIAL
            )
            await _seed_chunks(
                session,
                space,
                confidential,
                [_unit(angle=0.001, seed=i) for i in range(1, 40)],
                label="confidential",
            )
            public = await _seed_source(session, sensitivity=Sensitivity.PUBLIC)
            await _seed_chunks(
                session, space, public, [_unit(angle=1.1, seed=777)], label="public"
            )

        config = RetrievalConfig(k=5, ann_overfetch=1, exact_timeout_ms=1)
        async with rdb.session() as session:
            result = await _service(session, config).search_vector(
                QUERY_VECTOR, OPERATOR, space=space
            )
            # Whatever happened, the caller's transaction is still alive.
            assert (await session.execute(text("SELECT 1"))).scalar_one() == 1

        if result.diagnostics.strategy is RetrievalStrategy.ANN_PARTIAL_FALLBACK_TIMEOUT:
            assert result.diagnostics.degraded is True
            assert result.diagnostics.degradation_reason == "exact_fallback_timeout"
        else:
            # A 1 ms budget is not guaranteed to expire on a fast machine with a
            # tiny corpus. If it did not, the fallback must have succeeded
            # honestly - it may never silently return the ANN's answer while
            # claiming the exact strategy.
            assert result.diagnostics.strategy is RetrievalStrategy.EXACT_FALLBACK
            assert result.diagnostics.degraded is False


# ---------------------------------------------------------------------------
# Physical layout regression
# ---------------------------------------------------------------------------


class TestGenericPlanRegression:
    """Why the vectors are partitioned rather than partially indexed.

    Under ``plan_cache_mode = force_generic_plan`` the planner cannot see the
    value of ``:space_id``. A partial HNSW index predicated on that parameter
    becomes unusable and the scan silently degrades. Partition pruning happens
    at *runtime*, so it survives - the plan shows ``Subplans Removed`` and an
    index scan underneath.

    SQLAlchemy with asyncpg uses prepared statements, so generic plans are
    production behaviour, not a laboratory condition.
    """

    async def test_partition_pruning_and_index_use_survive_a_generic_plan(
        self, rdb: Database
    ) -> None:
        """``PREPARE`` + ``EXECUTE``, because that is what actually happens.

        An ad-hoc ``EXPLAIN`` with inline parameters is always planned with the
        literals visible, so it cannot show generic-plan behaviour no matter
        what ``plan_cache_mode`` says. The real driver prepares statements, so
        the test prepares one too.

        Two spaces are registered so that pruning has something to prune -
        with a single partition ``Subplans Removed`` would be vacuously absent
        and the assertion would prove nothing.
        """
        space = await _register_space(rdb)
        async with rdb.session() as session:
            # A second, empty partition. Its presence is the whole point: the
            # plan must be shown discarding it at run time.
            await EmbeddingSpaceService(session).register(
                SpaceRegistration(
                    space_key="decoy_768",
                    provider="deterministic",
                    model="decoy",
                    dimensions=DIMENSIONS,
                )
            )
        async with rdb.session() as session:
            source = await _seed_source(session, sensitivity=Sensitivity.PUBLIC)
            await _seed_chunks(
                session,
                space,
                source,
                [_unit(angle=0.0005 * i, seed=i) for i in range(500)],
                label="bulk",
            )

        parent = parent_relation(DIMENSIONS)
        literal = "[" + ",".join(f"{v:g}" for v in QUERY_VECTOR) + "]"
        async with rdb.session() as session:
            await session.execute(text(f'ANALYZE "{parent}"'))
            await session.execute(text("SET LOCAL plan_cache_mode = force_generic_plan"))
            # The question here is whether the index is *usable* under a generic
            # plan, not whether the planner prefers it on a 500-row table (it
            # reasonably does not - a top-N sort over 500 rows is cheap). With
            # sequential scans discouraged, an unusable index still produces a
            # Seq Scan, because PostgreSQL has nothing else to fall back on - so
            # the assertion below distinguishes the two cases sharply. This is
            # precisely what a partial HNSW index predicated on a bind parameter
            # would fail: the measurement that chose partitioning over it.
            await session.execute(text("SET LOCAL enable_seqscan = off"))
            await session.execute(
                text(
                    f"""
                    PREPARE ann_probe(vector, uuid) AS
                    SELECT e.chunk_id, e.embedding <=> $1 AS distance
                    FROM "{parent}" e
                    WHERE e.embedding_space_id = $2
                      AND e.is_current_embedding
                      AND e.is_retrievable
                    ORDER BY e.embedding <=> $1
                    LIMIT 10
                    """  # noqa: S608 - relation name is a code-level template
                )
            )
            plan_rows = await session.execute(
                text(
                    "EXPLAIN (COSTS OFF) EXECUTE ann_probe("
                    f"'{literal}'::vector, '{space.id}'::uuid)"
                )
            )
            plan = "\n".join(row[0] for row in plan_rows)

        # Generic, not custom: the parameter is still a placeholder.
        assert "$1" in plan, plan
        # Runtime pruning discarded the decoy partition.
        assert "Subplans Removed: 1" in plan, plan
        # And the surviving partition is reached through its HNSW index rather
        # than scanned - the measurement the physical layout was chosen on.
        assert "Index Scan" in plan, plan
        assert "Seq Scan" not in plan, plan

    async def test_a_search_still_returns_results_under_a_generic_plan(
        self, rdb: Database
    ) -> None:
        space = await _register_space(rdb)
        async with rdb.session() as session:
            source = await _seed_source(session, sensitivity=Sensitivity.PUBLIC)
            await _seed_chunks(
                session,
                space,
                source,
                [_unit(angle=0.01 * i, seed=i) for i in range(1, 60)],
                label="bulk",
            )

        async with rdb.session() as session:
            await session.execute(text("SET LOCAL plan_cache_mode = force_generic_plan"))
            result = await _service(session).search_vector(
                QUERY_VECTOR, OPERATOR, space=space, k=5
            )
        assert len(result.results) == 5
        assert result.diagnostics.strategy is RetrievalStrategy.ANN


# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------


class TestGuards:
    async def test_querying_an_unverified_space_is_refused(self, rdb: Database) -> None:
        async with rdb.session() as session:
            service = EmbeddingSpaceService(session)
            space = await service.register(
                SpaceRegistration(
                    space_key="unverified_768",
                    provider="deterministic",
                    model="deterministic-test",
                    dimensions=DIMENSIONS,
                    make_default=True,
                )
            )
            space_id = space.id
        async with rdb.session() as session:
            space = await EmbeddingSpaceService(session).get(space_id)
            with pytest.raises(ConflictError):
                await _service(session).search("anything", OPERATOR, space=space)

    async def test_wrong_dimension_query_is_fatal(self, rdb: Database) -> None:
        space = await _register_space(rdb)
        async with rdb.session() as session:
            service = KnowledgeRetrievalService(
                session, embedder=DeterministicEmbeddingProvider(384)
            )
            with pytest.raises(EmbeddingDimensionError):
                await service.search("anything", OPERATOR, space=space)

    async def test_empty_query_is_rejected(self, rdb: Database) -> None:
        space = await _register_space(rdb)
        async with rdb.session() as session:
            with pytest.raises(ValidationError):
                await _service(session).search("   ", OPERATOR, space=space)

    async def test_k_is_bounded(self) -> None:
        with pytest.raises(ValidationError):
            RetrievalConfig(k=0)
        with pytest.raises(ValidationError):
            RetrievalConfig(k=1000)


class TestSensitivityResync:
    async def test_reclassifying_a_source_repairs_the_denormalised_column(
        self, rdb: Database
    ) -> None:
        """A downgrade must make content visible, not merely stop hiding it.

        Retrieval requires the source's sensitivity *and* the vector row's copy
        to agree, which fails closed. Fail-closed is right, but a stale copy
        would then hide material the caller is entitled to read, so the resync
        is part of reclassification rather than a maintenance job.
        """
        space = await _register_space(rdb)
        async with rdb.session() as session:
            source = await _seed_source(session, sensitivity=Sensitivity.CONFIDENTIAL)
            await _seed_chunks(
                session, space, source, [_unit(angle=0.1, seed=1)], label="reclass"
            )
            source_id = source.id

        async with rdb.session() as session:
            result = await _service(session).search_vector(
                QUERY_VECTOR, OPERATOR, space=space, k=5
            )
            assert result.results == ()

        async with rdb.session() as session:
            source = await session.get(KnowledgeSource, source_id)
            assert source is not None
            source.sensitivity = Sensitivity.PUBLIC.value
            updated = await EmbeddingSpaceService(session).resync_source_sensitivity(
                source_id
            )
            assert updated == 1

        async with rdb.session() as session:
            result = await _service(session).search_vector(
                QUERY_VECTOR, OPERATOR, space=space, k=5
            )
            assert len(result.results) == 1
            assert result.results[0].sensitivity is Sensitivity.PUBLIC
