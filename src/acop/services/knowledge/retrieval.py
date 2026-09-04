"""Dense retrieval: approximate search with an exhaustive correctness floor.

**The problem this module exists to solve.** An HNSW index is an approximation.
It returns the *k* nearest vectors it can find quickly, with no awareness of who
is asking. Authorization, sensitivity and lifecycle are then applied to that
candidate list. When the candidates happen to be ineligible for this principal,
the naive result is an empty answer that looks exactly like "there is nothing
relevant" - and the caller cannot tell the two apart.

R3 §1 made the consequence concrete: five thousand CONFIDENTIAL chunks clustered
near a query, one PUBLIC chunk further away, and an operator asking. Any fixed
over-fetch multiplier returns nothing. Over-fetch is a *performance* tactic; it
is not a correctness guarantee, and no multiplier makes it one.

So retrieval here has three stages and a rule for moving between them:

1. **ANN.** The HNSW index proposes candidates. Fast, approximate, blind to
   authorization by design - baking policy into an index predicate would weld
   storage to today's role map.
2. **Eligibility, in SQL.** Every candidate is filtered against sensitivity,
   trust, lifecycle and the caller's explicit filters *before* any content
   crosses back into Python. Content that a principal may not read is never
   materialised in application memory, let alone in a model prompt.
3. **Exact fallback, only when it changes the answer.** If stage 2 yielded
   fewer than *k* results, that has exactly two possible causes and they demand
   opposite responses:

   * **(A) the ANN missed eligible rows** - there are more than the ANN found,
     so an exhaustive ranking over the eligible set returns a better answer;
   * **(B) fewer than *k* eligible rows exist at all** - the answer is already
     complete and an exhaustive scan would find precisely the same rows.

   Distinguishing them is a bounded ``COUNT`` over the eligible population, and
   it is the difference between a correct fallback and one that scans the whole
   corpus every time a narrow filter is used.

**Why ``MATERIALIZED`` and not ``enable_indexscan = off``.** The exact stage
must not use the HNSW index - that is the whole point of it. The obvious lever,
``SET LOCAL enable_indexscan = off``, changes plan selection for *every*
statement in the transaction, and in ACOP a retrieval call shares its
transaction with CMDB reads and audit writes. Silently de-optimising those to
fix this one query is not an acceptable trade. ``WITH eligible AS MATERIALIZED``
is a barrier scoped to a single CTE: the eligible set is computed first, and the
ranking that follows has no index to reach for.

**Degradation is reported, never hidden.** If the eligible population exceeds
``exact_max_rows``, or the exact scan exceeds its time budget, or the fallback
is disabled by configuration, the call returns a *structured degraded result*.
It never returns approximate results while claiming they are complete.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from typing import Any, Final

from pgvector.sqlalchemy import Vector
from sqlalchemy import String, bindparam, text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import UUID as PostgresUuid  # noqa: N811
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from acop.auth.principal import Principal
from acop.core.exceptions import ConflictError, ValidationError
from acop.core.logging import get_logger
from acop.models.embedding import EmbeddingSpace
from acop.models.knowledge_vocabulary import (
    DEFAULT_ROLE_SENSITIVITY,
    DEFAULT_RRF_K,
    DISTANCE_OPERATOR,
    LEXEME_CONFIG,
    NEVER_RETRIEVED_TRUST,
    DistanceMetric,
    KnowledgeLifecycle,
    RetrievalMethod,
    RetrievalMode,
    RetrievalStrategy,
    Sensitivity,
    TrustClass,
    parent_relation,
)
from acop.services.knowledge.embedding_provider import (
    EmbeddingDimensionError,
    EmbeddingProvider,
)

logger = get_logger(__name__)

#: Hard ceiling on ``k``. Not a tuning parameter - a guard against one request
#: pulling an unbounded amount of text into a model context.
MAX_K: Final[int] = 100

#: Whether a PostgreSQL setting exists, per process. The database does not grow
#: new GUCs at runtime, so this is safe to remember and saves a round trip on
#: every retrieval call.
_GUC_SUPPORT: dict[str, bool] = {}


@dataclass(frozen=True, slots=True)
class RetrievalPolicy:
    """What one principal is permitted to retrieve.

    Resolved from roles at call time and then immutable, so an authorization
    decision cannot drift between the count query and the ranking query.

    ``approver`` is deliberately not a clearance: it reads exactly what an
    operator reads. Approval authority and data classification are different
    axes, and conflating them is how "approver" quietly becomes a second admin.
    """

    allowed_sensitivities: frozenset[Sensitivity]
    excluded_trust: frozenset[TrustClass]

    @property
    def sensitivity_values(self) -> list[str]:
        return sorted(s.value for s in self.allowed_sensitivities)

    @property
    def excluded_trust_values(self) -> list[str]:
        return sorted(t.value for t in self.excluded_trust)


def policy_for(principal: Principal) -> RetrievalPolicy:
    """Resolve a principal's readable bands.

    The union across roles, which is the only defensible reading of "holds both
    operator and admin". ``QUARANTINED`` is excluded for everyone, including
    admin: it is not a classification, it is a statement that the material is
    not fit to be retrieved at all.
    """
    allowed: set[Sensitivity] = set()
    for role in principal.roles:
        allowed |= DEFAULT_ROLE_SENSITIVITY.get(role, frozenset())
    return RetrievalPolicy(
        allowed_sensitivities=frozenset(allowed),
        excluded_trust=frozenset(NEVER_RETRIEVED_TRUST),
    )


@dataclass(frozen=True, slots=True)
class RetrievalFilters:
    """Caller-supplied narrowing. Applied in SQL, never in Python.

    Every one of these is an *additional* restriction. None of them can widen
    what :class:`RetrievalPolicy` permits - the policy predicate is emitted
    unconditionally and these are ANDed onto it.
    """

    source_ids: tuple[uuid.UUID, ...] = ()
    document_ids: tuple[uuid.UUID, ...] = ()
    source_kinds: tuple[str, ...] = ()
    trust_classes: tuple[str, ...] = ()

    def as_params(self) -> dict[str, Any]:
        return {
            "source_ids": list(self.source_ids) or None,
            "document_ids": list(self.document_ids) or None,
            "source_kinds": list(self.source_kinds) or None,
            "trust_classes": list(self.trust_classes) or None,
        }


@dataclass(frozen=True, slots=True)
class RetrievalConfig:
    """Tuning. Every default here is a documented decision, not a guess."""

    k: int = 10
    ann_overfetch: int = 8
    """Candidates requested from the ANN per requested result. Purely a
    performance heuristic - correctness comes from the fallback, not from this
    number, which is exactly why it is allowed to be modest."""

    ann_candidate_cap: int = 2000
    """Absolute ceiling on ANN candidates, so a large ``k`` cannot turn one
    request into a scan of the index."""

    hnsw_ef_search: int = 100
    """HNSW search breadth. Scoped with ``SET LOCAL`` around the ANN statement
    only, and restored afterwards."""

    hnsw_iterative_scan: str | None = None
    """pgvector 0.8+ only (``off``/``relaxed_order``/``strict_order``). Applied
    when the running server actually has the setting, ignored when it does not,
    so the same code runs against 0.6 in development and 0.8.6 in production."""

    exact_fallback_enabled: bool = True
    """Disabling this is the negative control in the test suite, and an
    operational escape hatch. It never degrades silently: the diagnostics say
    the fallback was skipped and the result is marked degraded."""

    exact_max_rows: int = 50_000
    """Upper bound on the eligible population the exact stage will rank. Beyond
    it the call returns a structured degraded result rather than pretending an
    unbounded scan is acceptable."""

    exact_timeout_ms: int = 5_000
    """Time budget for the exact stage, enforced inside a SAVEPOINT so that a
    timeout aborts only the fallback, never the caller's transaction."""

    lexical_limit: int = 100
    """How deep the lexical leg goes. It is a full-text index scan with no
    approximation, so this is a cost bound rather than a correctness one."""

    rrf_k: int = DEFAULT_RRF_K

    def __post_init__(self) -> None:
        if not 1 <= self.k <= MAX_K:
            raise ValidationError(f"k must be between 1 and {MAX_K}.")
        if self.ann_overfetch < 1:
            raise ValidationError("ann_overfetch must be at least 1.")
        if self.exact_max_rows < 1:
            raise ValidationError("exact_max_rows must be at least 1.")
        if self.lexical_limit < 1:
            raise ValidationError("lexical_limit must be at least 1.")
        if self.rrf_k < 1:
            raise ValidationError("rrf_k must be at least 1.")

    @property
    def candidate_limit(self) -> int:
        return min(self.k * self.ann_overfetch, self.ann_candidate_cap)


@dataclass(frozen=True, slots=True)
class RetrievedChunk:
    """One passage, with the provenance a citation needs.

    ``method`` distinguishes an ANN hit from an exhaustively ranked one, so a
    reader auditing an answer can see whether the passage was found
    approximately or definitively.
    """

    chunk_id: uuid.UUID
    document_id: uuid.UUID
    source_id: uuid.UUID
    version_id: uuid.UUID
    ordinal: int
    content: str
    heading_path: tuple[str, ...]
    section_label: str | None
    flags: tuple[str, ...]
    token_estimate: int
    distance: float | None
    score: float
    rank: int
    method: RetrievalMethod
    sensitivity: Sensitivity
    trust_class: TrustClass
    source_kind: str
    source_title: str
    document_title: str
    external_ref: str
    embedding_space_id: uuid.UUID
    # Fusion provenance. Populated only on a hybrid call, and kept as the
    # per-leg ranks rather than a single blended number so that "why is this
    # third?" has an answer an auditor can recompute by hand.
    vector_rank: int | None = None
    lexical_rank: int | None = None
    lexical_score: float | None = None
    fused_score: float | None = None


@dataclass(frozen=True, slots=True)
class RetrievalDiagnostics:
    """Why the answer looks the way it does.

    This is not debug output. A retrieval that returned three results when ten
    were asked for is either complete or degraded, and an agent reasoning over
    the result - or a human auditing it later - has to be able to tell which.
    """

    strategy: RetrievalStrategy
    embedding_space_id: uuid.UUID
    requested_k: int
    ann_candidate_limit: int
    ann_candidates_returned: int
    ann_eligible_count: int
    eligible_population: int | None
    eligible_population_capped: bool
    exact_rows_ranked: int | None
    returned_count: int
    degraded: bool
    degradation_reason: str | None
    ann_latency_ms: float
    count_latency_ms: float | None
    exact_latency_ms: float | None
    total_latency_ms: float
    mode: RetrievalMode = RetrievalMode.VECTOR
    lexical_candidates: int | None = None
    lexical_latency_ms: float | None = None
    fused_candidates: int | None = None
    rrf_k: int | None = None

    def as_audit_fields(self) -> dict[str, Any]:
        """The subset safe to persist. Deliberately contains no query text."""
        return {
            "mode": self.mode.value,
            "strategy": self.strategy.value,
            "lexical_candidates": self.lexical_candidates,
            "fused_candidates": self.fused_candidates,
            "embedding_space_id": str(self.embedding_space_id),
            "requested_k": self.requested_k,
            "ann_candidates_returned": self.ann_candidates_returned,
            "ann_eligible_count": self.ann_eligible_count,
            "eligible_population": self.eligible_population,
            "eligible_population_capped": self.eligible_population_capped,
            "returned_count": self.returned_count,
            "degraded": self.degraded,
            "degradation_reason": self.degradation_reason,
            "total_latency_ms": round(self.total_latency_ms, 2),
        }


@dataclass(frozen=True, slots=True)
class RetrievalResult:
    results: tuple[RetrievedChunk, ...]
    diagnostics: RetrievalDiagnostics
    policy: RetrievalPolicy = field(
        compare=False,
        repr=False,
        default_factory=lambda: RetrievalPolicy(frozenset(), frozenset()),
    )


# ---------------------------------------------------------------------------
# SQL
# ---------------------------------------------------------------------------

#: Applied to every stage without exception. Written once, as a constant, so
#: that the ANN stage, the population count and the exact stage cannot drift
#: apart - a divergence between them would be an authorization bypass that no
#: single test would obviously catch.
#:
#: ``s.sensitivity`` is authoritative; ``e.sensitivity`` is the denormalised
#: copy that makes the per-partition eligible index usable. Both are required,
#: which fails closed: if they ever disagree, the row is excluded rather than
#: returned on the strength of the weaker one.
_ELIGIBILITY: Final[str] = """
      s.sensitivity = ANY(:sensitivities)
  AND s.trust_class <> ALL(:excluded_trust)
  AND s.lifecycle_state = :active_state
  AND d.lifecycle_state = :active_state
  AND d.current_version_id = c.version_id
  AND (:source_ids IS NULL OR c.source_id = ANY(:source_ids))
  AND (:document_ids IS NULL OR c.document_id = ANY(:document_ids))
  AND (:source_kinds IS NULL OR s.source_kind = ANY(:source_kinds))
  AND (:trust_classes IS NULL OR s.trust_class = ANY(:trust_classes))
"""

#: Space and lifecycle only - exactly the columns in the partition's HNSW index
#: predicate, and therefore the only vector-side predicate the ANN candidate CTE
#: may carry.
#:
#: Sensitivity is **deliberately absent here**. Putting it in the candidate CTE
#: was measured to defeat the entire fallback design: the index scan becomes
#: authorization-aware, the ANN stage silently does the eligibility filtering
#: itself, and the adversarial case - thousands of ineligible neighbours hiding
#: one eligible row - stops being reachable, so the correctness floor is never
#: exercised. Worse, it would be exercised *sometimes*, depending on how far
#: pgvector's scan happened to walk before its candidate list ran out, which is
#: a non-deterministic authorization-shaped filter. The ANN must stay blind.
_VECTOR_LIFECYCLE: Final[str] = """
      e.embedding_space_id = :space_id
  AND e.is_current_embedding
  AND e.is_retrievable
"""

#: The denormalised sensitivity copy, used only where an exhaustive scan is
#: already happening. It never narrows the ANN; it makes the per-partition
#: eligible index usable for the population count and the exact ranking, and it
#: fails closed against ``s.sensitivity`` if the two ever disagree.
_VECTOR_SENSITIVITY: Final[str] = """
      e.sensitivity = ANY(:sensitivities)
"""

_PROJECTION: Final[str] = """
    c.id            AS chunk_id,
    c.document_id   AS document_id,
    c.source_id     AS source_id,
    c.version_id    AS version_id,
    c.ordinal       AS ordinal,
    c.content       AS content,
    c.heading_path  AS heading_path,
    c.section_label AS section_label,
    c.flags         AS flags,
    c.token_estimate AS token_estimate,
    s.sensitivity   AS sensitivity,
    s.trust_class   AS trust_class,
    s.source_kind   AS source_kind,
    s.title         AS source_title,
    d.title         AS document_title,
    d.external_ref  AS external_ref
"""


#: The lexical leg.
#:
#: ``websearch_to_tsquery`` rather than ``to_tsquery`` because the input is a
#: human's search box, not a query language: it accepts quoted phrases, ``or``
#: and ``-term`` and, crucially, never raises a syntax error on ordinary prose.
#: ``to_tsquery('english', 'vlan 100')`` is a 500 for the caller; the same text
#: through ``websearch_to_tsquery`` is a working query.
#:
#: ``ts_rank_cd`` rather than ``ts_rank`` because cover density accounts for how
#: close the matched terms are to each other, which is what makes it prefer a
#: passage discussing VLAN 100 over one mentioning both words paragraphs apart.
#:
#: The join to the vector partition is not decoration. It is what makes the two
#: legs agree on what "retrievable" means: lifecycle lives on the embedding row,
#: so a lexical leg that skipped this join would happily return passages the
#: dense leg had already excluded as superseded.
_LEXICAL_SQL: Final[str] = """
    WITH matched AS (
        SELECT c.id AS chunk_id,
               ts_rank_cd(c.lexeme, websearch_to_tsquery(:ts_config, :query_text))
                   AS lexical_score
        FROM knowledge_chunk c
        JOIN knowledge_document d ON d.id = c.document_id
        JOIN knowledge_source s   ON s.id = c.source_id
        JOIN "{parent}" e         ON e.chunk_id = c.id
        WHERE c.lexeme @@ websearch_to_tsquery(:ts_config, :query_text)
          AND {vector_lifecycle} AND {vector_sensitivity} AND {eligibility}
        ORDER BY lexical_score DESC, c.id
        LIMIT :lexical_limit
    )
    SELECT {projection}, m.lexical_score AS lexical_score
    FROM matched m
    JOIN knowledge_chunk c    ON c.id = m.chunk_id
    JOIN knowledge_document d ON d.id = c.document_id
    JOIN knowledge_source s   ON s.id = c.source_id
    ORDER BY m.lexical_score DESC, c.id
"""


def _bindparams(dimensions: int, *, with_vector: bool = True) -> list[Any]:
    """Explicitly typed binds.

    Typing them is not decoration. An untyped array parameter is sent as text
    and compared against a ``uuid[]`` column with no cast, and an untyped vector
    parameter cannot be encoded at all - both fail at the driver, not in a test.

    ``with_vector`` exists because the population count deliberately does not
    mention the query vector: it asks how many rows are *eligible*, which is a
    question about policy, not about distance. SQLAlchemy rejects a bindparam a
    statement never uses, so the difference has to be explicit.
    """
    binds: list[Any] = [
        bindparam("sensitivities", type_=ARRAY(String)),
        bindparam("excluded_trust", type_=ARRAY(String)),
        bindparam("source_ids", type_=ARRAY(PostgresUuid(as_uuid=True))),
        bindparam("document_ids", type_=ARRAY(PostgresUuid(as_uuid=True))),
        bindparam("source_kinds", type_=ARRAY(String)),
        bindparam("trust_classes", type_=ARRAY(String)),
    ]
    if with_vector:
        binds.append(bindparam("qvec", type_=Vector(dimensions)))
    return binds


class KnowledgeRetrievalService:
    """Dense, lexical and hybrid retrieval over one embedding space."""

    def __init__(
        self,
        session: AsyncSession,
        *,
        embedder: EmbeddingProvider,
        config: RetrievalConfig | None = None,
    ) -> None:
        self._session = session
        self._embedder = embedder
        self._config = config or RetrievalConfig()

    @property
    def config(self) -> RetrievalConfig:
        return self._config

    # -- public ---------------------------------------------------------

    async def retrieve(
        self,
        query: str,
        principal: Principal,
        *,
        space: EmbeddingSpace,
        mode: RetrievalMode = RetrievalMode.HYBRID,
        filters: RetrievalFilters | None = None,
        k: int | None = None,
    ) -> RetrievalResult:
        """The general entry point: dense, lexical, or both fused.

        Hybrid is the default because the two legs fail in different
        directions. Dense retrieval finds a passage that says the same thing in
        different words and misses an exact identifier it never learned;
        lexical retrieval finds ``Gi1/0/24`` and ``%SPANTREE-2-BLOCK_BPDUGUARD``
        exactly and misses every paraphrase. Network and security documentation
        is full of both, so running one leg alone means choosing which half of
        the corpus to be bad at.
        """
        if not query.strip():
            raise ValidationError("A retrieval query must contain text.")
        if mode is RetrievalMode.VECTOR:
            return await self.search(query, principal, space=space, filters=filters, k=k)
        if mode is RetrievalMode.LEXICAL:
            return await self.search_lexical(
                query, principal, space=space, filters=filters, k=k
            )
        return await self.search_hybrid(
            query, principal, space=space, filters=filters, k=k
        )

    async def search(
        self,
        query: str,
        principal: Principal,
        *,
        space: EmbeddingSpace,
        filters: RetrievalFilters | None = None,
        k: int | None = None,
    ) -> RetrievalResult:
        """Retrieve the passages this principal may read, nearest first.

        Raises:
            ValidationError: The query is empty or ``k`` is out of range.
            ConflictError: The space's prefix behaviour has not been verified.
            EmbeddingDimensionError: The provider returned the wrong dimension.
        """
        if not query.strip():
            raise ValidationError("A retrieval query must contain text.")
        vector = await self.embed_query(query, space=space)
        return await self.search_vector(
            vector, principal, space=space, filters=filters, k=k
        )

    async def embed_query(self, query: str, *, space: EmbeddingSpace) -> list[float]:
        """Embed a query into ``space``, refusing an unverified space.

        The gate is here as well as in ingestion because the two failures are
        different. Ingesting with a wrong prefix poisons the corpus; *querying*
        with a wrong prefix leaves the corpus intact and simply returns
        confident nonsense, which is harder to notice.
        """
        if not space.prefix_verified_at:
            raise ConflictError(
                "Embedding space prefixes are unverified. Run "
                "scripts/probe_embedding_prefixes.py against the provider and "
                "record the result before querying.",
                context={"space_key": space.space_key},
            )
        vector = await self._embedder.embed_query(query, prefix=space.query_prefix)
        if len(vector) != space.dimensions:
            raise EmbeddingDimensionError(
                f"Query embedding has {len(vector)} dimensions; space "
                f"{space.space_key!r} is {space.dimensions}."
            )
        return vector

    async def search_vector(
        self,
        vector: list[float],
        principal: Principal,
        *,
        space: EmbeddingSpace,
        filters: RetrievalFilters | None = None,
        k: int | None = None,
    ) -> RetrievalResult:
        """The three-stage path, on an already-embedded query."""
        started = time.perf_counter()
        config = self._config if k is None else _with_k(self._config, k)
        policy = policy_for(principal)
        params = self._params(vector, space, policy, filters or RetrievalFilters())

        if not policy.allowed_sensitivities:
            # A principal with no readable band is not an error and not an
            # empty corpus - it is a complete answer that happens to be empty.
            return RetrievalResult(
                results=(),
                diagnostics=_empty_diagnostics(space, config, started),
                policy=policy,
            )

        ann_started = time.perf_counter()
        ann_rows = await self._ann_stage(space, config, params)
        ann_latency = _ms(ann_started)

        if len(ann_rows) >= config.k:
            return self._finish(
                ann_rows[: config.k],
                space=space,
                config=config,
                policy=policy,
                strategy=RetrievalStrategy.ANN,
                method=RetrievalMethod.VECTOR,
                ann_returned=len(ann_rows),
                ann_eligible=len(ann_rows),
                eligible_population=None,
                capped=False,
                exact_ranked=None,
                degraded=False,
                reason=None,
                ann_latency=ann_latency,
                count_latency=None,
                exact_latency=None,
                started=started,
            )

        # Fewer than k. Which of the two causes is it?
        count_started = time.perf_counter()
        population, capped = await self._eligible_population(space, config, params)
        count_latency = _ms(count_started)

        if population <= len(ann_rows):
            # (B) The eligible population is exhausted. The ANN found every row
            # there is, so an exact scan would return exactly these rows. This
            # is a *complete* answer that is merely short, and saying so is the
            # difference between "nothing else exists" and "we did not look".
            return self._finish(
                ann_rows,
                space=space,
                config=config,
                policy=policy,
                strategy=RetrievalStrategy.ANN_COMPLETE,
                method=RetrievalMethod.VECTOR,
                ann_returned=len(ann_rows),
                ann_eligible=len(ann_rows),
                eligible_population=population,
                capped=capped,
                exact_ranked=None,
                degraded=False,
                reason=None,
                ann_latency=ann_latency,
                count_latency=count_latency,
                exact_latency=None,
                started=started,
            )

        # (A) Eligible rows exist that the ANN did not surface.
        if not config.exact_fallback_enabled:
            return self._degraded(
                ann_rows,
                space=space,
                config=config,
                policy=policy,
                reason="exact_fallback_disabled",
                population=population,
                capped=capped,
                ann_latency=ann_latency,
                count_latency=count_latency,
                started=started,
            )
        if capped:
            return self._degraded(
                ann_rows,
                space=space,
                config=config,
                policy=policy,
                reason="eligible_population_exceeds_exact_max_rows",
                population=population,
                capped=capped,
                ann_latency=ann_latency,
                count_latency=count_latency,
                started=started,
            )

        exact_started = time.perf_counter()
        try:
            exact_rows = await self._exact_stage(space, config, params)
        except _ExactTimeoutError:
            return self._degraded(
                ann_rows,
                space=space,
                config=config,
                policy=policy,
                reason="exact_fallback_timeout",
                population=population,
                capped=capped,
                ann_latency=ann_latency,
                count_latency=count_latency,
                started=started,
                strategy=RetrievalStrategy.ANN_PARTIAL_FALLBACK_TIMEOUT,
                exact_latency=_ms(exact_started),
            )
        exact_latency = _ms(exact_started)

        return self._finish(
            exact_rows,
            space=space,
            config=config,
            policy=policy,
            strategy=RetrievalStrategy.EXACT_FALLBACK,
            method=RetrievalMethod.VECTOR_EXACT,
            ann_returned=len(ann_rows),
            ann_eligible=len(ann_rows),
            eligible_population=population,
            capped=capped,
            exact_ranked=population,
            degraded=False,
            reason=None,
            ann_latency=ann_latency,
            count_latency=count_latency,
            exact_latency=exact_latency,
            started=started,
        )

    async def search_lexical(
        self,
        query: str,
        principal: Principal,
        *,
        space: EmbeddingSpace,
        filters: RetrievalFilters | None = None,
        k: int | None = None,
    ) -> RetrievalResult:
        """Full-text retrieval over the same eligible population.

        No approximation and therefore no fallback: a GIN index scan either
        matches a row or it does not, so ``strategy`` is ``NOT_RUN`` - the
        dense leg's degradation vocabulary simply does not apply here, and
        borrowing it would be a lie about what happened.
        """
        if not query.strip():
            raise ValidationError("A retrieval query must contain text.")
        started = time.perf_counter()
        config = self._config if k is None else _with_k(self._config, k)
        policy = policy_for(principal)
        if not policy.allowed_sensitivities:
            return RetrievalResult(
                results=(),
                diagnostics=_empty_diagnostics(
                    space, config, started, mode=RetrievalMode.LEXICAL
                ),
                policy=policy,
            )
        params = self._params(None, space, policy, filters or RetrievalFilters())

        lexical_started = time.perf_counter()
        rows = await self._lexical_stage(space, config, params, query)
        lexical_latency = _ms(lexical_started)

        results = tuple(
            _to_chunk(
                row,
                index + 1,
                RetrievalMethod.LEXICAL,
                space.id,
                score=float(row["lexical_score"]),
                lexical_score=float(row["lexical_score"]),
                lexical_rank=index + 1,
            )
            for index, row in enumerate(rows[: config.k])
        )
        diagnostics = RetrievalDiagnostics(
            strategy=RetrievalStrategy.NOT_RUN,
            mode=RetrievalMode.LEXICAL,
            embedding_space_id=space.id,
            requested_k=config.k,
            ann_candidate_limit=0,
            ann_candidates_returned=0,
            ann_eligible_count=0,
            eligible_population=None,
            eligible_population_capped=False,
            exact_rows_ranked=None,
            returned_count=len(results),
            degraded=False,
            degradation_reason=None,
            ann_latency_ms=0.0,
            count_latency_ms=None,
            exact_latency_ms=None,
            lexical_candidates=len(rows),
            lexical_latency_ms=lexical_latency,
            total_latency_ms=_ms(started),
        )
        logger.info("knowledge.retrieval.completed", **diagnostics.as_audit_fields())
        return RetrievalResult(results=results, diagnostics=diagnostics, policy=policy)

    async def search_hybrid(
        self,
        query: str,
        principal: Principal,
        *,
        space: EmbeddingSpace,
        filters: RetrievalFilters | None = None,
        k: int | None = None,
    ) -> RetrievalResult:
        """Both legs, fused by Reciprocal Rank Fusion.

        The dense leg runs in full, fallback and all, so hybrid inherits the
        correctness floor rather than papering over its absence with lexical
        hits. If the dense leg degraded, the fused result says so: a hybrid
        answer built on an incomplete dense leg is still incomplete, and
        lexical matches arriving alongside it do not repair that.

        Fusion happens in Python, which is safe precisely because both inputs
        were already filtered in SQL - nothing enters this step that the caller
        was not entitled to see, so combining them cannot widen access.
        """
        if not query.strip():
            raise ValidationError("A retrieval query must contain text.")
        started = time.perf_counter()
        config = self._config if k is None else _with_k(self._config, k)
        policy = policy_for(principal)
        if not policy.allowed_sensitivities:
            return RetrievalResult(
                results=(),
                diagnostics=_empty_diagnostics(
                    space, config, started, mode=RetrievalMode.HYBRID
                ),
                policy=policy,
            )

        # Both legs are asked for k results; fusion then re-orders the union,
        # so the pool is up to 2k deep before it is trimmed back to k.
        dense = await self.search(query, principal, space=space, filters=filters, k=k)
        lexical_started = time.perf_counter()
        params = self._params(None, space, policy, filters or RetrievalFilters())
        lexical_rows = await self._lexical_stage(space, config, params, query)
        lexical_latency = _ms(lexical_started)

        fused = _fuse(
            dense.results,
            [
                _to_chunk(
                    row,
                    index + 1,
                    RetrievalMethod.LEXICAL,
                    space.id,
                    score=float(row["lexical_score"]),
                    lexical_score=float(row["lexical_score"]),
                    lexical_rank=index + 1,
                )
                for index, row in enumerate(lexical_rows[: config.k])
            ],
            rrf_k=config.rrf_k,
        )
        results = tuple(fused[: config.k])

        source = dense.diagnostics
        diagnostics = RetrievalDiagnostics(
            strategy=source.strategy,
            mode=RetrievalMode.HYBRID,
            embedding_space_id=space.id,
            requested_k=config.k,
            ann_candidate_limit=source.ann_candidate_limit,
            ann_candidates_returned=source.ann_candidates_returned,
            ann_eligible_count=source.ann_eligible_count,
            eligible_population=source.eligible_population,
            eligible_population_capped=source.eligible_population_capped,
            exact_rows_ranked=source.exact_rows_ranked,
            returned_count=len(results),
            # Inherited, not recomputed: the dense leg's incompleteness is the
            # whole call's incompleteness.
            degraded=source.degraded,
            degradation_reason=source.degradation_reason,
            ann_latency_ms=source.ann_latency_ms,
            count_latency_ms=source.count_latency_ms,
            exact_latency_ms=source.exact_latency_ms,
            lexical_candidates=len(lexical_rows),
            lexical_latency_ms=lexical_latency,
            fused_candidates=len(fused),
            rrf_k=config.rrf_k,
            total_latency_ms=_ms(started),
        )
        logger.info("knowledge.retrieval.completed", **diagnostics.as_audit_fields())
        return RetrievalResult(results=results, diagnostics=diagnostics, policy=policy)

    # -- stages ---------------------------------------------------------

    async def _lexical_stage(
        self,
        space: EmbeddingSpace,
        config: RetrievalConfig,
        params: dict[str, Any],
        query: str,
    ) -> list[Any]:
        parent = parent_relation(space.dimensions)
        statement = text(
            _LEXICAL_SQL.format(
                parent=parent,
                vector_lifecycle=_VECTOR_LIFECYCLE,
                vector_sensitivity=_VECTOR_SENSITIVITY,
                eligibility=_ELIGIBILITY,
                projection=_PROJECTION,
            )
        ).bindparams(*_bindparams(space.dimensions, with_vector=False))
        payload = {key: value for key, value in params.items() if key != "qvec"}
        rows = await self._session.execute(
            statement,
            {
                **payload,
                "ts_config": LEXEME_CONFIG,
                "query_text": query,
                "lexical_limit": config.lexical_limit,
            },
        )
        return list(rows.mappings())

    async def _ann_stage(
        self,
        space: EmbeddingSpace,
        config: RetrievalConfig,
        params: dict[str, Any],
    ) -> list[Any]:
        """Stage 1 and 2: index proposes, SQL disposes.

        The candidate CTE carries only lifecycle predicates, which are exactly
        the ones in the partition's HNSW index predicate, so the index is
        usable. Everything policy-shaped is applied in the outer query, where
        it filters candidates rather than constraining the index.
        """
        parent = parent_relation(space.dimensions)
        operator = DISTANCE_OPERATOR[DistanceMetric(space.distance_metric)]
        statement = text(
            f"""
            WITH candidates AS (
                SELECT e.chunk_id AS chunk_id,
                       e.embedding {operator} :qvec AS distance
                FROM "{parent}" e
                WHERE {_VECTOR_LIFECYCLE}
                ORDER BY e.embedding {operator} :qvec
                LIMIT :candidate_limit
            )
            SELECT {_PROJECTION}, cand.distance AS distance
            FROM candidates cand
            JOIN knowledge_chunk c    ON c.id = cand.chunk_id
            JOIN knowledge_document d ON d.id = c.document_id
            JOIN knowledge_source s   ON s.id = c.source_id
            WHERE {_ELIGIBILITY}
            ORDER BY cand.distance, c.id
            LIMIT :k
            """  # noqa: S608 - see _bindparams docstring
        ).bindparams(*_bindparams(space.dimensions))

        settings: dict[str, int | str] = {"hnsw.ef_search": config.hnsw_ef_search}
        if config.hnsw_iterative_scan is not None and await self._guc_exists(
            "hnsw.iterative_scan"
        ):
            settings["hnsw.iterative_scan"] = config.hnsw_iterative_scan

        async with self._local_settings(settings):
            rows = await self._session.execute(
                statement,
                {**params, "candidate_limit": config.candidate_limit, "k": config.k},
            )
            return list(rows.mappings())

    async def _eligible_population(
        self,
        space: EmbeddingSpace,
        config: RetrievalConfig,
        params: dict[str, Any],
    ) -> tuple[int, bool]:
        """How many rows are eligible, bounded.

        Bounded on purpose. An unbounded ``COUNT`` over a large corpus costs as
        much as the scan it is meant to decide against, which would make the
        cheap case pay the expensive case's price. The ``LIMIT`` is one above
        the ceiling so the caller can distinguish "exactly at the ceiling" from
        "beyond it".
        """
        parent = parent_relation(space.dimensions)
        statement = text(
            f"""
            SELECT count(*) FROM (
                SELECT 1
                FROM "{parent}" e
                JOIN knowledge_chunk c    ON c.id = e.chunk_id
                JOIN knowledge_document d ON d.id = c.document_id
                JOIN knowledge_source s   ON s.id = c.source_id
                WHERE {_VECTOR_LIFECYCLE} AND {_VECTOR_SENSITIVITY} AND {_ELIGIBILITY}
                LIMIT :count_cap
            ) probe
            """  # noqa: S608 - see _bindparams docstring
        ).bindparams(*_bindparams(space.dimensions, with_vector=False))
        cap = config.exact_max_rows + 1
        payload = {key: value for key, value in params.items() if key != "qvec"}
        result = await self._session.execute(statement, {**payload, "count_cap": cap})
        population = int(result.scalar_one())
        return population, population > config.exact_max_rows

    async def _exact_stage(
        self,
        space: EmbeddingSpace,
        config: RetrievalConfig,
        params: dict[str, Any],
    ) -> list[Any]:
        """Stage 3: exhaustive ranking over the eligible set.

        ``MATERIALIZED`` is the load-bearing word. Without it PostgreSQL is free
        to inline the CTE, notice the ``<=>`` ordering and reach straight back
        for the HNSW index - reproducing the approximation this stage exists to
        escape, with no error and no visible difference except wrong results.

        The whole thing runs inside a SAVEPOINT carrying its own
        ``statement_timeout``. A timeout therefore aborts the savepoint and
        nothing else: the caller's transaction, its CMDB reads and its audit
        writes are untouched, and the call degrades instead of failing.
        """
        parent = parent_relation(space.dimensions)
        operator = DISTANCE_OPERATOR[DistanceMetric(space.distance_metric)]
        statement = text(
            f"""
            WITH eligible AS MATERIALIZED (
                SELECT e.chunk_id AS chunk_id, e.embedding AS embedding
                FROM "{parent}" e
                JOIN knowledge_chunk c    ON c.id = e.chunk_id
                JOIN knowledge_document d ON d.id = c.document_id
                JOIN knowledge_source s   ON s.id = c.source_id
                WHERE {_VECTOR_LIFECYCLE} AND {_VECTOR_SENSITIVITY} AND {_ELIGIBILITY}
                LIMIT :exact_max_rows
            ),
            ranked AS (
                SELECT chunk_id, embedding {operator} :qvec AS distance
                FROM eligible
                ORDER BY embedding {operator} :qvec
                LIMIT :k
            )
            SELECT {_PROJECTION}, r.distance AS distance
            FROM ranked r
            JOIN knowledge_chunk c    ON c.id = r.chunk_id
            JOIN knowledge_document d ON d.id = c.document_id
            JOIN knowledge_source s   ON s.id = c.source_id
            ORDER BY r.distance, c.id
            """  # noqa: S608 - see _bindparams docstring
        ).bindparams(*_bindparams(space.dimensions))

        payload = {
            **params,
            "exact_max_rows": config.exact_max_rows,
            "k": config.k,
        }
        try:
            async with self._session.begin_nested():
                await self._session.execute(
                    text(f"SET LOCAL statement_timeout = {int(config.exact_timeout_ms)}")
                )
                rows = await self._session.execute(statement, payload)
                return list(rows.mappings())
        except DBAPIError as exc:
            if _is_query_cancelled(exc):
                logger.warning(
                    "knowledge.retrieval.exact_fallback_timeout",
                    space_key=space.space_key,
                    timeout_ms=config.exact_timeout_ms,
                )
                raise _ExactTimeoutError from exc
            raise

    # -- helpers --------------------------------------------------------

    def _params(
        self,
        vector: list[float] | None,
        space: EmbeddingSpace,
        policy: RetrievalPolicy,
        filters: RetrievalFilters,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "space_id": space.id,
            "sensitivities": policy.sensitivity_values,
            "excluded_trust": policy.excluded_trust_values,
            "active_state": KnowledgeLifecycle.ACTIVE.value,
            **filters.as_params(),
        }
        if vector is not None:
            params["qvec"] = vector
        return params

    @asynccontextmanager
    async def _local_settings(
        self, settings: Mapping[str, int | str]
    ) -> AsyncIterator[None]:
        """Apply ``SET LOCAL`` around one statement and put it back.

        Scoped deliberately. ``hnsw.ef_search`` changes how deeply *this* index
        scan searches and nothing else; it is emphatically not the same kind of
        lever as ``enable_indexscan``, which rewrites plan selection for every
        statement in the transaction. Even so it is restored on exit, so a
        retrieval call cannot leave a transaction it shares with other work in
        an altered state.

        Values are integers or validated identifiers - ``SET`` cannot take a
        bind parameter, so nothing else may reach this SQL.
        """
        if not settings:
            yield
            return
        previous: dict[str, str] = {}
        for name in settings:
            row = await self._session.execute(
                text("SELECT current_setting(:name, true)"), {"name": name}
            )
            previous[name] = row.scalar_one() or "DEFAULT"
        try:
            for name, value in settings.items():
                await self._session.execute(text(f"SET LOCAL {name} = {_literal(value)}"))
            yield
        finally:
            for name, old in previous.items():
                await self._session.execute(text(f"SET LOCAL {name} = {_literal(old)}"))

    async def _guc_exists(self, name: str) -> bool:
        """Whether this server has a setting, remembered per process.

        pgvector 0.6 (development) has no ``hnsw.iterative_scan``; 0.8.6
        (production) does. Detecting rather than assuming is what lets the same
        code run on both without a version branch.
        """
        cached = _GUC_SUPPORT.get(name)
        if cached is not None:
            return cached
        row = await self._session.execute(
            text("SELECT count(*) FROM pg_settings WHERE name = :name"), {"name": name}
        )
        exists = int(row.scalar_one()) > 0
        _GUC_SUPPORT[name] = exists
        return exists

    def _finish(
        self,
        rows: Sequence[Any],
        *,
        space: EmbeddingSpace,
        config: RetrievalConfig,
        policy: RetrievalPolicy,
        strategy: RetrievalStrategy,
        method: RetrievalMethod,
        ann_returned: int,
        ann_eligible: int,
        eligible_population: int | None,
        capped: bool,
        exact_ranked: int | None,
        degraded: bool,
        reason: str | None,
        ann_latency: float,
        count_latency: float | None,
        exact_latency: float | None,
        started: float,
    ) -> RetrievalResult:
        results = tuple(
            _to_chunk(row, index + 1, method, space.id) for index, row in enumerate(rows)
        )
        diagnostics = RetrievalDiagnostics(
            strategy=strategy,
            embedding_space_id=space.id,
            requested_k=config.k,
            ann_candidate_limit=config.candidate_limit,
            ann_candidates_returned=ann_returned,
            ann_eligible_count=ann_eligible,
            eligible_population=eligible_population,
            eligible_population_capped=capped,
            exact_rows_ranked=exact_ranked,
            returned_count=len(results),
            degraded=degraded,
            degradation_reason=reason,
            ann_latency_ms=ann_latency,
            count_latency_ms=count_latency,
            exact_latency_ms=exact_latency,
            total_latency_ms=_ms(started),
        )
        logger.info("knowledge.retrieval.completed", **diagnostics.as_audit_fields())
        return RetrievalResult(results=results, diagnostics=diagnostics, policy=policy)

    def _degraded(
        self,
        ann_rows: Sequence[Any],
        *,
        space: EmbeddingSpace,
        config: RetrievalConfig,
        policy: RetrievalPolicy,
        reason: str,
        population: int,
        capped: bool,
        ann_latency: float,
        count_latency: float,
        started: float,
        strategy: RetrievalStrategy = RetrievalStrategy.ANN_PARTIAL_FALLBACK_SKIPPED,
        exact_latency: float | None = None,
    ) -> RetrievalResult:
        """Return what the ANN found, labelled as incomplete.

        The results are real and usable; what is *not* true is that they are the
        best available. Saying so in the payload is the entire point - an
        approximate answer presented as complete is the failure mode this
        milestone was corrected to prevent.
        """
        return self._finish(
            ann_rows,
            space=space,
            config=config,
            policy=policy,
            strategy=strategy,
            method=RetrievalMethod.VECTOR,
            ann_returned=len(ann_rows),
            ann_eligible=len(ann_rows),
            eligible_population=population,
            capped=capped,
            exact_ranked=None,
            degraded=True,
            reason=reason,
            ann_latency=ann_latency,
            count_latency=count_latency,
            exact_latency=exact_latency,
            started=started,
        )


class _ExactTimeoutError(Exception):
    """Internal signal: the exact stage exceeded its budget."""


def _with_k(config: RetrievalConfig, k: int) -> RetrievalConfig:
    return RetrievalConfig(
        k=k,
        ann_overfetch=config.ann_overfetch,
        ann_candidate_cap=config.ann_candidate_cap,
        hnsw_ef_search=config.hnsw_ef_search,
        hnsw_iterative_scan=config.hnsw_iterative_scan,
        exact_fallback_enabled=config.exact_fallback_enabled,
        exact_max_rows=config.exact_max_rows,
        exact_timeout_ms=config.exact_timeout_ms,
    )


def _literal(value: int | str) -> str:
    """Render a ``SET LOCAL`` value. Integers pass through; strings are quoted.

    ``SET`` accepts no bind parameters, so this is the only place a value is
    interpolated. Integers are cast, and strings are single-quoted with any
    embedded quote doubled - the same escaping PostgreSQL itself uses.
    """
    if isinstance(value, int):
        return str(int(value))
    if value.upper() == "DEFAULT":
        return "DEFAULT"
    escaped = value.replace("'", "''")
    return f"'{escaped}'"


def _ms(since: float) -> float:
    return (time.perf_counter() - since) * 1000.0


def _is_query_cancelled(exc: DBAPIError) -> bool:
    """Recognise a statement-timeout cancellation without importing asyncpg.

    PostgreSQL SQLSTATE 57014 is ``query_canceled``. Matching on the code rather
    than the driver's exception class keeps this working if the driver changes.
    """
    sqlstate = getattr(exc.orig, "sqlstate", None) or getattr(exc.orig, "pgcode", None)
    return str(sqlstate) == "57014"


def _to_chunk(
    row: Any,
    rank: int,
    method: RetrievalMethod,
    space_id: uuid.UUID,
    *,
    score: float | None = None,
    lexical_score: float | None = None,
    vector_rank: int | None = None,
    lexical_rank: int | None = None,
) -> RetrievedChunk:
    distance = float(row["distance"]) if "distance" in row else None
    return RetrievedChunk(
        chunk_id=row["chunk_id"],
        document_id=row["document_id"],
        source_id=row["source_id"],
        version_id=row["version_id"],
        ordinal=int(row["ordinal"]),
        content=row["content"],
        heading_path=tuple(row["heading_path"] or ()),
        section_label=row["section_label"],
        flags=tuple(row["flags"] or ()),
        token_estimate=int(row["token_estimate"]),
        distance=distance,
        # Cosine distance is 1 - similarity, so the default reads as a
        # similarity. Reported alongside the raw distance rather than instead
        # of it: the distance is what the database ranked on and what an audit
        # can rerun.
        score=score if score is not None else 1.0 - (distance or 0.0),
        rank=rank,
        method=method,
        sensitivity=Sensitivity(row["sensitivity"]),
        trust_class=TrustClass(row["trust_class"]),
        source_kind=row["source_kind"],
        source_title=row["source_title"],
        document_title=row["document_title"],
        external_ref=row["external_ref"],
        embedding_space_id=space_id,
        vector_rank=vector_rank
        if vector_rank is not None
        else (
            rank
            if method in (RetrievalMethod.VECTOR, RetrievalMethod.VECTOR_EXACT)
            else None
        ),
        lexical_rank=lexical_rank,
        lexical_score=lexical_score,
    )


def _fuse(
    dense: Sequence[RetrievedChunk],
    lexical: Sequence[RetrievedChunk],
    *,
    rrf_k: int,
) -> list[RetrievedChunk]:
    """Reciprocal Rank Fusion over two already-authorized result lists.

    ``score = sum over legs of 1 / (rrf_k + rank)``. Rank-based rather than
    score-based because a cosine distance and a ``ts_rank_cd`` value have no
    common scale and inventing a normalisation between them would be a
    fabricated relevance model dressed up as arithmetic.

    A passage found by both legs necessarily outscores one found by either
    alone at the same rank, which is the property that makes hybrid retrieval
    worth the second query.

    Ties are broken by chunk id so the ordering is total and reproducible - two
    identical calls must not return different orders.
    """
    contributions: dict[uuid.UUID, dict[str, Any]] = {}
    for leg, chunks in (("dense", dense), ("lexical", lexical)):
        for chunk in chunks:
            entry = contributions.setdefault(
                chunk.chunk_id, {"score": 0.0, "dense": None, "lexical": None}
            )
            entry["score"] += 1.0 / (rrf_k + chunk.rank)
            entry[leg] = chunk

    fused: list[RetrievedChunk] = []
    for chunk_id, entry in contributions.items():
        dense_hit: RetrievedChunk | None = entry["dense"]
        lexical_hit: RetrievedChunk | None = entry["lexical"]
        # The dense row is preferred as the carrier because it holds the
        # distance; content and provenance are identical either way.
        base = dense_hit or lexical_hit
        assert base is not None  # noqa: S101 - a key exists only if a leg wrote it
        method = (
            RetrievalMethod.HYBRID
            if dense_hit is not None and lexical_hit is not None
            else (dense_hit.method if dense_hit is not None else RetrievalMethod.LEXICAL)
        )
        fused.append(
            replace(
                base,
                method=method,
                score=entry["score"],
                fused_score=entry["score"],
                vector_rank=dense_hit.rank if dense_hit is not None else None,
                lexical_rank=lexical_hit.rank if lexical_hit is not None else None,
                lexical_score=(
                    lexical_hit.lexical_score if lexical_hit is not None else None
                ),
                rank=0,
            )
        )
        del chunk_id

    fused.sort(key=lambda c: (-(c.fused_score or 0.0), str(c.chunk_id)))
    return [replace(chunk, rank=index + 1) for index, chunk in enumerate(fused)]


def _empty_diagnostics(
    space: EmbeddingSpace,
    config: RetrievalConfig,
    started: float,
    *,
    mode: RetrievalMode = RetrievalMode.VECTOR,
) -> RetrievalDiagnostics:
    return RetrievalDiagnostics(
        strategy=(
            RetrievalStrategy.NOT_RUN
            if mode is RetrievalMode.LEXICAL
            else RetrievalStrategy.ANN_COMPLETE
        ),
        mode=mode,
        embedding_space_id=space.id,
        requested_k=config.k,
        ann_candidate_limit=config.candidate_limit,
        ann_candidates_returned=0,
        ann_eligible_count=0,
        eligible_population=0,
        eligible_population_capped=False,
        exact_rows_ranked=None,
        returned_count=0,
        degraded=False,
        degradation_reason=None,
        ann_latency_ms=0.0,
        count_latency_ms=None,
        exact_latency_ms=None,
        total_latency_ms=_ms(started),
    )


__all__ = [
    "DEFAULT_RRF_K",
    "MAX_K",
    "KnowledgeRetrievalService",
    "RetrievalConfig",
    "RetrievalDiagnostics",
    "RetrievalFilters",
    "RetrievalPolicy",
    "RetrievalResult",
    "RetrievedChunk",
    "policy_for",
]
