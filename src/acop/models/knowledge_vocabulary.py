"""Milestone 3 knowledge vocabularies and code registries.

Every enumerated value here is stored as ``VARCHAR`` per ADR-0004, so adding a
member is a code change with no migration. The registries at the bottom are the
single definition each service references, so two modules cannot disagree about
what a value means.

**Why these vocabularies are separate from Milestone 2's.** Knowledge trust and
fact trust answer different questions. ``VerificationStatus`` says how much ACOP
believes a *claim about the estate*; ``TrustClass`` says how much ACOP believes
a *document*. Collapsing them would be the same mistake as collapsing
``fact_kind`` into ``verification_status`` - it reads as tidier and destroys the
distinction that makes conflict reporting possible.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------


class SourceKind(StrEnum):
    """What kind of thing a knowledge source is.

    ``INCIDENT_RECORD`` and ``CHANGE_RECORD`` are declared now and unused in
    Milestone 3. They exist so Milestones 10 and 11 can register their outputs
    as knowledge without a vocabulary migration, and so the retrieval filter's
    shape is right from the start.
    """

    DOCUMENT = "DOCUMENT"
    RUNBOOK = "RUNBOOK"
    POLICY = "POLICY"
    STANDARD = "STANDARD"
    PROCEDURE = "PROCEDURE"
    CONFIG_REFERENCE = "CONFIG_REFERENCE"
    VENDOR_DOCUMENTATION = "VENDOR_DOCUMENTATION"
    TROUBLESHOOTING = "TROUBLESHOOTING"
    MANUAL_NOTE = "MANUAL_NOTE"
    INCIDENT_RECORD = "INCIDENT_RECORD"
    CHANGE_RECORD = "CHANGE_RECORD"


class TrustClass(StrEnum):
    """How much weight a source's statements carry.

    Trust affects ranking and how a citation is labelled. It never promotes
    anything to authoritative CMDB state - that transition exists only in
    Milestone 2's verify workflow and requires a human.
    """

    AUTHORITATIVE_POLICY = "AUTHORITATIVE_POLICY"
    VENDOR = "VENDOR"
    INTERNAL_VERIFIED = "INTERNAL_VERIFIED"
    INTERNAL_DRAFT = "INTERNAL_DRAFT"
    EXTERNAL_UNVERIFIED = "EXTERNAL_UNVERIFIED"
    QUARANTINED = "QUARANTINED"


#: Trust classes that only an approver may assign. Raising a source to
#: "this is our policy" is an approval act, not an editorial one.
APPROVER_ONLY_TRUST: Final[frozenset[TrustClass]] = frozenset(
    {TrustClass.AUTHORITATIVE_POLICY}
)

#: Never retrieved, under any policy, for any principal.
NEVER_RETRIEVED_TRUST: Final[frozenset[TrustClass]] = frozenset({TrustClass.QUARANTINED})


class Sensitivity(StrEnum):
    """Data classification, on an axis independent of trust.

    A highly trusted document can be highly sensitive and vice versa, so this
    is deliberately not folded into :class:`TrustClass`.
    """

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"


class KnowledgeLifecycle(StrEnum):
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------


class IngestOutcome(StrEnum):
    """The result of one ingestion attempt.

    ``PENDING`` exists because the attempt row is written *before* the work is
    done - it is the record that a submission was made at all, and it must
    survive a rollback of everything that follows.
    """

    PENDING = "PENDING"
    CREATED = "CREATED"
    VERSIONED = "VERSIONED"
    UNCHANGED = "UNCHANGED"
    UNCHANGED_TEXT = "UNCHANGED_TEXT"
    REJECTED_INVALID = "REJECTED_INVALID"
    REJECTED_SECRET = "REJECTED_SECRET"  # noqa: S105 - an outcome, not a credential
    FAILED_EMBEDDING = "FAILED_EMBEDDING"


#: Outcomes that produced a canonical document version. The database enforces
#: that no other outcome may reference one; this tuple is where that list is
#: defined for the service layer and the migration alike.
CANONICAL_OUTCOMES: Final[tuple[IngestOutcome, ...]] = (
    IngestOutcome.CREATED,
    IngestOutcome.VERSIONED,
)


class ScreeningOutcome(StrEnum):
    """Screening result recorded on a *successful* version.

    ``QUARANTINED`` is deliberately absent: a quarantined submission never
    produces a version, so the state is unrepresentable here. That is the
    Milestone 3 correction (R3 §2) expressed in the vocabulary.
    """

    CLEAN = "CLEAN"
    FLAGGED = "FLAGGED"


class FindingType(StrEnum):
    SECRET_SUSPECTED = "SECRET_SUSPECTED"  # noqa: S105 - a finding type
    INJECTION_SUSPECTED = "INJECTION_SUSPECTED"
    OVERSIZE_INPUT = "OVERSIZE_INPUT"


class FindingSeverity(StrEnum):
    """``BLOCKING`` stops ingestion; ``ADVISORY`` is recorded and continues."""

    BLOCKING = "BLOCKING"
    ADVISORY = "ADVISORY"


class Disposition(StrEnum):
    """An approver's judgement about a finding.

    Only ``FALSE_POSITIVE`` can unblock content, and only for the exact bytes
    reviewed. ``REMEDIATED_AT_SOURCE`` records that a real secret was dealt
    with and can never make the original content ingestable - the submitter
    must edit their document, which produces a different hash.
    """

    FALSE_POSITIVE = "FALSE_POSITIVE"
    REMEDIATED_AT_SOURCE = "REMEDIATED_AT_SOURCE"


#: The only disposition that clears a blocking finding. Named here rather than
#: inlined so the rule has one definition and one place to review.
UNBLOCKING_DISPOSITIONS: Final[frozenset[Disposition]] = frozenset(
    {Disposition.FALSE_POSITIVE}
)


class ChunkFlag(StrEnum):
    """Security-relevant annotations carried on a chunk."""

    INJECTION_SUSPECTED = "INJECTION_SUSPECTED"
    TRUNCATED_FOR_EMBEDDING = "TRUNCATED_FOR_EMBEDDING"


# ---------------------------------------------------------------------------
# Embedding spaces
# ---------------------------------------------------------------------------


class DistanceMetric(StrEnum):
    COSINE = "cosine"


#: pgvector operator and ops-class for each metric. Measured: an HNSW index
#: requires a fixed dimension, so this mapping is only meaningful alongside a
#: dimension-typed column.
DISTANCE_OPERATOR: Final[dict[DistanceMetric, str]] = {DistanceMetric.COSINE: "<=>"}
DISTANCE_OPS_CLASS: Final[dict[DistanceMetric, str]] = {
    DistanceMetric.COSINE: "vector_cosine_ops"
}


class TruncationPolicy(StrEnum):
    """What to do with a chunk larger than the embedding model accepts.

    ``REJECT_OVERSIZE`` is the default because the alternative - letting the
    provider silently truncate - produces a vector that claims to represent a
    chunk it has only partly read, with no signal anywhere that it happened.
    """

    REJECT_OVERSIZE = "REJECT_OVERSIZE"
    TRUNCATE_TAIL = "TRUNCATE_TAIL"


class SpaceLifecycle(StrEnum):
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    RETIRED = "RETIRED"


#: Measured against pgvector: ``vector(2001)`` is a legal column but cannot
#: carry an HNSW index ("column cannot have more than 2000 dimensions for hnsw
#: index"), which would silently turn every search into a sequential scan.
MAX_INDEXABLE_DIMENSIONS: Final[int] = 2000

#: Physical parent relation for a dimension family. The suffix names a pgvector
#: *storage constraint*; it is never a semantic identity. Two spaces of the
#: same dimension share this parent and occupy different LIST partitions.
EMBEDDING_PARENT_TEMPLATE: Final[str] = "knowledge_embedding_d{dimensions}"

#: Partition name = parent + space key. Both halves are validated identifiers;
#: no value reaching SQL as an identifier comes from user input.
EMBEDDING_PARTITION_TEMPLATE: Final[str] = "{parent}_{space_key}"

SPACE_KEY_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]{2,47}$")


def parent_relation(dimensions: int) -> str:
    """Physical parent table for a dimension family."""
    return EMBEDDING_PARENT_TEMPLATE.format(dimensions=dimensions)


def partition_relation(dimensions: int, space_key: str) -> str:
    """Physical partition for one embedding space.

    Raises:
        ValueError: The space key is not a safe identifier fragment. This is a
            defence in depth: partition names are only ever built from a
            registry value that already passed a CHECK constraint, but a name
            that reaches SQL as an identifier is validated again here.
    """
    if not SPACE_KEY_PATTERN.match(space_key):
        raise ValueError(f"Unsafe embedding space key: {space_key!r}")
    return EMBEDDING_PARTITION_TEMPLATE.format(
        parent=parent_relation(dimensions), space_key=space_key
    )


# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------


class RetrievalMethod(StrEnum):
    """Which leg produced a result, and whether it was exhaustive.

    ``VECTOR_EXACT`` exists so a citation records not only *which* leg found a
    passage but whether that leg was approximate. A reader auditing an answer
    can tell an ANN hit from an exhaustively ranked one.
    """

    VECTOR = "VECTOR"
    VECTOR_EXACT = "VECTOR_EXACT"
    LEXICAL = "LEXICAL"
    HYBRID = "HYBRID"


class RetrievalStrategy(StrEnum):
    """How the *dense* leg of a retrieval call resolved.

    Deliberately about one leg rather than the whole call: the lexical leg has
    no approximation to fall back from, so folding both into a single value
    would either lose the dense leg's degradation state or invent lexical
    states that do not exist. :class:`RetrievalMode` records what was asked
    for; this records how the approximate half of it behaved.
    """

    ANN = "ANN"
    ANN_COMPLETE = "ANN_COMPLETE"
    EXACT_FALLBACK = "EXACT_FALLBACK"
    ANN_PARTIAL_FALLBACK_SKIPPED = "ANN_PARTIAL_FALLBACK_SKIPPED"
    ANN_PARTIAL_FALLBACK_TIMEOUT = "ANN_PARTIAL_FALLBACK_TIMEOUT"
    NOT_RUN = "NOT_RUN"
    """The dense leg was not executed - a purely lexical call."""


class RetrievalMode(StrEnum):
    """Which legs a caller asked for."""

    VECTOR = "VECTOR"
    LEXICAL = "LEXICAL"
    HYBRID = "HYBRID"


#: The text-search configuration the ``knowledge_chunk.lexeme`` generated column
#: is built with. A query must use the same one: matching a ``tsvector`` built
#: with English stemming against a ``tsquery`` built with another configuration
#: silently returns fewer rows rather than failing, so this is one constant used
#: by both the column definition and every lexical query.
#:
#: Changing it is a migration - the generated column has to be rebuilt - which
#: is exactly why it is not a runtime setting.
LEXEME_CONFIG: Final[str] = "english"

#: Reciprocal Rank Fusion's smoothing constant, from Cormack et al. (2009).
#:
#: RRF is used rather than score normalisation because a cosine distance and a
#: ``ts_rank_cd`` value are not on comparable scales and no principled mapping
#: between them exists; ranks are comparable by construction. The constant damps
#: the head of each list, so a single leg's top hit cannot outweigh a passage
#: both legs agree on - which is the behaviour hybrid retrieval exists to get.
DEFAULT_RRF_K: Final[int] = 60


class MentionSource(StrEnum):
    """How a chunk came to reference an asset.

    Exactly two members, and that is the whole of Milestone 3's entity linking.
    No fuzzy matching, no display-name heuristics, no NLP.
    """

    IDENTIFIER_MATCH = "IDENTIFIER_MATCH"
    EXPLICIT = "EXPLICIT"


#: Identifier namespaces whose values may be matched against document text.
#:
#: Deliberately a *subset*, and the exclusions are the interesting part. A
#: ``proxmox:vmid`` or a ``cisco:if-index`` is a bare integer; "VLAN 100" in a
#: runbook would match VMID 100 and produce a mention that is textually exact
#: and factually nonsense. ``acop:legacy-id`` is free-form for the same reason.
#: What remains is either globally unique by construction (serial, SMBIOS UUID,
#: MAC, Proxmox UUID, container id) or name-shaped and low-collision (hostname,
#: FQDN) - values whose literal appearance in prose really is evidence that the
#: document is talking about that asset.
#:
#: This is a code registry rather than a column so that widening it is a
#: reviewable change, not a configuration accident.
MENTIONABLE_NAMESPACES: Final[frozenset[str]] = frozenset(
    {
        "serial",
        "smbios:uuid",
        "mac",
        "proxmox:uuid",
        "docker:container-id",
        "hostname",
        "fqdn",
    }
)

#: Tokens shorter than this never produce a mention, and a purely numeric token
#: never does at any length. Both guard the same failure: a short or numeric
#: string collides with ordinary prose, and a false mention is worse than a
#: missing one because it attaches a document to the wrong machine.
MIN_MENTION_TOKEN_LENGTH: Final[int] = 3


class MentionResolution(StrEnum):
    """``AMBIGUOUS`` is the descendant of Milestone 2's IdentityConflictError.

    A mention matching two assets is recorded with both candidates and left
    unresolved rather than guessed - ADR-0006's rule applied to knowledge.
    """

    RESOLVED = "RESOLVED"
    AMBIGUOUS = "AMBIGUOUS"


class StatementKind(StrEnum):
    """The epistemic class of one statement in a knowledge answer.

    This is the Milestone 3 surface of the platform's central rule. A statement
    derived from a document is ``SOURCED``; a statement read from the CMDB is
    ``CMDB_FACT`` and carries the fact's real verification status; anything the
    model concluded is ``INFERENCE`` and is never presented as either.
    """

    SOURCED = "SOURCED"
    CMDB_FACT = "CMDB_FACT"
    OBSERVATION = "OBSERVATION"
    INFERENCE = "INFERENCE"
    UNRESOLVED = "UNRESOLVED"


#: Statement kinds that must carry at least one citation. Enforced in code,
#: not in the prompt: an uncited SOURCED statement fails validation rather
#: than being returned.
CITATION_REQUIRED_KINDS: Final[frozenset[StatementKind]] = frozenset(
    {StatementKind.SOURCED, StatementKind.CMDB_FACT}
)


class ConflictKind(StrEnum):
    DOC_VS_DOC = "DOC_VS_DOC"
    DOC_VS_CMDB = "DOC_VS_CMDB"


# ---------------------------------------------------------------------------
# Media types and the future CMDB promotion grammar
# ---------------------------------------------------------------------------

#: Milestone 3 parses exactly these. PDF, DOCX, HTML, CSV and OCR are deferred;
#: ``parser_name``/``parser_version`` are recorded per version so adding one
#: later does not invalidate anything already stored.
SUPPORTED_MEDIA_TYPES: Final[frozenset[str]] = frozenset({"text/markdown", "text/plain"})

#: Reserved grammar for a future CMDB fact derived from a document chunk.
#:
#: Milestone 3 never creates such a fact - it has no write path to any asset
#: table. This constant exists so that when Milestone 5 or later promotes
#: evidence through Milestone 2's explicit assert/verify workflow, there is one
#: definition of the convention rather than an ad-hoc string invented at the
#: call site. It is deliberately *not* a database constraint: see R3 §17.1.
KNOWLEDGE_FACT_SOURCE_PREFIX: Final[str] = "knowledge:chunk:"


def knowledge_fact_source_id(chunk_id: object) -> str:
    """Build the reserved ``source_id`` for a knowledge-derived CMDB fact."""
    return f"{KNOWLEDGE_FACT_SOURCE_PREFIX}{chunk_id}"


# ---------------------------------------------------------------------------
# Sensitivity policy
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SensitivityCeiling:
    """One role's readable sensitivity bands."""

    role: str
    allowed: frozenset[Sensitivity]


#: The Milestone 3 policy, exactly as ruled.
#:
#: ``approver`` is **not** a clearance - it is an authority to approve workflow
#: transitions, and it reads no more than an operator. Only ``admin`` reads
#: CONFIDENTIAL. This mapping lives in code rather than in a table or an index
#: predicate precisely so a future OIDC claim- or scope-based policy can
#: replace it without touching a single knowledge table.
DEFAULT_ROLE_SENSITIVITY: Final[dict[str, frozenset[Sensitivity]]] = {
    "viewer": frozenset({Sensitivity.PUBLIC, Sensitivity.INTERNAL}),
    "operator": frozenset({Sensitivity.PUBLIC, Sensitivity.INTERNAL}),
    "approver": frozenset({Sensitivity.PUBLIC, Sensitivity.INTERNAL}),
    "admin": frozenset(
        {Sensitivity.PUBLIC, Sensitivity.INTERNAL, Sensitivity.CONFIDENTIAL}
    ),
}


__all__ = [
    "APPROVER_ONLY_TRUST",
    "CANONICAL_OUTCOMES",
    "CITATION_REQUIRED_KINDS",
    "DEFAULT_ROLE_SENSITIVITY",
    "DEFAULT_RRF_K",
    "DISTANCE_OPERATOR",
    "DISTANCE_OPS_CLASS",
    "EMBEDDING_PARENT_TEMPLATE",
    "EMBEDDING_PARTITION_TEMPLATE",
    "KNOWLEDGE_FACT_SOURCE_PREFIX",
    "LEXEME_CONFIG",
    "MAX_INDEXABLE_DIMENSIONS",
    "MENTIONABLE_NAMESPACES",
    "MIN_MENTION_TOKEN_LENGTH",
    "NEVER_RETRIEVED_TRUST",
    "SPACE_KEY_PATTERN",
    "SUPPORTED_MEDIA_TYPES",
    "UNBLOCKING_DISPOSITIONS",
    "ChunkFlag",
    "ConflictKind",
    "Disposition",
    "DistanceMetric",
    "FindingSeverity",
    "FindingType",
    "IngestOutcome",
    "KnowledgeLifecycle",
    "MentionResolution",
    "MentionSource",
    "RetrievalMethod",
    "RetrievalMode",
    "RetrievalStrategy",
    "ScreeningOutcome",
    "Sensitivity",
    "SensitivityCeiling",
    "SourceKind",
    "SpaceLifecycle",
    "StatementKind",
    "TruncationPolicy",
    "TrustClass",
    "knowledge_fact_source_id",
    "parent_relation",
    "partition_relation",
]
