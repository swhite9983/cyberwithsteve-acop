"""Request and response schemas for the knowledge API.

Two properties are enforced here rather than left to the route handlers.

**No response model carries raw secret material or raw query text.** A finding
is described by its detector, its locator and its fingerprint, never by what it
matched; a search response echoes the query's *hash and length*, never the
query. Both are the same rule: the API is a place secrets leak from, and a
schema that cannot express the value cannot leak it.

**No response model can express an instruction.** The answer contract has no
field for a tool call, a command, a permission or a principal - see
:mod:`acop.services.knowledge.evidence` for why that structural absence is the
real control rather than any wording in a prompt.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field

from acop.models.knowledge_vocabulary import (
    Disposition,
    IngestOutcome,
    RetrievalMethod,
    RetrievalMode,
    RetrievalStrategy,
    Sensitivity,
    SourceKind,
    StatementKind,
    TrustClass,
)

ORM = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------


class SourceCreate(BaseModel):
    source_kind: SourceKind
    title: Annotated[str, Field(min_length=1, max_length=512)]
    origin: Annotated[str, Field(min_length=1, max_length=255)]
    trust_class: TrustClass
    sensitivity: Sensitivity
    uri: Annotated[str | None, Field(default=None, max_length=2048)]
    owner_subject: Annotated[str | None, Field(default=None, max_length=255)]
    metadata: dict[str, Any] = Field(default_factory=dict)


class SourceReclassify(BaseModel):
    """Trust and classification are separate axes, so both are optional here.

    Changing sensitivity has to propagate to the denormalised copy on every
    stored vector in the same transaction - see
    ``EmbeddingSpaceService.resync_source_sensitivity`` - which is why this is
    an operation rather than a generic PATCH.
    """

    trust_class: TrustClass | None = None
    sensitivity: Sensitivity | None = None
    reason: Annotated[str, Field(min_length=1, max_length=1000)]


class SourceRead(BaseModel):
    model_config = ORM

    id: uuid.UUID
    source_kind: str
    title: str
    uri: str | None
    origin: str
    owner_subject: str | None
    trust_class: str
    sensitivity: str
    lifecycle_state: str
    retired_at: datetime | None
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------------------
# Documents and versions
# ---------------------------------------------------------------------------


class DocumentIngest(BaseModel):
    source_id: uuid.UUID
    external_ref: Annotated[str, Field(min_length=1, max_length=1024)]
    title: Annotated[str, Field(min_length=1, max_length=512)]
    content: Annotated[str, Field(min_length=1)]
    media_type: Annotated[str, Field(default="text/markdown", max_length=64)]
    source_modified_at: datetime | None = None
    embedding_space_id: uuid.UUID | None = None


class DocumentRead(BaseModel):
    model_config = ORM

    id: uuid.UUID
    source_id: uuid.UUID
    external_ref: str
    title: str
    media_type: str
    lifecycle_state: str
    current_version_id: uuid.UUID | None
    retired_at: datetime | None
    created_at: datetime


class VersionRead(BaseModel):
    model_config = ORM

    id: uuid.UUID
    document_id: uuid.UUID
    version_no: int
    raw_content_hash: str
    text_content_hash: str
    byte_size: int
    char_count: int
    parser_name: str
    parser_version: str
    chunker_name: str
    chunker_version: str
    chunker_params: dict[str, Any]
    screening_outcome: str
    ingested_at: datetime
    ingested_by_subject: str
    supersedes_version_id: uuid.UUID | None
    superseded_at: datetime | None
    created_by_attempt_id: uuid.UUID


class ChunkRead(BaseModel):
    model_config = ORM

    id: uuid.UUID
    version_id: uuid.UUID
    document_id: uuid.UUID
    source_id: uuid.UUID
    ordinal: int
    content: str
    content_hash: str
    char_start: int
    char_end: int
    token_estimate: int
    heading_path: list[str] | None
    section_label: str | None
    flags: list[str]


class IngestResultRead(BaseModel):
    attempt_id: uuid.UUID
    outcome: IngestOutcome
    document_id: uuid.UUID | None
    version_id: uuid.UUID | None
    version_no: int | None
    chunk_count: int
    embedded_count: int
    advisory_finding_count: int


# ---------------------------------------------------------------------------
# Attempts, findings, dispositions
# ---------------------------------------------------------------------------


class FindingRead(BaseModel):
    """A finding names *where*, never *what*.

    ``locator`` is a line and column range and ``match_fingerprint`` is a salted
    HMAC. Between them a human can find the material in their own copy and ACOP
    can recognise a resubmission of the same bytes - without this table ever
    holding the secret.
    """

    model_config = ORM

    id: uuid.UUID
    attempt_id: uuid.UUID
    finding_type: str
    severity: str
    detector: str
    detector_version: str
    locator: str
    match_fingerprint: str
    created_at: datetime


class AttemptRead(BaseModel):
    model_config = ORM

    id: uuid.UUID
    source_id: uuid.UUID
    external_ref: str
    document_id: uuid.UUID | None
    version_id: uuid.UUID | None
    raw_content_hash: str
    text_content_hash: str | None
    byte_size: int
    media_type: str
    outcome: str
    requested_by_subject: str
    chunk_count: int | None
    embedded_count: int | None
    blocking_finding_count: int
    duration_ms: int | None
    error_code: str | None
    started_at: datetime
    finished_at: datetime | None


class AttemptDetail(BaseModel):
    attempt: AttemptRead
    findings: list[FindingRead]


class DispositionCreate(BaseModel):
    """An approver's judgement about one finding.

    ``FALSE_POSITIVE`` is the only disposition that can unblock content, and it
    unblocks exactly the reviewed bytes for exactly the reviewed target -
    ``REMEDIATED_AT_SOURCE`` records that a real secret was dealt with and can
    never make the original content ingestable, because the submitter has to
    edit their document and that produces a different hash.
    """

    disposition: Disposition
    reason: Annotated[str, Field(min_length=1, max_length=1024)]


class DispositionRead(BaseModel):
    model_config = ORM

    id: uuid.UUID
    origin_attempt_id: uuid.UUID
    source_id: uuid.UUID
    external_ref: str
    raw_content_hash: str
    match_fingerprint: str
    detector: str
    disposition: str
    reason: str
    decided_by_subject: str
    decided_at: datetime


# ---------------------------------------------------------------------------
# Embedding spaces
# ---------------------------------------------------------------------------


class EmbeddingSpaceCreate(BaseModel):
    space_key: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{2,47}$")]
    provider: Annotated[str, Field(min_length=1, max_length=32)]
    model: Annotated[str, Field(min_length=1, max_length=128)]
    dimensions: Annotated[int, Field(ge=1, le=2000)]
    model_digest: Annotated[str | None, Field(default=None, max_length=128)]
    document_prefix: Annotated[str, Field(default="", max_length=255)]
    query_prefix: Annotated[str, Field(default="", max_length=255)]
    max_input_tokens: Annotated[int, Field(default=2048, ge=1)]
    normalize_vectors: bool = True
    make_default: bool = False

    # ``model_`` is Pydantic's protected namespace; these fields are the
    # embedding *model's* identity and the name is the domain's, not ours.
    model_config = ConfigDict(protected_namespaces=())


class PrefixVerification(BaseModel):
    """Records that a human confirmed what the provider does with prefixes.

    Deliberately an attested act rather than a flag anyone can set in passing:
    an unverified prefix produces a corpus that cannot be searched correctly
    and reports nothing at all while doing it.
    """

    observed_document_prefix: Annotated[str, Field(max_length=255)]
    observed_query_prefix: Annotated[str, Field(max_length=255)]
    prefix_changes_vector: bool
    note: Annotated[str, Field(min_length=1, max_length=2000)]


class EmbeddingSpaceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    id: uuid.UUID
    space_key: str
    provider: str
    model: str
    model_digest: str | None
    dimensions: int
    distance_metric: str
    normalize_vectors: bool
    document_prefix: str
    query_prefix: str
    prefix_verified_at: datetime | None
    prefix_verified_by_subject: str | None
    max_input_tokens: int
    truncation_policy: str
    storage_relation: str
    partition_relation: str
    lifecycle_state: str
    is_default: bool
    created_at: datetime


# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------


class SearchRequest(BaseModel):
    query: Annotated[str, Field(min_length=1, max_length=4000)]
    mode: RetrievalMode = RetrievalMode.HYBRID
    k: Annotated[int, Field(default=10, ge=1, le=100)]
    embedding_space_id: uuid.UUID | None = None
    source_ids: list[uuid.UUID] = Field(default_factory=list)
    document_ids: list[uuid.UUID] = Field(default_factory=list)
    source_kinds: list[SourceKind] = Field(default_factory=list)
    trust_classes: list[TrustClass] = Field(default_factory=list)

    @property
    def query_hash(self) -> str:
        return hashlib.sha256(self.query.encode("utf-8")).hexdigest()


class RetrievalDiagnosticsRead(BaseModel):
    """Why the answer looks the way it does, in the response body.

    Present on every search rather than behind a debug flag: a result of three
    when ten were asked for is either complete or degraded, and a caller that
    cannot tell the difference will treat both as "there is nothing else".
    """

    mode: RetrievalMode
    strategy: RetrievalStrategy
    embedding_space_id: uuid.UUID
    requested_k: int
    returned_count: int
    ann_candidates_returned: int
    ann_eligible_count: int
    eligible_population: int | None
    eligible_population_capped: bool
    exact_rows_ranked: int | None
    lexical_candidates: int | None
    fused_candidates: int | None
    rrf_k: int | None
    degraded: bool
    degradation_reason: str | None
    total_latency_ms: float


class RetrievedChunkRead(BaseModel):
    chunk_id: uuid.UUID
    document_id: uuid.UUID
    source_id: uuid.UUID
    version_id: uuid.UUID
    ordinal: int
    content: str
    heading_path: list[str]
    section_label: str | None
    flags: list[str]
    rank: int
    score: float
    distance: float | None
    retrieval_method: RetrievalMethod
    vector_rank: int | None
    lexical_rank: int | None
    fused_score: float | None
    sensitivity: Sensitivity
    trust_class: TrustClass
    source_kind: str
    source_title: str
    document_title: str
    external_ref: str


class SearchResponse(BaseModel):
    """The query itself is deliberately absent.

    Only its hash and length are echoed, matching what the audit record stores.
    A search query is frequently the most sensitive thing about a search - it
    describes what an operator was worried about - and neither the response nor
    the immutable audit trail is a good place to keep it by default.
    """

    query_hash: str
    query_length: int
    results: list[RetrievedChunkRead]
    diagnostics: RetrievalDiagnosticsRead


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


class CitationRead(BaseModel):
    index: int
    chunk_id: uuid.UUID
    version_id: uuid.UUID
    document_id: uuid.UUID
    source_id: uuid.UUID
    document_title: str
    source_title: str
    external_ref: str
    ordinal: int
    heading_path: list[str]
    trust_class: TrustClass
    sensitivity: Sensitivity
    retrieval_method: RetrievalMethod
    rank: int
    score: float
    injection_suspected: bool


class AssetMentionRead(BaseModel):
    model_config = ORM

    id: uuid.UUID
    chunk_id: uuid.UUID
    asset_id: uuid.UUID | None
    mention_text: str
    mention_source: str
    resolution: str
    candidate_asset_ids: list[uuid.UUID]
    matched_namespace: str | None
    created_by_subject: str
    created_at: datetime


class MentionScanResult(BaseModel):
    version_id: uuid.UUID
    chunks_scanned: int
    candidates_considered: int
    mentions_created: int
    ambiguous: int


class ExplicitMentionCreate(BaseModel):
    asset_id: uuid.UUID
    mention_text: Annotated[str | None, Field(default=None, max_length=255)]


class EvidenceRequest(SearchRequest):
    include_prompt_render: bool = True


class EvidenceResponse(BaseModel):
    """What Milestone 3 hands to a caller who intends to ask a model.

    It stops at evidence. Milestone 3 runs no generation, executes no tool and
    returns no statement it did not receive - ``statement_kinds`` is published
    here so a caller building on this knows the contract its answers will be
    validated against, not because anything in this response has been through
    a model.
    """

    query_hash: str
    query_length: int
    citations: list[CitationRead]
    contents: list[str]
    mentions: dict[uuid.UUID, list[AssetMentionRead]]
    prompt_render: str | None
    diagnostics: RetrievalDiagnosticsRead
    statement_kinds: list[StatementKind] = Field(
        default_factory=lambda: list(StatementKind)
    )


__all__ = [
    "AssetMentionRead",
    "AttemptDetail",
    "AttemptRead",
    "ChunkRead",
    "CitationRead",
    "DispositionCreate",
    "DispositionRead",
    "DocumentIngest",
    "DocumentRead",
    "EmbeddingSpaceCreate",
    "EmbeddingSpaceRead",
    "EvidenceRequest",
    "EvidenceResponse",
    "ExplicitMentionCreate",
    "FindingRead",
    "IngestResultRead",
    "MentionScanResult",
    "PrefixVerification",
    "RetrievalDiagnosticsRead",
    "RetrievedChunkRead",
    "SearchRequest",
    "SearchResponse",
    "SourceCreate",
    "SourceRead",
    "SourceReclassify",
    "VersionRead",
]
