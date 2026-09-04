"""Milestone 3: knowledge ingestion, retrieval and the evidence contract.

The subpackage boundary is not organisational tidiness. Everything in here
produces *evidence*, and nothing in here has a write path to authoritative CMDB
state - no import of ``AssetFact``, ``AssetRelationship`` or
``FactAttestation`` appears anywhere below this line. Keeping that property
checkable at a glance is the point of the package.
"""

from acop.services.knowledge.catalog import KnowledgeCatalogService, SourceRegistration
from acop.services.knowledge.chunking import ChunkerParams, chunk_document, normalise
from acop.services.knowledge.embedding_provider import (
    DeterministicEmbeddingProvider,
    EmbeddingProvider,
    OllamaEmbeddingProvider,
    PrefixProbe,
)
from acop.services.knowledge.evidence import (
    Citation,
    Conflict,
    EvidenceBundle,
    KnowledgeAnswer,
    Statement,
    build_answer,
)
from acop.services.knowledge.ingest import (
    IngestRequest,
    IngestResult,
    KnowledgeIngestService,
)
from acop.services.knowledge.mentions import AssetMentionService, MentionReport
from acop.services.knowledge.retrieval import (
    KnowledgeRetrievalService,
    RetrievalConfig,
    RetrievalFilters,
    RetrievalResult,
    RetrievedChunk,
    policy_for,
)
from acop.services.knowledge.screening import DocumentScreen, ScreeningReport
from acop.services.knowledge.spaces import EmbeddingSpaceService, SpaceRegistration

__all__ = [
    "AssetMentionService",
    "ChunkerParams",
    "Citation",
    "Conflict",
    "DeterministicEmbeddingProvider",
    "DocumentScreen",
    "EmbeddingProvider",
    "EmbeddingSpaceService",
    "EvidenceBundle",
    "IngestRequest",
    "IngestResult",
    "KnowledgeAnswer",
    "KnowledgeCatalogService",
    "KnowledgeIngestService",
    "KnowledgeRetrievalService",
    "MentionReport",
    "OllamaEmbeddingProvider",
    "PrefixProbe",
    "RetrievalConfig",
    "RetrievalFilters",
    "RetrievalResult",
    "RetrievedChunk",
    "ScreeningReport",
    "SourceRegistration",
    "SpaceRegistration",
    "Statement",
    "build_answer",
    "chunk_document",
    "normalise",
    "policy_for",
]
