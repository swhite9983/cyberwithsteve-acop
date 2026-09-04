"""Embedding providers, behind an interface that knows nothing about Ollama.

``qwen3.8:27b`` is the *reasoning* model and is deliberately never used here -
it does not advertise an embedding capability, and its ``embedding_length``
metadata (5120) is an internal hidden size, not an embedding-space dimension.
Milestone 3's production space is ``embeddinggemma:latest`` at 768 dimensions,
configured separately from the generation model and possibly on a different
host.

**Prefix behaviour is part of embedding-space identity, and it is verified,
not assumed.** Prefix-trained retrieval models place prefixed and unprefixed
text in different regions of the space; embedding documents with one prefix and
queries with another, or changing a prefix between ingests, silently produces
incomparable vectors with no error anywhere. :class:`PrefixProbe` is what an
operator runs against the real host to establish what the installed model
actually does, and the ingestion gate refuses to persist canonical embeddings
into a space whose prefixes have not been verified.
"""

from __future__ import annotations

import hashlib
import math
import struct
from dataclasses import dataclass
from typing import Protocol

import httpx

from acop.core.exceptions import DependencyUnavailableError
from acop.core.logging import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class ProviderInfo:
    provider: str
    model: str
    dimensions: int
    model_digest: str | None


class EmbeddingUnavailableError(DependencyUnavailableError):
    """The embedding provider could not be reached or refused the request.

    A subclass of ``DependencyUnavailableError`` so it surfaces as 503 through
    the Milestone 1 handler - "we could not reach a dependency", which is a
    different thing from "your request was wrong".
    """


class EmbeddingDimensionError(RuntimeError):
    """A provider returned a vector of unexpected length.

    Fatal rather than a warning, deliberately: a silently wrong-dimension
    vector poisons a corpus invisibly.
    """


class EmbeddingProvider(Protocol):
    """Everything above this line knows nothing about which model is in use."""

    async def embed_documents(
        self, texts: list[str], *, prefix: str
    ) -> list[list[float]]: ...

    async def embed_query(self, text: str, *, prefix: str) -> list[float]: ...

    async def describe(self) -> ProviderInfo: ...


def l2_normalise(vector: list[float]) -> list[float]:
    norm = math.sqrt(sum(component * component for component in vector))
    if norm == 0.0:
        return vector
    return [component / norm for component in vector]


class OllamaEmbeddingProvider:
    """Embeddings from an Ollama host.

    Uses ``/api/embed``, which accepts a list and returns one vector per input,
    so a chunked document is one round trip rather than N.
    """

    def __init__(
        self,
        base_url: str,
        model: str,
        *,
        timeout_seconds: float = 120.0,
        normalize: bool = True,
        expected_dimensions: int | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout = timeout_seconds
        self._normalize = normalize
        self._expected = expected_dimensions

    async def _post(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(f"{self._base_url}{path}", json=payload)
                response.raise_for_status()
                body: dict[str, object] = response.json()
                return body
        except httpx.HTTPError as exc:
            raise EmbeddingUnavailableError(
                f"Embedding provider unreachable at {self._base_url}: "
                f"{type(exc).__name__}",
                context={"provider": "ollama", "model": self._model},
            ) from exc

    async def _embed(self, inputs: list[str]) -> list[list[float]]:
        body = await self._post("/api/embed", {"model": self._model, "input": inputs})
        raw = body.get("embeddings")
        if not isinstance(raw, list) or len(raw) != len(inputs):
            raise EmbeddingUnavailableError(
                "Embedding provider returned an unexpected payload shape.",
                context={"provider": "ollama", "model": self._model},
            )
        vectors = [[float(v) for v in vector] for vector in raw]
        if self._expected is not None:
            for vector in vectors:
                if len(vector) != self._expected:
                    raise EmbeddingDimensionError(
                        f"{self._model} returned {len(vector)} dimensions, "
                        f"expected {self._expected}."
                    )
        if self._normalize:
            vectors = [l2_normalise(vector) for vector in vectors]
        return vectors

    async def embed_documents(
        self, texts: list[str], *, prefix: str
    ) -> list[list[float]]:
        if not texts:
            return []
        return await self._embed([f"{prefix}{text}" for text in texts])

    async def embed_query(self, text: str, *, prefix: str) -> list[float]:
        return (await self._embed([f"{prefix}{text}"]))[0]

    async def describe(self) -> ProviderInfo:
        """Report the model's identity, including its digest where available.

        The digest matters more than it looks: Ollama tags are mutable, so
        pulling ``:latest`` twice can yield different weights. Two vectors from
        "the same model" that are actually from different weights are silently
        incomparable, and the digest is what makes that detectable.
        """
        digest: str | None = None
        dimensions = self._expected or 0
        try:
            body = await self._post("/api/show", {"model": self._model})
            details = body.get("details")
            if isinstance(details, dict):
                raw_digest = details.get("parent_model") or body.get("digest")
                digest = str(raw_digest) if raw_digest else None
            info = body.get("model_info")
            if isinstance(info, dict):
                for key, value in info.items():
                    if key.endswith(".embedding_length") and isinstance(value, int):
                        dimensions = value
                        break
        except EmbeddingUnavailableError:
            raise
        if not dimensions:
            probe = await self._embed(["dimension probe"])
            dimensions = len(probe[0])
        return ProviderInfo(
            provider="ollama",
            model=self._model,
            dimensions=dimensions,
            model_digest=digest,
        )


class DeterministicEmbeddingProvider:
    """A reproducible stand-in for tests and offline development.

    Not a mock in the usual sense: it produces stable, well-distributed unit
    vectors derived from the text, so semantic-ish tests ("this chunk is nearer
    than that one") are repeatable without a GPU host. It is never wired into
    production - the API only ever constructs the Ollama provider.

    Crucially it honours the prefix, so a test can prove that changing a prefix
    changes the vector, which is the property that makes prefix configuration
    part of space identity.
    """

    def __init__(self, dimensions: int = 768, *, normalize: bool = True) -> None:
        self._dimensions = dimensions
        self._normalize = normalize

    def _vector(self, text: str) -> list[float]:
        needed = self._dimensions * 4
        material = b""
        counter = 0
        while len(material) < needed:
            material += hashlib.sha256(
                text.encode("utf-8") + counter.to_bytes(4, "big")
            ).digest()
            counter += 1
        values = [
            struct.unpack(">I", material[i * 4 : i * 4 + 4])[0] / 0xFFFFFFFF - 0.5
            for i in range(self._dimensions)
        ]
        return l2_normalise(values) if self._normalize else values

    async def embed_documents(
        self, texts: list[str], *, prefix: str
    ) -> list[list[float]]:
        return [self._vector(f"{prefix}{text}") for text in texts]

    async def embed_query(self, text: str, *, prefix: str) -> list[float]:
        return self._vector(f"{prefix}{text}")

    async def describe(self) -> ProviderInfo:
        return ProviderInfo(
            provider="deterministic",
            model="deterministic-test",
            dimensions=self._dimensions,
            model_digest="deterministic",
        )


@dataclass(frozen=True, slots=True)
class PrefixObservation:
    """What a probe actually saw, for an operator to read and decide on."""

    document_prefix: str
    query_prefix: str
    dimensions: int
    prefixed_vs_unprefixed_similarity: float
    document_vs_query_similarity: float
    prefix_changes_vector: bool


def cosine_similarity(left: list[float], right: list[float]) -> float:
    dot = sum(a * b for a, b in zip(left, right, strict=True))
    left_norm = math.sqrt(sum(a * a for a in left))
    right_norm = math.sqrt(sum(b * b for b in right))
    if left_norm == 0.0 or right_norm == 0.0:
        return 0.0
    return dot / (left_norm * right_norm)


class PrefixProbe:
    """Empirically establishes what a provider does with task prefixes.

    This exists because guessing is not acceptable. ``scripts/probe_embedding_
    prefixes.py`` runs it against the real host and prints what it observed; an
    operator then registers the space with the prefixes they have decided on,
    and that decision is recorded with a subject and a timestamp.
    """

    SAMPLE_DOCUMENT = "VLAN 100 is the management VLAN on the core switch."
    SAMPLE_QUERY = "which VLAN is used for management?"

    def __init__(self, provider: EmbeddingProvider) -> None:
        self._provider = provider

    async def observe(self, document_prefix: str, query_prefix: str) -> PrefixObservation:
        bare = await self._provider.embed_query(self.SAMPLE_DOCUMENT, prefix="")
        prefixed = await self._provider.embed_query(
            self.SAMPLE_DOCUMENT, prefix=document_prefix
        )
        query = await self._provider.embed_query(self.SAMPLE_QUERY, prefix=query_prefix)
        similarity = cosine_similarity(bare, prefixed)
        return PrefixObservation(
            document_prefix=document_prefix,
            query_prefix=query_prefix,
            dimensions=len(bare),
            prefixed_vs_unprefixed_similarity=similarity,
            document_vs_query_similarity=cosine_similarity(prefixed, query),
            # A provider that ignores prefixes returns the identical vector.
            # That is a legitimate answer - it just has to be a *known* one.
            prefix_changes_vector=similarity < 0.999999,
        )


__all__ = [
    "DeterministicEmbeddingProvider",
    "EmbeddingDimensionError",
    "EmbeddingProvider",
    "EmbeddingUnavailableError",
    "OllamaEmbeddingProvider",
    "PrefixObservation",
    "PrefixProbe",
    "ProviderInfo",
    "cosine_similarity",
    "l2_normalise",
]
