#!/usr/bin/env python3
"""Observe what an embedding provider actually does with task prefixes.

**Run this before the first canonical ingest into a new embedding space.** Not
as a formality - as the thing that makes the space usable at all.

Prefix-trained retrieval models (EmbeddingGemma among them) place prefixed and
unprefixed text in different regions of the vector space. If documents are
embedded with one prefix and queries with another that the model was not trained
to pair with it, the resulting vectors are silently incomparable: no error, no
warning, just a corpus that returns confidently irrelevant passages. Changing a
prefix after content exists has the same effect retroactively, which is why
prefix configuration is part of embedding-space *identity* rather than a tuning
knob.

The design refuses to guess. ``EmbeddingSpace.prefix_verified_at`` is NULL until
a human records what they observed, and both ingestion and retrieval refuse to
touch an unverified space. This script produces the observation.

What to look at in the output:

* ``prefix_changes_vector`` false means the provider ignores prefixes entirely.
  That is a legitimate answer - it just has to be a *known* one, and the space
  should then be registered with empty prefixes.
* ``prefixed_vs_unprefixed`` well below 1.0 means prefixes matter, so the
  document and query prefixes must be the pair the model was trained on.
* ``document_vs_query`` should be materially higher for the matching pair than
  for a mismatched one. The script tries several candidate pairings so the
  difference is visible rather than asserted.

Usage:
    python scripts/probe_embedding_prefixes.py
    python scripts/probe_embedding_prefixes.py \
        --base-url http://10.10.10.51:11434 --model embeddinggemma:latest

Exit codes:
    0  the provider responded and the observation is printed
    1  the provider could not be reached, or returned an unusable response
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from acop.services.knowledge.embedding_provider import (
    EmbeddingDimensionError,
    EmbeddingUnavailableError,
    OllamaEmbeddingProvider,
    PrefixProbe,
    cosine_similarity,
)

#: Candidate pairings to observe. Deliberately *candidates* - this script
#: reports what the installed model does, it does not assert which pairing is
#: correct. A human reads the numbers and decides.
CANDIDATES: tuple[tuple[str, str, str], ...] = (
    ("none", "", ""),
    (
        "embeddinggemma-documented",
        "title: none | text: ",
        "task: search result | query: ",
    ),
    ("generic-labelled", "passage: ", "query: "),
)


async def probe(base_url: str, model: str, dimensions: int | None) -> int:
    provider = OllamaEmbeddingProvider(
        base_url, model, expected_dimensions=dimensions, normalize=True
    )
    try:
        info = await provider.describe()
    except EmbeddingUnavailableError as exc:
        print(f"[ FAIL ] Could not reach the embedding provider: {exc}")
        print(f"         -> Check that {base_url} is reachable and {model} is pulled.")
        return 1
    except EmbeddingDimensionError as exc:
        print(f"[ FAIL ] {exc}")
        return 1

    print("Provider")
    print(f"  endpoint   : {base_url}")
    print(f"  model      : {info.model}")
    print(f"  digest     : {info.model_digest or '(not reported)'}")
    print(f"  dimensions : {info.dimensions}")
    print()
    if not info.model_digest:
        print(
            "[ WARN ] The provider reported no model digest. Ollama tags are "
            "mutable: re-pulling ':latest' can change weights, and vectors from "
            "different weights are silently incomparable under one tag name. "
            "Record whatever identity you can pin."
        )
        print()

    prober = PrefixProbe(provider)
    print("Observations")
    print(f"  sample document: {PrefixProbe.SAMPLE_DOCUMENT!r}")
    print(f"  sample query   : {PrefixProbe.SAMPLE_QUERY!r}")
    print()
    print(
        f"{'pairing':<28}{'prefixed_vs_unprefixed':>24}"
        f"{'document_vs_query':>20}{'changes_vector':>16}"
    )
    try:
        for name, document_prefix, query_prefix in CANDIDATES:
            observation = await prober.observe(document_prefix, query_prefix)
            print(
                f"{name:<28}"
                f"{observation.prefixed_vs_unprefixed_similarity:>24.6f}"
                f"{observation.document_vs_query_similarity:>20.6f}"
                f"{observation.prefix_changes_vector!s:>16}"
            )
    except (EmbeddingUnavailableError, EmbeddingDimensionError) as exc:
        print(f"\n[ FAIL ] {exc}")
        return 1

    # A control: an unrelated query should score materially lower than the
    # matching one. Without it, a high document_vs_query number proves nothing -
    # a degenerate model returns high similarity for everything.
    document_prefix, query_prefix = CANDIDATES[1][1], CANDIDATES[1][2]
    document = await provider.embed_query(
        PrefixProbe.SAMPLE_DOCUMENT, prefix=document_prefix
    )
    on_topic = await provider.embed_query(PrefixProbe.SAMPLE_QUERY, prefix=query_prefix)
    off_topic = await provider.embed_query(
        "what is the quarterly toner replacement schedule?", prefix=query_prefix
    )
    print()
    print("Control (documented pairing)")
    print(f"  on-topic query  : {cosine_similarity(document, on_topic):.6f}")
    print(f"  off-topic query : {cosine_similarity(document, off_topic):.6f}")
    print()
    print(
        "Next: register the space with the prefixes you have chosen, then record\n"
        "the verification against it:\n"
        "  POST /knowledge/embedding-spaces\n"
        "  POST /knowledge/embedding-spaces/{space_id}/verify-prefixes\n"
        "Until that second call, ingestion and retrieval both refuse the space."
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        default=os.getenv("ACOP_KNOWLEDGE_EMBEDDING_BASE_URL", "http://127.0.0.1:11434"),
    )
    parser.add_argument(
        "--model",
        default=os.getenv("ACOP_KNOWLEDGE_EMBEDDING_MODEL", "embeddinggemma:latest"),
    )
    parser.add_argument("--dimensions", type=int, default=None)
    args = parser.parse_args()
    return asyncio.run(probe(args.base_url, args.model, args.dimensions))


if __name__ == "__main__":
    raise SystemExit(main())
