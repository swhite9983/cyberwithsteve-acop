# ADR-0011: Embedding-space identity, and one LIST partition per space

**Status:** Accepted
**Date:** 2026-09-04
**Milestone:** 3

## Context

Two vectors can only be compared if they were produced under the same
conditions. The obvious reading of "same conditions" is "same number of
dimensions", and it is wrong in a way that produces no error: two different
768-dimensional models produce numerically compatible, semantically unrelated
vectors. Cosine distance between them is a real number that means nothing.

The initial Milestone 3 design conflated "one table per embedding space" with
"one table per dimension". Those are not equivalent, and the review that caught
it forced the question of what an embedding space actually *is*.

Three further conditions turn out to matter as much as the model:

- **Model weights, not the tag.** Ollama tags are mutable. Pulling
  `embeddinggemma:latest` twice can yield different weights under one name, and
  vectors from the two are silently incomparable.
- **Normalisation.** Whether ACOP L2-normalises before storing changes what the
  distance metric means.
- **Task prefixes.** Prefix-trained retrieval models place prefixed and
  unprefixed text in different regions of the space. Embedding documents with one
  prefix and queries with another, or changing a prefix between ingests, produces
  incomparable vectors with no error anywhere.

Measurements against the target PostgreSQL then constrained the physical layout:

| Layout | Result |
|---|---|
| One dimensionless `vector` column | Accepts mixed dimensions but **cannot be indexed at all** (`ERROR: column does not have dimensions`) |
| One table, one *partial* HNSW index per space | Works under a custom plan; silently degrades to `Seq Scan` under a **generic** plan — PostgreSQL cannot prove `space_id = $1` implies the index predicate |
| Dimension-typed table, LIST-partitioned by space | Survives the generic plan: `Append → Subplans Removed: 1 → Index Scan` |

The generic-plan case is production, not theory: SQLAlchemy with asyncpg uses
prepared statements, and PostgreSQL switches to a generic plan once a statement
has been executed enough times.

## Decision

An **embedding space** is the composite of provider, model, model digest,
dimensions, distance metric, normalisation flag, document prefix, query prefix
and truncation policy. That tuple is a unique constraint on `embedding_space`,
so two rows differing in any element are two spaces by construction.

Storage is **dimension-typed and space-partitioned**: `knowledge_embedding_d768`
is a parent table `PARTITION BY LIST (embedding_space_id)`, with one partition
and one HNSW index per registered space. Adding a dimension family is a migration
plus one entry in a code-level map; it changes no public interface.

Repository and API code references `embedding_space_id`. Physical relation names
are derived from a code-level template and never read from the database as an
identifier, and are not exposed outside persistence internals.

**A space starts unverified.** `prefix_verified_at` is NULL until a human runs
`scripts/probe_embedding_prefixes.py`, observes what the installed model actually
does, and records the result. Both ingestion and retrieval refuse an unverified
space.

## Rationale

**Why the partition *is* the space.** Cross-space contamination stops being a
filter that can fail and becomes unrepresentable: a query against one space's
partition cannot see another's rows, whatever the planner decides. A filter is
only as good as every query that remembers to apply it. **[Best practice]**
Prefer structural guarantees to procedural ones.

**Why the ANN index predicate carries lifecycle but not sensitivity.** Baking
authorization into an index welds storage to today's role map, and the policy has
to stay replaceable — a future OIDC claim- or scope-based policy must not require
a reindex. Sensitivity is filtered in the query instead. This was also measured
to matter: with sensitivity inside the ANN candidate CTE, the index scan becomes
authorization-aware, the ANN silently performs the eligibility filtering itself,
and the exact-fallback correctness floor is never exercised — non-deterministically,
depending on how far pgvector's scan happened to walk. See ADR-0012.

**Why the digest is part of identity.** It is the element most likely to be
forgotten and the most damaging when it is. Everything else about a
misconfiguration eventually produces a visible symptom; a re-pulled tag produces
a corpus that is half in one space and half in another, with one name.

**Why prefix verification is an attested human act.** A migration cannot verify
anything, and a default cannot be wrong loudly. The failure mode of guessing is a
corpus that returns confident nonsense and reports nothing, which is the hardest
class of failure to notice. **[Assumption made explicit]** ACOP does not assume
what EmbeddingGemma's prefixes are; it refuses to run until someone has looked.

## Consequences

- A fresh deployment cannot ingest until an operator has run the probe and
  recorded the observation. This is deliberate friction at exactly the point
  where a mistake is unrecoverable.
- Changing a prefix, normalisation choice or model on an existing space is not
  possible: it is a *new* space, and re-embedding the corpus into it.
- `migrations/env.py` filters runtime-created partitions out of autogenerate;
  without it every `alembic check` after the first space registration would
  report them as tables to drop.
- pgvector 0.8's `hnsw.iterative_scan` is applied when the running server has the
  setting and ignored when it does not, so one configuration spans 0.6 in
  development and 0.8.6 in production.
