# Milestone 3 — Knowledge and retrieval foundation

**Status:** Implemented; local checks green; **blocked on an operator step before
first production ingest** (see *Before this can run in production*)
**Date:** 2026-09-04
**Builds on:** Milestone 2 (`e44995b`)

## Objective

Give ACOP a corpus it can search and cite — runbooks, vendor documentation,
policy, configuration references — without letting any of it become
authoritative state.

This is the milestone where the platform first reads text written by someone
else and puts it in front of a model. Two properties matter more than retrieval
quality, and both are structural rather than procedural:

- **Knowledge is evidence, never state.** Nothing here writes to the CMDB.
- **Retrieved text is data, never instruction.** Milestone 3 executes nothing,
  and the answer schema has no field an instruction could use.

## What was built

| Area | Where |
|---|---|
| Knowledge vocabularies and registries | `src/acop/models/knowledge_vocabulary.py` |
| Source / document / version / chunk models | `src/acop/models/knowledge.py` |
| Embedding-space registry and partitioned vectors | `src/acop/models/embedding.py` |
| Migrations | `migrations/versions/0005`, `0006` |
| Secret and injection screening | `src/acop/services/knowledge/screening.py` |
| Deterministic heading-aware chunker | `src/acop/services/knowledge/chunking.py` |
| Embedding providers and the prefix probe | `src/acop/services/knowledge/embedding_provider.py` |
| Space registration and partition DDL | `src/acop/services/knowledge/spaces.py` |
| The single ingest write path | `src/acop/services/knowledge/ingest.py` |
| Catalogue, lifecycle and dispositions | `src/acop/services/knowledge/catalog.py` |
| Dense, lexical and hybrid retrieval | `src/acop/services/knowledge/retrieval.py` |
| Exact asset-mention linking | `src/acop/services/knowledge/mentions.py` |
| Evidence bundle and answer contract | `src/acop/services/knowledge/evidence.py` |
| REST API (22 operations, no DELETE) | `src/acop/api/routes/knowledge_*.py` |
| Acceptance check | `scripts/verify_milestone3.py` (`make verify-knowledge`) |
| Prefix probe | `scripts/probe_embedding_prefixes.py` (`make probe-embedding-prefixes`) |

Design records: ADR-0010 (evidence, not state), ADR-0011 (embedding-space
identity and partitioning), ADR-0012 (ANN vs the exact fallback), ADR-0013
(attempts vs immutable history). Schema reference:
`docs/database/knowledge-schema.md`.

## The six load-bearing decisions

1. **Knowledge never becomes CMDB state.** No code path writes to `asset`,
   `asset_identifier`, `asset_fact`, `asset_relationship` or
   `fact_attestation`. The foreign key points from knowledge into the CMDB and
   nothing points back, so the entire corpus could be dropped without touching
   an authoritative row. A test reads the module source to prove no such import
   exists. (ADR-0010)

2. **An embedding space is a composite identity, and the partition is the
   space.** Provider, model, digest, dimensions, metric, normalisation and both
   task prefixes together define comparability; dimension alone does not. Storage
   is dimension-typed and LIST-partitioned by space, so cross-space contamination
   is unrepresentable rather than filtered. Measured: a partial HNSW index
   predicated on a bind parameter silently degrades to `Seq Scan` under a generic
   plan; partitioning survives it. (ADR-0011)

3. **ANN is an optimisation; the exact fallback is the correctness floor.** Over-
   fetch is not a guarantee — 5 000 CONFIDENTIAL chunks nearer than one PUBLIC
   chunk defeats any multiplier. When the eligible result count falls short, a
   bounded `COUNT` distinguishes "the ANN missed rows" from "no more rows exist",
   and only the first triggers an exhaustive ranking, behind a `MATERIALIZED`
   barrier inside a savepoint. Every call reports whether its answer is complete
   or degraded. (ADR-0012)

4. **Screening happens before the first content write, and rejected content
   creates no canonical row.** A refused submission leaves an ingest attempt with
   detector names, line-and-column locators and salted fingerprints — and no
   document, version, chunk or embedding. The database enforces it:
   `(outcome IN ('CREATED','VERSIONED')) = (version_id IS NOT NULL)`. (ADR-0013)

5. **Injection is flagged, never blocked.** A security corpus contains material
   *about* injection. Blocking it would make the platform unable to hold the
   documentation that teaches it about the threat. The controls are structural
   instead: no tools execute, the answer schema cannot express a tool call, and
   evidence is rendered as numbered delimited blocks in a user-role message.

6. **Asset mentions are exact matches or explicit human assertions, and nothing
   else.** No entity extraction, no NLP, no fuzzy matching. A value matching two
   assets is recorded `AMBIGUOUS` with both candidates and no resolution — the
   same rule as Milestone 2's `IdentityConflictError`.

## Retrieval, in one picture

```
query ──embed──► ANN over the space's partition        (lifecycle predicate only)
                          │  candidates
                          ▼
                 eligibility filter, in SQL            (classification, trust,
                          │  eligible                   lifecycle, caller filters)
                          ▼
                 enough for k?  ── yes ──► return, strategy = ANN
                          │ no
                          ▼
                 bounded COUNT of the eligible population
                          │
            ┌─────────────┴─────────────┐
   population ≤ found              population > found
            │                             │
   strategy = ANN_COMPLETE        exact ranking behind
   (a short but complete          WITH eligible AS MATERIALIZED,
    answer)                       inside a SAVEPOINT
                                          │
                                 strategy = EXACT_FALLBACK
```

The lexical leg (`websearch_to_tsquery` + `ts_rank_cd` over a generated
`tsvector`) runs over the same eligible population, and the two are fused with
Reciprocal Rank Fusion at k=60. Hybrid inherits the dense leg's degradation
state: a lexical hit does not repair an incomplete dense leg.

## Classification policy

| Role | Reads |
|---|---|
| `viewer` | PUBLIC, INTERNAL |
| `operator` | PUBLIC, INTERNAL |
| `approver` | PUBLIC, INTERNAL |
| `admin` | PUBLIC, INTERNAL, CONFIDENTIAL |

`approver` is **not** a clearance. It is authority to approve workflow
transitions, and it reads exactly what an operator reads. `QUARANTINED` trust is
excluded for everyone including admin — it is not a classification, it is a
statement that the material is unfit to retrieve.

## What the audit trail stores for a search

Principal, request id, **query hash and length**, retrieval mode and strategy,
embedding space, filters, result chunk ids, result count, degradation state,
timing and outcome.

Not the query text. A search query is frequently the most sensitive thing about
a search — it describes what an operator was worried about — and the audit trail
is immutable, so anything written there cannot later be redacted. The hash keeps
repeated queries correlatable, which is what an investigation actually needs.

## Before this can run in production

**The embedding space must be probed and verified first.** A registered space
starts with `prefix_verified_at` NULL, and both ingestion and retrieval refuse
it. This is deliberate: embedding documents and queries with a mismatched task
prefix produces a corpus that returns confident nonsense and reports nothing
while doing it.

```
make probe-embedding-prefixes                      # observe the real model
POST /knowledge/embedding-spaces                   # register with chosen prefixes
POST /knowledge/embedding-spaces/{id}/verify-prefixes   # record the observation
make verify-knowledge                              # acceptance check
```

Set `ACOP_KNOWLEDGE_FINGERPRINT_SALT` before starting outside development —
startup refuses without it. Generate one with `openssl rand -hex 32`.

## Deliberately not built

PDF, DOCX, HTML and CSV parsing; OCR; a learned reranker; query rewriting;
multi-hop retrieval; generation of any kind. `parser_name` and `parser_version`
are recorded per version so adding a parser later invalidates nothing already
stored. `SourceKind.INCIDENT_RECORD` and `CHANGE_RECORD` are declared and unused
so Milestones 10 and 11 need no vocabulary migration.

Promotion of a document claim into a CMDB fact is deferred to a milestone that
can put a human in the loop. `KNOWLEDGE_FACT_SOURCE_PREFIX` reserves the
convention; nothing uses it.
