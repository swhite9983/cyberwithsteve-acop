# Knowledge schema reference (Milestone 3)

Ten tables, in two families that never mix: a **process** family recording what
was submitted and what happened to it, and a **canonical** family holding
content that passed the security gate. ADR-0013 explains why the boundary
exists; this page is the reference.

Migrations: `0005_knowledge_core` (eight tables), `0006_embedding_spaces`
(pgvector extension, the space registry, the partitioned vector parent).

## Map

```
knowledge_source ──┬── knowledge_document ──┬── knowledge_document_version ──┬── knowledge_chunk
                   │        (current_version_id)      (supersedes_version_id)  │
                   │                                                          ├── knowledge_asset_mention ──► asset  (one-way)
                   │                                                          └── knowledge_embedding_d768
                   │                                                                 └── partition per embedding_space
                   └── knowledge_ingest_attempt ──┬── knowledge_finding
                                                  └── knowledge_finding_disposition
```

Solid arrows are foreign keys. The only edge leaving the knowledge family is
`knowledge_asset_mention.asset_id`, and no CMDB table points back.

## Canonical family

### `knowledge_source`

Where material comes from and how far it is trusted. Trust and classification
live here rather than on each document, so downgrading a source is one row
rather than a sweep, and both are inherited by every document, version and chunk
beneath.

| Column | Notes |
|---|---|
| `source_kind` | `SourceKind`. `INCIDENT_RECORD` / `CHANGE_RECORD` reserved, unused. |
| `trust_class` | `TrustClass`. `AUTHORITATIVE_POLICY` is approver-only to assign. |
| `sensitivity` | `PUBLIC` / `INTERNAL` / `CONFIDENTIAL`. Authoritative value. |
| `lifecycle_state` | CHECK: `(state = 'RETIRED') = (retired_at IS NOT NULL)` |
| `metadata` | Descriptive labelling. **Not** a fact store — no retrieval decision may depend on an unregistered key. |

### `knowledge_document`

One logical document within a source. `uq_knowledge_document_source_ref` is a
*partial* unique index on `(source_id, external_ref) WHERE lifecycle_state =
'ACTIVE'` — the analogue of Milestone 2's identity resolution, and what makes a
re-ingest resolve to the same document rather than duplicating it.

### `knowledge_document_version`

**Immutable.** One row per successful ingest of changed content.

| Column | Notes |
|---|---|
| `raw_content_hash` | SHA-256 of submitted bytes. Identical → `UNCHANGED`, no write. |
| `text_content_hash` | Hash after normalisation. Same text, different bytes → `UNCHANGED_TEXT`. |
| `parser_name` / `_version` | Recorded per version, so adding a parser later invalidates nothing. |
| `chunker_name` / `_version` / `_params` | The exact parameters that produced this version's chunks. |
| `supersedes_version_id` | Points backwards. History is a chain, never a rewrite. |
| `superseded_at` | The **one** permitted write to a historical row: a closure marker. |
| `screening_outcome` | `CLEAN` or `FLAGGED`. `QUARANTINED` is unrepresentable — see ADR-0013. |
| `created_by_attempt_id` | Every canonical version names the attempt that earned it. |

### `knowledge_chunk`

One retrievable passage; the anchor for every citation.

`document_id` and `source_id` are denormalised deliberately: they are retrieval
filter predicates, and a filter requiring a join can be neither an index
predicate nor a cheap count.

`lexeme` is a **generated** column — `to_tsvector('english', content)`,
`persisted=True`, with a GIN index. A generated column rather than a trigger
because PostgreSQL keeps it correct by construction and no code path can forget
it. The configuration is `LEXEME_CONFIG`, used by both the column definition and
every lexical query; changing it is a migration.

## Vector storage

### `embedding_space`

The registry of comparable vector populations. Its identity constraint is the
machine-readable definition of "same space":

```sql
UNIQUE (provider, model, model_digest, dimensions, distance_metric,
        normalize_vectors, document_prefix, query_prefix, truncation_policy)
```

`prefix_verified_at` / `prefix_verified_by_subject` are the ingestion and
retrieval gate. NULL means nobody has observed what the provider does with task
prefixes, and both refuse. See ADR-0011.

Exactly one default space, enforced by a partial unique index on
`is_default WHERE is_default`.

### `knowledge_embedding_d768`

```sql
CREATE TABLE knowledge_embedding_d768 (
    id uuid NOT NULL,
    embedding_space_id uuid NOT NULL,
    chunk_id uuid NOT NULL,
    source_id uuid NOT NULL,
    document_id uuid NOT NULL,
    embedding vector(768) NOT NULL,
    is_current_embedding boolean NOT NULL DEFAULT true,
    is_retrievable boolean NOT NULL DEFAULT true,
    sensitivity varchar(16) NOT NULL,
    input_token_estimate integer NOT NULL,
    was_truncated boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id, embedding_space_id)
) PARTITION BY LIST (embedding_space_id);
```

The primary key includes the partition key because PostgreSQL requires it.

**Two independent booleans, because they answer different questions.**
`is_current_embedding` — is this the live vector for this chunk in this space?
Re-embedding inserts new rows and flips old ones false, which is what makes
re-embedding non-destructive. `is_retrievable` — does this chunk take part in
default retrieval? False once its version is superseded or its document or
source retired.

Per partition, created at space registration:

- an **HNSW** index on `embedding vector_cosine_ops`
  `WHERE is_current_embedding AND is_retrievable` — lifecycle only, never
  classification (ADR-0011, ADR-0012);
- an **eligible** index on `(sensitivity, source_id, document_id)
  INCLUDE (chunk_id)` with the same predicate, which makes the population count
  and the exact fallback affordable.

`sensitivity` here is a denormalised copy of the source's. Retrieval requires
**both** to permit a row, which fails closed if they diverge; reclassifying a
source calls `resync_source_sensitivity` in the same transaction so they cannot
be observed apart.

`migrations/env.py` filters `knowledge_embedding_d\d+_.*` out of autogenerate —
partitions are runtime objects, and without the filter every `alembic check`
after the first registration would report them as tables to drop.

## Process family

### `knowledge_ingest_attempt`

Append-only. One row per submission, written **first** and on its own
transaction, so a submission about to be refused still leaves a record.

The rule, as a database invariant rather than a convention:

```sql
CHECK ((outcome IN ('CREATED','VERSIONED')) = (version_id IS NOT NULL))
CHECK ((outcome <> 'PENDING') = (finished_at IS NOT NULL))
```

### `knowledge_finding`

What a detector found — never what it found. `locator` is a position
("line 412, cols 18-64"); `match_fingerprint` is an HMAC-SHA256 with the
deployment salt. Findings belong to the *attempt*, the only thing guaranteed to
exist when a submission is rejected.

### `knowledge_finding_disposition`

An approver's judgement, scoped to one source, one external reference, one raw
content hash and one finding fingerprint. Append-only: a mistaken disposition is
corrected by a later row and the gate reads the most recent.

```sql
CHECK (disposition IN ('FALSE_POSITIVE','REMEDIATED_AT_SOURCE'))
```

Only `FALSE_POSITIVE` unblocks, and only those exact bytes for that exact
target.

## Mentions

### `knowledge_asset_mention`

| Constraint | Meaning |
|---|---|
| `(resolution = 'RESOLVED') = (asset_id IS NOT NULL)` | An unresolved mention cannot name an asset. |
| `resolution <> 'AMBIGUOUS' OR array_length(candidate_asset_ids, 1) > 1` | Ambiguity means more than one candidate, recorded. |
| `mention_source IN ('IDENTIFIER_MATCH','EXPLICIT')` | Two sources, and no third. No NLP, no fuzzy matching. |

`MENTIONABLE_NAMESPACES` is a code registry, not a column: `proxmox:vmid` and
`cisco:if-index` are bare integers, and "VLAN 100" in a runbook would otherwise
link the document to VMID 100 — textually exact, factually absurd.

## Identifier length

PostgreSQL truncates identifiers at 63 characters, silently, which turns a CHECK
constraint name into something a migration cannot later reference. Three
constraints carry deliberately shortened names for this reason:
`fk_kdv_supersedes_version_id_kdv`, `fk_kia_version_id_kdv`,
`fk_kfd_origin_attempt_id_kia`, plus the CHECK `successful_has_version`.
