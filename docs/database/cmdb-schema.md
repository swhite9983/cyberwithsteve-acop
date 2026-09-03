# CMDB schema reference

**Milestone:** 2
**Revisions:** `0002` (assets, identifiers), `0003` (facts, attestations), `0004` (relationships)
**Status:** Implemented, migrations verified up and down against PostgreSQL 16

This is the reference for what the digital twin actually stores. Five tables,
one extension, and a set of constraints that are the real specification — the
service layer enforces the same rules, but the database is what makes them
true regardless of which code path writes.

## Tables

| Table | Purpose | Grows by |
|---|---|---|
| `asset` | Identity and lifecycle of a thing ACOP knows about | one row per asset, ever |
| `asset_identifier` | External names that identify an asset | one row per identifier claim |
| `asset_fact` | Typed claims about an asset, with validity intervals | one row per *distinct* claim interval |
| `fact_attestation` | Immutable trust transitions on a fact | one row per verify/approve/revoke |
| `asset_relationship` | Typed edges between assets, with validity intervals | one row per distinct edge interval |

`audit_event` (Milestone 1) is unchanged and remains the record of who did what.

## Extension

`btree_gist` is created by migration `0002`, before any dependent statement.
It is required by the two `EXCLUDE USING gist` constraints, which mix equality
on scalar columns with overlap on a `tstzrange`. The downgrade deliberately
does **not** drop it: another object could depend on it, and dropping a shared
extension during a rollback is a worse failure than leaving it installed.

## `asset` — identity and lifecycle only

The asset row carries what makes it *this* asset and nothing else. There is no
JSONB attribute bag. Attributes are facts, and facts need provenance, validity
and trust that a bag cannot express.

`display_name` is ACOP's own label for the asset. It is **not** the hostname.
The hostname is a fact (`network.hostname`), because it is observed, can be
wrong, can change, and can be disputed between sources — none of which a
column on the identity row can represent.

| Constraint | What it prevents |
|---|---|
| `ck_asset_merged_state` | A `MERGED` asset with no merge target, or a merge target on a non-merged asset |
| `ck_asset_retired_state` | `RETIRED` without `retired_at`, or `retired_at` without `RETIRED` |
| `ck_asset_no_self_merge` | An asset merged into itself |
| `fk_asset_merged_into_id_asset` | A merge target that does not exist |

`ix_asset_display_name_lower` supports case-insensitive prefix search;
`ix_asset_type_state` supports the list filters; `ix_asset_created_at` backs
keyset pagination.

## `asset_identifier` — how the outside world names it

| Index | Rule enforced |
|---|---|
| `uq_asset_identifier_asset_ns_value` | One asset cannot claim the same `(namespace, value)` twice |
| `uq_asset_identifier_live_unique` | **Partial**: within a globally-unique namespace, one live identifier value belongs to at most one asset |

The second is the deduplication guarantee. It is partial on
`unique_in_namespace AND retired_at IS NULL`, which does two things: it exempts
namespaces where collision is normal (a MAC address behind a NAT, a label
someone typed), and it frees the value for reuse when the identifier is
retired — a serial number really can move to a different chassis.

`unique_in_namespace` is denormalised onto the row rather than looked up from
the namespace registry, because a partial index cannot call a Python function.
The service writes it from `IDENTIFIER_NAMESPACES`; the index enforces it.

**[Fact]** PostgreSQL partial unique indexes cannot be `DEFERRABLE`. The
uniqueness therefore bites at statement time, not at commit, which is why the
identity resolver reads before it writes rather than relying on catching an
`IntegrityError`.

## `asset_fact` — the claim table

Entity–attribute–value with typed value columns and a discriminator, not a
single JSON column. The reason is that `memory.total_bytes` has to be
comparable and orderable in SQL for drift detection (Milestone 8) to be a query
rather than a program.

### Value storage

| Column | Used when `value_type` is |
|---|---|
| `value_text` | `TEXT` |
| `value_number` | `NUMBER` |
| `value_bool` | `BOOL` |
| `value_timestamp` | `TIMESTAMP` |
| `value_json` | `JSON` |
| `value_asset_id` | `ASSET_REF` |

`ck_asset_fact_value_exclusive` requires exactly one populated. `value_json`
uses `JSONB(none_as_null=True)` in the model: without it SQLAlchemy stores a
Python `None` as the JSON value `null`, which is **not** SQL `NULL`, so the
exclusivity check would count it as populated and reject every non-JSON fact.

`value_asset_id` exists so a fact can point at another asset without inventing
a second edge representation. It is a foreign key; a dangling reference is not
possible.

### Validity and history

`valid_from` / `valid_to`, with `valid_to IS NULL` meaning live. Nothing is
updated in place except to close an interval. A changed value closes the old
row and inserts a new one carrying `supersedes_fact_id` pointing **backwards**
at what it replaced.

The pointer is backwards because a forward pointer is unsatisfiable: at the
moment a fact is superseded, the row that supersedes it does not exist yet, so
a forward pointer would require an update to a historical row after the fact —
the exact mutation this table exists to avoid.

| Constraint | Rule |
|---|---|
| `ck_asset_fact_interval` | `valid_to` is null or after `valid_from` |
| `ex_asset_fact_no_overlap` | For one `(asset_id, predicate, fact_kind, source_id)`, intervals cannot overlap in time |
| `uq_asset_fact_live_claim` | **Partial**: one live claim per `(asset_id, predicate, fact_kind, source_id)` |
| `uq_asset_fact_live_authority` | **Partial**: one live *authoritative* claim per `(asset_id, predicate, fact_kind)` |

The exclusion constraint is the one that makes history trustworthy. A unique
index alone would let two closed intervals overlap, which would make "what did
we believe on the 14th" ambiguous — and that question is the entire point of
keeping history.

`uq_asset_fact_live_authority` is why revocation had to exist. Two sources may
each hold a live claim, but only one of them may be `VERIFIED` or `APPROVED` at
a time; without a way to withdraw that standing, a mistaken verification would
be permanent.

### Trust and kind — two independent axes

`verification_status` answers *how much do we trust this*. `fact_kind` answers
*is this what we see, or what we want*. They are separate columns because the
questions are separate: an approved desired state and a verified observation
are both trustworthy and mean opposite things.

| Constraint | Rule |
|---|---|
| `ck_asset_fact_inference_not_authoritative` | An `INFERENCE` row can never be `VERIFIED` or `APPROVED` |
| `ck_asset_fact_verified_attribution` | `VERIFIED` requires both who and when |
| `ck_asset_fact_approved_attribution` | `APPROVED` requires both who and when |
| `ck_asset_fact_desired_is_approved` | A `DESIRED_STATE` row must be `APPROVED` — intent nobody approved is not intent |
| `ck_asset_fact_predicate_format` | Lowercase dotted identifiers only |
| `ck_asset_fact_confidence` | Between 0 and 1 |

`ck_asset_fact_inference_not_authoritative` is the database-level expression of
the brief's central rule: **AI conclusions must never silently overwrite
authoritative facts.** An inference reaching authoritative status is not a bug
to be caught in review, it is a write that PostgreSQL refuses.

## `fact_attestation` — who trusted it, and who stopped

Append-only. One row per `VERIFY`, `APPROVE` or `REVOKE`, carrying the acting
principal's provider-neutral subject, the timestamp, an optional reason, and
the correlating request id.

Two alternatives were rejected:

- **Columns on `asset_fact`.** A verify → revoke → verify → revoke cycle
  overwrites the earlier attribution. The requirement is that both survive.
- **Relying on `audit_event`.** Audit retention is an open question deferred to
  Milestone 10. Accountability for a fact's trust must not depend on a
  retention policy that has not been decided.

Revocation therefore clears the *current* attribution columns on `asset_fact`
(the fact is no longer verified, and claiming otherwise would be false) while
the lineage survives here in full.

## `asset_relationship` — edges, not facts

Edges live in their own table because they are the one thing an EAV row models
badly: two endpoints, a direction, an inverse reading, and endpoint-type rules.

`RELATIONSHIP_SPECS` blocks the reverse problem — a relationship expressed as a
fact predicate (`runs_on` as a predicate string) is rejected at the schema
boundary, because two representations of the same edge is silent corruption.

| Constraint | Rule |
|---|---|
| `ck_asset_relationship_no_self` | No self-loops |
| `ck_asset_relationship_symmetric_order` | A symmetric edge must be stored with `source_asset_id < target_asset_id` |
| `uq_asset_relationship_live` | **Partial**: one live edge per `(source, target, type, coalesce(qualifier,''), source_id)` |
| `ex_asset_relationship_no_overlap` | Intervals for that same key cannot overlap |
| `ck_asset_relationship_interval` | Same interval rule as facts |
| `ck_asset_relationship_inference_not_authoritative` | Same inference rule as facts |
| `ck_asset_relationship_verified_attribution` | Same attribution rule as facts |

Canonical ordering is what makes a symmetric edge one row rather than two. `A
CONNECTED_TO B` and `B CONNECTED_TO A` are the same cable; storing both would
make "how many links does this switch have" wrong by a factor of two, and
deduplicating at read time would be a permanent tax on every query.

There is deliberately **no** authority index on relationships. The endpoints
are part of the key, so two verified claims about the same edge necessarily
agree about the thing that matters.

`coalesce(qualifier,'')` appears in the unique index because `NULL` is not
equal to `NULL` in SQL: without the coalesce, two live unqualified edges would
both be permitted.

## Provenance, shared by facts and edges

`ProvenanceMixin` and `ValidityIntervalMixin` are shared rather than duplicated
so the trust rules cannot drift apart. A rule that applies to a claim about an
asset should apply identically to a claim about a link between assets; two
copies of that logic would eventually disagree.

| Column | Meaning |
|---|---|
| `statement_class` | `OBSERVATION`, `ASSERTION` or `INFERENCE` — derived from the source, never supplied by the caller |
| `source_type` | How it was learned |
| `source_id` | Which specific collector, file or person |
| `confidence` | 0–1, stored as `Numeric(4,3)` |
| `verification_status` | Trust level |
| `verified_by_subject` / `verified_at` | Current verification attribution |
| `approved_by_subject` / `approved_at` | Current approval attribution |
| `first_seen_at` / `last_seen_at` | When the claim was first and most recently observed |

`statement_class` and `verification_status` are derived server-side from
`source_type`. No API accepts either as input — a caller cannot assert that its
own claim is trustworthy, which is the property that makes the AI inference
rule enforceable rather than aspirational.

## Enum storage

Every enumerated column is `VARCHAR`, per ADR-0004. Milestone 2 adds seven more
vocabularies and the reasoning is unchanged: adding a member stays a code
change with no migration.
