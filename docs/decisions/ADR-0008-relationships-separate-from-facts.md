# ADR-0008: Relationships as typed edges in their own table, not as facts

**Status:** Accepted
**Date:** 2026-09-03
**Milestone:** 2

## Context

ACOP has to record that a VM runs on a host, that a switch port connects to a
NIC, that a container depends on a database. `asset_fact` already has an
`ASSET_REF` value type, so an edge *could* be stored as a fact whose value is
another asset's id. The question is whether it should be.

The brief also rules out Neo4j for the MVP, so whatever is chosen has to work
in PostgreSQL and has to still work when Milestone 8 adds multi-hop traversal.

## Decision

Relationships live in `asset_relationship`: a typed, directed edge with the
same provenance and validity-interval columns as a fact, plus endpoint-type
rules and canonical ordering for symmetric edges.

Relationship names are reserved: a predicate that matches a registered
relationship type is **rejected** at the schema boundary
(`RESERVED_RELATIONSHIP_PREDICATES`).

Traversal in Milestone 2 is depth 1 only. `GET /cmdb/assets/{id}/neighbours`
applies the inverse label so a VM reads `RUNS_ON` its host and the host reads
`HOSTS` the VM — from the same single stored row.

## Rationale

**Why a separate table.** An edge has properties an EAV row cannot express
without inventing conventions:

| Property | In `asset_relationship` | As a fact |
|---|---|---|
| Two endpoints | Two FK columns, both indexed | One column, one implied |
| Inverse reading | `EdgeSpec.inverse_label` | Nothing — the reverse question needs a scan and a naming convention |
| Endpoint-type rules | `EdgeSpec.permits()` | Not expressible |
| Symmetry | Canonical ordering, enforced by CHECK | Two rows, or a convention nobody enforces |
| Traversal | Index on each direction | Index on `value_asset_id`, then filter by predicate string |

**[Opinion]** The decisive one is the inverse reading. "What runs on this host"
is the single most common question a CMDB is asked, and as a fact it becomes a
scan filtered by a string predicate with a naming convention holding it
together. As an edge it is an index lookup.

**Why reserve the predicate names.** Two representations of the same edge is
silent corruption of exactly the kind the brief's fact-integrity rules exist to
prevent: `runs_on` as a fact and `RUNS_ON` as an edge would disagree, and no
query could tell which was right. Rejecting the predicate makes the second
representation impossible rather than merely discouraged.

**Why canonicalise symmetric edges.** **[Fact]** `A CONNECTED_TO B` and
`B CONNECTED_TO A` describe one cable. Storing both makes any count wrong by a
factor of two. Deduplicating at read time is a permanent tax on every query and
is forgotten exactly once. Ordering by `min(uuid), max(uuid)` and enforcing it
with `ck_asset_relationship_symmetric_order` makes the duplicate unstoreable.

**Why no authority index on edges.** Facts need one because two verified
sources can hold different *values*. An edge's endpoints are part of its key,
so two verified claims about the same edge necessarily agree about the thing
that matters. Adding the index would constrain nothing and cost writes.

**Why depth 1 now.** **[Assumption]** Recursive traversal, blast-radius
queries, and topology visualisation are Milestone 8. Depth 1 is what the API
needs today, and it uses the same indexes recursion will use, so nothing about
this decision has to be revisited to add depth later.

## Alternatives considered

**Store edges as `ASSET_REF` facts.** Rejected, per the table above. The
`ASSET_REF` value type is retained for facts that genuinely *reference* an
asset without being an edge (`backup.target_asset`, `monitored_by`), which is a
different thing.

**Neo4j.** Explicitly out of scope for the MVP, and correctly so: the estate is
hundreds of nodes, not millions. **[Fact]** PostgreSQL recursive CTEs handle
multi-hop traversal at this scale without difficulty. Introducing a second
datastore would mean a second backup, a second upgrade path, a second
consistency problem, and a synchronisation job — for a graph small enough to
fit in memory.

**Materialised closure table.** Rejected: premature at this size, and it would
need invalidating on every edge change.

**Untyped edges with a free-text label.** Rejected. Endpoint-type validation is
what stops "this VLAN runs on that container" from being stored, and a free
label cannot be validated.

## Consequences

- One cable, one row, whichever direction it was reported from.
- The reverse question is an index lookup with a correct label.
- An edge cannot be expressed twice, in two shapes, with two answers.
- Multi-hop traversal is additive in Milestone 8: the storage does not change.
- `EdgeSpec` grows as new asset types arrive. That is a code change with no
  migration, by design.
