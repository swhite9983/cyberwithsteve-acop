# Milestone 2 — Authoritative CMDB and digital-twin foundation

**Status:** Implemented; local checks green; not yet deployed to `acop-01`
**Date:** 2026-09-03
**Builds on:** Milestone 1 (`cc9b715`)

## Objective

Build the store every later milestone reads from and writes to: assets with
resolvable identity, typed facts with provenance and history, reversible trust,
and typed relationships. Nothing that touches infrastructure.

This is the milestone where the brief's central rule stops being a policy and
becomes a schema: **AI conclusions must never silently overwrite authoritative
facts.**

## What was built

| Area | Where |
|---|---|
| Vocabularies and code registries | `src/acop/models/vocabulary.py` |
| Shared provenance / validity columns | `src/acop/models/provenance_mixin.py` |
| Asset and identifier models | `src/acop/models/asset.py` |
| Fact and attestation models | `src/acop/models/fact.py` |
| Relationship model | `src/acop/models/relationship.py` |
| Migrations | `migrations/versions/0002`, `0003`, `0004` |
| Identity resolution | `src/acop/services/identity_resolver.py` |
| Fact write path and trust transitions | `src/acop/services/fact.py` |
| Relationship write path and traversal | `src/acop/services/relationship.py` |
| Asset lifecycle and pagination | `src/acop/services/asset.py` |
| Predicate-aware secret screen | `src/acop/services/value_screen.py` |
| Shared provenance rules | `src/acop/services/provenance.py` |
| REST API (21 endpoints) | `src/acop/api/routes/cmdb_*.py` |

Design records: ADR-0006 (identity), ADR-0007 (facts), ADR-0008
(relationships), ADR-0009 (denial durability). Schema reference:
`docs/database/cmdb-schema.md`.

## The five load-bearing decisions

1. **Identity is resolved before every write, and ambiguity is refused.** A
   multi-match returns 409 and writes nothing. Refusing is recoverable; merging
   two machines into one record is not. (ADR-0006)

2. **Facts are typed, interval-versioned and append-only.** A changed value
   closes the old interval and inserts a new row pointing backwards at what it
   replaced. An unchanged re-assertion writes no row at all — the property that
   makes a five-minute discovery sweep survivable. (ADR-0007)

3. **Trust is derived, exclusive, and reversible.** `statement_class` and the
   initial `verification_status` are computed from the source; no endpoint
   accepts either as input. One live authoritative claim per
   `(asset, predicate, kind)`, so two humans cannot bless contradictory values.
   Revocation withdraws standing without deleting anything, and every
   transition is recorded immutably in `fact_attestation`. (ADR-0007)

4. **Relationships are edges, not facts.** Typed, directed, with inverse labels
   and endpoint-type rules; symmetric edges canonicalised to one row. A
   predicate that names a relationship type is rejected, so an edge cannot
   exist in two contradictory representations. (ADR-0008)

5. **Denials are recorded outside the transaction they refuse.** Found by the
   HTTP tests, not by review: a `DENIED` row written inside the request session
   was rolled back by the very exception it documented. (ADR-0009)

## Security properties, and where they come from

| Requirement | Mechanism | Framework |
|---|---|---|
| Secrets never stored | `FactValueScreen` rejects secret-bearing predicates, redacts nested JSON keys, caps sizes | CIS 3.x; NIST `PR.DS-1` |
| AI cannot become authoritative | `ck_asset_fact_inference_not_authoritative` — a database refusal, not a review step | NIST `PR.AC-4`; Least Privilege |
| Every mutation attributable | `Principal.to_audit_fields()` into `audit_event`; `fact_attestation` for trust | NIST `PR.PT-1`; CIS 8.2 |
| Refusals recorded | `AuditService.record_denial` on an independent connection | CIS 8.2; NIST `DE.CM-1` |
| Trust changes need a higher role | `ApproverPrincipal` on verify / revoke; operator cannot self-verify | Separation of Duties; NIST `PR.AC-4` |
| Nothing destructive is reachable | No `DELETE` verb anywhere; retirement is a `POST` | Defence in Depth |
| Caller cannot assert its own trust | `verification_status` and `statement_class` absent from every input schema | Zero Trust — never trust the claim, derive it |

**Where enterprise practice and this home lab differ.** An enterprise CMDB at
this point would add a reconciliation engine with source precedence rules, an
approval workflow with segregation-of-duties enforcement across separate
identity groups, and audit shipping to an external immutable store (WORM or a
SIEM the CMDB cannot write to). ACOP has the schema for the first, defers the
second to Milestone 11, and defers the third to Milestone 10 — all recorded in
`BACKLOG.md`. The single-node PostgreSQL is also the disaster-recovery gap: the
audit log is append-only *within* the application, but an operator with
database credentials can still rewrite it. That is an accepted home-lab risk
with a named milestone, not an oversight.

## API surface — 21 endpoints, no DELETE

| Method | Path | Role |
|---|---|---|
| POST | `/cmdb/assets` | operator |
| POST | `/cmdb/assets/resolve` | operator |
| GET | `/cmdb/assets` | viewer |
| GET | `/cmdb/assets/{asset_id}` | viewer |
| PATCH | `/cmdb/assets/{asset_id}` | operator |
| POST | `/cmdb/assets/{asset_id}/retire` | operator |
| GET | `/cmdb/assets/{asset_id}/identifiers` | viewer |
| POST | `/cmdb/assets/{asset_id}/identifiers` | operator |
| POST | `/cmdb/identifiers/{identifier_id}/retire` | operator |
| POST | `/cmdb/assets/{asset_id}/facts` | operator |
| GET | `/cmdb/assets/{asset_id}/facts` | viewer |
| GET | `/cmdb/assets/{asset_id}/facts/{predicate}/history` | viewer |
| GET | `/cmdb/assets/{asset_id}/facts/{predicate}/effective` | viewer |
| GET | `/cmdb/assets/{asset_id}/conflicts` | viewer |
| POST | `/cmdb/assets/{asset_id}/desired-facts` | operator |
| GET | `/cmdb/facts/{fact_id}/attestations` | viewer |
| POST | `/cmdb/facts/{fact_id}/verify` | approver |
| POST | `/cmdb/facts/{fact_id}/revoke` | approver |
| POST | `/cmdb/relationships` | operator |
| GET | `/cmdb/relationships` | viewer |
| POST | `/cmdb/relationships/{relationship_id}/retire` | operator |
| GET | `/cmdb/assets/{asset_id}/related` | viewer |

`GET .../effective` reports its basis — `AUTHORITATIVE_SINGLE`, `UNANIMOUS`
(excluding inference), or `UNRESOLVED`. It never picks a winner. Milestone 8
replaces only the `UNRESOLVED` branch.

## Verification

| Gate | Result |
|---|---|
| `ruff check` | All checks passed |
| `ruff format --check` | 82 files already formatted |
| `mypy` (strict) | Success — no issues in 55 source files |
| Unit tests | passing |
| Integration tests (live PostgreSQL 16) | passing |
| Full suite | 249 passed, 4 skipped |
| `alembic check` | No new upgrade operations detected |
| Migration round trip | `head` → `base` → `head` clean; only `alembic_version` remains at base |

Constraint proofs are raw SQL in `tests/integration/test_cmdb_constraints.py`,
so they test the database rather than the ORM's opinion of it. The seven-event
walkthrough in `test_cmdb_lifecycle.py` is the scenario that surfaced two of
the design's must-fix items during design review.

## Explicitly not built

Proxmox / Cisco / Docker / Windows discovery, Prometheus, SSH, collectors, RAG,
pgvector usage, Neo4j, recursive traversal, an effective-value resolver, the
drift engine, remediation, the tool framework, topology visualisation, and any
frontend. `pgvector` remains installed and unused; `btree_gist` is the only
extension this milestone actually depends on.
