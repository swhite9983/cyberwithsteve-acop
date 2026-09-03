# ADR-0007: Typed facts with validity intervals, provenance, and reversible trust

**Status:** Accepted
**Date:** 2026-09-03
**Milestone:** 2

## Context

The brief's central requirement is that facts are separated from inference and
that AI conclusions never silently overwrite authoritative facts. That is a
statement about storage, not about prompt wording: if the store cannot
represent *who said this, how, when, and how much we trust it*, no amount of
care in the agent layer can compensate.

Three further requirements shape the table:

- Drift detection (Milestone 8) needs to compare desired against observed
  configuration in SQL.
- Incident timelines (Milestone 10) need to answer "what did we believe at
  14:05", which requires history, not a current-state row.
- Secrets must never reach the store, and predicates are attacker-adjacent
  input once collectors exist.

## Decision

**Entity–attribute–value, with typed value columns and a discriminator.** Six
value columns, exactly one populated, enforced by `ck_asset_fact_value_exclusive`.

**Validity intervals, append-only.** `valid_from` / `valid_to`, with
`valid_to IS NULL` meaning live. A changed value closes the old row and inserts
a new one carrying `supersedes_fact_id` — a **backward** pointer.

**An unchanged re-assertion advances `last_seen_at` and creates no row.** It is
still audited, as the distinct action `cmdb.fact.touch`.

**Two independent axes.** `verification_status` (trust) and `fact_kind`
(`OBSERVED_STATE` / `DESIRED_STATE`).

**Trust is derived, never supplied.** `statement_class` and the initial
`verification_status` are computed from `source_type` server-side. No endpoint
accepts either as input.

**Trust is reversible.** `POST /cmdb/facts/{id}/revoke` withdraws verification
or approval, and `fact_attestation` records every transition immutably.

**Predicates and values are screened before storage.** A secret-bearing
predicate is rejected loudly; nested JSON keys that look like secrets are
redacted; text and JSON are size-capped.

## Rationale

**Why typed columns rather than one JSON value.** **[Fact]** Comparing
`memory.total_bytes` between desired and observed in SQL requires the value to
be a number to the database. With a single JSON column, drift detection becomes
application code that pulls every fact into Python — and the same comparison
would then need reimplementing for reporting, for alerting, and for the agent
layer.

**Why a backward supersession pointer.** **[Fact]** A forward pointer is
unsatisfiable at write time: when a fact is superseded, its replacement does
not exist yet. Populating it later means updating a historical row, which is
precisely the mutation an append-only history exists to forbid.

**Why touch does not write a row.** **[Assumption]** A five-minute discovery
sweep across a few hundred assets with a few dozen predicates each produces on
the order of a million unchanged claims a day. Writing a row for each would
make history unreadable and storage a problem within weeks, for no information
gain — nothing changed. `last_seen_at` records the observation; the distinct
audit action keeps it separately retention-tierable once collector volume is
real.

**Why exclusion constraints and not just unique indexes.** **[Fact]** A partial
unique index constrains only the live row. Two *closed* intervals could still
overlap, making "what did we believe on the 14th" return two contradictory
answers. `EXCLUDE USING gist` over `tstzrange(valid_from, valid_to)` with
`btree_gist` for the scalar equality columns is the only mechanism PostgreSQL
offers that closes this.

**Why one live authoritative claim.** Without it, two sources could both be
`VERIFIED` with different values and the store would contain two mutually
exclusive truths, each apparently blessed by a human. The constraint forces the
disagreement to be resolved by a person rather than absorbed silently.

**Why revocation had to exist.** That constraint makes verification exclusive,
so a mistaken verification would otherwise be permanent. **[Best practice]**
Any authoritative assertion must be reversible with attribution — this is the
same principle as a reversing journal entry in accounting, and it is why the
revoke path does not delete or overwrite.

**Why `fact_attestation` rather than columns or the audit log.** Columns on
`asset_fact` are overwritten by a second verify → revoke cycle, so a repeat
sequence loses the earlier attribution. The audit log's retention policy is an
open Milestone 10 question, and accountability for a fact must not depend on a
decision nobody has made yet.

**Why the value screen exists at all.** **[Fact]** The Milestone 1 `redact()`
helper is key-based and screens structured log and audit context. It cannot see
an EAV row where the sensitive material is the *value* of a `value_text`
column and the key is just `value_text`. Without a predicate-aware screen,
`snmp.community` with value `public` would be stored, indexed, and later fed to
the model. This is the gap that closes it.

## Alternatives considered

**A JSONB attribute bag on the asset row.** Rejected. No provenance, no
history, no per-attribute trust, no SQL-comparable values — it fails every
requirement above simultaneously, and it is the design the brief's fact/
inference separation rule exists to prohibit.

**Separate tables per fact type.** Rejected: a new predicate would become a
migration, which makes discovery unworkable.

**Full bitemporality (valid time *and* transaction time).** Genuinely useful
for "what did we believe we knew" as distinct from "what was true". Rejected
for Milestone 2 as doubling the interval logic to answer a question nobody has
asked yet. Recorded in `BACKLOG.md`; adding a transaction-time dimension later
is a migration, not a rewrite, because nothing outside the fact service reads
the interval columns directly.

**Resolving conflicts automatically by confidence or source precedence.**
Rejected for Milestone 2. `GET .../effective` reports `AUTHORITATIVE_SINGLE`,
`UNANIMOUS` or `UNRESOLVED` and refuses to invent an answer. **[Opinion]** A
CMDB that reports "sources disagree" is more useful during an incident than one
that quietly picks a winner, and Milestone 8 can replace only the `UNRESOLVED`
branch without touching what is already stored.

**Storing the fact value in the audit context.** Rejected: it doubles the
storage of the field most likely to contain something sensitive, and the value
already has full history in `asset_fact`.

## Consequences

- Every fact carries where it came from, how much we trust it, and when it was
  true. The agent layer cannot be given an inference dressed as an observation.
- An AI-sourced row reaching authoritative status is refused by a CHECK
  constraint, not by review.
- History is queryable and provably non-overlapping.
- The store grows with *change*, not with observation volume.
- A new predicate needs no code change; a new predicate carrying a secret is
  rejected without one.
