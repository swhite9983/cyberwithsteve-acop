# Backlog

Deferred work, with the gate answer that deferred it.

**The gate:** *If postponed, would this force a rewrite of a foundational
interface, or corrupt / ambiguously store data already being created?*
**YES** → fix now. **NO** → here.

Every item below answered **NO**. Items that answered YES were fixed in the
milestone that found them and are listed at the bottom for the record.

---

## Deferred from Milestone 2

### B-01 — Asset merge workflow
Duplicates will happen; ACOP refuses to merge automatically (ADR-0006).
`LifecycleState.MERGED` and `merged_into_id` exist in the schema, so a
human-approved merge is additive.
**Gate:** NO — the columns and constraints are already correct; only the
workflow is missing. **Target:** Milestone 5, when discovery starts producing
duplicates in volume.

### B-02 — Conflict resolution / effective-value resolver
`GET .../effective` reports `UNRESOLVED` when live sources disagree rather than
picking a winner.
**Gate:** NO — the honest answer is stored correctly today, and a resolver
replaces only the `UNRESOLVED` branch. Nothing stored has to change.
**Target:** Milestone 8.

### B-03 — Transaction-time dimension (full bitemporality)
The fact table records when something *was true*, not when ACOP *learned* it
was true. Useful for "what did we believe we knew".
**Gate:** NO — adding a second interval pair is a migration, and nothing
outside `FactService` reads the interval columns directly. **Target:**
Milestone 10, if incident reconstruction actually needs it.

### B-04 — Identifier namespaces as data
`IDENTIFIER_NAMESPACES` is a code registry, so a new namespace needs a deploy.
**Gate:** NO — moving to a lookup table later does not change how identifiers
are stored, only where the `unique_in_namespace` flag is read from.
**Target:** revisit in Milestone 5.

### B-05 — Relationship verify / revoke endpoints
Edges carry the same provenance columns as facts, but only facts have trust
transitions exposed over HTTP.
**Gate:** NO — the columns exist and are constrained; adding the endpoints is
additive. **Target:** Milestone 8, with traversal.

### B-06 — Retention policy for `audit_event` and touch events
`cmdb.fact.touch` is a distinct action specifically so it can be tiered
separately once collector volume is real, but no policy exists yet.
**Gate:** NO — the action name is already distinct, which is the part that
would have been expensive to add later. **Target:** Milestone 10.

### B-07 — Audit shipping to an external immutable store
Append-only is enforced in the application. An operator with database
credentials can still rewrite history.
**Gate:** NO — a shipper reads the existing table. **Target:** Milestone 10.
**Risk accepted meanwhile:** single-node PostgreSQL, single trust boundary.
Enterprise practice would be WORM storage or a SIEM the writer cannot modify.

### B-08 — Bulk / batch fact assertion
Collectors will assert hundreds of facts per sweep; today that is one request
each.
**Gate:** NO — a batch endpoint is a new route over the same service call.
**Target:** Milestone 5, driven by measured collector latency, not by guess.

### B-09 — `CHECK` constraints on enumerated columns
ADR-0004 stores enums as `VARCHAR` and validates in Python. ADR-0004 itself
says to reconsider if anything writes outside the service layer.
**Gate:** NO — nothing does yet. **Target:** reconsider at Milestone 5 (bulk
import is the plausible trigger).

### B-10 — Connection-pool sizing review
`record_denial` briefly holds a second pooled connection (ADR-0009). Immaterial
at this scale, worth measuring before it is not.
**Gate:** NO — a configuration value. **Target:** first load test.

### B-11 — Middleware-based denial auditing
ADR-0009 dispatches on outcome inside the route helpers. A middleware would
generalise it, but would have to reconstruct route-specific context from the
exception.
**Gate:** NO — and the current form is less coupled, not more.
**Target:** reconsider at Milestone 4 when the tool registry adds its own
denials.

### B-12 — `MAC_ADDRESS` as an identifier namespace
Retained but marked discouraged: MACs are duplicated by virtualisation, cloned
appliances and NAT, and are trivially spoofed. It is not globally unique, so it
never participates in identity matching.
**Gate:** NO — the `unique_in_namespace` flag already prevents it from
mismatching assets. **Target:** remove if it proves to add nothing by
Milestone 5.

---

## Answered YES and fixed inside Milestone 2

Recorded so the gate's decisions are reviewable, not just its deferrals.

| Finding | Why it could not wait |
|---|---|
| Single live authoritative claim per `(asset, predicate, kind)` | Without it the store could hold two contradictory values each blessed by a human — ambiguous data, immediately |
| Fact revocation | The constraint above makes verification exclusive; without revocation a mistaken verification would be permanent |
| Backward `supersedes_fact_id` | A forward pointer needs a historical row updated after the fact, which breaks append-only history at the root |
| `EXCLUDE USING gist` non-overlap | A unique index leaves closed intervals free to overlap, making "what did we believe on the 14th" ambiguous |
| `JSONB(none_as_null=True)` | Python `None` stored as JSON `null` is not SQL `NULL`, so the value-exclusivity CHECK rejected every non-JSON fact |
| Predicate-aware value screen | Milestone 1's key-based `redact()` cannot see an EAV *value*; `snmp.community` would have been stored and later fed to the model |
| Denial records written out of band (ADR-0009) | Every `DENIED` audit row was rolled back by the exception it documented — the record of refusals did not exist |
| `eager_defaults=True` on the declarative base | A SQL-side `onupdate` left `updated_at` expired after any UPDATE; serialising a just-updated row raised `MissingGreenlet`, breaking every PATCH and every retirement |
| `require_roles` returning a dependency callable | The Milestone 1 form did not typecheck under mypy strict and tripped ruff B008; Milestone 2 was its first consumer |
| Alembic post-write hook type (`console_scripts` → `exec`) | `make migration` always failed after writing the revision file, leaving an unformatted migration behind — found the first time a migration was generated |
