# ADR-0005: Audit log in Milestone 1, typed core plus JSONB context

**Status:** Accepted
**Date:** 2026-09-03
**Milestone:** 1

## Context

Section 23 of the design brief requires that every AI action be auditable, and
lists eighteen fields to record — including several that describe subsystems
which do not exist until Milestone 4 or later (tool parameters, tool result,
approver identity, related incident, related change).

The brief places the tool framework at Milestone 4. Taken literally, the audit
log would arrive then.

## Decision

Create `audit_event` in Milestone 1, with a typed core plus a JSONB `context`
column. Do not pre-create nullable columns for concepts that do not yet exist.

### Why Milestone 1

- It is the one table every later subsystem writes to.
- It is append-only, so it will become the largest table in the database and
  the most disruptive to alter. Defining its shape before it holds data is
  materially cheaper than altering it at Milestone 11.
- Authentication events are themselves auditable, and authentication exists in
  Milestone 1 (see [ADR-0003](ADR-0003-provider-neutral-identity.md)). The table
  has a real consumer from the first day.

### The typed core

Fields that will be **queried or filtered** are real columns:

| Group | Columns |
|---|---|
| When | `occurred_at`, `recorded_at` |
| Who | `principal_subject`, `principal_type`, `principal_issuer`, `auth_method`, `source_address`, `user_agent` |
| What | `action`, `resource_type`, `resource_id`, `permission_class` |
| Result | `outcome`, `severity`, `message` |
| Correlation | `request_id` |

`occurred_at` and `recorded_at` are separate. Batch-ingested events (Milestone 6
onward) would otherwise corrupt incident timelines by recording ingestion time
as event time.

`permission_class` is a real column despite the tool registry not existing yet,
because access review queries will filter on it and adding an indexed column to
a large append-only table later is exactly the cost this ADR exists to avoid.

### The JSONB context

Everything else goes in `context`: tool parameters, tool results, evidence
references, whatever a future subsystem needs. When a field inside `context`
proves to need querying, the milestone that needs it adds an expression index or
a generated column — a cheap, additive change.

**Rationale:** pre-creating a dozen nullable columns for speculative concepts is
the alternative, and speculative columns accumulate and are rarely removed. A
JSONB column plus targeted indexing is the better trade at this scale.
**[Opinion]** This is a judgement call; the counter-argument is that JSONB is
less self-documenting than named columns, which is fair.

### Indexes

Four, each matching a query the platform will actually run:

| Index | Query it serves |
|---|---|
| `occurred_at` | "What happened during this window" — incident timelines, change validation |
| `(principal_subject, occurred_at)` | "What did this principal do" — access review |
| `request_id` | "Everything in this request" — the join between an AI request and the tool calls it produced |
| `(action, occurred_at)` | "How often has this action been taken" |

### Immutability

Three layers, because one is not enough:

1. No `updated_at` column on the model.
2. No update or delete method on `AuditService`. A test asserts the service's
   public surface is exactly `{record}`.
3. A database role without `UPDATE`/`DELETE` on this table — documented in
   [`../security/audit-immutability.md`](../security/audit-immutability.md),
   applied in the same milestone that introduces the secrets manager.

### Redaction

`context` is passed through the redaction filter before persistence, in addition
to the redaction in the logging pipeline. The audit log outlives log retention,
so a secret leaked into it is a longer-lived problem than one leaked to stdout.

### Failure policy

`AuditService.record` raises on failure rather than swallowing the error.
Callers decide:

- An action in a change-bearing permission class (Class 2 or 3) **must fail
  closed** — if it cannot be audited, it must not be executed. Enforced by the
  approval engine in Milestone 11; the contract exists now so that engine has
  something stable to build on.
- Informational events may log the failure and continue.

Silently discarding audit failures would defeat the purpose of the log, so it is
never the default.

## Consequences

- One table exists in Milestone 1 that nothing but `/whoami` and future
  subsystems write to. An integration test asserts it is the *only* domain
  table, guarding against speculative CMDB tables appearing early.
- Data inside `context` is not queryable without an index, and adding one is a
  small migration each time.
- The identity columns are denormalised strings rather than a foreign key, so
  changing the authentication backend cannot invalidate history.
