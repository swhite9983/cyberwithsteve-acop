# ADR-0009: Denial audit records are written outside the request transaction

**Status:** Accepted
**Date:** 2026-09-03
**Milestone:** 2 (amends the Milestone 1 audit contract)

## Context

Milestone 1 established `AuditService.record`, which writes into the caller's
session so that the audit row commits atomically with the change it describes.
For a successful mutation this is exactly right: an audited change that rolled
back would be a lie, and a change that committed without its audit row would be
unaccountable.

Milestone 2 introduced the first refusals: an identity conflict (409), a
rejected secret-bearing predicate (422). Each writes a `DENIED` audit record
and then re-raises. The HTTP integration tests found that the record was never
in the database.

The cause is the coupling that makes `record` correct for successes. The
request session rolls back on exception, and the denial row is inside it, so
the exception that *is* the event destroys the record of the event. The class
of events most worth keeping — the ones where ACOP said no — would have been
the only class never recorded.

This is not a Milestone 2 defect. It is a latent defect in the Milestone 1
audit contract that Milestone 2 was the first code to exercise.

## Decision

`AuditService.record_denial` writes the record on an independent connection, in
its own transaction, committed immediately. The route helpers dispatch on the
outcome: any event with `AuditOutcome.DENIED` takes this path automatically.

If the out-of-band write itself fails, it is logged at `error` level and
swallowed rather than raised.

## Rationale

**Why dispatch on outcome rather than at each call site.** A future denial
added by Milestone 4's tool registry or Milestone 11's approval engine will be
written by someone who has not read this ADR. Dispatching centrally means the
correct behaviour is the default, not a thing to remember. **[Best practice]**
Make the safe path the easy path.

**Why a separate connection rather than a savepoint.** A `SAVEPOINT` would
still be inside the outer transaction, which the session context manager rolls
back on the way out. Making savepoints work would require suppressing the
exception and re-raising it after the commit — more machinery, in the error
path, where it is hardest to test.

**Why swallow a failed denial write.** The module docstring forbids silently
discarding audit failures, and this is not silent: it emits a structured
`audit.denial_write_failed` error log. The substantive argument is that the
request is *already being refused*, so no unaudited change occurs — the failure
mode the fail-closed rule exists to prevent cannot happen here. Converting the
refusal into a 500 would replace the caller's actionable error with an
unrelated one and still produce no record. **[Opinion]** Losing the diagnostic
to gain nothing is the worse trade.

**Framework alignment.** **[Fact]** NIST CSF `PR.PT-1` and `DE.CM-1` both
concern audit-record generation and monitoring; CIS Control 8 (Audit Log
Management) 8.2 requires collection of audit logs including access denials. A
control that records only successful actions does not satisfy either — denial
records are the ones an investigation starts from.

## Alternatives considered

**Middleware that audits after the exception handler.** Attractive, and a
reasonable Milestone 4 generalisation. Rejected now because the specific
context (which identifiers clashed, which predicate was rejected) lives in the
route, and a middleware would have to reconstruct it from the exception. That
is more coupling, not less.

**A separate append-only denial table.** Rejected: two audit tables means two
retention policies, two query paths, and a reviewer who has to know to look in
both.

**Buffering denials in memory and flushing after the response.** Rejected: a
crash between refusal and flush loses the record, which is the failure this
decision exists to prevent.

## Consequences

- `AuditService` now has two public methods. The Milestone 1 guard test
  asserting a closed method set was updated, deliberately, to `{"record",
  "record_denial"}` — the set stays closed so adding a third is a decision
  someone has to make.
- Both remain append-only. Neither updates nor deletes.
- A denial consumes a second pooled connection briefly. At ACOP's scale this is
  immaterial; it is worth noting before a future load test finds it.
- The audit log now records what was refused, by whom, and why — which is the
  half of the record an investigation actually starts from.
