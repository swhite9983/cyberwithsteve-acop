# ADR-0016: One execution path, with one authoritative final gate

**Status:** Accepted
**Date:** 2026-09-04
**Milestone:** 4

## Context

The four permission classes have genuinely different requirements. Class 0
(`acop.system.health`) should answer in milliseconds and forcing a caller to
poll for it would be gratuitous. Class 3 (`test.security.rotate_key`) needs two
distinct approvers and must not execute until they have both agreed.

The obvious design gives them different code: a fast synchronous path for
read-only tools, a queued path with approval for change tools. It is the design
that first suggests itself, it is easy to write, and it is the one this ADR
rejects.

The second question is what authorization at request time actually
establishes. It establishes that the request was permissible **then**. Between
then and execution, an approval can be sought and granted, a tool can be
disabled during an incident, a capability tag can be added to the prohibited
registry in a release, and a stored request can be altered by anything with
`UPDATE` on the table.

## Decision

**There is exactly one execution path, and it is
`ExecutionDispatcher.execute_once`.** Class 0/1 and Class 2/3 differ only in
the *approval branch*, which lives entirely above `READY`:

```
REQUESTED → AUTHORIZED ─┬─────────────────────────────────→ READY   (Class 0/1)
                        └→ AWAITING_APPROVAL → APPROVED  →  READY   (Class 2/3)
```

From `READY` onward every class travels identical code: claim, final gate,
adapter dispatch, output validation, audit. `POST /tool-invocations` is the
only entry point — there is no `/execute`, no `/run`, no command endpoint and
no per-class shortcut, and a unit test asserts the API surface is exactly
sixteen operations with no `DELETE`.

A Class 0 request may **await** that mechanism rather than returning 202:
`run_inline` wraps `execute_once` in `asyncio.wait_for`. That is waiting on the
shared mechanism, not bypassing it — same claim, same final gate, same audit,
same adapter dispatch. If the inline budget elapses first, the caller gets the
current state and polls; the work continues under the same lease. **No endpoint
anywhere calls an adapter directly.**

**The final execution gate is the last word.** Immediately after winning the
claim and before touching an adapter, `_final_gate` re-checks:

| # | Check | Refusal reason |
|---|---|---|
| 1 | The declaration still exists in the code registry | `capability_not_bound` |
| 2 | The registration's **current** lifecycle state, read now | `tool_retired` / `tool_disabled` |
| 3 | The declaration's **current** prohibition status | `prohibited_capability` |
| 4 | Execution-envelope integrity, recomputed from stored input | `envelope_integrity_failed` |
| 5 | Approval validity, where the snapshot requires it | `approval_missing` / `approval_expired` / `approval_envelope_mismatch` |

A failure at the gate is `EXPIRED` with `final_gate_decision = DENY`, **not**
`FAILED`. Both decisions are recorded on the invocation:
`authorization_decision` / `authorization_reason` from request time, and
`final_gate_decision` / `final_gate_reason` from execution time.

## Rationale

**[Fact] A second way to run something is a second place for a gate to be
missing.** This is the whole argument. The gate list above is five checks long
today and will grow — change-freeze windows and resource ownership are named in
`PolicyContext` as the next additions. Every one of them has to be added to
every path. With one path that is one edit; with two it is two edits and a
review that has to notice the second. **[Opinion]** The failure mode is not
that someone forgets on purpose; it is that the fast path was written first,
looks simple, and stops being reviewed with the same attention.

**[Fact] Request-time authorization is necessary and not sufficient, because
time passes.** The integration suite exercises this directly:
`test_disabling_a_tool_stops_work_already_approved` disables a tool after its
invocation has been approved, and the queued work is refused at the gate. A
control that only stops *new* requests during an incident does not stop the
incident.

**[Fact] The gate reads current state from the database and current prohibition
from code, and those are different sources on purpose.** Lifecycle is the one
thing the database owns (ADR-0014); prohibition is a code registry, so adding
a capability tag to `PROHIBITED_CAPABILITIES` in a release stops queued work as
well as new work.

**[Fact] `EXPIRED` rather than `FAILED` is a statement about the target.**
Nothing was attempted, so the target is in whatever state it was in.
Recording `FAILED` would assert that something was tried and did not work,
which is false and would mislead whoever reads the record next.

**[Fact] Concurrency needs no coordination.** The claim is a single
compare-and-set `UPDATE ... WHERE id = :id AND state = 'READY'`. Under READ
COMMITTED the second worker blocks on the row lock and, on waking, PostgreSQL
re-evaluates the predicate against the new committed row version, which no
longer says `READY`; it matches zero rows. That is EvalPlanQual, and it is why
there is no advisory lock, no `SELECT FOR UPDATE` round trip and no retry loop.
`attempt_count` is incremented in the same statement, so a lease obtained is
always an attempt recorded.

**[Fact] The invocation row is written on its own transaction**, not the
request's, and that is what makes one path serve every class. If it were
written in the request transaction, a Class 0 tool executing inline would have
to wait for a commit that has not happened, and the dispatcher — running on its
own connection — would find nothing. The same independence is what lets a
*refusal* survive the rollback of the request that was refused, which is the
[ADR-0009](ADR-0009-denial-records-survive-rollback.md) reasoning applied
again.

**[Best practice] Timeouts are enforced from outside.** `asyncio.wait_for`
cancels an adapter that ignores its deadline. An adapter cannot extend its own
timeout because it is not the thing holding the clock, and
`test_an_adapter_cannot_extend_its_own_deadline` proves it against a
deliberately slow simulation.

**Where this maps.** NIST CSF `PR.AC-4` and `DE.CM-7`; CIS Control 4.7
(managed enforcement of configuration); Zero Trust — the gate is a per-request
policy decision point re-evaluated at the moment of access rather than a
session-level grant.

## Alternatives considered

**A fast path for read-only tools.** The alternative this ADR exists to reject.
It is genuinely tempting: Class 0 and Class 1 need no approval, so most of the
machinery above `READY` is inert for them, and a direct call would be shorter.
Rejected because the machinery *below* `READY` is not inert for them — the
lifecycle check, the prohibition check and the envelope integrity check all
apply, and a fast path would either duplicate them or skip them. Skipping them
is the concrete harm: a Class 1 tool disabled mid-incident would keep running,
and a capability newly added to the prohibited registry would keep executing
from queued rows. Duplicating them gives two implementations to keep in step,
which is the same defect with an extra step. The inline convenience is
delivered instead by *awaiting* the shared path, which costs one `wait_for`.

**Skipping the final gate for Class 0.** Rejected for the same reason in
miniature. Class 0 tools touch nothing outside ACOP, so the argument is that
there is nothing to protect. But `acop.system.health` is still a capability that
can be disabled, and the gate is also what proves the stored request has not
been altered. A gate that runs for four classes out of five is a gate someone
has to reason about before trusting.

**Trusting the request-time decision and gating only at approval.** Rejected:
it moves the last check earlier, which is exactly the wrong direction. The
window between approval and execution is the longest window in the system —
approvals have TTLs measured in minutes to an hour — and it is the window in
which an incident-driven disable would land.

**A separate queue or broker for change-class work.** Rejected as
infrastructure bought to solve a problem the database already solves. The
partial index on `state = 'READY'` plus a compare-and-set claim gives exactly
the semantics needed, with no second durable store to keep consistent with the
invocation record and no second place a message can be lost. `worker.py` polls
at one second; if the queue ever justifies `LISTEN/NOTIFY`, the change is local
to that file.

**Letting the adapter decide the outcome state.** Rejected — the adapter
reports an `AdapterOutcome`, and the framework maps it to a state. An adapter
that could set the state could report success for a change that did not happen,
which is the subject of [ADR-0017](ADR-0017-executed-is-not-succeeded.md).

## Consequences

- `POST /tool-invocations` returns 200 with the result for a Class 0/1 tool
  that finished inline, and 202 for anything still in
  `AWAITING_APPROVAL`, `READY`, `EXECUTING` or `VALIDATING`.
- The route reloads the invocation with `populate_existing=True` before
  responding, because the service wrote it on another connection and a stale
  identity-map hit would show `REQUESTED` for something already finished.
- Every gate refusal is recorded on the invocation and audited, so "we allowed
  it then and refused it now" is a distinguishable record from "we refused it".
- Losing a claim is normal and is logged at info, not error: another worker, or
  the inline caller, got there first.
- `worker.stop()` deliberately does not cancel an in-flight execution. If the
  process is killed anyway, the lease expires and the reaper records
  `EXECUTION_INDETERMINATE` — which is exactly what happened.
