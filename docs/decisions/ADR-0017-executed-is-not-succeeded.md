# ADR-0017: `EXECUTED` is not `SUCCEEDED`, and `EXECUTION_INDETERMINATE` is not `FAILED`

**Status:** Accepted
**Date:** 2026-09-04
**Milestone:** 4

## Context

An autonomous platform that acts on infrastructure has to answer one question
honestly: **did the change happen?** Two situations make that hard, and both
are ordinary rather than exotic.

The first is an adapter reporting success for a change that did not take
effect. `POST /services/nginx/restart` returns 200 and the service is not
running afterwards. The restart API told the truth about what it did — it
issued the restart — and the outcome is still wrong.

The second is a worker that disappears mid-execution: an OOM kill, a node
eviction, a container that lost its connection after the adapter call went out
and before the result came back. The adapter *was* called. Whether the change
landed is genuinely unknown.

A state machine with only `SUCCEEDED` and `FAILED` cannot express either
situation without lying.

## Decision

Two distinctions in `InvocationState` are load-bearing.

### `EXECUTED` is not `SUCCEEDED`

`EXECUTED` means the adapter reported success. `SUCCEEDED` means the intended
change was observed to be in effect. Between them sits `VALIDATING`, and the
observation is made by `ToolAdapter.validate` — a **separate observation**,
never a re-read of what `execute` returned.

- Without validation (`validation_required = False`), `EXECUTED → SUCCEEDED` is
  immediate, and that is honest: the tool declared there is nothing independent
  to observe.
- With validation, an entirely separate observation decides, and the adapter's
  own return value plays no part in it.

Import rule 2 makes `validation_required` mandatory for Class 2 and Class 3, so
no change-class tool can opt out. A change nobody checks is a change nobody
knows happened.

`ValidationOutcome` has three members, not two. `NOT_CONFIRMED` ("we checked
and it was wrong") and `INDETERMINATE` ("we could not check") both lead to
`VALIDATION_FAILED`, because both mean a human must look — but the column keeps
the difference, because the human responses differ.

### `EXECUTION_INDETERMINATE` is not `FAILED`

When a worker is lost mid-execution, `InvocationReaper` finds an `EXECUTING`
row whose lease has expired. There are three ways to record that and only one
is honest:

| Recording | Why it is wrong |
|---|---|
| `FAILED` | False, and dangerous: it invites a retry that double-executes |
| `SUCCEEDED` | False in the other direction, and worse — a change that never happened is now believed to have happened |
| `EXECUTION_INDETERMINATE` | Says exactly what is true |

`EXECUTION_INDETERMINATE` is **terminal** and **never retried automatically**.
It is closed only by an *appended* reconciliation record — a separately
attributed human judgement written to
`tool_invocation_reconciliation`, which never rewrites the execution event and
never changes `tool_invocation.state`.

A lost **validation** lease gets a different answer: `VALIDATION_FAILED` with
`validation_outcome = INDETERMINATE`. The adapter already reported success, so
the execution outcome is known; what is unknown is the confirmation.

### The deliberate non-goal

Reconciliation is **not an incident or workflow system**. There is no
assignment, no status, no queue, no notification, no reopening. One row: who,
when, what they concluded, why, and an optional reference to whatever evidence
they looked at.

## Rationale

**[Fact] Validation must be a separate observation or it confirms nothing.** An
adapter that "validated" by echoing its own `execute` return value would agree
with itself in every case, including the one case that matters. The simulated
adapter's `validate` reads simulated world state and never consults what
`execute` returned; `test_executed_is_not_succeeded_when_validation_disagrees`
drives the gap with an asset named `sim-stays-down`, where the restart reports
success and the service is not running afterwards. The invocation ends
`VALIDATION_FAILED`.

**[Fact] `validation_delay_seconds` exists because a change often needs a
moment to become observable.** Checking instantly and reporting `NOT_CONFIRMED`
would be a race dressed up as a finding. Waiting is part of validating
honestly.

**[Fact] The retry rule follows from the same honesty.** Only
`ADAPTER_UNAVAILABLE` and `TARGET_UNAVAILABLE` are ever retried — the two
categories where "it did not happen" is knowable — and only when the tool also
declares `adapter_idempotent`. A **timeout is deliberately not retryable**: a
request that timed out may still be in flight on the far side, so retrying
could act twice. Import rule 8 additionally pins `max_attempts = 1` for any
`NON_IDEMPOTENT` tool, so the safe configuration cannot be typed wrong.

**[Fact] Retries are the framework's decision, never the adapter's.** The
adapter reports an `AdapterOutcome`; the dispatcher maps it to a state and
decides whether to try again. An adapter that could set the state could report
success for a change that did not happen.

**[Opinion] `EXECUTION_INDETERMINATE` is the state most likely to be argued
away by a future contributor**, on the grounds that it complicates dashboards
and that "it probably failed". That instinct is exactly the failure this exists
to prevent, and it is why the state is in `TERMINAL_STATES` and has no outgoing
transition in `LEGAL_TRANSITIONS`. Getting back to a determinate answer
requires a person to go and look, which is the correct amount of work for a
change of unknown status on production infrastructure.

**[Best practice] The determination is appended, not applied.** Rewriting the
execution event once a human has looked would replace evidence with a
conclusion, and an auditor could no longer tell which was which. The record
reads as two facts — *ACOP did not know*, and *later, this named person
determined this* — with full four-field attribution on the second, matching the
Milestone 1 identity model. **Multiple reconciliations are allowed and are not a
mistake**: a first-look `UNKNOWN` followed a week later by `CONFIRMED_FAILED`
is a more honest history than one row edited twice.

**[Fact] Reconciliation is refused on any other state.** Offering it elsewhere
would invite people to "correct" outcomes ACOP is certain about, which is
precisely the mutation the append-only design exists to prevent.

**Where this maps.** NIST CSF `DE.AE-3` and `RS.AN-1` (analysis of detected
events); CIS Control 8 (audit log management) — a log that records only
determinate outcomes omits the cases an investigation starts from.

## Alternatives considered

**Collapsing `EXECUTED` into `SUCCEEDED`.** Rejected: it makes "the restart API
returned 200" indistinguishable from "the service is running". That is the
single most common way an automation platform reports a change it did not make,
and the distinction costs one state and one adapter method.

**Recording a lost worker as `FAILED`.** Rejected, and this is the concretely
dangerous option. `FAILED` reads as "nothing happened", and the natural next
action — by an operator or by a future auto-retry — is to run it again. For
`test.security.rotate_key` that produces a second key; for a non-idempotent
change it produces a second change. The state exists specifically so that no
automatic path can lead from "we do not know" to "try again".

**Recording a lost worker as `SUCCEEDED`, on the grounds that the adapter was
called and usually works.** Rejected as the worse error of the two. A false
`FAILED` at least prompts someone to look; a false `SUCCEEDED` is believed and
closed, and the estate diverges from the record silently.

**Automatic reconciliation — re-running `validate` against an indeterminate
invocation to work out what happened.** Superficially attractive and rejected
for two reasons. First, it is not sound in general: `validate` observes present
state, and for a non-idempotent tool present state does not distinguish "the
change landed once" from "it landed and something else changed it back". For
`rotate_key`, a key being present does not say which execution created it.
Second, it would make the indeterminate state auto-clearing, which removes
exactly the human attention the state exists to demand. **[Opinion]** A
validation probe is a reasonable *aid* to a person reconciling, and belongs in
the operator guide, not in an automatic path.

**Mutating the invocation state on reconciliation — `EXECUTION_INDETERMINATE →
SUCCEEDED`.** Rejected. It destroys the distinction between what ACOP observed
and what a person concluded. It would also mean the state machine could move
out of a terminal state, which every other part of the framework relies on not
happening.

**Building reconciliation as a workflow — assignment, queue, notifications,
reopening.** Rejected as scope that belongs to incident management (a later
milestone) and would arrive here without the model to support it. The narrow
version — one attributed row, appended — is complete for the question being
asked, and a workflow built on top of it later loses nothing.

## Consequences

- `TERMINAL_STATES` contains ten members, including both `SUCCEEDED` and
  `VALIDATION_FAILED`. A tool that executed and failed validation is finished;
  the framework will not act on it again.
- `POST /tool-invocations/{id}/reconcile` is approver-scoped and returns 201.
  It appends an event whose `from_state` and `to_state` are both
  `EXECUTION_INDETERMINATE`, because the state did not change and the history
  must not suggest it did.
- `evidence_ref` is passed through Milestone 1's `redact` before storage. It is
  the one field in the milestone a human types freely, so it is the one place a
  secret could plausibly arrive by accident.
- Dashboards must handle a terminal state that is neither success nor failure.
  That is a real cost, and it is the correct one: the alternative is a
  dashboard that is confidently wrong.
- `rollback_hint` is advisory text captured before the change. **ACOP performs
  no automatic rollback** — it is a note for a human, not a mechanism.
