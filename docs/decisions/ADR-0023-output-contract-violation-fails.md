# ADR-0023 — A declared-output contract violation fails the invocation

**Status:** Accepted
**Date:** 2026-09-06
**Milestone:** 4 (corrective, raised during Milestone 5 design review as B-M5-4)
**Supersedes part of:** ADR-0017 *Executed is not succeeded* — extends it rather
than contradicting it.

## Context

`ExecutionDispatcher._declared_output` is the single place an adapter's report is
checked against the tool's own code-declared `output_model`. It is what makes the
allow-list in `sanitize_output` meaningful: the model says what the tool returns,
and nothing outside it is published.

Until this decision, a payload that failed that model was answered with `{}`:

```python
except PydanticValidationError:
    logger.error("tools.output.contract_violation", ...)
    return {}
```

The caller published that empty dict as `result_summary`, moved the invocation to
`EXECUTED`, and — since no read-only tool sets `validation_required` —
`_after_execution` carried it straight to **`SUCCEEDED`**.

The original reasoning is in the docstring that was replaced, and it is worth
stating fairly because half of it is right:

> A payload that does not satisfy the model is a defect in the adapter or the
> declaration, not a statement about the target. The execution still happened and
> is still recorded as such — saying otherwise would be a lie about a change that
> may have landed.

That is correct about **`EXECUTED`**. `EXECUTED` means "the adapter was called and
returned"; a contract violation does not undo that, and pretending nothing ran
would be the exact failure ADR-0017 exists to prevent.

It is wrong about **`SUCCEEDED`**, and `SUCCEEDED` is where the row actually
stopped.

## The problem

A `SUCCEEDED` invocation with `result_summary = {}` is a false statement about an
execution, written into an append-only table that is ACOP's evidence base.

Three consequences, in ascending order of seriousness:

1. **It is indistinguishable from a true empty result.** A tool that legitimately
   returns nothing — one whose output model declares no fields, like `NeverOut` —
   produces exactly the same row.
2. **A consumer reads it as data.** Anything that treats `result_summary` as the
   tool's answer sees an empty collection where it should see a failure. The
   Milestone 5 discovery service is the first such consumer, and the specific harm
   there is concrete: an empty guest inventory is indistinguishable from a cluster
   with no guests, and the absence pass would mark **every** guest absent.
3. **No signal reaches an operator.** `error_category` is `NULL`, the audit outcome
   is `SUCCESS`, and the only trace is one `logger.error` line. A tool broken by a
   refactor would be silently returning nothing, indefinitely, while every
   dashboard reported success.

Consequence 2 could be defended against downstream — and the Milestone 5 design
does re-validate `result_summary` independently. But that makes each consumer
responsible for repairing a false state the framework produced, and the first
consumer to forget inherits the bug. Correctness belongs here.

## Decision

**An adapter payload that fails the tool's declared `output_model` fails the
invocation.**

1. `_declared_output` returns `dict[str, Any] | None`, and answers a validation
   failure with `None`.
2. `_record_adapter_result` branches on `None` and releases the lease to
   `FAILED` with `error_category = OUTPUT_CONTRACT_VIOLATION`,
   `error_detail_sanitized` set to that category's fixed phrase,
   `result_summary = NULL` and `result_digest = NULL`.
3. `ToolErrorCategory.OUTPUT_CONTRACT_VIOLATION` is added, with the phrase
   *"The tool returned a result that does not match its declared output."*

### Why `FAILED` and not `EXECUTION_INDETERMINATE`

`EXECUTION_INDETERMINATE` means **ACOP does not know whether the change landed**.
It is terminal, it is never retried automatically, and it can only be closed by a
human recording a determination (ADR-0017, `acop.services.tools.reconciliation`).
It is deliberately expensive, because it should be rare.

This is not that. ACOP knows exactly what happened: the adapter was called, it
returned, it reported success, and its payload did not match the declaration. The
cause is known, it is in ACOP's own code, and the fix is a code fix. Recording it
as indeterminate would manufacture manual reconciliation work for a defect that
needs none, and would dilute the one state that is supposed to mean "a human must
investigate what happened to the target".

`FAILED` is the honest state: the invocation did not produce a usable result.

### Why `None` and not `{}`

`{}` is a **valid** result. A tool whose output model declares no fields validates
an empty payload and dumps to exactly `{}`. A sentinel that collides with a
legitimate value cannot distinguish the broken case from the correct one — it
would either fail a well-behaved tool or let a broken one pass, depending on which
way the check was written. `None` collides with nothing.

(An all-optional model does *not* produce `{}`: pydantic dumps unset optional
fields as explicit nulls. Only a model with no declared fields does. Both cases
are pinned by unit tests.)

### Why a return value and not an exception

An exception would be more expressive and it was rejected on safety grounds.
`_declared_output` is called from `_record_adapter_result`, which is called from
`_execute`, which is called from `_run_claimed`. An exception that escaped the
local catch would leave the invocation in `EXECUTING` holding a live lease until
`InvocationReaper` recorded `EXECUTION_INDETERMINATE` — turning a precisely known
defect into an unknown outcome requiring a human, which is the opposite of what
this decision is for. A returned value cannot escape.

### Why a new category and not `INTERNAL_ERROR`

`INTERNAL_ERROR` already covers a policy-engine malfunction
(`PolicyEngineFailureError`) and an unhandled adapter exception. Those have
different remediations from this one — the role table, a traceback, and a tool
declaration respectively. A category shared by three unrelated causes stops
directing an investigation anywhere, which is the argument Milestone 4 finding F-4
made when `PolicyEngineFailureError` was separated out. This follows that
precedent.

### Retry

`OUTPUT_CONTRACT_VIOLATION` is deliberately **absent** from
`RETRYABLE_CATEGORIES`. No new machinery was needed to achieve that, and none was
added: `RetryPolicy.retry_on` defaults to `RETRYABLE_CATEGORIES`, import rule 8
refuses any declaration whose `retry_on` is not a subset of it, and the retry loop
wraps `adapter.execute` — which has already exited by the time the output model is
checked. A contract violation is therefore unreachable from the retry path
structurally, not by configuration. An integration test proves the adapter is
called exactly once for a tool declaring `max_attempts=2`.

## Disclosure

The rejected payload reaches nothing durable.

- `result_summary` and `result_digest` are left `NULL`, so the offending value
  enters neither the database nor any response.
- `error_detail_sanitized` is the fixed phrase from `ERROR_PHRASES`, never adapter
  text — the same guarantee `ToolError` gives.
- The structured log carries `fields=sorted(payload)` — **key names only, never
  values**. The names are what an engineer needs in order to fix the declaration,
  and a key name is not a credential. Asserted by a unit test that puts a
  connection string in the payload and searches the whole captured record for it.
- `rollback_hint` is **not** carried onto this path. It is raw adapter output,
  stored today without output-model validation or `sanitize_output`, and "no raw
  adapter output" applies to it too. No read-only tool sets one. That
  `rollback_hint` and `validation_detail` are unsanitised *at all* is a separate
  open finding (backlog B-12), not addressed here.

## Consequences

**Positive**

- A `SUCCEEDED` invocation now means the tool returned what it declared. That is a
  property consumers can rely on rather than re-derive.
- A tool broken by a refactor surfaces as failed invocations with a specific,
  greppable category instead of silently returning nothing.
- Milestone 5's discovery service still re-validates `result_summary` as defence in
  depth, but is no longer *responsible* for repairing a false framework state.

**Negative, and accepted**

- A tool whose adapter and declaration have drifted now fails where it previously
  half-worked. That is the intent: it was never working, it was reporting.
- One more `ToolErrorCategory` member for operators to know.

**Neutral**

- No schema change. `FAILED` is already in `ck_tool_invocation_state`,
  `EXECUTING → FAILED` is already in `LEGAL_TRANSITIONS`, `error_category` is
  `String(40)` with no CHECK constraint, and `"OUTPUT_CONTRACT_VIOLATION"` is 25
  characters. Alembic head remains `0007_tool_framework`.
- No change to `_run_claimed`, the state machine, the retry framework, the policy
  gates, or any adapter. The correction is one branch and one return type.

## Alternatives considered

| Alternative | Rejected because |
|---|---|
| Leave it as `{}` and let each consumer re-validate | Makes every consumer responsible for repairing a false framework state; the first one to forget inherits the bug |
| `EXECUTION_INDETERMINATE` | Manufactures manual reconciliation for a defect whose cause is known, and dilutes the meaning of the one state reserved for genuinely unknown outcomes |
| Raise an exception | Escapes into `_run_claimed`, stranding the invocation in `EXECUTING` until the reaper converts it to `EXECUTION_INDETERMINATE` — strictly worse than the behaviour being fixed |
| Reuse `INTERNAL_ERROR` | Three unrelated causes under one category; contradicts the F-4 precedent |
| Publish the invalid payload with a warning flag | Defeats the allow-list, which exists precisely so that unvalidated adapter output is never stored |
