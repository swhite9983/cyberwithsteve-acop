# The ACOP tool framework

Milestone 4 is the first part of ACOP that acts on anything outside its own
process. Everything before it read, stored or retrieved; this restarts services
and rotates credentials. This document is the operator and engineer reference:
what the controls are, in what order they run, what each state means, and what
to do when something goes wrong.

Design records: [ADR-0014](../decisions/ADR-0014-code-authoritative-tool-registry.md)
(code-authoritative registry), [ADR-0015](../decisions/ADR-0015-capability-binding-invariant.md)
(Capability Binding Invariant), [ADR-0016](../decisions/ADR-0016-one-execution-path-and-final-gate.md)
(one execution path), [ADR-0017](../decisions/ADR-0017-executed-is-not-succeeded.md)
(`EXECUTED` vs `SUCCEEDED`), [ADR-0018](../decisions/ADR-0018-execution-envelope-and-digest.md)
(execution envelope), [ADR-0019](../decisions/ADR-0019-separation-of-duties-and-class-3-strength.md)
(separation of duties). To add a capability, see
[`adding-a-tool.md`](adding-a-tool.md).

## The one-paragraph summary

A tool is a **declaration in reviewed Python**, not a row. The database owns
one thing about it: whether it is `ACTIVE`, `DISABLED` or `RETIRED`. Every
invocation passes eight policy gates at request time, is frozen into an
**execution envelope** whose SHA-256 digest an approval binds to, and passes a
**final execution gate** immediately before an adapter is touched. There is
exactly one execution path for all four permission classes. Nothing is deleted;
everything is appended.

---

## 1. Permission classes

The classes are `acop.models.provenance.PermissionClass`, declared in
Milestone 1 so the audit log could record a class from its first row onward.

| Class | Meaning | Target | Approval | Validation | Idempotency key | Minimum role to request |
|---|---|---|---|---|---|---|
| `CLASS_0_INFORMATION` | Touches nothing outside ACOP | Must be `NONE` | No | No | Not required | `viewer` |
| `CLASS_1_READ_ONLY` | Reads something outside ACOP | Must name one | No | No | Not required | `viewer` |
| `CLASS_2_LOW_RISK_CHANGE` | Makes a low-risk change | Must name one | **Required** | **Required** | **Required** | `operator` |
| `CLASS_3_HIGH_RISK_CHANGE` | Makes a high-risk change | Must name one | **Required** | **Required** | **Required** | `operator` |
| `PROHIBITED` | Never executes, for anyone | — | Irrelevant | Irrelevant | Irrelevant | — |

The "minimum role" column is a **floor**, not a grant: a tool may require more
than its class minimum and may never require less (import rule 3). Class 0 and
`TargetKind.NONE` must coincide in both directions (rule 7) — a Class 0 tool
with a target would reach outside ACOP, and a non-Class-0 tool without one has
nothing to be scoped against.

The three Class 2/3 requirements above are enforced in three independent
places: the import rules refuse a declaration that omits them, the policy
engine applies them, and the database refuses to store an invocation that
contradicts them:

```sql
CHECK (permission_class NOT IN (...) OR approval_required IS TRUE)
CHECK (permission_class NOT IN (...) OR validation_required IS TRUE)
CHECK (permission_class NOT IN (...) OR idempotency_key IS NOT NULL)
```

### Prohibition is a separate policy, not a fifth class

`PROHIBITED_CAPABILITIES` in `acop/models/tool_vocabulary.py` is a **code
registry of capability categories** ACOP will not expose through any tool, ever:

| Group | Categories |
|---|---|
| Generic execution | `arbitrary.shell`, `arbitrary.ssh`, `arbitrary.cli`, `arbitrary.powershell`, `arbitrary.sql`, `arbitrary.winrm`, `model.generated.command` |
| Destructive | `storage.format`, `vm.delete`, `container.delete` |
| Control-disabling | `audit.disable`, `logging.disable`, `monitoring.disable` |
| Security bypass | `authn.bypass`, `authz.bypass` |
| Unrestricted network | `firewall.unrestricted`, `routing.unrestricted` |
| Secret exposure | `secrets.read`, `secrets.export` |

The check is on a tool's **capability tags**, not on a `prohibited` flag, and
that is the point. A flag denies what someone remembered to flag; a category
denies a *shape* of capability. A future `proxmox.vm.delete` whose honest tag
set includes `vm.delete` is refused at import — not at review, and not at 3am.

A prohibited category is **not reachable by role, approval or configuration**.
There is no admin override, no setting, and no environment in which one
executes. Removing an entry requires an ADR; that is a documentation
convention, named as such rather than pretended to be enforcement.

---

## 2. The three separations

The framework keeps three questions apart, and never lets an answer to one
substitute for an answer to another.

| Separation | Question | Where it is answered | Failure mode it prevents |
|---|---|---|---|
| **Authorization** | May *this caller* invoke *this tool*? | Gate 6, against the tool's declared `required_roles` | A viewer restarting a service |
| **Approval** | Does *someone other than the caller* agree to *this specific request*? | Gates 8 + the approval service + the final gate | An operator making an unreviewed change |
| **Prohibition** | May *anyone at all* do this? | Gate 3, against `PROHIBITED_CAPABILITIES` | The platform acquiring a generic execution surface |

Holding a role never satisfies the approval question, and being approved never
satisfies the prohibition question. Prohibition is evaluated **before**
authorization so that the refusal does not vary by who asked — see §4.

---

## 3. The state machine

### States

| State | Terminal | Meaning |
|---|---|---|
| `REQUESTED` | | The invocation row exists; nothing has been decided |
| `REJECTED` | ✔ | A request-time gate refused it. Nothing was attempted |
| `AUTHORIZED` | | All eight gates allowed it |
| `AWAITING_APPROVAL` | | Class 2/3, waiting for `min_approvals` distinct approvers |
| `APPROVED` | | The threshold was met; rejoins the single path immediately |
| `DENIED` | ✔ | An eligible approver denied it. Terminal on the first denial |
| `READY` | | Eligible for a worker to claim. The one queue |
| `EXECUTING` | | A worker holds the lease; the adapter has been called |
| `EXECUTED` | | The adapter **reported** success. Not the same as success |
| `VALIDATING` | | An independent observation of the target is in progress |
| `SUCCEEDED` | ✔ | The intended change was **observed** to be in effect |
| `VALIDATION_FAILED` | ✔ | It executed and the change could not be confirmed. See `validation_outcome` |
| `FAILED` | ✔ | The adapter reported failure, or raised. Nothing landed |
| `TIMED_OUT` | ✔ | The deadline elapsed. **Never retried** — it may still be in flight |
| `EXECUTION_INDETERMINATE` | ✔ | A worker was lost mid-execution. **ACOP does not know** whether the change landed |
| `EXPIRED` | ✔ | An approval window elapsed, or the final gate refused |
| `CANCELLED` | ✔ | Withdrawn by the requester or an admin before execution |
| `SUPERSEDED` | ✔ | Replaced by an idempotent replacement |

Ten of the eighteen are terminal. `EXECUTION_INDETERMINATE` is terminal **and**
reconcilable: a human appends what they determined, and the state is never
rewritten (§8.2).

### Legal transitions

```
                    ┌──────────► REJECTED  (terminal)
                    │
REQUESTED ──────────┴──► AUTHORIZED ──┬────────────────────────► READY
                                      │                            ▲
                                      └──► AWAITING_APPROVAL ──────┤
                                             │   │   │             │
                                             │   │   └──► APPROVED─┘
                                             │   ├──► DENIED     (terminal)
                                             │   ├──► EXPIRED    (terminal)
                                             │   └──► CANCELLED  (terminal)
                                             │
READY ──┬──► EXECUTING ──┬──► EXECUTED ──┬──► SUCCEEDED          (terminal)
        │                │               └──► VALIDATING ──┬──► SUCCEEDED
        ├──► EXPIRED     ├──► FAILED                       └──► VALIDATION_FAILED
        └──► CANCELLED   ├──► TIMED_OUT
                         └──► EXECUTION_INDETERMINATE

Any non-terminal state ──► SUPERSEDED
```

Enforced **twice**, deliberately:

1. **In Python**, against `LEGAL_TRANSITIONS`. Catches a bug during development
   with an error naming the attempted move.
2. **In PostgreSQL**, by a `WHERE state = :expected` predicate on every
   `UPDATE`. Catches the case Python cannot — two workers racing, where both
   read `READY` and both believe the move is legal.

The second is the one that matters operationally. Under READ COMMITTED the
second worker blocks on the row lock, and on waking PostgreSQL re-evaluates the
predicate against the new committed row version, which no longer says `READY`.
It matches zero rows. That is EvalPlanQual, and it is why the claim needs no
advisory lock, no `SELECT FOR UPDATE` round trip and no retry loop.

Every transition appends a row to `tool_invocation_event`, ordered by a
per-invocation `sequence` counter rather than a timestamp, because two
transitions can share a millisecond and "what happened first" must not depend on
clock resolution.

---

## 4. The eight policy gates

Evaluated in order by `ToolPolicyEngine`. **Fail closed, structurally**: the
only statement in the module producing `allowed=True` is the final line, after
all eight checks have run — a unit test asserts against the AST that exactly one
such statement exists. Any unhandled exception is caught and converted to a
denial with `internal_error`, because an engine that raises has not decided
anything, and "has not decided" must never mean "go ahead".

| # | Gate | Checks | Denial reason |
|---|---|---|---|
| 1 | Capability binding | A code declaration exists for this name and version | `capability_not_bound` |
| 2 | Lifecycle | The registration row is not `RETIRED` or `DISABLED` | `tool_retired`, `tool_disabled` |
| 3 | **Prohibition** | `prohibited` flag or any tag in `PROHIBITED_CAPABILITIES` | `prohibited_capability` |
| 4 | **Schema** | Input validates against the tool's Pydantic model; canonicalised | `schema_invalid` |
| 5 | Target | Kind matches; asset exists, is `ACTIVE`, and is an accepted type | `target_invalid`, `target_retired`, `target_out_of_scope` |
| 6 | Authorization | Caller's effective roles ⊇ tool's `required_roles` | `role_insufficient` |
| 7 | Context | Environment restriction (extension point) | `environment_restricted` |
| 8 | Approval | Computes whether approval is required. **Never denies** | — |

### Why prohibition (3) precedes authorization (6)

If a prohibited tool were refused for "insufficient role", the error would tell
an attacker **which role would have worked**. The denial reason for a
prohibited capability must not vary by who asked, or the endpoint becomes an
oracle for privilege escalation targets. Prohibited tools are also absent from
every catalog listing for every role, admin included, for the same reason.

### Why schema (4) precedes target (5)

A malformed request must not be able to cause a database lookup on
attacker-controlled input. This is a property of the **code path**, not of a
comment: `evaluate_prerequisites` runs gates 1–4 and returns early, and the
caller resolves a target only after it returns `None`. There is no ordering
left to get wrong. Gates 1–4 are pure and cheap, so `evaluate` re-runs them
rather than trusting that the prerequisite method was called first.

### Why gate 8 never denies

Computing that approval is *required* is a different act from *refusing*.
Conflating them would mean a tool that needs approval and a tool that is
forbidden produce the same shape of answer, and an operator could not tell "ask
someone" from "this will never work".

### Extending the gates

`PolicyContext` is the extension point. Change-freeze windows, resource
ownership and per-environment restrictions become new checks reading that
object, with no signature change and no schema change.

---

## 5. The final execution gate

Request-time authorization is **necessary and not sufficient**, because time
passes. Between authorization and execution a tool can be disabled, a
capability can be added to the prohibited registry, an approval can expire, and
a stored request can be altered. So immediately after winning the claim and
**before touching an adapter**, `ExecutionDispatcher._final_gate` re-checks:

| # | Check | Source | Refusal reason |
|---|---|---|---|
| 1 | The declaration still exists | Code registry | `capability_not_bound` |
| 2 | Current lifecycle state | Database, read now | `tool_retired`, `tool_disabled` |
| 3 | Current prohibition status | Code registry | `prohibited_capability` |
| 4 | Envelope integrity — digest recomputed from stored canonical input | Database + code | `envelope_integrity_failed` |
| 5 | Approval validity, where the snapshot requires it | Database | `approval_missing`, `approval_expired`, `approval_envelope_mismatch` |

A failure here is **`EXPIRED` with `final_gate_decision = DENY`, not
`FAILED`** — nothing was attempted, and recording a failure would be a false
statement about the target.

Both decisions are kept on the invocation: `authorization_decision` /
`authorization_reason` / `authorized_at` from request time, and
`final_gate_decision` / `final_gate_reason` / `final_gate_at` from execution
time. "We allowed it then and refused it now" is a materially different record
from "we refused it".

---

## 6. API operations

Sixteen operations. There is **no `DELETE` anywhere**, and no `/execute` or
`/run` endpoint — a unit test asserts both. Authorization for an invocation is
**per-tool**, not per-endpoint: `POST /tool-invocations` requires only an
authenticated principal, and the policy engine compares the caller's roles
against the tool's declared `required_roles`. A blanket role guard there would
be too permissive for Class 3 or too strict for Class 0.

| # | Operation | Minimum role | Success | Notable failures |
|---|---|---|---|---|
| 1 | `GET /tools` | any authenticated | 200 | — |
| 2 | `GET /tools/{name}` | any authenticated | 200 | 404 if absent, disabled, or not invocable by you |
| 3 | `GET /tools/{name}/versions` | any authenticated | 200 | 404 |
| 4 | `POST /tools/{name}/disable` | `admin` | 200 | 404 |
| 5 | `POST /tools/{name}/enable` | `admin` | 200 | 404 (including a `RETIRED` tool) |
| 6 | `POST /tool-invocations` | any authenticated | 200 finished / 202 in progress | 403 any policy-gate denial, 404 no registration for that name and version, 409 idempotency conflict, 422 malformed body or missing justification |
| 7 | `GET /tool-invocations` | `viewer`+ | 200 | — |
| 8 | `GET /tool-invocations/{id}` | `viewer`+ | 200 | 404 |
| 9 | `GET /tool-invocations/{id}/envelope` | `approver`/`admin` | 200 | 404 |
| 10 | `GET /tool-invocations/{id}/result` | `viewer`+ | 200 | 404 |
| 11 | `GET /tool-invocations/{id}/events` | `viewer`+ | 200 | 404 |
| 12 | `GET /tool-invocations/{id}/approvals` | `approver`/`admin` | 200 | 404 |
| 13 | `POST /tool-invocations/{id}/approve` | `approver`/`admin` | 200 | 403 no authority, self-approval, or wrong state; 409 envelope mismatch; 404 |
| 14 | `POST /tool-invocations/{id}/deny` | `approver`/`admin` | 200 | as above |
| 15 | `POST /tool-invocations/{id}/cancel` | requester or `admin` | 200 | 403 not yours, 409 the invocation was advanced first, 422 wrong state, 404 |
| 16 | `POST /tool-invocations/{id}/reconcile` | `approver`/`admin` | 201 | 403 not `EXECUTION_INDETERMINATE`, 404 |

Notes an integrator needs:

- **A gate denial's status names what the caller got wrong.** The refusal
  reason is mapped through one table, `_REFUSAL_ERRORS` in
  `acop.services.tools.invocation`, which is total over `PolicyReason`:

  | Reason | Status | Code |
  |---|---|---|
  | `schema_invalid` | 422 | `tool_input_invalid` |
  | `target_invalid`, `target_out_of_scope`, `target_retired` | 422 | `invalid_target` |
  | `tool_disabled`, `tool_retired` | 409 | `tool_disabled` |
  | `capability_not_bound` | 404 | `tool_not_found` |
  | `role_insufficient` | 403 | `tool_not_authorized` |
  | `prohibited_capability` | 403 | `prohibited_capability` |
  | `internal_error` | 403 | `policy_engine_error` |
  | everything else | 403 | `tool_policy_denied` |

  A 403 for a malformed body would send an integrator to look at their
  credentials instead of their payload, which is why the distinction exists.

  Two of these rows are load-bearing beyond convenience.
  `prohibited_capability` is **identical for every role** — viewer, operator,
  approver and admin all receive the same status, code and message — because a
  reason that varied by role would be an oracle telling an attacker which
  privilege to acquire. And `internal_error` carries its own code precisely so
  that a policy-engine *malfunction* is not silently filed as an ordinary
  refusal: it is additionally audited as `tool.policy_failure` at `CRITICAL`
  severity, where a routine denial is `tool.invoke` at `WARNING`. The status
  stays 403 because the engine did decide — it failed closed — and because a
  500 would let a caller distinguish "I broke the engine" from "I was refused"
  by status line alone.

  The machine-readable `PolicyReason` is on the invocation row and in the audit
  record either way. A 422 can also come from the *request body itself* being
  malformed, or a Class 2/3 request omitting its justification, before any tool
  policy is consulted.
- **A denied request still creates an invocation row**, in `REJECTED`, written
  and committed on an independent transaction so it survives the rollback of
  the request that was refused. A rejected invocation does **not** consume its
  idempotency key: the caller should be able to fix the request and retry with
  the same key.
- **`GET /tools` lists only what the caller could actually invoke.**
  Enumerating capabilities someone cannot use is reconnaissance. Prohibited
  tools are absent from every listing regardless of role.
- **`GET /tools/{name}` returns the same 404** whether the tool does not exist,
  is disabled, or is one this caller may not use. Distinguishing them would
  turn the endpoint into an oracle.
- **`GET .../versions` shows `DISABLED` and `RETIRED` versions to admins only**,
  because during an incident "why is this not running" is the question and the
  answer is in the lifecycle row.
- **`.../approve` and `.../deny` require the envelope digest** the approver
  reviewed, in the request body. See §8.3.
- **Cancellation is only possible from `AWAITING_APPROVAL` or `READY`.**
  Something already `EXECUTING` cannot be un-dispatched; if the worker is then
  lost, the honest outcome is `EXECUTION_INDETERMINATE`, not `CANCELLED`.
- **Cancellation can lose a race, and that is a 409 (`invocation_state_conflict`),
  not a 500.** A worker claiming a `READY` row and a person withdrawing it are
  both acting correctly, so the compare-and-set that refuses the later of the
  two is not reporting a fault. Nothing is written when it refuses; the state
  that won stands, and re-reading the invocation shows which one it was.
- **A Class 2/3 request must carry a `justification`.** An approver needs to
  know why, not only what.
- **No adapter identity ever appears in a response.** Knowing which adapter
  backs a tool tells an attacker where to aim; a unit test asserts no response
  schema mentions one.
- **Error text is a fixed phrase per category** (`ERROR_PHRASES`), constructed
  rather than filtered. Adapter text never reaches an HTTP response, an audit
  record, an invocation row, or a model — the raw exception goes to the
  structured log keyed by invocation id.

---

## 7. The six catalog tools

All six exist to prove the framework rather than to do useful work. None can
affect the host, Docker, the network or real infrastructure. Two adapters back
them: `acop.local` (touches nothing outside the process) and `test.simulated`
(a module-level dict behind a lock — no table, no file, no socket, no
subprocess; a static test asserts it imports none of `subprocess`, `socket`,
`asyncssh`, `paramiko`, `pexpect` or `winrm`).

| Tool | Class | Adapter | What it proves |
|---|---|---|---|
| `acop.system.health@1.0` | 0 | `acop.local` | The framework works against something that genuinely does work, not a stub. Class 0 + `TargetKind.NONE` coincide. Two attempts, because a health probe that lost a connection tells you about the connection |
| `acop.test.echo_metadata@1.0` | 0 | `acop.local` | The invocation record, envelope and HTTP response agree; an undeclared field such as `api_key` is **rejected**, not redacted; envelope canonicalisation is stable regardless of key order |
| `test.device.status@1.0` | 1 | `test.simulated` | The Class 1 path against the **real CMDB** — a retired or wrongly typed asset produces a genuine `INVALID_TARGET` from policy rather than a fabricated success. Retry on unavailable |
| `test.service.restart@1.0` | 2 | `test.simulated` | The complete change path: request → approval → final gate → execute → validate. Separation of duties, envelope binding, approval expiry, idempotency, and the gap between "the adapter said yes" and "the change happened" |
| `test.security.rotate_key@1.0` | 3 | `test.simulated` | Class 3 strength through **policy, not role**: `required_roles={operator}`, two distinct approvers, 900s TTL, no retry (`NON_IDEMPOTENT`, `max_attempts=1`). An explicit `output_allow_list` |
| `test.prohibited.shell_exec@1.0` | `PROHIBITED` | `test.simulated` | The prohibition mechanism. Every setting on it is deliberately permissive — admin may request it, approval is possible, the adapter is bound — and it is still denied for viewer, operator, approver and admin alike, at the request gate and again at the final gate |

Three simulated behaviours are selected by the **target asset's display name**,
so the input schema stays free of any field that steers execution — a caller
cannot ask for the failure path because there is nowhere in the request to ask:

| Display name | Behaviour |
|---|---|
| `sim-stays-down` | The restart reports success and the service is not running afterwards → `EXECUTED` then `VALIDATION_FAILED` |
| `sim-unreachable` | The adapter or target cannot be reached → retry where permitted, then `FAILED` |
| `sim-slow` | Sleeps past the declared timeout → cancelled from outside → `TIMED_OUT` |

`test.prohibited.shell_exec` carries `allow_registration_for_testing`, the
single escape hatch for import rule 6; exactly one catalog tool may set it and
a unit test asserts that. It permits **registration, not execution** — gate 3
denies every invocation regardless, and the adapter raises loudly if it is ever
reached, because reaching it would mean a policy defect.

---

## 8. Operating notes

### 8.1 Taking a tool out of service during an incident

This is the reason the database owns lifecycle at all. It takes effect
immediately and requires no deploy.

```bash
curl -sS -X POST "$ACOP/tools/test.service.restart/disable" \
  -H "X-ACOP-API-Key: $ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"tool_version": "1.0", "reason": "INC-1234: restarts leaving services down"}'
```

Checklist:

- [ ] `reason` is mandatory and is stored. A disable without an attributed
      actor and a stated reason is unrepresentable — the schema refuses it.
- [ ] **Already-approved, queued work stops too.** The final gate reads current
      lifecycle, so an invocation sitting in `READY` is refused with
      `tool_disabled` and moves to `EXPIRED`. A control that only stopped new
      requests would not stop the incident.
- [ ] Work already `EXECUTING` is **not** interrupted. It finishes and records
      its outcome, or the lease expires and the reaper records
      `EXECUTION_INDETERMINATE`.
- [ ] The disable is audited at `WARNING` with the reason in `context`.
- [ ] Re-enable with `POST /tools/{name}/enable` and a reason. A `RETIRED` tool
      **cannot** be enabled: retirement means the code declaration is gone, so
      restoring it is a deploy, which is the correct amount of ceremony.

To find what is disabled and why:

```sql
SELECT tool_name, tool_version, lifecycle_state,
       disabled_at, disabled_by_subject, disabled_reason
FROM tool_registration
WHERE lifecycle_state <> 'ACTIVE'
ORDER BY tool_name;
```

### 8.2 Reading and reconciling an `EXECUTION_INDETERMINATE` record

**What it means.** A worker was lost between calling the adapter and recording
the result. The adapter **was** called. Whether the change landed is genuinely
unknown. `FAILED` would be false and would invite a retry that double-executes;
`SUCCEEDED` would be false in the other direction.

**It is never retried automatically.** It is closed only by a human recording
what they determined.

How to read one:

```sql
SELECT id, tool_name, tool_version, permission_class, principal_subject,
       target_asset_id, started_at, finished_at, attempt_count,
       error_category, final_gate_reason
FROM tool_invocation
WHERE state = 'EXECUTION_INDETERMINATE'
ORDER BY finished_at DESC;
```

Then the ordered history — `GET /tool-invocations/{id}/events`, or:

```sql
SELECT sequence, from_state, to_state, actor_subject, reason, occurred_at, detail
FROM tool_invocation_event
WHERE invocation_id = :id
ORDER BY sequence;
```

Reconciliation checklist:

- [ ] Read the envelope (`GET /tool-invocations/{id}/envelope`) to see exactly
      what was requested — tool, version, class, target, arguments.
- [ ] Determine what actually happened **from the target itself**, not from
      ACOP. A Class 1 read-only tool against the same asset is a legitimate aid.
- [ ] Record the determination:

```bash
curl -sS -X POST "$ACOP/tool-invocations/$ID/reconcile" \
  -H "X-ACOP-API-Key: $APPROVER_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"disposition": "CONFIRMED_FAILED",
       "justification": "Service manager log shows no restart at 14:02Z; PID unchanged.",
       "evidence_ref": {"ticket": "INC-1234", "log_query": "journalctl -u nginx --since 14:00"}}'
```

- [ ] `disposition` is one of `CONFIRMED_SUCCEEDED`, `CONFIRMED_FAILED`,
      `UNKNOWN`. `UNKNOWN` is a legitimate answer and is better than a guess.
- [ ] `evidence_ref` holds **references only** — a ticket id, a log query, a
      knowledge document id. No captured output, no credentials, no raw device
      response. It is redacted before storage as defence in depth.
- [ ] The invocation's `state` **does not change**. The determination is
      appended beside the execution record and separately attributed, so the
      history reads as two facts: *ACOP did not know*, and *later, this named
      person determined this*.
- [ ] Reconciling more than once is allowed and is not a mistake. A first-look
      `UNKNOWN` followed a week later by `CONFIRMED_FAILED` is a more honest
      history than one row edited twice.
- [ ] Only an `EXECUTION_INDETERMINATE` invocation can be reconciled. The
      endpoint refuses anything else, so nobody can "correct" an outcome ACOP is
      certain about.

Note the neighbouring case: `VALIDATION_FAILED` with `validation_outcome =
INDETERMINATE` means the change **did** happen and the confirmation is what is
missing. That is not reconcilable through this endpoint, because the execution
outcome was never in doubt.

### 8.3 Approving a change

```bash
# 1. Read what you are being asked to approve.
curl -sS "$ACOP/tool-invocations/$ID/envelope" -H "X-ACOP-API-Key: $APPROVER_KEY"

# 2. Approve, quoting the digest you just read.
curl -sS -X POST "$ACOP/tool-invocations/$ID/approve" \
  -H "X-ACOP-API-Key: $APPROVER_KEY" -H 'Content-Type: application/json' \
  -d '{"envelope_digest": "<from step 1>", "justification": "CHG-991 approved in CAB."}'
```

The digest is required so that an approver cannot fetch an envelope, have the
request change underneath them, and approve the new one by clicking a stale
button. A mismatch is refused rather than silently substituted.

- The **first denial is terminal.** There is no "one more approver might say
  yes" — making a denial provisional would let an approver who objected be
  outvoted by attrition.
- You cannot approve your own request. The API has no field for it, the service
  derives it server-side, and the database refuses the row (`CHECK
  (approver_subject <> requester_subject OR self_approval IS TRUE)`).
- `admin` gets **no** separation-of-duties bypass.
- For Class 3, two **distinct** approvers are required, enforced by a partial
  unique index as well as by a `COUNT(DISTINCT approver_subject)`.

### 8.4 The reaper, the sweeper, and the lease timeout

`ToolWorker` runs one asyncio task per process and owns no execution logic of
its own — it is a *scheduler*, not a second execution path. It polls for
`READY` invocations every `poll_seconds` and calls the same `execute_once` an
inline request awaits. Several processes may run it; each claims with a
compare-and-set `UPDATE`, so exactly one wins. No leader election, no advisory
lock, no distributed queue. One bad invocation never stops the loop.

| Duty | What it closes | Result |
|---|---|---|
| **Reaper** | An `EXECUTING` row whose lease expired — the worker is gone | `EXECUTION_INDETERMINATE`, audited at `CRITICAL` |
| **Reaper** | A `VALIDATING` row whose lease expired | `VALIDATION_FAILED` with `validation_outcome = INDETERMINATE`, audited at `WARNING` |
| **Sweeper** | `AWAITING_APPROVAL` or `READY` past its TTL | `EXPIRED`, audited at `NOTICE` |

Both run every `ACOP_TOOLS_REAPER_INTERVAL_SECONDS`.

**The lease timeout must exceed the longest declared tool timeout.**
`ACOP_TOOLS_EXECUTION_LEASE_SECONDS` defaults to 120s; the longest catalog
timeout is 30s. If the lease were shorter than a tool's timeout, the reaper
would record `EXECUTION_INDETERMINATE` for an invocation that is still running
perfectly well — a false alarm demanding human attention, on every slow call.
Raise the lease before raising a tool timeout, never after.

The **sweeper is not the authority on expiry; the final gate is.** A sweeper
alone would let a dispatcher paused for a week execute last week's approval the
moment it came back. The sweeper is tidiness: it stops a queue filling with
requests nobody will ever approve. Both windows are measured against the
invocation's **snapshotted** `approval_ttl_seconds`, so shortening a tool's TTL
tomorrow cannot retroactively expire an approval granted under yesterday's
rules, and lengthening it cannot extend one.

`worker.stop()` deliberately does not cancel an in-flight execution: an adapter
mid-change should be allowed to finish and record its outcome. If the process is
killed anyway, the lease expires and the reaper records what actually happened —
that ACOP does not know.

---

## 9. Settings

All in `src/acop/config/settings.py`, all prefixed `ACOP_` in the environment.

| Setting | Env var | Default | Notes |
|---|---|---|---|
| `tools_allow_self_approval` | `ACOP_TOOLS_ALLOW_SELF_APPROVAL` | `false` | **Startup fails** in staging or production if `true`. Exists so a single-operator development environment can exercise the approval path without two identities |
| `tools_dispatcher_enabled` | `ACOP_TOOLS_DISPATCHER_ENABLED` | `true` | Whether the background worker polls for `READY` |
| `tools_dispatcher_poll_seconds` | `ACOP_TOOLS_DISPATCHER_POLL_SECONDS` | `1.0` | Poll interval over a partial index on `state = 'READY'` |
| `tools_execution_lease_seconds` | `ACOP_TOOLS_EXECUTION_LEASE_SECONDS` | `120.0` | **Must exceed the longest declared tool timeout** — see §8.4 |
| `tools_reaper_interval_seconds` | `ACOP_TOOLS_REAPER_INTERVAL_SECONDS` | `30.0` | How often the reaper and sweeper run |
| `tools_inline_wait_seconds` | `ACOP_TOOLS_INLINE_WAIT_SECONDS` | `30.0` | How long a Class 0/1 request waits for the **shared** execution path before returning 202 and letting the caller poll |

Disabling the dispatcher does not disable execution: an inline Class 0/1
request still awaits `execute_once` directly. It disables the *background*
draining of the `READY` queue, which is what Class 2/3 work depends on.

---

## 10. Security control mapping

| Control implemented here | NIST CSF | CIS Controls v8 | Zero Trust | Least Privilege | Defence in Depth |
|---|---|---|---|---|---|
| Code-authoritative registry; capability change requires a reviewed commit | `PR.DS-6`, `PR.IP-1` | 2 (software inventory), 4.1 | Capability set is an explicit allow-list, not an inferred one | Only declared capabilities exist | Code + reconciliation + final gate re-check |
| Capability Binding Invariant (adapter resolution, policy source, one-directional reconciliation) | `PR.AC-4`, `PR.DS-6` | 2.5, 3.3 | A database row is never sufficient authority | A compromised row grants nothing executable | Three mechanisms, each independently tested |
| Prohibited capability categories, unreachable by role or approval | `PR.AC-4`, `PR.PT-3` | 2.6, 4.8 | No principal is trusted with a generic execution surface | No path to arbitrary shell / SQL / secrets | Import rule + gate 3 + final gate + adapter raise |
| Per-tool `required_roles` with a class floor | `PR.AC-1`, `PR.AC-4` | 5, 6 | Per-request authorization, not session-level | Minimum role per capability, raisable never lowerable | HTTP role guard + policy gate 6 |
| Separation of duties on approval | `PR.AC-4`, `PR.AC-3` | 5.4, 6.8 | Requester identity is never sufficient for a change | Approval authority is distinct from clearance | API schema + service derivation + DB `CHECK` |
| Two-person control for Class 3 | `PR.AC-4` | 6.8 | Two independent decisions per high-risk grant | Strength from policy, not role inflation | `COUNT(DISTINCT ...)` + partial unique index |
| Execution envelope digest, recomputed at execution | `PR.DS-6`, `PR.DS-1` | 3.11, 8 | Grant is bound to one action, time-bounded | An approval authorises exactly one request | Approver-stated digest + gate recomputation |
| Final execution gate re-checking lifecycle, prohibition, approval, integrity | `PR.AC-4`, `DE.CM-7` | 4.7 | Continuous verification at the moment of access | Authorization does not persist across time | Request gates + final gate |
| Append-only invocation, approval, event and reconciliation records | `PR.PT-1`, `DE.CM-1`, `RS.AN-1` | 8.2, 8.5 | Every decision is attributable and non-repudiable | No delete path, `ON DELETE RESTRICT` throughout | Model + service + FK constraints |
| `EXECUTION_INDETERMINATE` and independent validation | `DE.AE-3`, `RS.AN-1` | 8 | Outcomes are observed, not asserted | An adapter cannot declare its own success | Separate `validate` + reaper + reconciliation |
| Fixed error phrases; no adapter text leaves the boundary | `PR.DS-5` | 3.3 | Untrusted output is never trusted downstream | Output allow-list, not deny-list | Allow-list + `redact` + fixed phrases |
| No secret, locator or command field in any tool input schema | `PR.AC-4`, `PR.DS-5` | 3, 4.8 | Adapters hold their own credentials; callers hold none | A caller cannot name a destination or a command | Import rules 9/10/11 + `extra="forbid"` + redaction |
| Attributed, immediate tool disable without a deploy | `RS.MI-1`, `RS.MI-2` | 4.7, 17 | Revocation takes effect on the next access decision | Scoped to one tool version | Lifecycle column + `CHECK` attribution + final gate |

**[Opinion]** Framework mappings are a communication aid, not a compliance
claim. Nothing here has been assessed by an auditor; the table exists so that a
reviewer who thinks in CSF subcategories can find the corresponding mechanism
quickly.
