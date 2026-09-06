# ADR-0019: Separation of duties in three layers, and Class 3 strength through policy

**Status:** Accepted
**Date:** 2026-09-04
**Milestone:** 4

## Context

Class 2 and Class 3 tools require human approval before they execute. The
entire value of that requirement rests on one property: **the approver is not
the requester**. An approval record that a requester produced for themselves
looks identical to a real one in every query, every dashboard and every audit
export. If self-approval is possible, the control is decorative and nothing
downstream can tell.

A second question follows: what makes Class 3 stronger than Class 2? The
intuitive answer — require a higher role to approve it — was drafted for this
milestone and then withdrawn.

## Decision

### Separation of duties, enforced three times

**1. The API cannot express it.** `ApprovalDecisionRequest` has no
`self_approval` field. `FORBIDDEN_APPROVAL_FIELDS` lists the name along with
`approver_subject`, `approver_roles`, `requester_subject`, `min_approvals`,
`distinct_approvers_required`, `expires_at`, `approval_ttl_seconds`,
`permission_class` and `force`, and a unit test asserts none of them appears in
any request schema in the generated OpenAPI document. Every model sets
`extra="forbid"`, so an injected field is a **rejection**, not something
silently dropped.

**2. The service derives it.** `_derive_self_approval` computes the value
server-side from three facts that must *all* hold: configuration permits it,
the tool's own snapshotted policy permits it, and the approver's subject equals
the requester's. Any one missing and a same-subject approval raises
`SelfApprovalForbiddenError`. The normal case — a different subject — returns
`False` without consulting configuration at all.

**3. The database refuses it.**

```sql
CHECK (approver_subject <> requester_subject OR self_approval IS TRUE)
```

`requester_subject` is denormalised onto `tool_approval` for exactly this
reason: so separation of duties can be a database invariant rather than only a
service rule. If both layers above were wrong, the `INSERT` aborts the
transaction.

**Production never reaches layer 2's permissive branch.** A validator on
`Settings` refuses to start a staging or production process with
`ACOP_TOOLS_ALLOW_SELF_APPROVAL` enabled. The setting exists so a
single-operator development environment can exercise the approval path end to
end without two identities — not as an operational escape hatch. Every
self-approval, wherever permitted, is logged at `warning` and audited at
`CRITICAL`, and a partial index (`ix_tool_approval_self`) makes "prove there
were none" a one-row scan.

### Approval authority is the same for every class

`APPROVAL_AUTHORITY_ROLES` is `{approver, admin}`, for **every** permission
class including Class 3. Import rule 4 refuses a declaration naming any role
outside that set, and a unit test asserts the authority set does not vary by
class.

`admin` is in the set **only because it is a superset role**
(`ROLE_IMPLICATIONS` expands `admin` to `{admin, approver, operator, viewer}`),
not because high-risk work needs an administrator. An admin gets no implicit
separation-of-duties bypass and is subject to exactly the same rule as an
approver — `test_an_admin_gets_no_separation_of_duties_bypass` proves it.

### Class 3 strength comes from policy

| Mechanism | Class 2 (`test.service.restart`) | Class 3 (`test.security.rotate_key`) |
|---|---|---|
| `min_approvals` | 1 | 2 |
| `distinct_approvers_required` | false | true |
| `ttl_seconds` | 3600 | 900 |
| `allowed_environments` | any | available, unset in the catalog |
| `required_roles` (to *request*) | `{operator}` | `{operator}` |
| Approver roles | `{approver, admin}` | `{approver, admin}` |

Distinctness is enforced twice: the service counts
`COUNT(DISTINCT approver_subject)` rather than incrementing a stored counter
that could drift, and a partial unique index on
`(invocation_id, approver_subject) WHERE decision = 'APPROVED'` makes a second
approval from the same subject impossible at the storage layer. Import rule 5
additionally refuses `min_approvals > 1` without
`distinct_approvers_required` — asking two people and accepting the same person
twice is one approval wearing a disguise.

## Rationale

**[Fact] The three layers close three different failure modes.** Layer 1 stops
a caller asserting an exemption. Layer 2 stops a service-layer path that forgot
to check. Layer 3 stops a bug in layer 2, a future importer, a backfill, or a
repair script run at 2am by someone who has not read this ADR. **[Best
practice]** Put invariants where they cannot be bypassed — the same reasoning as
[ADR-0013](ADR-0013-ingest-attempts-and-immutable-knowledge-history.md).

**[Fact] The failure has to be at startup, not at approval time.** A deployment
that quietly enabled self-approval would keep producing approval records that
are indistinguishable from real ones. There is no downstream query that could
tell the difference after the fact, so the refusal has to happen before the
process serves a request.

**[Fact] Authority is read from the invocation's snapshot, not from the tool
declaration as it stands today.** Changing a tool's approver roles must not
silently change who can approve a request that is already pending — the
approver set was part of what was authorised, and it is inside the envelope
digest.

**[Fact] The first terminal decision wins.** A denial is terminal immediately;
there is no "one more approver might say yes". Making a denial provisional
would mean an approver who objected could be outvoted by attrition.

**[Fact] A refused approval attempt is written out of band.**
`_audit_refused` uses `AuditService.record_denial`, on an independent
connection that commits immediately, because the session is about to roll back
when the exception propagates. An attempt to approve one's own Class 3 change
is exactly the event that must survive the rollback of the request that made it
— the [ADR-0009](ADR-0009-denial-records-survive-rollback.md) reasoning, applied
to the case it was written for.

**[Fact] An approval must expire.** Import rule 5 refuses a non-positive TTL,
and the schema enforces `expires_at > decided_at`. An approval that never
expires is a standing grant, which is the thing the approval requirement exists
to avoid.

**Where this maps.** NIST CSF `PR.AC-4` (separation of duties) and `PR.AC-3`;
CIS Control 5 and 6 (account and access management); COBIT / SOX-style
segregation of duties; Zero Trust — the requester's identity is never
sufficient authority for a change, and the grant is time-bounded and bound to
one envelope.

## Alternatives considered

**Admin-only approval for Class 3 — proposed, and withdrawn.** This was the
first draft, and rejecting it is the most useful thing in this ADR. It is a
**category error**: it conflates *clearance* (what work you are allowed to be
involved in) with *approval authority* (whose agreement makes a control
meaningful). Those are different axes, and Milestone 3 already ruled the same
way when it decided `approver` is not a clearance.

The concrete harm is the second-order effect. Restricting Class 3 approval to
administrators would mean **the only people able to approve high-risk work are
the people most able to bypass the control** — the same accounts that hold
database access, deployment rights and the ability to change the tool
declarations themselves. Rather than strengthening the control it narrows it
onto the population against which it offers least protection, and it makes the
approval queue depend on the availability of the smallest, busiest group of
accounts, which reliably produces standing approvals and shared credentials.

`test.security.rotate_key` is declared with `required_roles={operator}`
precisely to pin this: an operator may *request* a high-risk change and an
approver may approve it. A unit test asserts no catalog tool names `admin` as a
clearance for Class 3.

**A dedicated `senior_approver` role for Class 3.** Rejected as the same error
with an extra role. The role would have no meaning beyond "may approve Class 3
things", so it is not a clearance either — it is approval authority renamed.
Where an organisation genuinely wants a distinct approver population, the
mechanism already exists and is data, not code: a tool declares its own
`approver_roles` subset. Adding a role to the code registry commits every
deployment to a distinction most will not want.

**Making `self_approval` a request field with a justification.** Rejected
outright. A field a caller can set is a field an attacker can set, and no
amount of required justification changes that; the justification is written by
the same person asserting the exemption. The API having no such field is the
control.

**Enforcing separation of duties only in the service layer.** Rejected. The
service layer is the layer most likely to be refactored, extended by a future
milestone, or bypassed by a maintenance script. A `CHECK` constraint holds for
all of them, and costs one denormalised column.

**A stored `approvals_received` counter as the authority for the threshold.**
Rejected: a counter can drift — a double-increment, a partially applied
transaction, a repair script. `COUNT(DISTINCT approver_subject)` cannot, and it
agrees with the partial unique index by construction rather than by
maintenance. The counter column still exists, clamped to `min_approvals` and
constrained by `CHECK (approvals_received >= 0 AND approvals_received <=
min_approvals)`, but it is a display convenience and nothing reads it to make a
decision.

**Letting an admin cancel or override a pending approval.** Not offered.
Cancellation is available to the requester or an admin and moves the invocation
to `CANCELLED` — a terminal state with no execution — which is a withdrawal,
not an override. There is no path by which anyone can cause execution without a
qualifying approval.

## Consequences

- A single-identity deployment cannot approve anything outside development.
  That is the intended outcome: a Class 2 or Class 3 tool in production
  requires at least two identities to be useful.
- `ACOP_TOOLS_ALLOW_SELF_APPROVAL=true` in staging or production is a startup
  failure with a message naming the setting, not a runtime denial.
- Class 3 approvals expire in fifteen minutes. An approval given under pressure
  does not sit valid for an hour, and an approver who walks away leaves nothing
  usable behind.
- An insufficient approval is **recorded, never raised**. `approval_failure`
  returns the `PolicyReason` and the final gate writes it onto the invocation,
  because the gate runs on a background worker with no caller to raise to — an
  exception there would be swallowed by the worker loop and the invocation
  would sit in `READY` with nothing explaining why it never ran.
- `justification` is required and non-empty on every approval and denial
  (`CHECK (length(trim(justification)) > 0)`), and Class 2/3 invocation
  requests must carry one too — checked in the route rather than the schema,
  because the requirement follows from the *tool's* class and a request field
  naming its own class is exactly what the schema exists to refuse.
