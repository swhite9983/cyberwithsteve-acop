# ADR-0018: The execution envelope and its digest

**Status:** Accepted
**Date:** 2026-09-04
**Milestone:** 4

## Context

An approval that means "yes, run something called `test.service.restart`" is
worthless. Between the moment an approver agrees and the moment a worker
dispatches, several things can change: the arguments, the target, the tool's
declared policy, or the tool's contract altogether. If the approval survives
those changes, it is not an approval of anything in particular.

So the approval has to bind to a specific statement — *this tool, at this
version, under this permission class, against this target, with these
arguments, under this execution and approval policy* — and it has to be
possible to **prove at execution time** that none of it changed.

## Decision

### The envelope

`build_envelope` assembles one dictionary per invocation:

| Block | Contents | Why an approval must not survive its change |
|---|---|---|
| `tool` | `name`, `version`, `contract_hash` | A different version is a different capability; the contract hash catches an in-place edit |
| `permission_class` | The class from the code registry | A Class 3 action approved as a Class 2 one was never approved |
| `target` | `kind`, `asset_id`, `target_ref` | Restarting a different host is a different act |
| `input` | The canonical validated input | The arguments are what was reviewed |
| `execution` | Timeout, idempotency, attempts, backoff, retry categories, validation policy | These determine what "run it" does |
| `approval` | The approval-policy snapshot, including approver roles and TTL | The rules the approval is measured against |

Everything an approver would **not** have cared about is deliberately outside
it — the request id, the wall-clock time, the requester's display name — so an
approval is not invalidated by noise. `build_target_block` includes only the
resolved identity and **not** the asset's display name: renaming an asset would
otherwise invalidate every pending approval against it, which is a surprising
failure with no security benefit.

### The digest

`envelope_digest` is SHA-256 over the canonical rendering. It is computed once
at request time, stored on `tool_invocation.envelope_digest`, copied onto every
approval as `approved_envelope_digest`, and **recomputed** at the final
execution gate from the stored canonical input. If the two differ, the approval
does not transfer — it is invalidated, not carried forward.

`input_digest` is a second, narrower digest over the arguments alone. The two
answer different questions: "did the arguments change?" is useful in an audit
query and an idempotency comparison; "did anything an approver agreed to
change?" is what gates execution.

### Canonicalisation rules

Every rule exists because **a digest that varies with something insignificant
is a digest that fails randomly**, and a control that fails randomly is a
control people learn to work around.

| Rule | Failure it prevents |
|---|---|
| Object keys sorted (`sort_keys=True`) | JSON preserves insertion order; `{"b":1,"a":2}` and `{"a":2,"b":1}` are the same request |
| Tight separators, `ensure_ascii=False` | The encoding is one fixed choice rather than the interpreter's default |
| Values from Pydantic **JSON mode**, not Python mode | A `datetime` or `UUID` gets one textual representation rather than a repr that could change with a library version |
| Sets sorted into lists | A `frozenset` has no stable iteration order |
| Unknown types raise rather than stringify | Silently stringifying an object would make the digest depend on its `__str__` |

### Why the digest is recomputable at all

Because **import rule 9 forbids secret-bearing fields in any tool input
schema**, the canonical input is safe to persist verbatim — so
`tool_invocation.input_canonical` holds the same bytes the digest was taken
over, and the gate can recompute it exactly.

## Rationale

**[Fact] An earlier draft persisted a redacted input while hashing the raw
one.** The intent was defensible — do not store what might be a secret — and
the result was that the final gate could not verify anything: recomputing from
the redacted value never matched the digest taken over the raw value, so the
check could only ever be disabled or made vacuous. The fix is not to weaken the
check, it is to make the stored value trustworthy: rule 9 refuses any input
field whose name contains a fragment from Milestone 1's
`SENSITIVE_KEY_FRAGMENTS`, checked recursively into nested models, at import
time. `credentials.password` is a password one level down and is refused the
same way. **[Opinion]** This is the single most important coupling in the
milestone, and it is the reason rule 9 is a build failure rather than a
runtime filter.

**[Fact] The binding is checked in two places, and they prove different
things.** `ToolApprovalService._check_envelope` compares the digest the
approver **states** in their request body against the invocation's. The final
gate recomputes the invocation's digest from stored data and compares it to
what each approval recorded. The first proves the approver acted on the
envelope they were shown, not on one that changed between the `GET` and the
`POST`. The second proves the stored request has not been altered since. Either
alone leaves a real gap.

**[Fact] `envelope_digest` and `envelope_digest` as a request field are opposite
things.** `FORBIDDEN_INVOCATION_FIELDS` lists `envelope` and `envelope_digest`,
because an invocation's envelope is *computed*, never supplied. They are
deliberately **not** forbidden on an approval body, where a caller-stated
digest does the opposite job — it binds the approver to what they saw. A unit
test asserts both lists against the generated OpenAPI schema.

**[Fact] The contract hash inside the envelope is what turns a schema edit into
a startup failure.** `contract_hash()` covers identity, class, roles, schemas,
approval policy and execution policy, and deliberately excludes `description`
and `lifecycle_default` — prose and an operational hint. Reconciliation refuses
to start when a stored hash differs from the code's, because pending approvals
were bound to envelopes computed under the old contract. The remedy is a
version bump, never an in-place edit.

**[Fact] Envelope integrity is checked before approval validity at the gate.**
A tampered stored input produces `envelope_integrity_failed` rather than an
approval error, which is the more useful diagnosis: it says the record is
untrustworthy, not that someone needs to re-approve.
`test_a_tampered_canonical_input_fails_envelope_integrity` alters
`input_canonical` by raw SQL — the shape a database compromise would take — and
the gate refuses.

**[Fact] `approval_failure` reports the most actionable reason first.** A
changed envelope is reported as such even if the approval had also expired,
because re-approving would not help; the request has to be re-made.

**Where this maps.** NIST CSF `PR.DS-6` (integrity checking mechanisms) and
`PR.AC-4`; CIS Control 3.11 / 8; Zero Trust — the approval is a
narrowly-scoped, time-bounded, cryptographically-bound grant for one specific
action rather than a standing permission.

## Alternatives considered

**Binding an approval to the tool, not the request.** Rejected: it is
indistinguishable from granting the approver's role to the requester for the
TTL. Anyone could then change the target or the arguments after approval and
execute something nobody agreed to.

**Binding to the input digest alone.** Rejected because the arguments are only
part of what an approver agreed to. Approving a restart of asset A and having
it execute against asset B involves no change to the arguments at all, since
the target is not an argument. The same applies to the permission class and the
approval policy: a change to either alters what the approval means without
touching the input.

**Storing a redacted input and hashing the raw one.** The earlier draft,
withdrawn. It made the final gate's most important check unverifiable — see the
first rationale point. Recorded here rather than quietly dropped, because the
instinct that produced it ("never persist anything that might be a secret") is
sound and will recur; the correct expression of it is rule 9, which makes the
secret unable to arrive in the first place.

**Hashing the raw request body as received.** Rejected: it is not canonical.
The same request sent with different key order, different whitespace, or a
different `datetime` serialisation would produce a different digest, so an
approval would fail for reasons that have nothing to do with what was being
approved. Validation-then-canonicalisation also means the digest covers what
the tool's schema actually accepted, including defaults, rather than what the
caller happened to type.

**Including the asset's display name in the target block, for readability.**
Rejected. Renaming an asset in the CMDB would invalidate every pending approval
against it — a surprising, hard-to-diagnose failure with no security benefit,
since the identity that matters is the id. Readability is the envelope
endpoint's job (`GET /tool-invocations/{id}/envelope`), not the digest's.

**A MAC or signature over the envelope instead of a bare digest.** Rejected as
solving a different problem. A digest detects alteration of stored data, which
is the threat here; a MAC would additionally prove *who* computed it, which
matters only if the envelope crossed a trust boundary. It does not — it is
computed and verified in the same process from the same code — so a MAC would
add a key to manage and nothing else. **Reconsider this** if envelopes are ever
computed by one service and verified by another.

## Consequences

- `tool_invocation.input_canonical` is stored verbatim and is readable by
  anyone who can read the row. That is safe **only** because of rule 9, and the
  coupling is documented in the column's own `doc=` string so it survives
  someone reading the schema without this ADR.
- A rejected invocation stores `envelope = {"refused": True, "reason": ...}`
  with a digest of sixty-four zeroes. There is no validated input to hash, and
  fabricating one would be worse than saying so.
- A tool declaration change without a version bump fails startup. This is the
  loudest failure in the milestone, and it is deliberate.
- The digest depends on `model_json_schema()` output, so a Pydantic upgrade
  that changes schema generation will change every contract hash. That is a
  real operational cost: it presents as contract drift on the first startup
  after the upgrade, and the remedy is a deliberate rehash in development
  followed by a normal release, not a silent acceptance in production.
