# ADR-0015: The Capability Binding Invariant — a row alone can never execute

**Status:** Accepted
**Date:** 2026-09-04
**Milestone:** 4

## Context

[ADR-0014](ADR-0014-code-authoritative-tool-registry.md) decided that tool
definitions live in code and the database owns lifecycle. That decision is only
worth as much as its enforcement. Stated as an intention it is a convention;
stated as an invariant with named mechanisms and a test per mechanism, it is a
property of the build.

The threat this exists against is not exotic. It is the ordinary consequence of
a web application holding `INSERT` on its own tables: a SQL injection, a
compromised service credential, a migration written against the wrong
environment, or a backup restored past a removal. Each of those ends with an
attacker-chosen row in `tool_registration`. The question is what that row can
do.

## Decision

**G5, the Capability Binding Invariant:**

> A database row alone can never make anything executable.

Three mechanisms enforce it. All three are required, because each closes a
different route, and each is pinned by a test rather than by intent.

### Mechanism 1 — Adapter resolution is code-only

`ADAPTER_REGISTRY` in `acop/tools/adapters/base.py` is a module-level dict
populated by `register_adapter` at import. The only lookup is
`resolve_adapter(adapter_id)`, and its argument comes from
`ToolDefinition.adapter_id` — a literal in a reviewed declaration. **No function
in ACOP resolves an adapter from a database value.** A unit test parses the
module's AST and asserts it imports nothing from `acop.models.tool`.

### Mechanism 2 — Policy reads code, not the ORM

`ToolPolicyEngine.evaluate` takes a `ToolDefinition`, never an ORM object. The
one thing it takes from the database is `lifecycle_state`, passed in as a
value. A unit test parses `src/acop/tools/policy.py` and asserts it imports
neither `acop.models.tool` **nor anything beginning with `sqlalchemy`** — the
second half matters, because a module that can issue a query can reach the
first via a different name.

Gate 1 is where the invariant is observed from the inside: when
`PolicyContext.definition` is `None`, the engine denies
`capability_not_bound` and **nothing below that line runs**. No target is
looked up, no role is consulted, no adapter is reached.

### Mechanism 3 — Reconciliation is one-directional

`ToolRegistryReconciler` writes code into the database and never reads a
definition out. The only columns it reads are `lifecycle_state` and
`contract_hash`, which are facts *about* a declaration rather than the
declaration itself. A row naming a tool code does not declare is set `RETIRED`
with a stated reason — never deleted, because invocations reference it, and
never resurrected.

### The adversarial test

`tests/integration/test_tool_framework.py::TestProhibitionAndBinding::
test_a_registration_row_alone_cannot_mint_a_capability` inserts a
`tool_registration` row **by raw SQL** for a tool no code declares — the exact
shape a SQL injection, a compromised credential or a careless migration would
take — and then invokes it. The invocation is refused `capability_not_bound`
without reaching an adapter.

## Rationale

**[Fact] The invariant is only meaningful as a conjunction.** Any one mechanism
alone leaves a route open:

| Mechanism missing | What the row could then do |
|---|---|
| 1 — adapter resolution from code | Name an `adapter_id` and get real code called |
| 2 — policy reads code | Supply its own `permission_class` and `required_roles`, so a Class 3 capability could present as Class 0 with no approval |
| 3 — one-directional reconciliation | Survive a deploy that removed the declaration, or be written back into code's view of the world |

**[Best practice] Each mechanism is asserted by a test that reads source, not
behaviour.** An AST assertion that `policy.py` imports no ORM cannot be
satisfied accidentally and cannot pass while the property is false. A
behavioural test could pass because the offending code path simply was not
exercised. **[Opinion]** Source-level assertions are the right tool for
"this module must not be able to do X"; they are the wrong tool for almost
everything else, and are used here deliberately and sparingly.

**[Fact] `get_definition` returns `None` rather than raising.** That is what
lets the caller distinguish two genuinely different states: a name with no row
at all is a `404` (`ToolNotFoundError`), while a name that exists as a row but
has no code behind it is a policy denial with reason `capability_not_bound`.
Collapsing them would hide the second, which is the one that indicates
tampering.

**[Fact] The invariant is re-asserted at execution time.** The final execution
gate calls `get_definition` again and refuses `capability_not_bound` if the
declaration has gone (ADR-0016). A tool removed from the catalog between
authorization and execution must not run from a stale row.

**Where this maps.** NIST CSF `PR.AC-4` (access permissions managed with least
privilege and separation of duties) and `PR.DS-6` (integrity checking of
software); CIS Control 2 (Inventory and Control of Software Assets) — the code
catalog *is* the allow-list, and reconciliation is the enforcement that the
running inventory matches it.

## Alternatives considered

**A database-level guard: a trigger or a constraint on `tool_registration`.**
Rejected as protection against the wrong actor. Whatever can insert the row can
generally drop the trigger, because the application connects as an owner
today ([`../security/audit-immutability.md`](../security/audit-immutability.md)
documents the role split that would change this, and it is not yet applied).
More fundamentally, a trigger can only check the row against other rows; it has
no way to ask whether code declares the tool, which is the actual question.

**Signing registration rows and verifying the signature at dispatch.**
Rejected. It replaces "does code declare this?" — a question with a free,
exact, in-process answer — with a key-management problem whose compromise is a
new way to mint a capability. It would also still need mechanism 2, since a
correctly signed row could still carry a permission class.

**Accepting the class from the row and validating it against code.** Rejected
because it is mechanism 2 with an extra failure mode. The row's copy is either
identical to code's (in which case reading the row is pointless) or different
(in which case something is wrong and the safe response is to ignore the row).
Reading it at all creates the possibility of a validation that is skipped on
one path.

**Deleting orphaned registration rows at startup instead of retiring them.**
Rejected on two counts. `ON DELETE RESTRICT` on `tool_invocation` would refuse
the delete anyway, and correctly: an invocation whose registration vanished is
an execution with no explanation of what it was. `RETIRED` with a stated reason
keeps the history intact and makes the removal itself visible.

## Consequences

- An attacker with `INSERT` on `tool_registration` gains the ability to name a
  tool that does not resolve to an adapter, and nothing else. The attempt is
  audited as a denial.
- Policy cannot be given a database-derived fact without a change that breaks
  a test. Adding a `sqlalchemy` import to `policy.py` fails the suite before it
  fails a review.
- `TargetFacts` exists as a value object purely so the policy engine can reason
  about a target without querying for one. The caller does the lookup and
  passes the facts in.
- Prohibited capabilities are excluded from every listing for every role,
  admin included (`_invocable_by` in `api/routes/tools.py`), so the catalog
  endpoint cannot be used to confirm that a prohibited capability is declared.
- The cost is a small amount of duplication: gates 1–4 are re-run by
  `evaluate` even when `evaluate_prerequisites` already ran them. They are pure
  and cheap, and duplicated work is the accepted price of not having a
  fail-open when a caller skips a step.
