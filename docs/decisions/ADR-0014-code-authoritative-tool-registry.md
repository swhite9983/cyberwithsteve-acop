# ADR-0014: The tool registry is code; the database owns lifecycle only

**Status:** Accepted
**Date:** 2026-09-04
**Milestone:** 4

## Context

Milestone 4 introduces the first thing in ACOP that acts on the world outside
the process. Every earlier milestone read, stored or retrieved; this one
restarts services and rotates credentials. The question that has to be answered
before any of it is written is **where a capability comes from** — what act, by
whom, brings a new executable capability into existence.

There are only two candidate answers. Either a capability is a row somebody
inserts, or it is a declaration somebody commits. The choice determines the
threat model for the entire milestone, because it determines which credentials
and which failure modes can mint one.

Alongside that sits a genuinely operational need that pulls the other way: at
3am, an on-call engineer must be able to take a misbehaving tool out of service
**immediately**, and the record must say who did it and why.

## Decision

**Tool definitions live in reviewed Python.** A tool is a frozen
`ToolDefinition` dataclass in `src/acop/tools/catalog/`, registered at import
by `acop.tools.registry.register`, which applies fourteen validation rules
before admitting it. Identity, version, permission class, required roles,
input and output schemas, capability tags, approval policy, validation policy,
timeouts, idempotency, retry policy and adapter binding are all owned there and
only there.

**PostgreSQL owns exactly one thing about a tool: its operational lifecycle.**
`tool_registration` carries `lifecycle_state` (`ACTIVE` / `DISABLED` /
`RETIRED`), the attribution for a disable (`disabled_at`,
`disabled_by_subject`, `disabled_reason`), the attribution for a retirement,
`first_registered_at`, and a `contract_hash` used only for drift detection.

**`tool_registration` deliberately carries no `permission_class` column.** The
authoritative class for *policy* is read from the code registry at request
time. The authoritative class for *history* is snapshotted onto
`tool_invocation.permission_class`, which is what reporting queries group by.

Rows are created by `ToolRegistryReconciler`, from code, at startup. No API
creates one; the only tool-lifecycle endpoints are
`POST /tools/{name}/disable` and `POST /tools/{name}/enable`, both admin-only,
both requiring a stated reason, both audited. There is no `DELETE`.

## Rationale

**[Fact] If a tool definition were data, the set of things that can mint a
capability is the set of things that can write a row.** That set is large and
includes several events that are not attacks at all: a SQL injection anywhere
in the application, a compromised admin credential, a careless migration, a
restored backup from before a capability was removed, a misdirected `psql`
session. As code, minting a capability requires a commit, a review and a
deploy, and `git log src/acop/tools/catalog/` is the complete capability change
history — a property no audit query over a mutable table can offer.

**[Fact] The fourteen rules can only fail the build if declarations are code.**
Rules 9, 10 and 11 refuse a tool whose input schema names a secret, a network
locator or a command. Enforced at import, a violating declaration produces a
process that will not start. Enforced against rows, the same check would be a
runtime denial for a capability that already exists in the database — the
attacker's row is still there, and the check is now a filter that has to be
right every time rather than a gate that ran once.

**[Fact] Only the class-in-code arrangement makes the contract hash meaningful.**
`ToolDefinition.contract_hash()` covers the security-significant declaration
and excludes prose. Reconciliation refuses to start when a stored hash differs
from the code's, because approvals already given were bound to execution
envelopes computed under the previous contract (see ADR-0018). If the
declaration lived in the database, there would be nothing stable to hash it
against.

**[Opinion] The database is still needed, and the line is drawn at the right
place.** "This tool is misbehaving, stop it now" is an operational fact about a
capability, not the definition of one. Requiring a deploy to express it would
be worse than useless: it creates pressure to leave a misbehaving tool enabled
during exactly the incident the control exists for. Lifecycle is therefore the
one thing the database owns, and the schema is written so a disable without an
attributed actor and a stated reason is not representable:

```sql
CHECK ((disabled_at IS NULL) = (disabled_by_subject IS NULL))
CHECK ((disabled_at IS NULL) = (disabled_reason IS NULL))
```

**[Best practice] Reconciliation retires, never deletes.** A registration row
is referenced by every invocation that used it, under `ON DELETE RESTRICT`.
When code stops declaring a tool, reconciliation sets `RETIRED` with a stated
reason, and the invocation history stays readable.

## Alternatives considered

**A pure-database registry — tools as rows, editable through an admin API.**
Rejected, and this is the decision the rest of the milestone is built on. Tool
creation would become a data operation, which means every path that can write
a row becomes a path that can create an executable capability: a SQL injection
in an unrelated endpoint, a compromised admin credential, a migration written
in a hurry, a backup restored from a point at which a since-removed capability
still existed. Each of those is an ordinary operational event; none of them
should be able to give an autonomous system a new way to act on infrastructure.
The secondary problem is as bad: there would be no reviewed artifact to point
at when asked "what can this platform do?", only a table whose current contents
answer for today.

**Pure code with lifecycle by configuration and restart.** Attractive on paper —
one source of truth, nothing in the database at all — and rejected on
operational grounds. Disabling a misbehaving tool would require a config change
and a process restart, i.e. a deploy. During an incident that is minutes at
best and a change-approval cycle at worst, and the predictable human response
is to leave the tool enabled and "watch it", which is precisely the outcome the
control exists to prevent. It also loses attribution: a config file records
what is set, not who set it or why, and six months later an unexplained outage
is what remains. **[Opinion]** A control that is too slow to use during an
incident is not a control.

**Code mirrored into the database "for reporting".** Rejected, and this one was
drafted and then removed. The proposal was a `permission_class` column on
`tool_registration`, populated by reconciliation, read only by dashboards. Two
objections, both concrete. First, it is a second copy of a security-significant
value, and two sources of truth can disagree — after a partial reconciliation,
after a manual `UPDATE`, after a restored backup that predates a class change.
Second, **a column that exists is a column something eventually reads**: the
next contributor writing a policy query has no way to know the column is
decorative, and a join that "just works" is how a reporting column becomes a
policy input. The reporting need is met better anyway by
`tool_invocation.permission_class`, which is the class that actually applied to
each request rather than the class that applies today.

**Signed declaration files loaded at startup.** Rejected as ceremony that adds
a key-management problem without changing the trust boundary. The deployed
artifact already has to be trusted to run at all; signing a file that lives
inside it proves nothing extra, and introduces a signing key whose compromise
is a new way to mint a capability.

## Consequences

- Adding, changing or removing a capability requires a pull request. This is
  the intended friction and it is stated plainly in the catalog's docstring.
- Editing a tool's schema in place fails startup with a `ConfigurationError`
  naming the stored and computed hashes. The correct action is a version bump
  (see `docs/tools/adding-a-tool.md`).
- `ToolRegistryReconciler.reconcile(allow_rehash=True)` exists for development,
  where rewriting the stored hash is convenient. Nothing in the application
  passes it; `main.py` calls `reconcile()` with the default, and a
  contract-drift `ConfigurationError` is deliberately re-raised out of the
  lifespan so the process stops.
- A `tool_registration` row for a tool no code declares is inert. It resolves
  to no definition, and every invocation against it is refused
  `capability_not_bound` before an adapter is reached — see ADR-0015.
- Startup tolerates an unreachable database (the rest of the lifespan does too)
  but no tool can execute until reconciliation succeeds, because no
  registration row exists to invoke against.
