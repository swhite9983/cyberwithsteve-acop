# Adding a tool

A tool is a **declaration in reviewed Python**, not a row and not a config
file. Adding one is a commit, a review and a deploy, and
`git log src/acop/tools/catalog/` is the complete capability change history.
That friction is the control — see
[ADR-0014](../decisions/ADR-0014-code-authoritative-tool-registry.md).

This guide is the checklist. For what the framework does with the declaration
once it exists, read [`tool-framework.md`](tool-framework.md).

**Everything here fails the build, not a request.** `validate_declaration` runs
at import, from `register`, and the catalog is imported during application
startup. A declaration that breaks a rule produces a process that will not
start. That is the correct severity: rules 9, 10 and 11 are what make the "no
generic execution surface" claim true by construction rather than by
vigilance.

---

## Step 1 — Name and version

`domain.object.verb`. Three to five lower-case, dot-separated segments matching
`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){2,4}$`.

| Good | Why |
|---|---|
| `test.service.restart` | Domain, object, verb. Sorts usefully, reads well, and the blast radius of the namespace is obvious at a glance |
| `acop.system.health` | Same shape; `acop.` marks a tool that touches nothing outside the process |
| `proxmox.vm.snapshot.create` | Four segments where the object genuinely has two levels |

Version is `MAJOR.MINOR`, matching `^\d+\.\d+$`.

**There is no `latest`, and there never will be.** An approval binds to a
version. If a request could name `latest`, a deploy between approval and
execution would silently change what the queued approval refers to — the
approver agreed to one capability and a different one would run. The version is
part of the execution envelope and therefore part of its digest
([ADR-0018](../decisions/ADR-0018-execution-envelope-and-digest.md)).

Bump **MAJOR** for a breaking input or output change; **MINOR** for an additive
one. Either way it is a new registry key, a new registration row, and a
separate lifecycle.

---

## Step 2 — Choose the permission class honestly

| Ask | If yes |
|---|---|
| Does it touch anything outside the ACOP process? | Not Class 0 |
| Does it change anything, anywhere? | Class 2 or Class 3 |
| Could getting it wrong cause an outage, lose data, or affect a security control? | Class 3 |
| Is it a category in `PROHIBITED_CAPABILITIES`? | It cannot be declared at all |

The class is not a label. It determines what the framework *requires* of you,
and every requirement is checked rather than supplied:

| Class | What the import rules will then demand |
|---|---|
| 0 | `target_type` **must** be `NONE` (rule 7, both directions) |
| 1 | `target_type` must **not** be `NONE`; `required_roles` ⊇ `{viewer}` |
| 2, 3 | `approval_required=True` (rule 1), `validation_required=True` (rule 2), `required_roles` ⊇ `{operator}` (rule 3), `target_type` not `NONE` |

**Nothing is silently corrected.** A Class 2 tool that forgets
`approval_required` is *rejected*, not quietly fixed. A silent correction trains
people to omit the field and hides the one case where the omission was a
mistake in the other direction.

Understating a class is the failure mode to guard against, and it is not caught
by any rule — declaring a genuinely destructive change as Class 1 will pass
every check and skip approval entirely. That is what the review in step 10 is
for.

---

## Step 3 — Declare capability tags honestly

Tags describe the *shape* of what the tool does, independent of its name.

```python
capability_tags=frozenset({"service.restart"}),
```

**If any tag intersects `PROHIBITED_CAPABILITIES`, the build fails — not a
review, not a runtime denial.** `_check_prohibition` raises
`ToolDeclarationError` at import and the process does not start.

This is deliberately checked on the tags rather than on the `prohibited` flag.
A flag denies what someone remembered to flag; a category denies a shape of
capability. A future `proxmox.vm.delete` whose honest tag set includes
`vm.delete` is refused at import, which is the point: the check works even when
the person writing the declaration has not read this document.

The tags to be honest about, because they are the ones people are tempted to
soften: `arbitrary.shell`, `arbitrary.ssh`, `arbitrary.cli`,
`arbitrary.powershell`, `arbitrary.sql`, `arbitrary.winrm`,
`model.generated.command`, `storage.format`, `vm.delete`, `container.delete`,
`audit.disable`, `logging.disable`, `monitoring.disable`, `authn.bypass`,
`authz.bypass`, `firewall.unrestricted`, `routing.unrestricted`,
`secrets.read`, `secrets.export`.

**Do not omit a tag to get a declaration to compile.** If your tool genuinely
performs a prohibited category, the answer is that ACOP does not do that.
Removing an entry from the registry requires an ADR.

`allow_registration_for_testing` is the single escape hatch, exactly one
catalog tool may set it (`test.prohibited.shell_exec`), a unit test asserts
that, and it permits **registration, not execution** — gate 3 denies every
invocation regardless.

---

## Step 4 — Write the input and output models

Both are Pydantic models in `src/acop/tools/catalog/schemas.py` (or beside your
tool), and both must set:

```python
model_config = ConfigDict(extra="forbid")
```

That is import rule 12, checked **recursively over the whole schema tree**
including `$defs`. It is what turns an injected field such as `api_key` into a
*rejection* rather than something merely redacted downstream. A model that
silently dropped unknown keys would let a prompt-injected payload reach the
framework, be stripped, and leave no trace that anything was attempted.

### Field names that fail the build

Checked over every field name in the model **and every nested model**, because
`credentials.password` is a password one level down.

| Rule | Forbidden | Why |
|---|---|---|
| 9 | Anything containing a fragment from `SECRET_FIELD_FRAGMENTS` (Milestone 1's `SENSITIVE_KEY_FRAGMENTS`) — `password`, `token`, `secret`, `api_key`, … | Credentials belong to the adapter. **This is also what makes the canonical input safe to persist verbatim, and therefore what makes the envelope digest recomputable at the final gate.** A tool that must change a credential accepts a *reference*, never a value |
| 10 | `host`, `hostname`, `ip`, `ip_address`, `address`, `url`, `uri`, `endpoint`, `dsn`, `connection_string`, `server`, `target_host` | Resolving an address is the adapter's job, from the asset's registered identifiers plus the adapter's own configuration — never from a caller's argument. This is what makes server-side request forgery structurally impossible rather than merely unlikely |
| 11 | `command`, `cmd`, `commands`, `script`, `shell`, `exec`, `execute`, `query`, `sql`, `statement`, `payload`, `raw`, `body`, `powershell` | ACOP has no generic execution surface, and this is one of the three static checks that prove it |

If you need to express something adjacent, name it for what it *is*:
`test.prohibited.shell_exec` takes an `intent` field — prose, not a command —
precisely because a field named `command` would be refused and the tool could
not be declared at all, leaving nothing to prove the prohibition against.

### Output models

Same `extra="forbid"`. What ACOP stores and returns is an **allow-list** built
from the declared field names, not the returned dictionary stripped of
forbidden ones — a deny-list lets through the first key nobody anticipated.
Milestone 1's `redact` is applied afterwards as defence in depth; for a
correctly declared tool it changes nothing, and if it ever *does* change
something that is a declaration defect and it is logged at `error`.

Set `output_allow_list` when you want the published surface to be narrower than
the model, or when you want adding a field to the model to be a deliberate act
that must also be added here before it can leave the boundary.
`test.security.rotate_key` does this.

---

## Step 5 — Bind an adapter

```python
adapter_id="test.simulated",
```

Import rule 13 refuses a declaration whose `adapter_id` does not resolve
through `ADAPTER_REGISTRY`. Checked at import so that a tool which could be
requested but never executed is a failed build rather than a confusing runtime
denial. **Import the adapter module before the catalog** — the catalog's
`__init__` does this with `import acop.tools.adapters` at the top.

An adapter:

- receives typed, validated input and a **resolved** target — never a caller's
  raw request, never a command, never a network locator;
- owns its own credentials and never sees a caller's;
- **reports an outcome, not a state**. It returns an `AdapterResult` saying what
  it observed; whether that becomes `EXECUTED`, `FAILED` or `TIMED_OUT` is the
  framework's decision. An adapter that could set the state could report success
  for a change that did not happen;
- implements `validate` as a **separate observation**, never a re-read of what
  `execute` returned. An adapter that validated by echoing its own return value
  would confirm nothing at all.

Registering two adapters under one id raises. Import order must not decide
which code executes.

---

## Step 6 — Approval policy

```python
approval_policy=ApprovalPolicy(
    approval_required=True,
    min_approvals=2,
    approver_roles=frozenset(role.value for role in APPROVAL_AUTHORITY_ROLES),
    distinct_approvers_required=True,
    ttl_seconds=900,
    self_approval_permitted=False,
),
```

| Field | Rule that governs it |
|---|---|
| `approval_required` | Rule 1 — mandatory `True` for Class 2/3 |
| `approver_roles` | Rule 4 — must be non-empty and a subset of `{approver, admin}`. A tool naming any other role is refused: it would name approvers who could never approve |
| `min_approvals` | Rule 5 — at least 1 |
| `distinct_approvers_required` | Rule 5 — mandatory when `min_approvals > 1`. Asking two people and accepting the same person twice is one approval wearing a disguise |
| `ttl_seconds` | Rule 5 — must be positive. An approval that never expires is a standing grant |
| `allowed_environments` | Gate 7. Empty means any |
| `self_approval_permitted` | **Declarative only.** A tool cannot grant itself the exemption; whether a self-approval is actually permitted is derived server-side from configuration *and* policy *and* subject identity |

**Do not reach for a higher role to express severity.** Approval authority is
`{approver, admin}` for every class, and `admin` is in that set only because it
is a superset role. Class 3 strength comes from `min_approvals`, distinct
approvers, a shorter TTL and environment restrictions — see
[ADR-0019](../decisions/ADR-0019-separation-of-duties-and-class-3-strength.md),
which records why admin-only Class 3 approval was proposed and withdrawn.

---

## Step 7 — Validation, timeout, idempotency and retry

```python
validation_required=True,
validation_delay_seconds=0.05,
timeout_seconds=30.0,
idempotency=IdempotencyKind.KEYED,
adapter_idempotent=True,
retry_policy=RetryPolicy(max_attempts=1),
```

**Validation.** Mandatory for Class 2/3 (rule 2). Your adapter's `validate` must
observe the target independently. Use `validation_delay_seconds` when a change
needs a moment to become observable — checking instantly and reporting
`NOT_CONFIRMED` would be a race dressed up as a finding.

**Timeout.** Enforced from outside by `asyncio.wait_for`; an adapter cannot
extend its own deadline. It must be **less than**
`ACOP_TOOLS_EXECUTION_LEASE_SECONDS` (120s by default), or the reaper will
record `EXECUTION_INDETERMINATE` for an invocation that is still running.

**Idempotency.** Pick honestly:

| Kind | Meaning | Consequence |
|---|---|---|
| `NATURALLY_IDEMPOTENT` | Reading state; repetition changes nothing | Retries are safe |
| `KEYED` | Repetition is deduplicated by an idempotency key | Class 2/3 requests must carry a key; the database enforces it |
| `NON_IDEMPOTENT` | Repetition would act twice | Rule 8 pins `max_attempts` to 1 |

**Retry.** Rule 8 refuses `retry_on` categories outside `RETRYABLE_CATEGORIES`
— only `ADAPTER_UNAVAILABLE` and `TARGET_UNAVAILABLE`, the two where "it did
not happen" is knowable — and refuses `max_attempts > 1` when
`adapter_idempotent` is `False`. **A timeout is deliberately not retryable**: a
request that timed out may still be in flight on the far side.

---

## Step 8 — The fourteen import-time rules

The complete list, with what each prevents. Rules 1–13 live in
`validate_declaration`; rule 14's uniqueness half lives in `register`, because
only the registry can see two declarations at once.

| # | Rule | What it prevents |
|---|---|---|
| 1 | Class 2/3 must declare `approval_required=True` | A change class that skips approval because someone forgot a keyword |
| 2 | Class 2/3 must declare `validation_required=True` | A change nobody checks is a change nobody knows happened |
| 3 | `required_roles` must reach the class floor (`CLASS_MINIMUM_ROLES`) | A Class 2 tool invocable by a viewer |
| 4 | `approver_roles` must be non-empty and ⊆ `{approver, admin}` | Naming an approver population that cannot approve, or inventing approval authority outside the two roles that hold it |
| 5 | `min_approvals ≥ 1`; `> 1` requires distinct approvers; TTL positive | One approval wearing a disguise, and standing grants |
| 6 | No `capability_tags` may intersect `PROHIBITED_CAPABILITIES` | The platform acquiring a shell, a SQL surface, or a way to disable its own controls |
| 7 | `target_type is NONE` ⟺ `CLASS_0_INFORMATION`; an `ASSET` tool must name accepted types | A Class 0 tool that reaches outside ACOP; a targeted tool with nothing to scope against, so no target could ever be refused |
| 8 | `NON_IDEMPOTENT` ⇒ one attempt; retry categories restricted; retries require an idempotent adapter | A framework retry that acts twice |
| 9 | No secret-bearing field name in the input schema | A credential arriving from a caller — **and** an unpersistable canonical input, which would make the envelope digest unverifiable |
| 10 | No network-locator field name | Server-side request forgery; a caller choosing a destination |
| 11 | No command field name | A generic execution surface |
| 12 | Input and output models must forbid additional properties, recursively | An injected `api_key` being redacted rather than rejected |
| 13 | The `adapter_id` must resolve to registered code | A tool that can be requested and never executed |
| 14 | Name and version shape; and the `(name, version)` key must be unique | Ambiguous identity, `latest`, and import order deciding which contract applies |

`IMPORT_RULE_COUNT = 14` is exported from `acop.tools.contract` so the count
can be pinned. If you add a rule, update it and add the assertion — the
constant's docstring anticipates a test that does not yet exist.

---

## Step 9 — Changing an existing tool

**A schema change needs a version bump. Never edit in place.**

`ToolDefinition.contract_hash()` is a SHA-256 over the security-significant
declaration: identity, class, adapter id, required roles, target type and
accepted asset types, capability tags, prohibition, the whole approval policy,
validation and timeout, idempotency, retry attempts, sensitivity, and both JSON
schemas. `description` and `lifecycle_default` are excluded — prose and an
operational hint.

At startup, `ToolRegistryReconciler` compares the stored hash to the computed
one. **If they differ, the process refuses to start:**

```
Tool test.service.restart@1.0 changed without a version bump. Approvals already
given were bound to envelopes computed under the previous contract, so the
correct action is a MAJOR or MINOR version increment, not an in-place edit.
```

That looks harsh until you consider what it prevents: editing a Class 2 tool's
input schema in place, in a release, while approvals bound to envelopes
computed under the old schema are still pending. Those approvals would then be
carried onto a request that means something different from the one the approver
read.

| What you changed | Do this |
|---|---|
| Input or output schema, in any way | New version. MAJOR if breaking, MINOR if additive |
| Permission class, required roles, approval policy, target types, capability tags, timeout, idempotency, retry, sensitivity | New version |
| `description` | Edit in place. Not in the hash |
| `lifecycle_default` | Edit in place. Not in the hash |
| Removing a tool entirely | Delete the declaration. Reconciliation marks the row `RETIRED` with a stated reason and never deletes it, because invocations reference it |

`reconcile(allow_rehash=True)` rewrites the stored hash instead of raising. It
is for development only, nothing in the application passes it, and it must not
be used to make a production startup failure go away — the failure is the
control working.

Adding a new version does not retire the old one. Both are registered, both
have independent lifecycles, and an admin can disable the old one once nothing
requests it.

---

## Step 10 — Review checklist before merging

Structural checks the build already does are not on this list. These are the
judgements a reviewer has to make, because no rule can.

**Class and severity**

- [ ] Is the permission class honest? Would you be comfortable if this ran
      **without approval** — because that is what Class 0 and Class 1 mean?
- [ ] Could a wrong argument here cause an outage, lose data, or weaken a
      security control? If so it is Class 3, not Class 2.
- [ ] Are the capability tags honest, including the ones that would make the
      declaration fail?

**Blast radius**

- [ ] Are `target_asset_types` as narrow as they can be? A tool that accepts
      every asset type can act on every asset.
- [ ] Does the input schema constrain ranges, lengths and enumerations, so a
      valid-but-absurd argument is rejected at gate 4 rather than acted on?
- [ ] Is there a `Literal` or an enum where a free string would let a caller
      steer behaviour?

**The adapter**

- [ ] Does it derive every address from registered identifiers and its own
      configuration, and never from the payload?
- [ ] Does `validate` observe the target independently, rather than re-reading
      what `execute` returned?
- [ ] Does it raise a typed `ToolError` for known failures, so the framework can
      classify and possibly retry, rather than a bare `Exception`?
- [ ] Does it return **nothing** in `payload` that could carry a credential, a
      device banner, or an echoed request body?

**Approval and idempotency**

- [ ] For Class 3: is `min_approvals=2` with `distinct_approvers_required`, and
      is the TTL short enough that an approval given under pressure does not sit
      valid for an hour?
- [ ] Is `self_approval_permitted` `False`? It should be, for anything real.
- [ ] Is `idempotency` right? If running it twice would act twice, it is
      `NON_IDEMPOTENT` and gets one attempt.
- [ ] Is `timeout_seconds` comfortably below the deployment's execution lease?

**Tests**

- [ ] A test that the tool is refused for a principal lacking its roles.
- [ ] A test that an undeclared input field is rejected, not ignored.
- [ ] For Class 2/3: a test that it cannot execute without approval, and a test
      that the change is *observed*, not merely reported.
- [ ] For a new prohibited-category tag, if you added one: a test that
      declaring a tool with it fails the build.

**Documentation**

- [ ] Does the tool's module docstring say what it proves or what it is for,
      and why its class and policy are what they are? Every catalog tool does.
- [ ] If this decision was contentious, does it need an ADR rather than a
      docstring?
