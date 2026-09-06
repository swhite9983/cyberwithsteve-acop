# Milestone 5 — Proxmox foundation (Checkpoint 1C)

**Scope of this checkpoint: vocabulary, configuration and a bound adapter.
Nothing here talks to Proxmox.** No HTTP client, no tool declarations, no
discovery, no CMDB writes, no credentials created. Those arrive in later
checkpoints, each reviewed on its own.

This note records the identity decisions, because they are the ones that are
expensive to change after data exists.

---

## 1. `AssetType.CLUSTER`

A Proxmox cluster is now a first-class asset type, and `MEMBER_OF` accepts
`HOST → CLUSTER`.

Before this change the only `MEMBER_OF` targets were `VLAN` and `DEVICE`, so a
cluster would have had to be stored as a `DEVICE`. That is a false statement at
the **root** of the graph: every node's membership edge and every cluster-level
fact would hang off an asset whose declared type is wrong. Correcting it later
means re-typing an asset that identifiers, facts and edges already reference.

The widening is **target-side only**:

| | Before | After |
|---|---|---|
| `MEMBER_OF.sources` | `SWITCH_PORT, HOST, VM` | unchanged |
| `MEMBER_OF.targets` | `VLAN, DEVICE` | `VLAN, DEVICE, CLUSTER` |

A host joins a cluster. A cluster joins nothing. Adding `CLUSTER` to the source
set would permit `CLUSTER MEMBER_OF CLUSTER` with nothing to say what that
means, and a constraint is only worth having while it is narrow. No other
`EdgeSpec` learned about clusters, and a test asserts that.

---

## 2. Instance-scoped identifiers

### What changed

| Namespace | Unique | Value | Status |
|---|---|---|---|
| `proxmox:instance` | ✅ | the instance id | **new** |
| `proxmox:node` | ✅ | `<instance>/<node>` | **new** |
| `proxmox:guest` | ✅ | `<instance>/<vmid>` | **new** |
| `proxmox:storage` | ✅ | `<instance>/<storage_id>` | **new** |
| `proxmox:uuid` | ✅ | SMBIOS UUID | retained |
| `proxmox:vmid` | ❌ | — | **removed** |
| `proxmox:cluster` | ❌ | — | **removed** |

### Why the old pair had to go

Both were registered **non-unique**, and `IdentityResolver.find_matches`
considers only unique namespaces. So neither participated in identity resolution
at all. A guest with no readable SMBIOS UUID — every LXC container, and any VM
whose config ACOP had not read — matched nothing, and would have been **created
fresh on every discovery sweep**. Unbounded duplicates, with no merge workflow
to clean them up.

The replacements are unique, so they correlate.

### Why the cluster name is excluded

The obvious composite is `<cluster>/<vmid>`. It is the wrong one, and the reason
is ownership rather than taste.

| | `<instance>/<vmid>` (chosen) | `<cluster>/<vmid>` |
|---|---|---|
| Who owns every segment | **ACOP** | **Proxmox** |
| Cluster renamed by an administrator | no effect | **every guest identifier changes at once** |
| Result of that rename | — | all guests orphaned, all re-created, unbounded duplicates |

A correlator built on a value somebody else can change orphans everything under
it the day they change it. The instance id is ACOP-owned, assigned once,
validated against `^[a-z0-9][a-z0-9-]{0,31}$`, and never derived from anything
Proxmox reports — not the cluster name, not a hostname, not a certificate.

The cluster name is still worth recording, as an ordinary **non-unique**
attribute of the cluster asset. It is a label, not an identity, and a rename is
then harmless.

The narrow instance-id pattern is also load-bearing rather than cosmetic: the
value is concatenated into `<instance>/<vmid>`, so a slash, colon or space in it
would make the identifier ambiguous about where the instance ends and the object
begins.

### Unique means "at most one live asset"

All five Proxmox namespaces are declared **unique**, because every value is
already scoped: four carry the ACOP-owned instance id, and `proxmox:uuid` is
globally unique on its own. Unique here means *at most one **live** asset* — the
index is partial (`WHERE retired_at IS NULL AND unique_in_namespace`), so
retiring an identifier frees its value. That is what makes legitimate VMID reuse
representable without a merge: the old asset keeps its history, its identifier
is retired, and the reused value resolves to nothing and creates a new asset.

Both halves are proved against the real partial unique index in
`tests/integration/test_cmdb_constraints.py`: two live assets cannot share
`homelab-pve/100`, the same VMID in a *different* instance is not a collision,
and the value becomes available again once the prior identifier is retired.

### Removing a namespace migrates nothing

An unregistered namespace is still **accepted** by `normalise`; it is simply
forced non-unique. So an `asset_identifier` row written under `proxmox:vmid`
before this change keeps working and merely stops being a correlator — which is
what it already was, since it was registered non-unique. There is nothing to
migrate and no schema change: `asset_identifier.namespace` is `String(48)` with
no CHECK constraint, and `IDENTIFIER_NAMESPACES` is a Python dict.

---

## 3. QEMU strong identity vs LXC ambiguity

These are **not** equally identifiable, and pretending otherwise is how a
recreated guest silently inherits a dead one's history.

**QEMU — strong.** A VM carries a SMBIOS UUID, exposed in its config. A
recreated VM gets a new one. `proxmox:uuid` is therefore an authoritative
discriminator: if the scoped identifier matches an existing asset but the UUID
disagrees, that is a *different guest wearing a reused VMID*, and it must be
refused rather than merged.

**LXC — weak.** A container has no SMBIOS UUID. The only discriminators are
hostname and OS, both of which a legitimate rename also changes. A container
destroyed and recreated with the same VMID, hostname and OS, between two
consecutive sweeps, with no absence observed in between, is **not
distinguishable** by anything in the read-only Proxmox surface.

That risk is recorded rather than designed away. It is bounded — normal
operation retires the identifier when a guest is first seen absent, which
narrows the window to "recreated between two consecutive sweeps" — and the
reconnaissance checkpoint explicitly looks for a durable LXC creation timestamp
or config digest. If one exists it becomes the discriminator and the risk
disappears. If none exists, that is a design amendment to raise, not a detail to
absorb quietly.

---

## 4. No automatic merge

Where identity is ambiguous, ACOP **refuses and asks a human**. It never merges.

`IdentityResolver` already raises `IdentityConflictError` when two unique
identifiers on one observation resolve to two different assets, and that
behaviour is unchanged and relied upon. Nothing in this milestone adds automatic
merge logic, a similarity heuristic, or a "probably the same machine" rule.

Two assets that are genuinely one machine stay two assets, visibly, until a
person decides. That is the correct failure: a wrong merge is silent and
destroys history, while a duplicate is loud and reversible.

---

## 5. Configuration

Seven `ACOP_PROXMOX_*` settings, all adapter-owned, defaulting to **disabled**
so an existing deployment is unchanged by this milestone.

| Setting | Default | Note |
|---|---|---|
| `ACOP_PROXMOX_ENABLED` | `false` | |
| `ACOP_PROXMOX_INSTANCE_ID` | `""` | Assign once; never change |
| `ACOP_PROXMOX_BASE_URL` | `""` | **https only** |
| `ACOP_PROXMOX_TOKEN_ID` | `""` | `user@realm!tokenname`; not a secret |
| `ACOP_PROXMOX_TOKEN_SECRET` | `""` | `SecretStr` |
| `ACOP_PROXMOX_VERIFY_TLS` | `true` | May be `false` only in development |
| `ACOP_PROXMOX_TIMEOUT_SECONDS` | `15.0` | Must be positive |

**A caller can never supply any of these.** Contract rules 9, 10 and 11 refuse
at *import* any tool whose input schema names a secret, a network locator
(`host`, `url`, `endpoint`, `server`, …) or a command. The endpoint and the
credential can only come from the environment, and only the adapter reads them.

Validators refuse, at startup rather than at first use:

- enabled with no base URL, token id or token secret;
- a base URL that is not `https` — the token travels in a request header, and
  plain http would put it on the management network in clear text. There is no
  development exemption, because a self-signed certificate is what
  `ACOP_PROXMOX_VERIFY_TLS` is for; abandoning transport security is a different
  and worse answer to that problem;
- `verify_tls = false` in staging or production — unverified TLS authenticates
  nothing, it encrypts to whoever answered;
- a malformed instance id, or a non-positive timeout.

The token secret is `SecretStr`, so a `repr`, a `str` or a structured log line
rendering the settings object cannot spill it. The token *id* is deliberately
**not** hidden: it names a principal rather than proving one, possession of it
grants nothing, and redacting it would only make a misconfigured token harder to
diagnose.

---

## 6. The adapter, and what it deliberately does not do

`ProxmoxAdapter`, `adapter_id = "proxmox"`, registered in code.

It exists so the **binding** is real. When the first Proxmox tool is declared,
import rule 13 resolves its `adapter_id` through `resolve_adapter`; registering
now means a misspelt id fails the build rather than surfacing later as a
confusing runtime denial.

- **`execute` refuses every tool name**, naming the tool. In this checkpoint
  every tool name is one it does not implement, so if a declaration appears
  before the client does, the error says exactly which tool arrived early.
- **`validate` refuses permanently.** This is not a placeholder. Every
  Milestone 5 tool is `CLASS_1_READ_ONLY`; import rule 2 only forces
  `validation_required` for Class 2 and Class 3, so no read-only tool sets it
  and the dispatcher never calls it. A read makes no change, so there is nothing
  to independently confirm afterwards.
- **It raises rather than returning an empty success.** An `AdapterResult` with
  `outcome=SUCCESS` and an empty payload would be recorded by the dispatcher as
  a completed execution. Raising is what keeps "not implemented" and "observed
  nothing" different states.
- **It does not read `proxmox_enabled`.** Settings are already available through
  `request.services.settings` — `AdapterServices` was **not** widened — but no
  tool is bound to this adapter, so there is no reachable path for that flag to
  gate. It becomes load-bearing in the checkpoint that adds the client.
- **It imports nothing that could reach a host.** Asserted the same way the
  simulated and local adapters are: by reading the module's imports. When the
  client lands, `httpx` has to be removed from that assertion deliberately and
  visibly, in the commit that earns it.

---

## 7. What is still absent after this checkpoint

No Proxmox connectivity. No tool catalog entries. No discovery service. No CMDB
writes. No credentials created. No Prometheus. No generic API-path tool — and
that one is not "not yet" but **never**: an arbitrary-URL read tool would
reintroduce every locator the input rules exist to keep out.
