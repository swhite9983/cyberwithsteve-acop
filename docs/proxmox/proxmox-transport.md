# Milestone 5 — Proxmox read-only transport and tool contracts (Checkpoint 2)

**Scope: ten read-only capabilities and the transport behind them.** No write of
any kind reaches Proxmox, and no write of any kind reaches the CMDB. Discovery,
reconciliation, absence detection and retirement are the next checkpoint;
Prometheus is Milestone 6. Both statements are made again, explicitly, in §10.

Checkpoint 1C registered a binding that talked to nothing. This checkpoint fills
it in.

---

## 1. The transport boundary

One package may open a socket to a hypervisor, and inside it one module may.

| Module | Job |
|---|---|
| `endpoints.py` | The allow-list. Ten templates, three validation layers, one import-time assertion. |
| `client.py` | **The only socket.** `GET` only, HTTPS only, token only, bounded body, no redirects. |
| `identity.py` | Resolved target → trusted address. Instance verified before the first request. |
| `projection.py` | Proxmox JSON → the narrow mappings the tools declare. |
| `adapter.py` | Ten names, ten reads, no eleventh branch. |
| `errors.py` | Transport failures mapped onto Milestone 4's existing taxonomy. |

`httpx` is imported by `client.py` and by nothing else in ACOP's Proxmox path.
That replaces the Checkpoint 1C assertion — "no Proxmox module imports `httpx` at
all" — which was honest while the adapter was inert and would be a false comfort
now. It is not weakened, it is made specific: *which code can reach a
hypervisor* is answered by reading one file. `subprocess`, `socket`, `asyncssh`,
`paramiko` and the rest remain forbidden in every module including `client.py`,
and a unit test asserts all of it by parsing the imports.

### There is no method parameter, and no path parameter

`ProxmoxClient.get_data(endpoint_key, *, deadline, **segments)` is the entire
public surface. It issues `GET`. A contributor cannot POST by passing a
different argument, because there is no argument to pass — adding one is a
visible change to that file rather than a call site somewhere else. Likewise the
caller names a **tool**, not a path, and a string that is not a key of
`TOOL_ENDPOINTS` cannot become a request.

Redirects are refused (`follow_redirects=False`). A redirect is a
server-controlled instruction to send the `Authorization` header somewhere else,
and the Proxmox API has no legitimate reason to issue one for a GET under
`/api2/json/`.

Responses are streamed and abandoned above **8 MiB**. An unbounded body from a
compromised or malfunctioning hypervisor would otherwise be a memory-exhaustion
path into ACOP.

---

## 2. Credential ownership

The adapter owns its credentials. Nothing else in ACOP reads them, and nothing
outside ACOP can supply them.

- `ACOP_PROXMOX_TOKEN_ID` and `ACOP_PROXMOX_TOKEN_SECRET` are read in
  `ProxmoxClient.__init__` and assembled into `Authorization: PVEAPIToken=<id>=<secret>`
  inside `_headers`. The value exists only in the client's header dict.
- The secret is a `SecretStr`, so a traceback, a `repr` or a structured log line
  rendering the settings object cannot spill it.
- **Token authentication only.** Ticket/password authentication is not
  implemented and must not be: it would mean ACOP holds a user password, obtains
  a session cookie and a CSRF token, and renews them — three more secrets and a
  session lifecycle, in exchange for nothing a token does not already give a
  read.
- No error carries a response body. An error body may quote the request, and the
  request carried the token; the status code and the path are what reach the
  log.

In the other direction, import rule 9 refuses any tool input schema that *names*
a secret. There is no channel through which a credential could arrive from
outside, which is stronger than sanitising one that did.

---

## 3. The endpoint allow-list

No API path is accepted from a caller. Each tool maps internally to exactly one
GET.

| Tool | Endpoint |
|---|---|
| `proxmox.cluster.status` | `GET /api2/json/cluster/status` |
| `proxmox.node.list` | `GET /api2/json/nodes` |
| `proxmox.node.status` | `GET /api2/json/nodes/{node}/status` |
| `proxmox.node.network` | `GET /api2/json/nodes/{node}/network` |
| `proxmox.guest.list` | `GET /api2/json/cluster/resources?type=vm` |
| `proxmox.vm.status` | `GET /api2/json/nodes/{node}/qemu/{vmid}/status/current` |
| `proxmox.vm.config` | `GET /api2/json/nodes/{node}/qemu/{vmid}/config` |
| `proxmox.container.status` | `GET /api2/json/nodes/{node}/lxc/{vmid}/status/current` |
| `proxmox.container.config` | `GET /api2/json/nodes/{node}/lxc/{vmid}/config` |
| `proxmox.storage.list` | `GET /api2/json/nodes/{node}/storage`, per online node |

Three checks, then a fourth at import:

1. The template is a literal in `endpoints.py`, keyed by tool name.
2. Each substituted segment must match a narrow pattern — digits for a VMID, a
   DNS-label shape for a node — so a value that somehow arrived from a
   compromised upstream cannot contain `/` or `..`.
3. Each segment is then percent-encoded with `safe=""`.
4. `_assert_templates_are_sane()` runs at import and refuses any template that
   does not begin with `/api2/json/`, contains `..`, or names a placeholder the
   module cannot validate. A bad template is a failed build, not a runtime
   surprise.

**There is no `proxmox.api.get`, and there will not be one.** An arbitrary-path
read tool would take a locator from a caller through a field import rules 9, 10
and 11 do not inspect, and would undo the static proof those rules exist to give.

### Why `storage.list` is node-scoped but cluster-targeted

Proxmox's storage listing reports each node's own view, and a non-shared
definition such as `local` or `local-lvm` is a *different volume* on each node
under the same name. The adapter therefore reads `/nodes`, filters to
`status == "online"`, queries each, and returns the union — with every row
carrying its source `node`. Choosing a single node would report that node's free
space as the instance's: overstating capacity by a factor of the cluster size for
local storage, and understating it for shared.

`nodes_queried` is on the output for a related reason: without it, an empty
`storages` list is ambiguous between "no storage is defined" and "no node was
online to ask", and those need different human responses.

---

## 4. The ten tools

All ten are `CLASS_1_READ_ONLY`, `TargetKind.ASSET`, `adapter_id="proxmox"`,
`required_roles={viewer}`, no approval, no validation, naturally idempotent.
Those invariants are set once in `_read_only()` rather than copied ten times —
ten copies is ten chances for one to drift, and the one that drifts is the one
nobody notices.

| Tool | Target asset type | Trusted identifier | Requests |
|---|---|---|---|
| `proxmox.cluster.status` | `CLUSTER` | `proxmox:instance` | 1 |
| `proxmox.node.list` | `CLUSTER` | `proxmox:instance` | 1 |
| `proxmox.guest.list` | `CLUSTER` | `proxmox:instance` | 1 |
| `proxmox.storage.list` | `CLUSTER` | `proxmox:instance` | 1 + N |
| `proxmox.node.status` | `HOST` | `proxmox:node` | 2 |
| `proxmox.node.network` | `HOST` | `proxmox:node` | 2 |
| `proxmox.vm.status` | `VM` | `proxmox:guest` | 2 |
| `proxmox.vm.config` | `VM` | `proxmox:guest` | 2 |
| `proxmox.container.status` | `CONTAINER` | `proxmox:guest` | 2 |
| `proxmox.container.config` | `CONTAINER` | `proxmox:guest` | 2 |

`required_roles` is the class minimum for all ten, including the two config
reads. Raising those to `operator` would conflate "may change" with "may see
detail" — the same distinction Milestone 3 drew when it decided `approver` is not
a clearance.

### Every input model has no fields at all

All ten declare `EmptyInput`. That is stronger than "no forbidden field names":
rules 9, 10 and 11 refuse a schema that *names* a locator, a secret or a command,
but a schema with no fields cannot name anything, and `extra="forbid"` turns any
attempt to supply `node`, `vmid`, `endpoint` or `api_path` into a rejection at
the request boundary — no invocation row, no canonical input, nothing to
sanitise later.

### Timeouts are arithmetic, not taste

With the default `ACOP_PROXMOX_TIMEOUT_SECONDS` of 15s:

| Shape | Declared `timeout_seconds` | Covers |
|---|---|---|
| One request | 20s | 1 × 15s |
| Resolve, then read | 35s | 2 × 15s |
| `storage.list` fan-out | 90s | 1 + 5 nodes × 15s |

The adapter opens **one deadline for the whole invocation** and each request
gets `min(configured_timeout, time remaining)`. Without that, a fan-out could run
for N times its declared deadline and be cancelled from outside by
`asyncio.wait_for`, producing a `TIMED_OUT` invocation with no indication which
call was slow.

---

## 5. Trusted identifier derivation

The chain, and why every link is where it is:

1. The caller names an **asset**. Policy has already refused a retired asset or
   one of a type this tool does not accept.
2. The dispatcher hands the adapter that asset's live registered identifiers —
   rows ACOP selected, in the normalised form it stores them.
3. The adapter parses `<instance>/<object>` and **fails before the first HTTP
   request** if the instance segment is not the configured one.
4. The node that appears in the URL comes from **Proxmox's own response**.

### Guest node resolution (the ratified algorithm)

`proxmox:guest` = `<instance>/<vmid>`. The guest technology is a constant of the
tool — `proxmox.vm.*` looks for `qemu`, `proxmox.container.*` for `lxc` — never
caller input. `GET /cluster/resources?type=vm` is matched on VMID **and** type,
exactly one match is required, and the node is taken only from that record.

- Zero matches → `INVALID_TARGET`. Not `TARGET_UNAVAILABLE`: a VMID Proxmox has
  no record of is not unreachable, it is gone, and retrying returns the same
  empty answer.
- More than one → `EXECUTION_FAILED`. Proxmox reporting two guests with one VMID
  and type is impossible; picking one would be a guess about infrastructure.

Reading the node live rather than from a stored `RUNS_ON` edge means a guest that
migrated since the last sweep routes correctly on the first call instead of after
the next one. On a standalone node that is theoretical; it stops being
theoretical the day a second node joins.

No `proxmox:node` identifier is attached to a guest asset. No `ResolvedTarget`,
`AdapterServices`, `AdapterRequest` or M2 change was needed or made.

### Node resolution, and why the identifier is not pasted into the URL

`AssetIdentifier.value_normalized` for `proxmox:node` is
`value.strip().lower()`. Proxmox node names appear **literally** in API paths, so
an instance whose node is `PVE-01` would be addressed as `/nodes/pve-01` — a
request for a node that, as far as the API is concerned, does not exist.

The identifier therefore selects *which* node, case-insensitively, and
`GET /nodes` supplies the spelling. One extra request per node-scoped invocation,
in exchange for the property the guest design already has: **every path segment
ACOP sends came from Proxmox.**

---

## 6. Error semantics

Every failure is a `ToolError` subclass carrying an **existing**
`ToolErrorCategory`. No new category was added and none was needed.

| Condition | Class | Category | Retryable |
|---|---|---|---|
| Disabled / incomplete configuration | `ProxmoxNotConfiguredError` | `ADAPTER_UNAVAILABLE` | yes |
| Missing or malformed identifier | `ProxmoxIdentifierError` | `INVALID_TARGET` | no |
| Identifier names another instance | `ProxmoxInstanceMismatchError` | `INVALID_TARGET` | no |
| Node or guest absent from live inventory | `ProxmoxObjectNotFoundError` | `INVALID_TARGET` | no |
| Two matches where one was required | `ProxmoxAmbiguousObjectError` | `EXECUTION_FAILED` | no |
| HTTP 401, **or TLS verification failure** | `ProxmoxAuthenticationError` | `AUTHENTICATION` | no |
| HTTP 403 | `ProxmoxAuthorizationError` | `AUTHORIZATION` | no |
| Request or budget expired | `ProxmoxTimeoutError` | `TIMEOUT` | no |
| DNS / refused / reset | `ProxmoxConnectionError` | `TARGET_UNAVAILABLE` | yes |
| Any other status | `ProxmoxHTTPStatusError` | `EXECUTION_FAILED` | no |
| Non-JSON, no envelope, wrong shape, oversized | `ProxmoxProtocolError` | `EXECUTION_FAILED` | no |
| Declared output not satisfied | *(framework)* | `OUTPUT_CONTRACT_VIOLATION` | no |

Three of those mappings are deliberate and the obvious answer is wrong:

**A TLS verification failure is authentication, not connectivity.** The socket
opened; what failed is the server proving it is the server. Unlike
`TARGET_UNAVAILABLE` it is not retryable — retrying a certificate mismatch cannot
succeed, and if the mismatch is an active interception, retrying is the one thing
that must not happen.

**A malformed response is `EXECUTION_FAILED`, never
`OUTPUT_CONTRACT_VIOLATION`.** ADR-0023 gives that category one meaning: ACOP's
own projection or declaration is wrong, and the fix is in ACOP's code. Proxmox
answering wrongly is a different fault with a different remediation, and
conflating them would send an engineer to read `projection.py` when the answer is
on the other host.

**A malformed response is never answered with an empty result.** An empty guest
inventory and an unparseable one are different facts. The discovery checkpoint's
absence pass would read the second as "every guest is gone" and retire the lot,
which is precisely the harm ADR-0023 was raised to prevent. Malformed → `FAILED`,
`result_summary` NULL; genuinely empty → `SUCCEEDED`, `{"guests": []}`.

---

## 7. TLS behaviour

- `ACOP_PROXMOX_BASE_URL` must be `https`. Enforced by the settings validator
  **and** again in `ProxmoxClient.__init__`, because that object is the one that
  would actually put a token on the wire and a guarantee is worth having at the
  point of use as well as the point of configuration.
- `ACOP_PROXMOX_VERIFY_TLS` is passed to `httpx` as `verify`. It defaults to
  true, may be false in development or test for a self-signed lab certificate,
  and the settings validator refuses false in staging or production. Unverified
  TLS authenticates nothing — it encrypts to whoever answered, which is exactly
  the property an interception needs.
- There is no development exemption for plain http. A self-signed certificate is
  what `ACOP_PROXMOX_VERIFY_TLS` is for; abandoning transport security is a
  different and worse answer to that problem.

---

## 8. Output contracts

Explicit Pydantic models for all ten tools, in
`src/acop/tools/catalog/proxmox_schemas.py`. Two rules governed every field.

**Nothing that is not needed.** Extra upstream fields do not automatically become
ACOP output. Disk and network *device* lines are absent from both config models:
they carry storage volume paths and MAC addresses, and both belong to decisions
this checkpoint explicitly does not make — the Checkpoint 3 storage-identity gate
(§9), and the ratified position that a MAC is not lifecycle identity. `pid`,
`blockstat` and `nics` are absent from VM status for the same reason.

**Anything not observed is optional.** ADR-0023 turned a declared field the
adapter cannot populate into a *failed invocation*. A field is required only
where its absence would mean the response was not the API's documented shape, and
three areas are optional for a specific evidentiary reason:

| Area | Why every field is optional |
|---|---|
| `ClusterStatusOut.cluster_name` / `.quorate` | The verified standalone response carries neither. A required field there would make ACOP unable to read the lab it was built for. `standalone` is derived from the absence of a `type: "cluster"` member. |
| `NodeStatusOut` | `/nodes/{node}/status` was **not** captured during Checkpoint 0. The fields come from the documented API shape, which is a good source but not an observed one. |
| `ContainerStatusOut`, `ContainerConfigOut` | `GET /nodes/{node}/lxc` answered `[]`: the lab has no containers, so no container payload has ever been observed. |

**No container model carries a UUID field of any kind.** LXC has no durable
lifecycle identifier — the reconnaissance looked and found none, and `--unique`
is a restore-time random MAC rather than an identity. `config_digest` is carried
as a *change detector*: it can say "this configuration differs from what we saw",
and it can never say "this is the same container", because two identically
configured containers share it. A unit test asserts the absence structurally
rather than trusting this paragraph.

For QEMU, `smbios_uuid` is parsed out of the `smbios1` line, validated as a UUID,
and answered as `None` if either step fails. A VM whose UUID ACOP cannot read is
a VM with no strong correlator — which the identity design already accounts for,
and which is not an invitation to fall back to something weaker.

---

## 9. Checkpoint 3 architecture gate — storage identity

**Do not perform a storage identity write until this is resolved.**

Checkpoint 1C declares `proxmox:storage = <instance>/<storage_id>`, unique. That
is correct for **shared** storage and ambiguous for **node-local** storage in a
multi-node cluster: `local` on `node-a` and `local` on `node-b` are different
volumes with different capacity, and both would normalise to
`<instance>/local` — one live unique identifier for two things.

It is not load-bearing yet. Checkpoint 2 writes no CMDB storage assets, and the
lab is a standalone node where the two cases cannot differ. The vocabulary is
therefore **unchanged in this checkpoint**, deliberately.

Before Checkpoint 3's first storage identity write, decide explicitly whether
storage identity needs separate semantics for shared versus node-local storage —
for example a node-scoped composite for non-shared definitions, keyed on the
`shared` flag this checkpoint already returns. `StorageSummaryOut` carries both
`node` and `shared` on every row precisely so that decision has the evidence it
needs when it is taken.

---

## 10. What this checkpoint does *not* do

Stated explicitly, because each was an instruction rather than an omission:

- **No CMDB discovery state is written.** No asset is created, no identifier
  asserted, no fact recorded, no relationship written, no absence detected, no
  retirement performed, no reconciliation run. The tools observe and return typed
  data; nothing they return reaches the CMDB.
- **No Proxmox write exists.** No start, stop, reboot, shutdown, snapshot,
  migrate, clone or configuration change. No shell, no SSH, no `pvesh`. The
  prohibition registry refuses those as *categories* at import, so a future
  declaration whose honest tag set includes `arbitrary.shell` fails the build.
- **Prometheus remains Milestone 6.** Nothing here reads or writes metrics.
- **No generic API GET.** See §3.
- **No database migration.** Nothing in this checkpoint touches the schema:
  `AssetType.CLUSTER` and the `proxmox:*` namespaces are Python registries
  (Checkpoint 1C), `tool_registration` rows are written by the existing
  reconciler, and `OUTPUT_CONTRACT_VIOLATION` fits the existing
  `String(40)` column. Alembic head remains `0007_tool_framework`.
- **B-11 stays open.** `target_ref` is free-form and not covered by input rules
  9, 10 and 11. Checkpoint 2 is safe from it because no tool declares
  `EXTERNAL_REF` and the adapter forms paths only from validated registered
  identifiers and live Proxmox responses. B-11 must be closed before the first
  `EXTERNAL_REF` tool, and certainly before any Proxmox Class 2 or Class 3
  capability.
