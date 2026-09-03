# ACOP Architecture Review — Milestone 1 Compatibility

**Reviewer:** Claude (acting as senior architect during development)
**Date:** 2026-09-03
**Scope:** Section 36 of the design brief asks for a review of the architecture
for anything that would make Milestone 1 incompatible with later milestones,
*before* writing code.

**Verdict:** The architecture is sound. No fundamental redesign is warranted.
Eight items would have caused rework if left until the milestone that needs
them; each is addressed in Milestone 1 at low cost. Four further items are
flagged as decisions to make later, not now.

Throughout, statements are labelled: **[Fact]** verifiable and verified,
**[Best practice]** established industry practice, **[Opinion]** the reviewer's
judgement, **[Assumption]** taken as true without verification.

---

## 1. Findings that changed Milestone 1

### 1.1 Identity had to exist before the audit log

**Severity:** High — this is the expensive one.

The brief places authentication nowhere and the approval engine at Milestone 11.
But every durable record ACOP creates answers "who did this": audit events,
incidents, change requests, approvals, tool executions. **[Best practice]**
Retrofitting a subject through those tables and their call sites after they hold
real data is one of the more disruptive refactors in this kind of system.

**Action taken:** Milestone 1 ships a provider-neutral `Principal` and a
pluggable authentication backend, with static API keys as the first (and, for
now, only) backend.

**Neutrality is a design constraint, not a description.** It is enforced by
three mechanisms:

| Mechanism | What it prevents |
|---|---|
| `Principal.to_audit_fields()` is the only sanctioned way to write identity into a record, and returns exactly four fields | A new backend widening what downstream tables store |
| `claims` (provider-specific data) is quarantined — only the issuing backend may read it | Provider concepts leaking into services, agents or tools |
| Backends receive `PresentedCredentials`, not a framework request | Backends depending on transport details, and vice versa |

The four neutral fields are `subject`, `principal_type`, `issuer`,
`auth_method`. `subject` is opaque and stable; `issuer` is a free-form string
naming whichever authority vouched for the identity. Adding OIDC later is a
one-line registration in `_build_authenticator()`. A test asserts that the same
actor authenticated two different ways produces identical record shapes.

**Operational note:** when an identity provider is introduced, map its subject
claim onto the *existing* `subject` value for each person. If the subject
changes, historical audit records stop being attributable to that person. This
is the single most important thing to get right at that point.

### 1.2 Async or synchronous — decide now, not at Milestone 5

**Severity:** High.

**[Fact]** ACOP's dominant workload is waiting: on Ollama for tens of seconds
per reasoning turn, on Cisco devices over SSH, on Proxmox and Prometheus HTTP
APIs. **[Opinion]** A synchronous stack would need a thread pool sized to the
worst-case concurrent investigation count, and converting a synchronous data
layer to async once agents, tools and collectors exist is a rewrite rather than
a refactor.

**Action taken:** async SQLAlchemy 2.0 + asyncpg, async Alembic, async HTTP
client, from the first line. Cost today is close to zero.

### 1.3 Ollama silently truncates prompts

**Severity:** High — and it is the failure mode most likely to be misread.

**[Fact]** Ollama applies its own default context window when the caller does
not set `num_ctx`, and truncates the prompt to fit. It does not error, warn, or
report the truncation.

**[Opinion]** In a platform whose entire purpose is reasoning over retrieved
evidence, silent truncation is operationally indistinguishable from
hallucination. You would see the model "ignore" a switch configuration you know
you gave it, and you would reasonably conclude the model is unreliable — when
the real cause is a configuration default.

**Action taken:** `num_ctx` is a required setting, sent explicitly on every
call. `scripts/check_qwen.py` reports the model's declared context length
against what ACOP requests, and warns when the request uses a small fraction of
what is available. A live test asserts the requested context does not exceed
what the model declares.

**Recommendation for your hardware:** a ~32B model at Q4_K_M occupies roughly
19–20 GB, and KV cache for a large context comes out of the ~4 GB remaining on
a 24 GB card. **[Assumption]** You will need to tune `ACOP_OLLAMA_NUM_CTX`
empirically, checking `nvidia-smi` and `ollama ps` after each change. If
throughput collapses below roughly 5 tokens/s, the model has spilled to system
RAM — `check_qwen.py` flags this explicitly.

### 1.4 The model name in the brief does not exist

**Severity:** Low, but worth stating plainly.

**[Fact]** There is no "Qwen 3.8 27B". Qwen3 ships at 0.6B / 1.7B / 4B / 8B /
14B / 32B / 30B-A3B / 235B-A22B. The 27B parameter count belongs to Gemma 3.
**[Assumption]** You are most likely running `qwen3:32b`, which is what the
configuration defaults to.

**Action taken:** the model tag is configuration, never hard-coded, and the
health endpoint reports what is actually present rather than assuming. Run
`ollama list` on the GPU host and pin the exact tag in `.env`. A bare name
resolves by prefix and is deliberately reported as `degraded`, so an ambiguous
configuration is visible rather than silent — which matters once the evaluation
framework in Milestone 19 starts attributing scores to models.

### 1.5 One health endpoint is not enough

**Severity:** Medium.

The brief specifies a single `GET /health` reporting each component. **[Best
practice]** Three consumers want three different things, and conflating them
causes self-inflicted outages:

| Endpoint | Consumer | Behaviour |
|---|---|---|
| `/health/live` | Container orchestrator | No dependency calls at all. Always 200 while the process serves. |
| `/health/ready` | Load balancer / monitoring | Checks dependencies. 503 when unhealthy, 200 when degraded. |
| `/health` | Humans, dashboards | The brief's full report. Always 200 so the body can be read. |

**[Opinion]** A liveness probe that queries PostgreSQL will restart a perfectly
healthy API container during a database blip — turning a brief database
interruption into an application outage as well. This is a common and avoidable
mistake.

Two further additions: probe results are cached (default 10 s) so a monitoring
scrape interval cannot turn the health endpoint into a load generator against
the GPU host; and a third state, `degraded`, exists so that a missing model
does not cause an orchestrator to restart a working container.

**Deviation from the brief, stated explicitly:** the model component is keyed
`model`, not `qwen`. A key that changes when the model changes would break every
dashboard panel and alert rule referencing it, and would keep reporting
`qwen: healthy` after a switch to a different model. The model actually checked
is reported in `details.model.metadata.resolved_model`.

### 1.6 The audit log belongs in Milestone 1, not Milestone 4

**Severity:** Medium.

**[Opinion]** It is the one table every later subsystem writes to, and it is
append-only — meaning it will be the largest table in the database and the most
disruptive to alter. Defining its shape once, before it holds data, is
materially cheaper than altering it at Milestone 11.

Authentication events are themselves auditable, so the table has a consumer from
day one.

**Extensibility approach:** rather than pre-creating a dozen nullable columns
for concepts that do not exist yet, the record has a typed core plus a JSONB
`context` column. Later milestones add narrowly-scoped indexes or side tables
when a field proves to need querying. **[Opinion]** This is the better trade:
speculative columns accumulate and are rarely removed.

**Immutability** is enforced in three layers: no `updated_at` column, no update
or delete method on the service, and a database role restriction documented for
the milestone that introduces the secrets manager.

### 1.7 Constraint naming and timezone-aware timestamps

**Severity:** Medium, entirely preventable.

**[Best practice]** Without an explicit constraint naming convention on
`MetaData`, PostgreSQL assigns names that differ between environments and
Alembic cannot reliably drop unnamed constraints. Fixing this after a dozen
migrations exist is genuinely unpleasant.

**[Fact]** Naive timestamps break correlation. Milestones 9 and 10 compare ACOP
events against Prometheus, syslog and Windows Event Log timestamps. A naive
datetime makes that correlation quietly wrong rather than loudly broken — the
worst kind of defect for a root-cause engine.

**Action taken:** naming convention set on `Base.metadata`;
`TIMESTAMP WITH TIME ZONE` everywhere, verified by an integration test that
inspects `information_schema`.

### 1.8 Use the pgvector image now, enable the extension later

**Severity:** Low, but free.

Milestone 3 needs pgvector. Swapping the base image at that point means a base
image change and a data directory migration on a database that by then holds the
CMDB and the audit log. **Action taken:** `docker-compose.yml` uses
`pgvector/pgvector:pg16` from Milestone 1. No migration creates the extension —
that remains Milestone 3 work. Milestone 3 becomes `CREATE EXTENSION vector;`.

---

## 2. Defects found by running the code, not reading it

Three of these were invisible to review and only surfaced during verification.
They are recorded because each would have been a confusing production problem.

### 2.1 SQLAlchemy does not wrap asyncpg connection errors

**[Fact, verified]** With SQLAlchemy 2.0 and asyncpg, an unreachable PostgreSQL
raises a bare `ConnectionRefusedError` (an `OSError`) that SQLAlchemy does not
wrap in its own exception hierarchy.

**Consequence if unhandled:** an infrastructure condition surfaces to callers as
an unclassified HTTP 500 with an asyncpg traceback, while `/health`
simultaneously reports the database as unhealthy. Two contradictory signals
during an incident, and a driver traceback leaked to the caller.

**Fix:** `acop.db.session` classifies connection-level failures and raises
`DatabaseUnavailableError` (503). Constraint violations are deliberately *not*
classified this way — a duplicate key is an ACOP defect, and reporting it as 503
would send an operator to inspect healthy infrastructure. Eight unit tests pin
the boundary.

### 2.2 Module-level loggers froze the log format at import time

**[Fact, verified]** structlog's `.bind()` resolves the active configuration
immediately. Modules create their logger at import time, which is *before*
`configure_logging()` runs — so every module logger was permanently bound to
structlog's default console renderer.

**Consequence:** a deployment configured for JSON emits human-formatted lines
into its log pipeline. Nothing errors. Nothing in the code looks wrong. It was
only visible in the actual output of the running server.

**Fix:** the logger name is passed as an initial value, keeping the proxy lazy.
A regression test creates a logger before configuration and asserts the output
parses as JSON.

### 2.3 Redaction was masking a non-secret

The startup log reported `configured_api_keys: ***REDACTED***` — the *count* of
credentials, masked because the field name contains `api_key`. The field was
renamed rather than the redaction rule weakened. **[Opinion]** When a
conservative security control produces a false positive, move the data, not the
control.

A related deliberate exclusion: `hash` is **not** treated as a secret fragment.
Configuration hashes are first-class evidence for drift detection in Milestone 7
and must stay readable; `password_hash` is still covered by the `password`
fragment.

---

## 3. Decisions deferred — deliberately

These do not affect Milestone 1 and should not be made yet.

| Decision | When | Note |
|---|---|---|
| Graph database | After Milestone 8 | The brief is right to defer this. Recursive CTEs in PostgreSQL handle dependency traversal at home-lab scale. Revisit only if a real query proves too slow — **[Opinion]** at this scale, it very likely will not. |
| Vector store | After Milestone 3 | pgvector until measurement says otherwise. Keep the embedding pipeline behind an interface so the store is swappable. |
| Secrets manager | Before any Class 2 tool exists | Environment variables are acceptable while ACOP has no credentials that can change infrastructure. That stops being true at Milestone 12. You already run OpenBao — that is the natural target. |
| Streaming inference | When a UI exists | Buffering and cancellation semantics are not worth building before there is something to stream to. |

---

## 4. Two risks worth naming

**Milestone sprawl.** The brief lists twelve milestones plus future capability.
**[Opinion]** The most likely failure mode for this project is not a technical
one; it is a half-built Milestone 7 sitting next to a half-built Milestone 9.
The `test_only_milestone_1_endpoints_are_exposed` test is a small mechanical
guard against that — it fails if an endpoint appears without the milestone that
justifies it. Consider keeping an equivalent guard at each milestone.

**The LLM is not the safety boundary.** Section 33 of the brief has this exactly
right, and it is worth restating because it is the thing most easily eroded
under time pressure: the tool layer and the approval engine are the enforcement
mechanism. Every permission decision must be executable and testable *without*
the model in the loop. When Milestone 4 arrives, the test that matters is not
"does the model choose the right tool" — it is "does the tool layer refuse the
wrong call regardless of what the model asked for".

---

## 5. What was deliberately not built

Milestone 1 contains no Cisco collectors, no Proxmox client, no Prometheus
integration, no agents, no orchestrator, no RAG, no tool registry, no dashboard,
and no capability to change anything. The CMDB is not stubbed. `docs/`,
`migrations/` and `src/acop/` contain no empty placeholder modules for later
subsystems.

Two forward-looking artefacts are present and are worth naming so they are not
mistaken for scope creep:

- `acop/models/provenance.py` defines the vocabulary from sections 7 and 10
  (source types, verification statuses, statement classes, permission classes).
  It creates no tables. It exists so the audit log can record a permission class
  from its first record, and so Milestone 2 does not renumber anything.
- `Principal`, `Role` and the authentication backend interface, per §1.1.

Both are inert declarations, not partial implementations. If you disagree with
either, they can be deleted without touching anything else.
