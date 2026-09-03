# ADR-0002: Three health endpoints, three states, cached probes

**Status:** Accepted
**Date:** 2026-09-03
**Milestone:** 1

## Context

The design brief specifies one endpoint, `GET /health`, reporting each component
independently, with a firm requirement: *"Do not fake health results."*

Three different consumers will read health data, and they want different things:

- A container orchestrator needs to know whether to **restart** the process.
- A load balancer or monitor needs to know whether to **route traffic**.
- A human needs to know **what is wrong**.

Conflating these is a well-known source of self-inflicted outages.

## Decision

### Three endpoints

| Endpoint | Consumer | Dependency calls | Status codes |
|---|---|---|---|
| `GET /health/live` | Orchestrator | None | Always 200 while serving |
| `GET /health/ready` | LB / monitoring | Yes | 200 healthy or degraded, 503 unhealthy |
| `GET /health` | Humans, dashboards | Yes | Always 200; the body carries the verdict |

`/health` returns the exact `components` map the brief specifies, plus a
`details` object with per-component latency, an operator-facing message, and
metadata.

### Three states

`healthy`, `degraded`, `unhealthy`.

`degraded` exists because ACOP with a missing model is still working — the fix
is `ollama pull`, not restarting the container. Collapsing that into `unhealthy`
would cause an orchestrator to restart a healthy service; collapsing it into
`healthy` would hide a real problem.

Aggregation rule: a failure in a **required** component (`database`, `ollama`)
makes the service unhealthy. Any other non-healthy component degrades it.

### Cached probes

Results are cached for `ACOP_HEALTH_CACHE_TTL_SECONDS` (default 10 s), behind a
single-flight lock. Without this, a monitoring scrape interval turns the health
endpoint into a load generator against the GPU host. `?fresh=true` bypasses it.

### Availability, not inference

The model check verifies the configured tag is **present** on the inference
host. It does not run a completion. A health check that generated tokens would
put ACOP's own monitoring in competition with ACOP's reasoning for the GPU, and
would let a scrape interval saturate the card. A test asserts that a health
check never calls `/api/generate` or `/api/chat`.

Real inference testing is a deliberate, separate operation:
`scripts/check_qwen.py` and the opt-in live test suite.

### No information disclosure

All three endpoints are unauthenticated — a probe that needs a credential fails
during a credential problem, which is when you most need it. Messages are
therefore categorical, never raw upstream error text. A test asserts that the
database password and the string `asyncpg` do not appear in the response.

## Deviation from the brief

Section 36 names the model component `qwen`. This implementation names it
`model`.

A component key that changes with the model would break every dashboard panel
and alert rule referencing it, and would keep reporting `qwen: healthy` after a
switch to a different model. The model actually checked is reported in
`details.model.metadata.resolved_model`.

## Consequences

- Four endpoints' worth of behaviour instead of one, and a caching layer to
  reason about.
- Slightly more surface to test — offset by the tests being straightforward.
- Anything written against the brief's `components` contract keeps working.
