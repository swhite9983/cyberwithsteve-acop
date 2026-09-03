# ADR-0001: Async SQLAlchemy and asyncpg from Milestone 1

**Status:** Accepted
**Date:** 2026-09-03
**Milestone:** 1

## Context

ACOP's data layer choice has to be made before any model or service exists,
because converting between synchronous and asynchronous SQLAlchemy is not a
refactor — it changes every call site, every session lifecycle, and every test.

The eventual workload is dominated by waiting on external systems:

| Operation | Typical duration |
|---|---|
| Ollama reasoning turn | 10–120 s |
| Cisco `show` command over SSH | 1–5 s |
| Proxmox API call | 100 ms – 2 s |
| Prometheus range query | 100 ms – 5 s |
| PostgreSQL query | 1–50 ms |

A single root-cause investigation (Milestone 9) fans out across many of these
concurrently, and Milestone 32 adds alert-driven investigations that start
without a human waiting.

## Decision

Use SQLAlchemy 2.0 in async mode with the asyncpg driver, async Alembic
migrations, and an async HTTP client, from Milestone 1.

## Alternatives considered

**Synchronous SQLAlchemy with psycopg.** Simpler to write and debug, and better
supported by tooling. Rejected: it would require a thread pool sized to the
worst-case concurrent investigation count, and the conversion cost grows with
every milestone. The simplicity advantage is real but small; the conversion cost
is large and increasing.

**Synchronous now, async later.** Rejected for the same reason — this is the
decision that gets more expensive with time, which is exactly the kind that
should be made early.

**Async ORM with a synchronous escape hatch.** Rejected as unnecessary
complexity for a single-database application.

## Consequences

**Positive**

- Long-running inference calls do not consume a worker thread.
- One concurrency model across the data layer, the Ollama client, and future
  device collectors.
- Migrations use the same driver as the application, so a connection problem
  cannot appear in one and not the other.

**Negative**

- Alembic's `env.py` needs `asyncio.run` and `connection.run_sync`, which is
  more setup than the synchronous template.
- A blocking call inside an async handler stalls the event loop. Any future
  synchronous library (some Cisco SSH libraries, for example) must be wrapped in
  `asyncio.to_thread`. This is a real ongoing discipline cost, and it is the
  main argument against this decision.
- Async tests need `pytest-asyncio` and careful fixture scoping.

**Verified:** an Alembic env.py calling `asyncio.run` cannot be invoked from
inside a running event loop. The integration suite runs migrations via
`asyncio.to_thread` so that the real migration path is exercised rather than
bypassed.
