# Milestone 1 — Foundation

**Status:** Complete and verified
**Date:** 2026-09-03

## Objective

A rock-solid, boring foundation: FastAPI, PostgreSQL, Alembic, configuration,
logging, an Ollama client, and honest health reporting. Nothing else.

## Deliverables against the design brief

Section 36 lists fifteen required deliverables.

| # | Deliverable | Where |
|---|---|---|
| 1 | Repository structure | this tree |
| 2 | Docker Compose configuration | `docker-compose.yml` |
| 3 | PostgreSQL container | `postgres` service (`pgvector/pgvector:pg16`) |
| 4 | FastAPI application | `src/acop/main.py`, `src/acop/api/` |
| 5 | Environment-variable configuration | `src/acop/config/settings.py` |
| 6 | SQLAlchemy database connection | `src/acop/db/session.py` |
| 7 | Alembic migrations | `alembic.ini`, `migrations/` |
| 8 | Application logging | `src/acop/core/logging.py` |
| 9 | Ollama API client | `src/acop/ai/ollama/` |
| 10 | Model connectivity test | `scripts/check_qwen.py`, `tests/integration/test_live_ollama.py` |
| 11 | `GET /health` | `src/acop/api/routes/health.py` |
| 12 | Automated tests | `tests/` — 111 tests |
| 13 | README installation instructions | `README.md` |
| 14 | `.env.example` | `.env.example` |
| 15 | `.gitignore` | `.gitignore` |

## Success criteria

| Criterion | Status | Evidence |
|---|---|---|
| FastAPI runs | Met | `uvicorn acop.main:app` serves; `/health/live` returns 200 |
| PostgreSQL runs | Met | Compose service healthy; real `SELECT 1` in the health probe |
| Database migrations succeed | Met | `alembic upgrade head` → revision `0001`; downgrade-then-upgrade tested |
| ACOP can call the model through Ollama | Met | `check_qwen.py` completes a real generation and reports throughput |
| `GET /health` reports healthy components | Met | See below |
| Automated tests succeed | Met | 111 passed |

### Observed health output

```json
{
  "status": "healthy",
  "components": {
    "api": "healthy",
    "database": "healthy",
    "ollama": "healthy",
    "model": "healthy"
  }
}
```

Every component status is the result of a real connectivity check. Verified
failure behaviour, with the inference host stopped:

| Endpoint | Response |
|---|---|
| `GET /health/live` | 200 — the process is fine |
| `GET /health/ready` | 503 — do not route traffic |
| `GET /health` | 200, `status: unhealthy`, `ollama` and `model` unhealthy with actionable messages |

## Beyond the brief, and why

| Addition | Justification |
|---|---|
| Provider-neutral identity + API-key backend | Retrofitting a subject through audit, incident, change and approval records is the highest-cost deferred item. [ADR-0003](../decisions/ADR-0003-provider-neutral-identity.md) |
| `audit_event` table and service | The one table every later subsystem writes to, and append-only. [ADR-0005](../decisions/ADR-0005-audit-log-shape.md) |
| `/health/live` and `/health/ready` | A liveness probe that queries the database restarts a healthy container during a database blip. [ADR-0002](../decisions/ADR-0002-health-endpoint-design.md) |
| Request correlation IDs | The join key between an AI request, its tool calls, its approval and its audit trail. Free now, invasive later. |
| Secret redaction | Required by section 24; belongs in the logging pipeline from the first log line. |
| `provenance.py` vocabulary | Sections 7 and 10 vocabularies as inert enums. No tables. Lets the audit log record a permission class from its first row. |

## Explicitly not built

No Cisco, Proxmox, Prometheus, Docker or Windows integration. No agents,
orchestrator, RAG, tool registry, approval engine, incident or change
management, dashboard, or any capability to change infrastructure. The CMDB is
not stubbed.

An automated test asserts the API exposes exactly `/health`, `/health/live`,
`/health/ready` and `/whoami`, and that no path contains `tool`, `execute`,
`command`, `ssh` or `remediat`. An integration test asserts `audit_event` is the
only domain table in the database. These fail if a later milestone leaks
backwards.

## Verification performed

| Check | Result |
|---|---|
| `ruff check` | Clean |
| `ruff format --check` | Clean, 55 files |
| `mypy` (strict) | Clean, 38 source files |
| Unit tests | 101 passed, no external dependencies |
| Integration tests | 10 passed against live PostgreSQL 16 |
| Coverage | 94% |
| Alembic upgrade via CLI | Applied `0001`; schema inspected |
| Alembic downgrade → upgrade | Clean |
| Live server end-to-end | Health, readiness, liveness, `/whoami`, audit row written |
| Dependency failure behaviour | Verified with the inference host stopped |
| `docker compose config` | Valid |

**Not verified in the build environment:** the Docker image build, because no
Docker daemon was available. The Dockerfile is written but unbuilt — `make up`
on the Ubuntu host is the first real test of it. Build it before relying on it.

## Defects found during verification

Three, all found by running the software rather than reading it. Each is
documented in [`../ARCHITECTURE-REVIEW.md`](../ARCHITECTURE-REVIEW.md) §2:

1. SQLAlchemy does not wrap asyncpg connection errors — an unreachable database
   surfaced as an unclassified 500 with a driver traceback.
2. Module-level loggers froze the log format at import time — a JSON-configured
   deployment emitted console-formatted lines.
3. Redaction masked the credential *count* in the startup log.

All three are fixed and pinned by regression tests.

## Entry criteria for Milestone 2

Do not start the CMDB until all of these hold in your environment:

- [ ] `make up` succeeds on the Ubuntu host, including the image build
- [ ] `make verify` reports all criteria met against the real GPU host
- [ ] `python scripts/check_qwen.py` completes with acceptable throughput
- [ ] `ACOP_OLLAMA_NUM_CTX` tuned against `nvidia-smi`, with the model fully in VRAM
- [ ] `.env` has `chmod 600` and is confirmed absent from git history
- [ ] The repository is pushed to your remote
- [ ] You have read [`../ARCHITECTURE-REVIEW.md`](../ARCHITECTURE-REVIEW.md) and
      accepted or rejected each addition beyond the brief
