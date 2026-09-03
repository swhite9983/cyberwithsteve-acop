# CyberWithSteve ACOP

**Autonomous Cyber Operations Platform** — Milestone 1 (Foundation).

ACOP is a locally-hosted, AI-assisted operations platform for the CyberWithSteve
home lab. It uses a local model served by Ollama as its reasoning engine and is
designed so that no external AI API is ever a production dependency.

> **Milestone 1 scope.** This deployment does exactly four things: it starts, it
> talks to PostgreSQL, it talks to Ollama, and it reports honestly on all three.
> There are no infrastructure integrations, no agents, and no capability to
> change anything. That is deliberate — see
> [`docs/ARCHITECTURE-REVIEW.md`](docs/ARCHITECTURE-REVIEW.md).

---

## Table of contents

- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Verifying the milestone](#verifying-the-milestone)
- [API surface](#api-surface)
- [Configuration reference](#configuration-reference)
- [Development](#development)
- [Security posture](#security-posture)
- [Troubleshooting](#troubleshooting)
- [What comes next](#what-comes-next)

---

## Architecture

```
        Ubuntu Docker host                      GPU host (RTX 3090)
 ┌──────────────────────────────┐        ┌────────────────────────────┐
 │  acop-api    (FastAPI)       │        │  Ollama                    │
 │      │                       │  HTTP  │    └── qwen3:32b           │
 │      ├───────────────────────┼───────►│        (or your tag)       │
 │      │                       │ :11434 │                            │
 │  postgres  (pgvector/pg16)   │        └────────────────────────────┘
 │      └── acop database       │
 └──────────────────────────────┘
```

Ollama is reached over the network and is **not** part of the ACOP compose
stack. Keeping the inference engine separate from the application means each can
be upgraded, restarted, backed up and secured independently, and it leaves room
for more than one model host later.

### Layout

```
├── docker-compose.yml        postgres + migrate + api
├── Dockerfile                multi-stage, non-root, read-only rootfs
├── alembic.ini               DB URL comes from the environment, never from here
├── migrations/               Alembic revisions
├── docs/
│   ├── ARCHITECTURE-REVIEW.md   Read this first
│   ├── architecture/            Milestone notes
│   ├── decisions/               ADRs
│   └── security/                Secrets and audit-immutability posture
├── scripts/
│   ├── check_qwen.py            Real inference round-trip + VRAM sanity checks
│   └── verify_milestone1.py     Milestone 1 acceptance check
├── src/acop/
│   ├── ai/ollama/            Typed async Ollama client
│   ├── api/                  Routes, dependencies, middleware
│   ├── auth/                 Provider-neutral identity + pluggable backends
│   ├── config/              Environment-driven settings
│   ├── core/                 Logging, correlation, errors, redaction
│   ├── db/                   Async engine and session management
│   ├── models/               SQLAlchemy models
│   ├── schemas/              Pydantic wire schemas
│   └── services/             Business logic (health, audit)
└── tests/
    ├── unit/                 No external dependencies
    └── integration/          Requires PostgreSQL; live Ollama tests opt-in
```

---

## Requirements

| Component | Version | Where |
|---|---|---|
| Docker Engine + Compose v2 | 24+ | Ubuntu application host |
| Ollama | 0.5+ | GPU host, reachable on TCP/11434 |
| A pulled model | — | `ollama list` on the GPU host |
| Python | 3.11+ | Only for local development outside containers |

### Before you start: check the GPU host

Ollama binds `127.0.0.1` by default, which makes it unreachable from another
machine. On the GPU host:

```bash
sudo systemctl edit ollama
```

```ini
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
```

```bash
sudo systemctl daemon-reload && sudo systemctl restart ollama
ollama list          # note the EXACT model tag — you will need it below
```

Then confirm reachability from the application host:

```bash
curl -s http://<gpu-host>:11434/api/version
```

If that fails, check the host firewall and any VLAN ACL between the two hosts
before going further. **Do not expose TCP/11434 beyond the lab** — Ollama has no
authentication of its own.

---

## Installation

### 1. Clone and configure

```bash
git clone <your-remote>/cyberwithsteve-acop.git
cd cyberwithsteve-acop
cp .env.example .env
```

Edit `.env`. At minimum:

```bash
# Generate a database password
openssl rand -base64 32

# Generate an API key
openssl rand -hex 32
```

| Setting | Value |
|---|---|
| `ACOP_POSTGRES_PASSWORD` | the generated password |
| `ACOP_OLLAMA_BASE_URL` | `http://<gpu-host>:11434` |
| `ACOP_OLLAMA_MODEL` | the exact tag from `ollama list` |
| `ACOP_API_KEYS` | JSON array; put the generated key in `secret` |

`.env` is git-ignored. Keep it that way.

> **On `subject` in `ACOP_API_KEYS`:** this is an opaque, permanent identifier
> for the person or service. Every audit record, and later every incident,
> change and approval, references it. When you introduce an identity provider,
> map its subject claim onto this same string. Do not use an email address or
> anything else that might change.

### 2. Start the stack

```bash
make up          # build images and start postgres, run migrations, start the API
make ps
make logs
```

Migrations run as a separate one-shot `migrate` service rather than in the API's
entrypoint, so a failed migration is a clear failure rather than a crash loop,
and multiple API replicas cannot race to migrate.

### 3. Verify

```bash
make health
ACOP_VERIFY_API_KEY=<your key> make verify
python scripts/check_qwen.py
```

---

## Verifying the milestone

`scripts/verify_milestone1.py` checks the section 35 success criteria against
the running service and reports what it actually observed. Expected output:

```
[ PASS ] API is live at http://127.0.0.1:8000 (version 0.1.0)
[ PASS ] Responses carry an X-Request-ID correlation header.

  Overall status: healthy
    api        healthy
    database   healthy (5.95 ms)
    ollama     healthy (4.87 ms)
    model      healthy (4.44 ms)

[ PASS ] PostgreSQL connectivity verified by a real query.
[ PASS ] Ollama reachable (server version 0.5.7).
[ PASS ] Configured model qwen3:32b is present on the inference host.
[ PASS ] Health probe results are cached between scrapes.
[ PASS ] Readiness probe returned HTTP 200, consistent with overall status 'healthy'.
[ PASS ] Unauthenticated request to /whoami is rejected with 401.
[ PASS ] Authenticated as subject 'acop:user:steve' (issuer 'acop:api-key', ...).
[ PASS ] Identity is provider-neutral: ...
[ PASS ] OpenAPI schema published. Endpoints: /health, /health/live, /health/ready, /whoami
[ PASS ] No endpoints outside Milestone 1 scope. ...

[ PASS ] Milestone 1 acceptance criteria met (0 warning(s)).
```

`scripts/check_qwen.py` goes further: it runs a real completion, reports
throughput, and compares the model's declared context length against what ACOP
requests. Read its output — see [Context window](#context-window) below.

---

## API surface

Swagger UI is at `http://<host>:8000/docs`.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/health/live` | none | Liveness. No dependency calls. Always 200 while serving. |
| GET | `/health/ready` | none | Readiness. 503 when a required dependency is down. |
| GET | `/health` | none | Full report. Always 200; read the body. `?fresh=true` bypasses the cache. |
| GET | `/whoami` | required | The platform's view of the authenticated caller. |

### Why three health endpoints

| Endpoint | Consumer | Rule |
|---|---|---|
| `/health/live` | Docker / orchestrator | Restart on failure. Never touches a dependency — a liveness probe that queries PostgreSQL restarts a healthy API during a database blip. |
| `/health/ready` | Load balancer, monitoring | Remove from rotation on 503. Degraded stays in service. |
| `/health` | Humans, dashboards | Diagnose. Reports every component independently. |

Component states are `healthy`, `degraded`, `unhealthy`. A missing model is
`unhealthy` at the component level but only `degraded` overall: the fix is
`ollama pull`, not restarting ACOP.

Probe results are cached for `ACOP_HEALTH_CACHE_TTL_SECONDS` (default 10 s) so a
scrape interval cannot turn the endpoint into a load generator against the GPU
host.

### Authentication

```bash
curl -H "X-ACOP-API-Key: <key>" http://<host>:8000/whoami
# or
curl -H "Authorization: Bearer <key>" http://<host>:8000/whoami
```

```json
{
  "subject": "acop:user:steve",
  "principal_type": "human",
  "issuer": "acop:api-key",
  "auth_method": "api_key",
  "display_name": "Steve White",
  "roles": ["admin"],
  "authenticated_at": "2026-09-03T03:27:56.304972Z"
}
```

API keys are the Milestone 1 mechanism only. `issuer` and `auth_method` are
separate fields precisely so an identity provider can be added later without
changing this response shape or anything downstream of it. See
[ADR-0003](docs/decisions/ADR-0003-provider-neutral-identity.md).

---

## Configuration reference

Every setting is an environment variable prefixed `ACOP_`. Full annotated list
in [`.env.example`](.env.example). The ones that matter most:

| Variable | Default | Notes |
|---|---|---|
| `ACOP_OLLAMA_BASE_URL` | — | The GPU host. Not localhost, unless ACOP runs there outside a container. |
| `ACOP_OLLAMA_MODEL` | `qwen3:32b` | Pin the exact tag from `ollama list`. |
| `ACOP_OLLAMA_NUM_CTX` | `8192` | See below. This one matters. |
| `ACOP_OLLAMA_GENERATE_TIMEOUT_SECONDS` | `300` | Inference. Separate from the control-plane timeout. |
| `ACOP_API_KEYS` | `[]` | JSON array. Required outside development. |
| `ACOP_AUTH_ENABLED` | `true` | `false` only for local development. Refused in staging/production. |
| `ACOP_LOG_FORMAT` | `json` | `console` for readable local output. |

### Context window

**This is the setting most likely to cause confusing behaviour later.**

Ollama applies its own default context window when the caller does not set
`num_ctx`, and silently truncates the prompt to fit — no error, no warning. In a
platform whose purpose is reasoning over retrieved evidence, silent truncation
looks exactly like hallucination: you would see the model "ignore" a switch
configuration you know you provided.

ACOP therefore sends `num_ctx` explicitly on every call. Tune it:

1. Run `python scripts/check_qwen.py` and note the declared context length.
2. Raise `ACOP_OLLAMA_NUM_CTX` and restart.
3. Watch `nvidia-smi` and `ollama ps` on the GPU host during a request.
4. If throughput drops below roughly 5 tokens/s, the model has spilled to system
   RAM — back off. `check_qwen.py` flags this.

A ~32B model at Q4_K_M occupies roughly 19–20 GB of a 24 GB card; KV cache for a
large context comes out of what remains. Expect to trade context length against
throughput.

---

## Development

```bash
make venv        # local virtualenv with dev dependencies
make check       # ruff + mypy (strict) + unit tests
make test        # unit tests only, no external dependencies
```

Integration tests need PostgreSQL:

```bash
docker compose up -d postgres
ACOP_TEST_DATABASE=1 \
ACOP_TEST_POSTGRES_PASSWORD=<your password> \
ACOP_TEST_POSTGRES_DB=acop_test \
  pytest
```

Live inference tests are opt-in and use your real `.env`:

```bash
ACOP_TEST_OLLAMA=1 pytest tests/integration/test_live_ollama.py
```

Unit tests point the database at a refused port on purpose, so results never
depend on what happens to be listening on 5432.

### Migrations

```bash
make migration m="add asset table"   # generate
make migrate                          # apply
```

Import every new model module in `src/acop/models/__init__.py` — Alembic walks
`Base.metadata`, and a model that is never imported is silently absent from the
generated migration.

---

## Security posture

Mapped to the frameworks this project is a portfolio piece for.

| Control | Implementation | NIST CSF | CIS Control |
|---|---|---|---|
| No secrets in source, git, logs or the database | `.gitignore`, `SecretStr`, redaction in the logging pipeline and the audit service | PR.DS-5 | 3.11 |
| Identity on every request | Provider-neutral `Principal`; audit records carry subject, type, issuer, method | PR.AC-1 | 5.1, 6.1 |
| Append-only audit trail | No `updated_at`, no update/delete methods, DB role restriction documented | PR.PT-1, DE.AE-3 | 8.2, 8.5 |
| Least privilege in containers | Non-root user, read-only root filesystem, `cap_drop: ALL`, `no-new-privileges` | PR.AC-4 | 4.1 |
| Reduced attack surface | Database bound to loopback; Ollama not exposed; no tool-execution surface exists | PR.AC-5 | 4.8, 12.2 |
| No information disclosure | Errors return a stable code and a correlation ID; detail goes to logs only | PR.DS-5 | 8.2 |
| Constant-time credential comparison | `secrets.compare_digest`, every key compared | PR.AC-7 | 6.5 |

**Known and accepted for Milestone 1**, each with a defined exit:

| Limitation | Accepted because | Resolved by |
|---|---|---|
| API key secrets stored in plaintext in `.env` | ACOP holds no credential that can change infrastructure | Secrets manager (OpenBao), before Milestone 12 |
| No credential rotation, expiry or revocation | Single operator, single key | Identity provider integration |
| No rate limiting on authentication | API is not internet-exposed | Before any external exposure |
| No TLS between ACOP and PostgreSQL | Same Docker host, private bridge network | If the database moves to another host |
| `acop_app` DB role still holds UPDATE/DELETE on `audit_event` | Documented, not yet applied | Same milestone as the secrets manager |

Detail in [`docs/security/`](docs/security/).

---

## Troubleshooting

**`ollama: unhealthy`** — `curl http://<gpu-host>:11434/api/version` from the
application host. If that fails, Ollama is bound to localhost (see
[Requirements](#requirements)), or a firewall or VLAN ACL is blocking TCP/11434.

**`model: unhealthy`** — the tag in `ACOP_OLLAMA_MODEL` is not on the host. The
health report's `details.model.metadata.available_models` lists what is. Fix
with `ollama pull <tag>` or correct the tag.

**`model: degraded`** — you configured a bare name (`qwen3`) and it matched a
tag by prefix. Pin the exact tag so evaluation results and audit records name
the model unambiguously.

**`database: unhealthy`** — `docker compose logs postgres`. Check
`ACOP_POSTGRES_PASSWORD` matches what the volume was initialised with; changing
it in `.env` after first start does **not** change the password inside an
existing volume.

**503 `database_unavailable` from an endpoint** — the datastore is unreachable.
`/health` will agree. This is deliberately distinct from a 500, which means a
defect in ACOP rather than an infrastructure problem.

**Migrations fail on a fresh start** — the `migrate` service runs after
`postgres` reports healthy. `docker compose logs migrate`.

Every response carries an `X-Request-ID`. Every log line carries the same value
as `request_id`. Quote it when investigating:

```bash
docker compose logs api | grep <request-id>
```

---

## What comes next

Milestone 2 (CMDB) begins only after Milestone 1 is verified in your
environment. The full roadmap is in the design brief; the review of it is in
[`docs/ARCHITECTURE-REVIEW.md`](docs/ARCHITECTURE-REVIEW.md).

Nothing in this repository reads from or writes to your infrastructure. That
remains true until Milestone 5, and nothing can *change* infrastructure until
Milestone 12 — after the approval engine exists.
