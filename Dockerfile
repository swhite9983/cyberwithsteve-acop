# syntax=docker/dockerfile:1
#
# ACOP API image.
#
# Two stages so that build tooling (compilers needed by asyncpg wheels on some
# platforms) does not ship in the runtime image. The runtime stage runs as an
# unprivileged user with no shell-writable application directory.

# ---------------------------------------------------------------------------
# Stage 1: build wheels
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

RUN apt-get update \
    && apt-get install --no-install-recommends -y build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN python -m pip wheel --wheel-dir /wheels -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/src

# curl is required by the container HEALTHCHECK below. Nothing else is added.
RUN apt-get update \
    && apt-get install --no-install-recommends -y curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 acop \
    && useradd --system --uid 10001 --gid acop --no-create-home acop

WORKDIR /app

COPY --from=builder /wheels /wheels
COPY requirements.txt ./
RUN python -m pip install --no-index --find-links=/wheels -r requirements.txt \
    && rm -rf /wheels

COPY --chown=root:root alembic.ini ./
COPY --chown=root:root migrations ./migrations
COPY --chown=root:root src ./src
COPY --chown=root:root scripts ./scripts

# Application files are owned by root and readable, not writable, by the
# running user. A compromised process cannot rewrite its own code.
USER acop

EXPOSE 8000

# Liveness only. A container healthcheck that probed the database would restart
# a working API container during a database blip.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl --fail --silent http://127.0.0.1:8000/health/live || exit 1

CMD ["uvicorn", "acop.main:app", "--host", "0.0.0.0", "--port", "8000"]
