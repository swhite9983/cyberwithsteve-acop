#!/usr/bin/env python3
"""Milestone 1 acceptance check against a running ACOP stack.

Verifies the success criteria from section 35 of the design brief, in order,
against the real running service. Every check is an observation, not an
assumption - the script reports what it actually saw.

Usage:
    python scripts/verify_milestone1.py
    python scripts/verify_milestone1.py --base-url http://acop-host:8000

Exit codes:
    0  all criteria met
    1  one or more criteria not met
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from acop.config import get_settings

#: The endpoints Milestone 1 delivered. Later milestones add to the surface;
#: none may remove from it.
MILESTONE_1_ENDPOINTS = ("/health", "/health/live", "/health/ready", "/whoami")

PASS = "[ PASS ]"  # noqa: S105 - an output label, not a credential
FAIL = "[ FAIL ]"
WARN = "[ WARN ]"


class Checker:
    """Accumulates pass/fail results."""

    def __init__(self) -> None:
        self.failures = 0
        self.warnings = 0

    def ok(self, message: str) -> None:
        print(f"{PASS} {message}")

    def bad(self, message: str, remedy: str | None = None) -> None:
        self.failures += 1
        print(f"{FAIL} {message}")
        if remedy:
            print(f"        -> {remedy}")

    def warn(self, message: str) -> None:
        self.warnings += 1
        print(f"{WARN} {message}")


async def verify(base_url: str, api_key: str | None) -> int:
    check = Checker()
    base_url = base_url.rstrip("/")

    async with httpx.AsyncClient(base_url=base_url, timeout=30.0) as client:
        # 1. API responds -------------------------------------------------
        try:
            live = await client.get("/health/live")
        except httpx.HTTPError as exc:
            check.bad(
                f"API unreachable at {base_url}: {type(exc).__name__}",
                "Start the stack with `make up`, then `make logs`.",
            )
            return 1

        if live.status_code == 200 and live.json().get("status") == "alive":
            check.ok(f"API is live at {base_url} (version {live.json().get('version')})")
        else:
            check.bad(f"Liveness probe returned HTTP {live.status_code}")

        # 2. Correlation header -------------------------------------------
        if live.headers.get("X-Request-ID"):
            check.ok("Responses carry an X-Request-ID correlation header.")
        else:
            check.bad("No X-Request-ID header on the response.")

        # 3. Full health report -------------------------------------------
        report = await client.get("/health", params={"fresh": "true"})
        if report.status_code != 200:
            check.bad(f"/health returned HTTP {report.status_code}")
            return 1

        body = report.json()
        components: dict[str, str] = body.get("components", {})
        details: dict[str, dict] = body.get("details", {})
        print(f"\n  Overall status: {body.get('status')}")
        for name in ("api", "database", "ollama", "model"):
            status = components.get(name, "MISSING")
            detail = details.get(name, {})
            latency = detail.get("latency_ms")
            suffix = f" ({latency} ms)" if latency is not None else ""
            print(f"    {name:<10} {status}{suffix}")
            message = detail.get("message")
            if status != "healthy" and message:
                print(f"               {message}")
        print()

        for required in ("api", "database", "ollama", "model"):
            if required not in components:
                check.bad(f"Health report does not include component '{required}'.")

        if components.get("database") == "healthy":
            check.ok("PostgreSQL connectivity verified by a real query.")
        else:
            check.bad(
                "PostgreSQL is not healthy.",
                "Check `make ps` and `docker compose logs postgres`.",
            )

        if components.get("ollama") == "healthy":
            ollama_version = (
                details.get("ollama", {}).get("metadata", {}).get("ollama_version")
            )
            check.ok(f"Ollama reachable (server version {ollama_version}).")
        else:
            check.bad(
                "Ollama is not reachable.",
                "Verify ACOP_OLLAMA_BASE_URL and that Ollama binds 0.0.0.0:11434.",
            )

        model_status = components.get("model")
        if model_status == "healthy":
            resolved = details.get("model", {}).get("metadata", {}).get("resolved_model")
            check.ok(f"Configured model {resolved} is present on the inference host.")
        elif model_status == "degraded":
            check.warn(details.get("model", {}).get("message", "Model is degraded."))
        else:
            check.bad(
                "Configured model is not available.",
                "Run `python scripts/check_qwen.py` for the specific cause.",
            )

        # 4. Health caching ------------------------------------------------
        cached = await client.get("/health")
        if cached.json().get("cached") is True:
            check.ok("Health probe results are cached between scrapes.")
        else:
            check.warn(
                "Second /health call was not served from cache. "
                "Check ACOP_HEALTH_CACHE_TTL_SECONDS."
            )

        # 5. Readiness semantics -------------------------------------------
        ready = await client.get("/health/ready")
        overall = body.get("status")
        expected = 503 if overall == "unhealthy" else 200
        if ready.status_code == expected:
            check.ok(
                f"Readiness probe returned HTTP {ready.status_code}, "
                f"consistent with overall status '{overall}'."
            )
        else:
            check.bad(
                f"Readiness returned HTTP {ready.status_code}, expected {expected}."
            )

        # 6. Authentication -------------------------------------------------
        unauth = await client.get("/whoami")
        if unauth.status_code == 401:
            check.ok("Unauthenticated request to /whoami is rejected with 401.")
        elif unauth.status_code == 200:
            check.warn(
                "/whoami succeeded without a credential. "
                "Authentication is disabled (ACOP_AUTH_ENABLED=false)."
            )
        else:
            check.bad(f"/whoami returned unexpected HTTP {unauth.status_code}.")

        if api_key:
            authed = await client.get("/whoami", headers={"X-ACOP-API-Key": api_key})
            if authed.status_code == 200:
                identity = authed.json()
                check.ok(
                    f"Authenticated as subject '{identity['subject']}' "
                    f"(issuer '{identity['issuer']}', "
                    f"method '{identity['auth_method']}', "
                    f"roles {identity['roles']})."
                )
                check.ok(
                    "Identity is provider-neutral: subject, issuer and auth_method "
                    "are separate fields, so swapping the backend does not change "
                    "what downstream records store."
                )
            else:
                check.bad(
                    f"Authenticated /whoami returned HTTP {authed.status_code}.",
                    "Confirm the key matches an entry in ACOP_API_KEYS.",
                )
        else:
            check.warn(
                "No API key supplied, so the authenticated path was not exercised. "
                "Pass --api-key or set ACOP_VERIFY_API_KEY."
            )

        # 7. OpenAPI ---------------------------------------------------------
        openapi = await client.get("/openapi.json")
        if openapi.status_code == 200:
            paths = sorted(openapi.json().get("paths", {}))
            check.ok(f"OpenAPI schema published. Endpoints: {', '.join(paths)}")
            missing = [p for p in MILESTONE_1_ENDPOINTS if p not in paths]
            if missing:
                check.bad(
                    f"Milestone 1 endpoints are missing: {missing}",
                    "The Milestone 1 surface must survive every later milestone.",
                )
            else:
                check.ok(
                    "Every Milestone 1 endpoint is still present: "
                    + ", ".join(MILESTONE_1_ENDPOINTS)
                )

            # Later milestones legitimately add endpoints, so their presence is
            # not a Milestone 1 failure. This check originally asserted that
            # nothing outside /health and /whoami existed, which made it fail on
            # a correct Milestone 2 deployment - a false alarm, and the same
            # stale-scope-assertion defect that was corrected in
            # verify_milestone2.py. Scope enforcement now lives where it can be
            # kept current: the per-milestone required-route contracts and
            # tests/unit/test_api_identity.py.
            # This prefix list is the one thing here that must be kept current
            # as milestones land. It is a *scope* guard, not a contract: the
            # per-milestone required-route sets in verify_milestone2.py and
            # verify_milestone3.py, pinned by unit tests, are what actually
            # enforce each API surface.
            accepted_prefixes = ("/health", "/whoami", "/cmdb", "/knowledge")
            later = [path for path in paths if not path.startswith(accepted_prefixes)]
            if later:
                check.warn(
                    "Endpoints outside Milestones 1-3 are exposed, which no "
                    f"accepted milestone justifies: {later}"
                )
            else:
                check.ok(
                    "No endpoints beyond the accepted milestones. No "
                    "infrastructure integration and no action-executing "
                    "capability is present."
                )
        else:
            check.warn("OpenAPI schema is disabled (ACOP_DOCS_ENABLED=false).")

    print()
    if check.failures:
        print(
            f"{FAIL} Milestone 1 NOT met: {check.failures} failure(s), "
            f"{check.warnings} warning(s)."
        )
        return 1
    print(f"{PASS} Milestone 1 acceptance criteria met ({check.warnings} warning(s)).")
    return 0


def main() -> int:
    try:
        settings = get_settings()
        default_url = f"http://127.0.0.1:{settings.api_port}"
    except Exception:
        default_url = "http://127.0.0.1:8000"

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url", default=os.getenv("ACOP_VERIFY_BASE_URL", default_url)
    )
    parser.add_argument("--api-key", default=os.getenv("ACOP_VERIFY_API_KEY"))
    args = parser.parse_args()
    return asyncio.run(verify(args.base_url, args.api_key))


if __name__ == "__main__":
    raise SystemExit(main())
