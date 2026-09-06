#!/usr/bin/env python3
"""Milestone 4 acceptance check against a real ACOP server over TCP.

Every assertion corresponds to a property the design promised, not to an
implementation detail:

* there is exactly one execution entry point, and no DELETE anywhere
* no request schema can weaken policy, name a class, or carry a command
* all six declared tools are ACTIVE, and the catalog lists only what the
  caller could actually invoke
* Class 0/1 run inline and still pass the shared final gate
* an undeclared input field is refused rather than quietly dropped
* Class 2 goes request -> envelope -> approval -> final gate -> execute ->
  validate, and "the adapter said yes" is not "the change happened"
* the requester cannot approve their own work, and an admin gets no bypass
* Class 3 needs two distinct approvers, and an operator may still request it
* a prohibited capability is refused identically for every role, and recorded
* disabling a tool stops work that was already approved
* the transition history is gap-free and the outcome is sanitized
* an idempotency key replays, and never means two different things

The script starts its own Uvicorn server unless it is given credentials for one
that is already running, because the milestone needs five distinct principals -
viewer, operator, an operator who may also approve, two approvers and an admin -
and a running deployment rarely has exactly those.

Usage:
    python scripts/verify_milestone4.py
    python scripts/verify_milestone4.py --include-slow
    python scripts/verify_milestone4.py --base-url http://acop-01:8000 \\
        --viewer-key KEY --operator-key KEY --requester-approver-key KEY \\
        --approver-key KEY --second-approver-key KEY --admin-key KEY

Exit codes:
    0  all criteria met
    1  one or more criteria not met
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import socket
import subprocess
import sys
import time
import uuid
from collections.abc import AsyncIterator, Mapping, Sequence
from pathlib import Path
from typing import Any, NamedTuple

import httpx
from sqlalchemy import text

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from acop.config import get_settings
from acop.core.logging import configure_logging
from acop.db import Database

REPO_ROOT = Path(__file__).resolve().parent.parent

PASS = "[ PASS ]"  # noqa: S105 - an output label, not a credential
FAIL = "[ FAIL ]"
WARN = "[ WARN ]"
INFO = "[ INFO ]"

#: The Milestone 4 REST contract. Counting endpoints is uninformative; naming
#: them means the check can say precisely which is missing.
#:
#: tests/unit/test_api_tools_contract.py asserts the running application
#: registers exactly this set, so the verifier and the API cannot drift apart.
REQUIRED_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        # Catalog and lifecycle
        ("GET", "/tools"),
        ("GET", "/tools/{tool_name}"),
        ("GET", "/tools/{tool_name}/versions"),
        ("POST", "/tools/{tool_name}/disable"),
        ("POST", "/tools/{tool_name}/enable"),
        # The single execution entry point, and everything you may ask about
        # what it produced.
        ("POST", "/tool-invocations"),
        ("GET", "/tool-invocations"),
        ("GET", "/tool-invocations/{invocation_id}"),
        ("GET", "/tool-invocations/{invocation_id}/envelope"),
        ("GET", "/tool-invocations/{invocation_id}/result"),
        ("GET", "/tool-invocations/{invocation_id}/events"),
        ("GET", "/tool-invocations/{invocation_id}/approvals"),
        ("POST", "/tool-invocations/{invocation_id}/approve"),
        ("POST", "/tool-invocations/{invocation_id}/deny"),
        ("POST", "/tool-invocations/{invocation_id}/cancel"),
        ("POST", "/tool-invocations/{invocation_id}/reconcile"),
    }
)

#: The six tools this build declares. Named rather than counted, so a missing
#: one is reported by name.
DECLARED_TOOLS: tuple[str, ...] = (
    "acop.system.health",
    "acop.test.echo_metadata",
    "test.device.status",
    "test.service.restart",
    "test.security.rotate_key",
    "test.prohibited.shell_exec",
)

PROHIBITED_TOOL = "test.prohibited.shell_exec"

#: Field names no *request* schema may carry. A caller that could send any of
#: them would be setting its own policy or smuggling a command.
FORBIDDEN_REQUEST_FIELDS: frozenset[str] = frozenset(
    {
        "permission_class",
        "approval_required",
        "validation_required",
        "min_approvals",
        "required_roles",
        "timeout_seconds",
        "skip_validation",
        "force",
        "adapter_id",
        "command",
        "script",
        "shell",
        "sql",
        "raw",
    }
)

#: Request models the milestone publishes. Named explicitly so a model added
#: later is not silently exempted by a prefix match.
REQUEST_MODELS: tuple[str, ...] = (
    "InvocationCreate",
    "TargetSpec",
    "ApprovalDecisionRequest",
    "CancelRequest",
    "ReconcileRequest",
    "ToolLifecycleRequest",
)

#: Display names that select the simulated adapter's failure behaviours. The
#: adapter keys off the *asset's* name precisely so no request field can steer
#: execution, so the acceptance run has to create assets called these.
SIM_STAYS_DOWN = "sim-stays-down"
SIM_UNREACHABLE = "sim-unreachable"
SIM_SLOW = "sim-slow"

#: The fixed phrase an unreachable adapter produces, and a fragment of the
#: adapter's own internal wording that must never reach the caller.
ADAPTER_UNAVAILABLE_PHRASE = "The adapter could not be reached."
ADAPTER_INTERNAL_TEXT = "simulated service manager"

TERMINAL_STATES: frozenset[str] = frozenset(
    {
        "REJECTED",
        "DENIED",
        "EXPIRED",
        "CANCELLED",
        "FAILED",
        "TIMED_OUT",
        "EXECUTION_INDETERMINATE",
        "SUCCEEDED",
        "VALIDATION_FAILED",
        "SUPERSEDED",
    }
)

#: Obviously-fake credentials for the server this script starts. They are
#: printed nowhere, they authorise nothing outside a throwaway process, and
#: they are shaped so that anyone who finds one in a log can see what it is.
_FAKE = "not-a-real-credential"
FIXTURE_KEYS: tuple[dict[str, Any], ...] = (
    {
        "subject": "acop:verify:m4-viewer",
        "secret": f"verify-m4-viewer-{_FAKE}",
        "display_name": "M4 acceptance viewer",
        "roles": ["viewer"],
        "principal_type": "service",
    },
    {
        "subject": "acop:verify:m4-operator",
        "secret": f"verify-m4-operator-{_FAKE}",
        "display_name": "M4 acceptance operator",
        "roles": ["operator"],
        "principal_type": "service",
    },
    {
        # Holds both roles, which is the only way to prove separation of duties
        # rather than merely proving that an operator cannot approve anything.
        "subject": "acop:verify:m4-operator-approver",
        "secret": f"verify-m4-operator-approver-{_FAKE}",
        "display_name": "M4 acceptance operator who may approve",
        "roles": ["operator", "approver"],
        "principal_type": "service",
    },
    {
        "subject": "acop:verify:m4-approver-a",
        "secret": f"verify-m4-approver-a-{_FAKE}",
        "display_name": "M4 acceptance approver A",
        "roles": ["approver"],
        "principal_type": "service",
    },
    {
        "subject": "acop:verify:m4-approver-b",
        "secret": f"verify-m4-approver-b-{_FAKE}",
        "display_name": "M4 acceptance approver B",
        "roles": ["approver"],
        "principal_type": "service",
    },
    {
        "subject": "acop:verify:m4-admin",
        "secret": f"verify-m4-admin-{_FAKE}",
        "display_name": "M4 acceptance admin",
        "roles": ["admin"],
        "principal_type": "service",
    },
)


class Checker:
    """Accumulates pass/fail results."""

    def __init__(self) -> None:
        self.failures = 0
        self.warnings = 0
        self.criteria = 0

    def heading(self, title: str) -> None:
        print()
        print(f"-- {title} " + "-" * max(0, 66 - len(title)))

    def note(self, message: str) -> None:
        print(f"{INFO} {message}")

    def ok(self, message: str) -> None:
        self.criteria += 1
        print(f"{PASS} {message}")

    def bad(self, message: str, remedy: str | None = None) -> None:
        self.criteria += 1
        self.failures += 1
        print(f"{FAIL} {message}")
        if remedy:
            print(f"        -> {remedy}")

    def warn(self, message: str) -> None:
        self.warnings += 1
        print(f"{WARN} {message}")

    def expect(self, condition: bool, message: str, remedy: str | None = None) -> bool:
        if condition:
            self.ok(message)
        else:
            self.bad(message, remedy)
        return condition


class Principals(NamedTuple):
    """One header dict per principal the milestone needs.

    A NamedTuple rather than a dataclass because the contract test loads this
    module by path without registering it in ``sys.modules``, and building a
    dataclass under those conditions raises.
    """

    viewer: dict[str, str]
    operator: dict[str, str]
    requester_approver: dict[str, str]
    approver: dict[str, str]
    second_approver: dict[str, str]
    admin: dict[str, str]


def _headers(key: str) -> dict[str, str]:
    return {"X-ACOP-API-Key": key}


def _free_port() -> int:
    """Ask the kernel for a port nothing is using."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@contextlib.asynccontextmanager
async def _uvicorn(port: int, check: Checker) -> AsyncIterator[str]:
    """Run a real server on a real socket for the duration of the check.

    Over TCP rather than in-process, because half of what this milestone
    promises is a property of the HTTP boundary - status codes, role guards,
    what a response body does and does not contain - and an ASGI transport that
    skips the socket also skips the thing being verified.
    """
    environment = dict(os.environ)
    environment["ACOP_API_KEYS"] = json.dumps(list(FIXTURE_KEYS))
    # The child imports acop from the working tree, exactly as this script does.
    existing = environment.get("PYTHONPATH", "")
    src = str(REPO_ROOT / "src")
    environment["PYTHONPATH"] = f"{src}{os.pathsep}{existing}" if existing else src

    base_url = f"http://127.0.0.1:{port}"
    check.note(f"Starting a Uvicorn server on {base_url}.")
    process = subprocess.Popen(  # noqa: S603 - a fixed argv, no shell
        [
            sys.executable,
            "-m",
            "uvicorn",
            "acop.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=str(REPO_ROOT),
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        await _await_liveness(base_url, process, check)
        yield base_url
    finally:
        process.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=15)
        if process.poll() is None:  # pragma: no cover - shutdown race
            process.kill()
        check.note("Stopped the Uvicorn server.")


async def _await_liveness(
    base_url: str, process: subprocess.Popen[bytes], check: Checker
) -> None:
    """Wait until the server answers, or give up loudly."""
    deadline = time.monotonic() + 90.0
    async with httpx.AsyncClient(base_url=base_url, timeout=5.0) as client:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(
                    f"The server exited with code {process.returncode} before it "
                    "became live."
                )
            with contextlib.suppress(httpx.HTTPError):
                if (await client.get("/health/live")).status_code == 200:
                    check.note("The server is live.")
                    return
            await asyncio.sleep(0.5)
    raise RuntimeError(f"The server at {base_url} did not become live in 90s.")


# ---------------------------------------------------------------------------
# Small HTTP helpers. Every one of them returns the raw response, because a
# check that swallows a status code cannot report what it actually saw.
# ---------------------------------------------------------------------------
def _body(response: httpx.Response) -> dict[str, Any]:
    try:
        payload: Any = response.json()
    except ValueError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _rows(response: httpx.Response) -> list[dict[str, Any]]:
    try:
        payload: Any = response.json()
    except ValueError:
        return []
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)]


def _error_code(response: httpx.Response) -> str:
    error = _body(response).get("error")
    if isinstance(error, dict):
        return str(error.get("code", ""))
    return ""


async def _create_asset(
    client: httpx.AsyncClient,
    headers: Mapping[str, str],
    *,
    asset_type: str,
    display_name: str,
) -> str | None:
    response = await client.post(
        "/cmdb/assets",
        headers=dict(headers),
        json={"asset_type": asset_type, "display_name": display_name},
    )
    if response.status_code != 201:
        return None
    return str(_body(response)["id"])


async def _invoke(
    client: httpx.AsyncClient,
    headers: Mapping[str, str],
    tool_name: str,
    *,
    arguments: dict[str, Any] | None = None,
    asset_id: str | None = None,
    justification: str | None = None,
    idempotency_key: str | None = None,
) -> httpx.Response:
    payload: dict[str, Any] = {
        "tool_name": tool_name,
        "tool_version": "1.0",
        "input": arguments if arguments is not None else {},
    }
    if asset_id is not None:
        payload["target"] = {"kind": "ASSET", "asset_id": asset_id}
    if justification is not None:
        payload["justification"] = justification
    if idempotency_key is not None:
        payload["idempotency_key"] = idempotency_key
    return await client.post("/tool-invocations", headers=dict(headers), json=payload)


async def _approve(
    client: httpx.AsyncClient,
    headers: Mapping[str, str],
    invocation_id: str,
    digest: str,
    justification: str,
) -> httpx.Response:
    return await client.post(
        f"/tool-invocations/{invocation_id}/approve",
        headers=dict(headers),
        json={"envelope_digest": digest, "justification": justification},
    )


async def _read(
    client: httpx.AsyncClient, headers: Mapping[str, str], invocation_id: str
) -> dict[str, Any]:
    """Fetch one invocation, tolerating a dropped keep-alive connection.

    The polling loops below make many small requests over minutes, and a
    connection the server closed between two of them is not a failed
    criterion - reporting it as one would make the verifier's verdict depend
    on socket timing.
    """
    for attempt in range(3):
        try:
            return _body(
                await client.get(
                    f"/tool-invocations/{invocation_id}", headers=dict(headers)
                )
            )
        except httpx.HTTPError:
            if attempt == 2:
                raise
            await asyncio.sleep(0.5)
    return {}  # pragma: no cover - the loop either returns or raises


async def _settle(
    client: httpx.AsyncClient,
    headers: Mapping[str, str],
    invocation_id: str,
    *,
    timeout: float,
) -> dict[str, Any]:
    """Poll until the invocation reaches a state nothing else will change.

    Polling rather than waiting on a signal because that is exactly what an
    external caller has to do: the background dispatcher is asynchronous by
    design, and a verifier that reached inside it would be checking something
    no client can observe.
    """
    deadline = time.monotonic() + timeout
    invocation = await _read(client, headers, invocation_id)
    while time.monotonic() < deadline:
        if str(invocation.get("state", "")) in TERMINAL_STATES:
            return invocation
        await asyncio.sleep(0.5)
        invocation = await _read(client, headers, invocation_id)
    return invocation


async def _states(
    client: httpx.AsyncClient, headers: Mapping[str, str], invocation_id: str
) -> list[dict[str, Any]]:
    return _rows(
        await client.get(
            f"/tool-invocations/{invocation_id}/events", headers=dict(headers)
        )
    )


async def _registration_columns() -> set[str] | None:
    """The live column names of ``tool_registration``, if the DB is reachable.

    Read from ``information_schema`` rather than from the ORM model, because
    the claim being checked is about what the *database* holds: a column that
    exists is a column something eventually reads, and a second copy of a
    security-significant value is a second thing that can be wrong.
    """
    try:
        # ACOP's own logging writes to stdout, and this is the only place the
        # verifier constructs an ACOP resource. Silencing it keeps the report
        # one line per criterion rather than interleaved with library output.
        configure_logging(level="CRITICAL")
        database = Database(get_settings())
    except Exception:
        return None
    try:
        async with database.session() as session:
            rows = (
                await session.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_name = 'tool_registration'"
                    )
                )
            ).scalars()
            return {str(name) for name in rows}
    except Exception:
        return None
    finally:
        with contextlib.suppress(Exception):
            await database.dispose()


# ---------------------------------------------------------------------------
# The criteria
# ---------------------------------------------------------------------------
async def _check_contract(check: Checker, client: httpx.AsyncClient) -> bool:
    check.heading("Routes and contract")
    spec = await client.get("/openapi.json")
    if spec.status_code != 200:
        check.bad(
            "Could not read /openapi.json.",
            "Is ACOP running, and is ACOP_DOCS_ENABLED true?",
        )
        return False
    schema = _body(spec)
    paths: dict[str, Any] = schema.get("paths", {})
    registered = {
        (method.upper(), path)
        for path, operations in paths.items()
        for method in operations
        if method.upper() in {"GET", "POST", "PATCH", "PUT", "DELETE"}
    }
    missing = sorted(REQUIRED_ROUTES - registered)
    check.expect(
        not missing,
        f"All {len(REQUIRED_ROUTES)} Milestone 4 operations are registered.",
        f"Missing: {missing}" if missing else None,
    )
    undeclared = sorted(
        route
        for route in registered
        if route[1].startswith("/tool") and route not in REQUIRED_ROUTES
    )
    check.expect(
        not undeclared,
        "The tool API exposes nothing beyond the declared contract - a second "
        "way to run something is a second place for a gate to be missing.",
        f"Found: {undeclared}" if undeclared else None,
    )
    deletes = sorted(
        route
        for route in registered
        if route[0] == "DELETE" and route[1].startswith("/tool")
    )
    check.expect(
        not deletes,
        "The tool API exposes no DELETE - cancellation is a POST that leaves the record.",
        f"Found: {deletes}" if deletes else None,
    )
    shortcuts = sorted(
        path for path in paths if path.endswith(("/execute", "/run", "/command"))
    )
    check.expect(
        not shortcuts,
        "There is no /execute, /run or /command path - one entry point, and no "
        "per-class shortcut.",
        f"Found: {shortcuts}" if shortcuts else None,
    )

    models: dict[str, Any] = schema.get("components", {}).get("schemas", {})
    open_models = sorted(
        name
        for name in REQUEST_MODELS
        if models.get(name, {}).get("additionalProperties") is not False
    )
    check.expect(
        not open_models,
        "Every request schema forbids additional properties, so an undeclared "
        "key is a 422 rather than something quietly ignored.",
        f"Permissive: {open_models}" if open_models else None,
    )
    offending = sorted(
        f"{name}.{field}"
        for name in REQUEST_MODELS
        for field in models.get(name, {}).get("properties", {})
        if field in FORBIDDEN_REQUEST_FIELDS
    )
    check.expect(
        not offending,
        "No request schema can name a permission class, weaken approval or "
        "validation, or carry a command.",
        f"Found: {offending}" if offending else None,
    )
    approval = models.get("ApprovalDecisionRequest", {}).get("properties", {})
    check.expect(
        "self_approval" not in approval and "envelope_digest" in approval,
        "The approval schema has no self_approval and does require an "
        "envelope_digest - an approver states what they reviewed, never their "
        "own exemption.",
        f"Fields: {sorted(approval)}",
    )
    disclosing = sorted(
        f"{name}.{field}"
        for name, model in models.items()
        if name.startswith(("Tool", "Invocation", "Approval", "Envelope"))
        for field in model.get("properties", {})
        if "adapter" in field.lower()
    )
    check.expect(
        not disclosing,
        "No response schema discloses an adapter - knowing what backs a tool "
        "tells an attacker where to aim.",
        f"Found: {disclosing}" if disclosing else None,
    )
    return True


async def _check_registry(
    check: Checker, client: httpx.AsyncClient, who: Principals
) -> None:
    check.heading("Registry")
    states: dict[str, str] = {}
    for tool in DECLARED_TOOLS:
        response = await client.get(f"/tools/{tool}/versions", headers=who.admin)
        rows = _rows(response)
        states[tool] = str(rows[0]["lifecycle_state"]) if rows else "ABSENT"
    inactive = sorted(f"{k}={v}" for k, v in states.items() if v != "ACTIVE")
    check.expect(
        not inactive,
        f"All {len(DECLARED_TOOLS)} declared tools are registered ACTIVE after startup.",
        f"Not ACTIVE: {inactive}" if inactive else None,
    )

    columns = await _registration_columns()
    if columns is None:
        check.warn(
            "The database was not reachable from this process, so the "
            "tool_registration column set could not be inspected. Run the "
            "verifier where ACOP_POSTGRES_* points at the same database."
        )
    else:
        owned_by_code = sorted(
            name
            for name in ("permission_class", "adapter_id", "input_schema")
            if name in columns
        )
        check.expect(
            not owned_by_code,
            "tool_registration has no permission_class column - the database "
            "owns lifecycle and nothing else about a tool.",
            f"Found: {owned_by_code}" if owned_by_code else None,
        )

    viewer_tools = {
        row["tool_name"] for row in _rows(await client.get("/tools", headers=who.viewer))
    }
    operator_tools = {
        row["tool_name"]
        for row in _rows(await client.get("/tools", headers=who.operator))
    }
    admin_tools = {
        row["tool_name"] for row in _rows(await client.get("/tools", headers=who.admin))
    }
    check.expect(
        viewer_tools
        == {"acop.system.health", "acop.test.echo_metadata", "test.device.status"}
        and {"test.service.restart", "test.security.rotate_key"} <= operator_tools,
        "GET /tools lists only the tools the caller could invoke - enumerating "
        "capabilities someone cannot use is reconnaissance.",
        f"viewer={sorted(viewer_tools)} operator={sorted(operator_tools)}",
    )
    check.expect(
        PROHIBITED_TOOL not in viewer_tools | operator_tools | admin_tools,
        "The prohibited tool appears in no listing, for any role including admin.",
    )
    hidden = await client.get(f"/tools/{PROHIBITED_TOOL}", headers=who.admin)
    check.expect(
        hidden.status_code == 404,
        "Fetching the prohibited tool by name is a 404 even for an admin - the "
        "endpoint is not an oracle.",
        f"Got {hidden.status_code}.",
    )


async def _check_read_only(
    check: Checker,
    client: httpx.AsyncClient,
    who: Principals,
    run: str,
    assets: dict[str, str],
) -> str | None:
    check.heading("Class 0 and Class 1")
    health = await _invoke(client, who.viewer, "acop.system.health")
    check.expect(
        health.status_code == 200,
        "acop.system.health executes inline and returns 200 with its result - "
        "a Class 0 tool does not make the caller poll.",
        f"Got {health.status_code}: {health.text[:200]}",
    )
    health_body = _body(health)
    health_id = str(health_body.get("id", "")) or None
    if health_id:
        result = _body(
            await client.get(f"/tool-invocations/{health_id}/result", headers=who.viewer)
        )
        check.expect(
            result.get("state") == "SUCCEEDED" and bool(result.get("result_summary")),
            "The Class 0 invocation succeeded and carries a sanitized result.",
            f"state={result.get('state')} error={result.get('error_category')}",
        )
        check.expect(
            health_body.get("final_gate_decision") == "ALLOW",
            "final_gate_decision is ALLOW on the record, so the shared final "
            "gate ran even for Class 0 - there is no fast path.",
            f"Got {health_body.get('final_gate_decision')}.",
        )
    else:
        check.bad("The Class 0 invocation returned no record to inspect.")
        check.bad("Cannot confirm the final gate ran for Class 0.")

    note = f"acop-verify-{run}"
    echo = await _invoke(
        client, who.viewer, "acop.test.echo_metadata", arguments={"note": note}
    )
    echo_body = _body(echo)
    echo_id = str(echo_body.get("id", "")) or None
    echo_result = (
        _body(await client.get(f"/tool-invocations/{echo_id}/result", headers=who.viewer))
        if echo_id
        else {}
    )
    summary = echo_result.get("result_summary") or {}
    check.expect(
        echo.status_code == 200
        and isinstance(summary, dict)
        and summary.get("note") == note,
        "acop.test.echo_metadata executes inline and returns exactly what the "
        "invocation record says it was asked.",
        f"Got {echo.status_code}: {echo_result.get('state')}",
    )

    device = assets.get("device")
    if device:
        status = await _invoke(
            client,
            who.viewer,
            "test.device.status",
            arguments={"include_facts": True},
            asset_id=device,
        )
        status_id = str(_body(status).get("id", "")) or None
        status_result = (
            _body(
                await client.get(
                    f"/tool-invocations/{status_id}/result", headers=who.viewer
                )
            )
            if status_id
            else {}
        )
        device_summary = status_result.get("result_summary") or {}
        check.expect(
            status.status_code == 200
            and isinstance(device_summary, dict)
            and device_summary.get("asset_id") == device,
            "test.device.status succeeds against a real CMDB asset - the Class "
            "1 path reads Milestone 2 rather than inventing a reply.",
            f"Got {status.status_code}: {status_result.get('state')}",
        )

    retired = assets.get("retired")
    if retired:
        refused = await _invoke(
            client, who.viewer, "test.device.status", asset_id=retired
        )
        record = _rejected_record(
            await client.get(
                "/tool-invocations",
                headers=who.viewer,
                params={"tool_name": "test.device.status", "state": "REJECTED"},
            ),
            asset_id=retired,
        )
        check.expect(
            refused.status_code == 422
            and record.get("authorization_reason") == "target_retired",
            "A retired asset is refused before anything executes, recorded as "
            "target_retired rather than as a wrong target, and answered 422 - "
            "the target is the caller's problem, not their credentials.",
            f"Got {refused.status_code}, reason {record.get('authorization_reason')!r}.",
        )

    out_of_scope = assets.get("vlan")
    if out_of_scope:
        refused = await _invoke(
            client, who.viewer, "test.device.status", asset_id=out_of_scope
        )
        record = _rejected_record(
            await client.get(
                "/tool-invocations",
                headers=who.viewer,
                params={"tool_name": "test.device.status", "state": "REJECTED"},
            ),
            asset_id=out_of_scope,
        )
        check.expect(
            refused.status_code == 422
            and record.get("authorization_reason") == "target_out_of_scope",
            "An asset of a type the tool does not declare is refused as "
            "target_out_of_scope, and answered 422.",
            f"Got {refused.status_code}, reason {record.get('authorization_reason')!r}.",
        )

    undeclared = await _invoke(
        client,
        who.viewer,
        "acop.test.echo_metadata",
        arguments={"note": note, "api_key": "obviously-fake"},
    )
    schema_reason = _rejected_record(
        await client.get(
            "/tool-invocations",
            headers=who.viewer,
            params={"tool_name": "acop.test.echo_metadata", "state": "REJECTED"},
        )
    ).get("authorization_reason")
    check.expect(
        undeclared.status_code == 422,
        "An undeclared input field such as api_key is rejected, not silently "
        "dropped, and answered 422 as the acceptance wording names - a 403 "
        "would send an integrator to look at their credentials instead of "
        "their payload.",
        f"Got {undeclared.status_code}: {undeclared.text[:200]}",
    )
    check.expect(
        schema_reason == "schema_invalid",
        "The refusal is recorded as schema_invalid, so an injected field "
        "leaves a trace rather than vanishing.",
        f"Got {schema_reason!r}.",
    )
    return echo_id


def _rejected_record(
    response: httpx.Response, *, asset_id: str | None = None
) -> dict[str, Any]:
    """The most recent REJECTED invocation, optionally for one target.

    The listing is newest-first, so the first match is the attempt just made.
    """
    for row in _rows(response):
        if asset_id is None or row.get("target_asset_id") == asset_id:
            return row
    return {}


async def _run_change(
    client: httpx.AsyncClient,
    who: Principals,
    *,
    asset_id: str,
    idempotency_key: str,
    timeout: float,
) -> dict[str, Any]:
    """Request, approve and settle one Class 2 restart. Returns the record."""
    requested = await _invoke(
        client,
        who.operator,
        "test.service.restart",
        arguments={"graceful": True},
        asset_id=asset_id,
        justification="Milestone 4 acceptance check.",
        idempotency_key=idempotency_key,
    )
    body = _body(requested)
    invocation_id = str(body.get("id", ""))
    if not invocation_id:
        return {}
    await _approve(
        client,
        who.approver,
        invocation_id,
        str(body.get("envelope_digest", "")),
        "Milestone 4 acceptance check.",
    )
    return await _settle(client, who.viewer, invocation_id, timeout=timeout)


async def _check_change_path(
    check: Checker,
    client: httpx.AsyncClient,
    who: Principals,
    run: str,
    assets: dict[str, str],
    *,
    timeout: float,
    include_slow: bool,
) -> str | None:
    check.heading("Class 2, the complete change path")
    service = assets.get("service")
    if not service:
        check.bad("No SERVICE asset was created, so the Class 2 path cannot run.")
        return None

    requested = await _invoke(
        client,
        who.operator,
        "test.service.restart",
        arguments={"graceful": True, "drain_seconds": 0},
        asset_id=service,
        justification="Milestone 4 acceptance check.",
        idempotency_key=f"m4-{run}-restart",
    )
    body = _body(requested)
    invocation_id = str(body.get("id", ""))
    check.expect(
        requested.status_code == 202 and body.get("state") == "AWAITING_APPROVAL",
        "A Class 2 request returns 202 in AWAITING_APPROVAL - a human has to "
        "agree before anything runs.",
        f"Got {requested.status_code}: {requested.text[:200]}",
    )
    if not invocation_id:
        return None
    digest = str(body.get("envelope_digest", ""))

    envelope = await client.get(
        f"/tool-invocations/{invocation_id}/envelope", headers=who.approver
    )
    envelope_body = _body(envelope)
    check.expect(
        envelope.status_code == 200
        and envelope_body.get("envelope_digest") == digest
        and isinstance(envelope_body.get("envelope"), dict),
        "GET .../envelope returns the whole envelope and its digest, which is "
        "what an approver is actually agreeing to.",
        f"Got {envelope.status_code}.",
    )
    viewer_envelope = await client.get(
        f"/tool-invocations/{invocation_id}/envelope", headers=who.viewer
    )
    check.expect(
        viewer_envelope.status_code == 403,
        "The envelope is reached through the approval workflow, not browsed - "
        "a viewer gets 403.",
        f"Got {viewer_envelope.status_code}.",
    )

    wrong = await _approve(
        client, who.approver, invocation_id, "f" * 64, "Approving something else."
    )
    check.expect(
        wrong.status_code == 409 and _error_code(wrong) == "approval_envelope_mismatch",
        "Approving with the wrong digest is refused - an approval binds to the "
        "version of the request the approver was shown.",
        f"Got {wrong.status_code}: {_error_code(wrong)!r}.",
    )

    approved = await _approve(
        client, who.approver, invocation_id, digest, "Change ticket ACCEPT-M4."
    )
    check.expect(
        approved.status_code == 200 and _body(approved).get("decision") == "APPROVED",
        "Approving with the correct digest is accepted and attributed.",
        f"Got {approved.status_code}: {approved.text[:200]}",
    )
    settled = await _settle(client, who.viewer, invocation_id, timeout=timeout)
    history = [
        str(row.get("to_state"))
        for row in await _states(client, who.viewer, invocation_id)
    ]
    check.expect(
        "APPROVED" in history and "READY" in history,
        "The approval moves it to READY, where the approval branch rejoins the "
        "single execution path.",
        f"History: {history}",
    )
    check.expect(
        "EXECUTING" in history,
        "The background dispatcher picked it up and executed it, with no "
        "further call from the caller.",
        f"History: {history}",
    )
    check.expect(
        settled.get("state") == "SUCCEEDED"
        and settled.get("validation_outcome") == "CONFIRMED",
        "It ends SUCCEEDED with validation_outcome CONFIRMED - the change was "
        "independently observed, not merely reported.",
        f"state={settled.get('state')} validation={settled.get('validation_outcome')} "
        f"error={settled.get('error_category')}",
    )

    stays_down = assets.get("stays_down")
    if stays_down:
        record = await _run_change(
            client,
            who,
            asset_id=stays_down,
            idempotency_key=f"m4-{run}-stays-down",
            timeout=timeout,
        )
        check.expect(
            record.get("state") == "VALIDATION_FAILED"
            and record.get("validation_outcome") == "NOT_CONFIRMED",
            "The sim-stays-down variant ends VALIDATION_FAILED - the adapter "
            "reported success and validation disagreed, which is exactly why "
            "EXECUTED and SUCCEEDED are different states.",
            f"state={record.get('state')} validation={record.get('validation_outcome')}",
        )

    unreachable = assets.get("unreachable")
    if unreachable:
        record = await _run_change(
            client,
            who,
            asset_id=unreachable,
            idempotency_key=f"m4-{run}-unreachable",
            timeout=timeout,
        )
        check.expect(
            record.get("state") == "FAILED"
            and record.get("error_category") == "ADAPTER_UNAVAILABLE"
            and record.get("error_detail_sanitized") == ADAPTER_UNAVAILABLE_PHRASE,
            "The sim-unreachable variant ends FAILED with a fixed phrase per "
            "category, never a message the adapter chose.",
            f"state={record.get('state')} category={record.get('error_category')} "
            f"detail={record.get('error_detail_sanitized')!r}",
        )
        check.expect(
            ADAPTER_INTERNAL_TEXT not in json.dumps(record).lower(),
            "No adapter text reaches the invocation record - adapter output is "
            "the least trustworthy string in the system.",
        )

    slow = assets.get("slow")
    if include_slow and slow:
        record = await _run_change(
            client,
            who,
            asset_id=slow,
            idempotency_key=f"m4-{run}-slow",
            timeout=max(timeout, 120.0),
        )
        check.expect(
            record.get("state") == "TIMED_OUT"
            and record.get("error_category") == "TIMEOUT",
            "The sim-slow variant is cancelled from outside at its declared "
            "deadline - an adapter cannot extend its own timeout.",
            f"state={record.get('state')} category={record.get('error_category')}",
        )
    elif slow:
        check.note(
            "Skipping the sim-slow timeout criterion; it takes about 35 "
            "seconds. Pass --include-slow to exercise it."
        )
    return invocation_id


async def _check_separation_of_duties(
    check: Checker,
    client: httpx.AsyncClient,
    who: Principals,
    run: str,
    assets: dict[str, str],
    pending: list[tuple[str, dict[str, str]]],
) -> None:
    check.heading("Separation of duties")
    service = assets.get("service")
    if not service:
        check.bad("No SERVICE asset was created, so separation of duties is untested.")
        return

    own = await _invoke(
        client,
        who.requester_approver,
        "test.service.restart",
        arguments={"graceful": True},
        asset_id=service,
        justification="Requested by a principal who also holds approver.",
        idempotency_key=f"m4-{run}-self",
    )
    own_body = _body(own)
    own_id = str(own_body.get("id", ""))
    if own_id:
        pending.append((own_id, who.requester_approver))
        refused = await _approve(
            client,
            who.requester_approver,
            own_id,
            str(own_body.get("envelope_digest", "")),
            "I am sure it is fine.",
        )
        check.expect(
            refused.status_code == 403
            and _error_code(refused) == "self_approval_forbidden",
            "The requester cannot approve their own invocation, even holding "
            "the approver role (403 self_approval_forbidden).",
            f"Got {refused.status_code}: {_error_code(refused)!r}.",
        )
        viewer = await _approve(
            client,
            who.viewer,
            own_id,
            str(own_body.get("envelope_digest", "")),
            "Looks fine to me.",
        )
        check.expect(
            viewer.status_code == 403,
            "A viewer holds no approval authority (403).",
            f"Got {viewer.status_code}.",
        )
    else:
        check.bad("Could not create an invocation to test self-approval.")
        check.bad("Could not test that a viewer holds no approval authority.")

    admin_own = await _invoke(
        client,
        who.admin,
        "test.service.restart",
        arguments={"graceful": True},
        asset_id=service,
        justification="Requested by an admin.",
        idempotency_key=f"m4-{run}-admin",
    )
    admin_body = _body(admin_own)
    admin_id = str(admin_body.get("id", ""))
    if admin_id:
        pending.append((admin_id, who.admin))
        refused = await _approve(
            client,
            who.admin,
            admin_id,
            str(admin_body.get("envelope_digest", "")),
            "Admin override.",
        )
        check.expect(
            refused.status_code == 403
            and _error_code(refused) == "self_approval_forbidden",
            "An admin gets no bypass - admin is a superset role, not an "
            "exemption from separation of duties.",
            f"Got {refused.status_code}: {_error_code(refused)!r}.",
        )
    else:
        check.bad("Could not create an admin-requested invocation to test the bypass.")


async def _check_high_risk(
    check: Checker,
    client: httpx.AsyncClient,
    who: Principals,
    run: str,
    assets: dict[str, str],
    *,
    timeout: float,
) -> None:
    check.heading("Class 3, strength through policy rather than role")
    host = assets.get("host")
    if not host:
        check.bad("No HOST asset was created, so the Class 3 path cannot run.")
        return

    requested = await _invoke(
        client,
        who.operator,
        "test.security.rotate_key",
        arguments={"key_slot": "primary"},
        asset_id=host,
        justification="Milestone 4 acceptance check.",
        idempotency_key=f"m4-{run}-rotate",
    )
    body = _body(requested)
    invocation_id = str(body.get("id", ""))
    check.expect(
        requested.status_code == 202
        and body.get("state") == "AWAITING_APPROVAL"
        and body.get("min_approvals") == 2
        and body.get("distinct_approvers_required") is True,
        "An operator may request a Class 3 change, and its strength is two "
        "distinct approvals rather than an admin-only role.",
        f"Got {requested.status_code}: {requested.text[:200]}",
    )
    if not invocation_id:
        return
    digest = str(body.get("envelope_digest", ""))

    first = await _approve(client, who.approver, invocation_id, digest, "First approval.")
    after_first = await _read(client, who.viewer, invocation_id)
    check.expect(
        first.status_code == 200
        and after_first.get("state") == "AWAITING_APPROVAL"
        and after_first.get("approvals_received") == 1,
        "One approval is not enough - it is still awaiting approval afterwards.",
        f"state={after_first.get('state')} "
        f"received={after_first.get('approvals_received')}",
    )
    duplicate = await _approve(client, who.approver, invocation_id, digest, "And again.")
    after_duplicate = await _read(client, who.viewer, invocation_id)
    check.expect(
        duplicate.status_code >= 400
        and after_duplicate.get("approvals_received") == 1
        and after_duplicate.get("state") == "AWAITING_APPROVAL",
        "The same approver cannot supply both approvals - two-person control "
        "is not satisfiable by one person twice.",
        f"Got {duplicate.status_code}, "
        f"received={after_duplicate.get('approvals_received')}.",
    )
    if duplicate.status_code >= 500:
        check.warn(
            "The duplicate approval is refused by the database's partial "
            f"unique index and surfaces as HTTP {duplicate.status_code}. The "
            "control holds, but a second approval from the same subject is a "
            "foreseeable client error and deserves a 409."
        )

    second = await _approve(
        client, who.second_approver, invocation_id, digest, "Second approval."
    )
    check.expect(
        second.status_code == 200,
        "A second, distinct approver satisfies the policy - and no admin was "
        "involved anywhere in the Class 3 path.",
        f"Got {second.status_code}: {second.text[:200]}",
    )
    settled = await _settle(client, who.viewer, invocation_id, timeout=timeout)
    result = _body(
        await client.get(f"/tool-invocations/{invocation_id}/result", headers=who.viewer)
    )
    summary = result.get("result_summary") or {}
    check.expect(
        settled.get("state") == "SUCCEEDED"
        and isinstance(summary, dict)
        and set(summary) == {"asset_id", "key_slot", "key_identifier", "rotated_at"},
        "The result carries only the four allow-listed fields - constructed "
        "from what the tool declared, not filtered from what the adapter "
        "returned.",
        f"state={settled.get('state')} fields={sorted(summary)}",
    )
    serialised = json.dumps(result).lower()
    check.expect(
        not any(
            fragment in serialised
            for fragment in ("private", "secret", "password", "begin rsa", "token")
        ),
        "No key material appears anywhere in the result - the rotation returns "
        "an opaque handle that is not derived from anything secret.",
    )


async def _check_prohibition(
    check: Checker, client: httpx.AsyncClient, who: Principals, assets: dict[str, str]
) -> None:
    check.heading("Prohibition")
    host = assets.get("host")
    outcomes: list[tuple[str, int, str]] = []
    for name, headers in (
        ("viewer", who.viewer),
        ("operator", who.operator),
        ("approver", who.approver),
        ("admin", who.admin),
    ):
        response = await _invoke(
            client,
            headers,
            PROHIBITED_TOOL,
            arguments={"intent": "have a look around"},
            asset_id=host,
            justification="Milestone 4 acceptance check.",
        )
        outcomes.append((name, response.status_code, _error_code(response)))
    check.expect(
        all(status == 403 for _, status, _ in outcomes),
        "test.prohibited.shell_exec is denied for viewer, operator, approver "
        "and admin alike - no role, approval or configuration lifts it.",
        f"Got {outcomes}",
    )
    distinct = {(status, code) for _, status, code in outcomes}
    check.expect(
        len(distinct) == 1,
        "The denial is identical for every role, so the refusal cannot be used "
        "as an oracle for which privilege would have worked.",
        f"Distinct outcomes: {sorted(distinct)}",
    )
    recorded = _rows(
        await client.get(
            "/tool-invocations",
            headers=who.viewer,
            params={"tool_name": PROHIBITED_TOOL, "limit": 200},
        )
    )
    reasons = {str(row.get("authorization_reason")) for row in recorded}
    states = {str(row.get("state")) for row in recorded}
    check.expect(
        len(recorded) >= len(outcomes)
        and reasons == {"prohibited_capability"}
        and states == {"REJECTED"},
        "Every attempt is recorded as REJECTED for prohibited_capability, and "
        "none ever reached execution.",
        f"states={sorted(states)} reasons={sorted(reasons)}",
    )


async def _check_lifecycle(
    check: Checker,
    client: httpx.AsyncClient,
    who: Principals,
    run: str,
    assets: dict[str, str],
    pending: list[tuple[str, dict[str, str]]],
    *,
    timeout: float,
) -> None:
    check.heading("Lifecycle")
    service = assets.get("service")
    if not service:
        check.bad("No SERVICE asset was created, so lifecycle cannot be tested.")
        return

    requested = await _invoke(
        client,
        who.operator,
        "test.service.restart",
        arguments={"graceful": True},
        asset_id=service,
        justification="Milestone 4 acceptance check.",
        idempotency_key=f"m4-{run}-disable",
    )
    body = _body(requested)
    invocation_id = str(body.get("id", ""))
    digest = str(body.get("envelope_digest", ""))

    lifecycle = {"tool_version": "1.0", "reason": f"acop-verify-{run}: incident drill."}
    by_operator = await client.post(
        "/tools/test.service.restart/disable", headers=who.operator, json=lifecycle
    )
    check.expect(
        by_operator.status_code == 403,
        "Taking a tool out of service is an admin act (403 for an operator).",
        f"Got {by_operator.status_code}.",
    )
    disabled = await client.post(
        "/tools/test.service.restart/disable", headers=who.admin, json=lifecycle
    )
    check.expect(
        disabled.status_code == 200
        and _body(disabled).get("lifecycle_state") == "DISABLED"
        and _body(disabled).get("disabled_reason") == lifecycle["reason"],
        "An admin can disable a tool immediately and attributably, with a "
        "required reason.",
        f"Got {disabled.status_code}: {disabled.text[:200]}",
    )

    if invocation_id:
        approved = await _approve(
            client, who.approver, invocation_id, digest, "Approved before the disable."
        )
        settled = await _settle(client, who.viewer, invocation_id, timeout=timeout)
        check.expect(
            approved.status_code == 200
            and settled.get("state") == "EXPIRED"
            and settled.get("final_gate_decision") == "DENY"
            and settled.get("final_gate_reason") == "tool_disabled",
            "Disabling stops an approved invocation at the final gate: EXPIRED "
            "with DENY and tool_disabled, because request-time authorization is "
            "necessary and not sufficient.",
            f"state={settled.get('state')} gate={settled.get('final_gate_decision')} "
            f"reason={settled.get('final_gate_reason')}",
        )
        result = _body(
            await client.get(
                f"/tool-invocations/{invocation_id}/result", headers=who.viewer
            )
        )
        check.expect(
            result.get("result_summary") is None
            and result.get("validation_outcome") is None,
            "Nothing was attempted: the gated invocation produced no result and "
            "no validation, so the record is not a false statement about the "
            "target.",
            f"result={result.get('result_summary')} "
            f"validation={result.get('validation_outcome')}",
        )
    else:
        check.bad("Could not create an invocation to hold across the disable.")
        check.bad("Could not confirm the invocation was not attempted.")

    enabled = await client.post(
        "/tools/test.service.restart/enable",
        headers=who.admin,
        json={"tool_version": "1.0", "reason": f"acop-verify-{run}: drill over."},
    )
    restored = await _invoke(
        client,
        who.operator,
        "test.service.restart",
        arguments={"graceful": True},
        asset_id=service,
        justification="Milestone 4 acceptance check.",
        idempotency_key=f"m4-{run}-enabled",
    )
    restored_id = str(_body(restored).get("id", ""))
    if restored_id:
        pending.append((restored_id, who.operator))
    check.expect(
        enabled.status_code == 200
        and _body(enabled).get("lifecycle_state") == "ACTIVE"
        and restored.status_code == 202,
        "Enabling returns the tool to service, and a new request is accepted again.",
        f"enable={enabled.status_code} request={restored.status_code}",
    )


async def _check_evidence(
    check: Checker,
    client: httpx.AsyncClient,
    who: Principals,
    invocation_id: str | None,
) -> None:
    check.heading("Evidence")
    if not invocation_id:
        check.bad("No completed Class 2 invocation to inspect.")
        return
    events = await _states(client, who.viewer, invocation_id)
    sequences = [int(row.get("sequence", -1)) for row in events]
    chained = all(
        events[index].get("from_state") == events[index - 1].get("to_state")
        for index in range(1, len(events))
    )
    check.expect(
        bool(events)
        and sequences == list(range(1, len(events) + 1))
        and events[0].get("from_state") is None
        and chained,
        "GET .../events returns a gap-free ordered transition history, each "
        "step starting where the previous one ended.",
        f"sequences={sequences}",
    )
    record = await _read(client, who.viewer, invocation_id)
    snapshot = (
        "permission_class",
        "approval_required",
        "min_approvals",
        "distinct_approvers_required",
        "approval_ttl_seconds",
        "validation_required",
        "authorization_decision",
        "authorization_reason",
        "final_gate_decision",
        "envelope_digest",
        "input_digest",
        "input_canonical",
        "principal_subject",
    )
    absent = sorted(field for field in snapshot if record.get(field) is None)
    check.expect(
        not absent,
        "The invocation record carries the full security snapshot - what the "
        "tool required when this ran, not what it requires today.",
        f"Missing or null: {absent}" if absent else None,
    )
    result = _body(
        await client.get(f"/tool-invocations/{invocation_id}/result", headers=who.viewer)
    )
    summary = result.get("result_summary") or {}
    declared = {
        "asset_id",
        "restart_initiated",
        "previous_state",
        "simulated_pid",
        "initiated_at",
    }
    check.expect(
        isinstance(summary, dict) and set(summary) <= declared,
        "GET .../result returns sanitized output only - the fields the tool "
        "declared, and nothing an adapter added.",
        f"fields={sorted(summary) if isinstance(summary, dict) else summary}",
    )


async def _check_reconciliation(
    check: Checker,
    client: httpx.AsyncClient,
    who: Principals,
    invocation_id: str | None,
) -> None:
    check.heading("Reconciliation")
    if not invocation_id:
        check.bad("No settled invocation to attempt reconciliation against.")
        return
    refused = await client.post(
        f"/tool-invocations/{invocation_id}/reconcile",
        headers=who.approver,
        json={
            "disposition": "CONFIRMED_FAILED",
            "justification": "Trying to correct a settled outcome.",
            "evidence_ref": {"ticket": "ACCEPT-M4"},
        },
    )
    check.expect(
        refused.status_code == 403,
        "Reconciliation is refused for anything but an EXECUTION_INDETERMINATE "
        "invocation - a settled outcome is not rewritable after the fact.",
        f"Got {refused.status_code}: {refused.text[:200]}",
    )


async def _check_idempotency(
    check: Checker,
    client: httpx.AsyncClient,
    who: Principals,
    run: str,
    assets: dict[str, str],
    pending: list[tuple[str, dict[str, str]]],
) -> None:
    check.heading("Idempotency")
    service = assets.get("service")
    if not service:
        check.bad("No SERVICE asset was created, so idempotency cannot be tested.")
        return
    key = f"m4-{run}-idem"
    first = await _invoke(
        client,
        who.operator,
        "test.service.restart",
        arguments={"graceful": True},
        asset_id=service,
        justification="Milestone 4 acceptance check.",
        idempotency_key=key,
    )
    first_id = str(_body(first).get("id", ""))
    if first_id:
        pending.append((first_id, who.operator))
    replay = await _invoke(
        client,
        who.operator,
        "test.service.restart",
        arguments={"graceful": True},
        asset_id=service,
        justification="Milestone 4 acceptance check.",
        idempotency_key=key,
    )
    check.expect(
        bool(first_id) and str(_body(replay).get("id", "")) == first_id,
        "Replaying an idempotency key returns the original invocation rather "
        "than starting a second one.",
        f"first={first_id} replay={_body(replay).get('id')}",
    )
    clash = await _invoke(
        client,
        who.operator,
        "test.service.restart",
        arguments={"graceful": False},
        asset_id=service,
        justification="Milestone 4 acceptance check.",
        idempotency_key=key,
    )
    check.expect(
        clash.status_code == 409 and _error_code(clash) == "idempotency_conflict",
        "Reusing the key for a different envelope is a 409 - a key that meant "
        "one thing cannot silently come to mean another.",
        f"Got {clash.status_code}: {_error_code(clash)!r}.",
    )


async def _make_assets(
    check: Checker, client: httpx.AsyncClient, who: Principals, run: str
) -> dict[str, str]:
    """Create the inventory the simulated adapter keys its behaviour off.

    The failure-path names are exact rather than run-scoped because the adapter
    selects behaviour by ``display_name`` - which is precisely how the input
    schema stays free of any field that could steer execution.
    """
    wanted = (
        ("service", "SERVICE", f"sim-ok-{run}"),
        ("stays_down", "SERVICE", SIM_STAYS_DOWN),
        ("unreachable", "SERVICE", SIM_UNREACHABLE),
        ("slow", "SERVICE", SIM_SLOW),
        ("device", "DEVICE", f"sim-device-{run}"),
        ("host", "HOST", f"sim-keystore-{run}"),
        ("vlan", "VLAN", f"sim-vlan-{run}"),
        ("retired", "DEVICE", f"sim-retired-{run}"),
    )
    assets: dict[str, str] = {}
    for name, asset_type, display_name in wanted:
        asset_id = await _create_asset(
            client, who.operator, asset_type=asset_type, display_name=display_name
        )
        if asset_id is None:
            check.warn(f"Could not create the {display_name!r} asset.")
            continue
        assets[name] = asset_id
    if "retired" in assets:
        await client.post(
            f"/cmdb/assets/{assets['retired']}/retire", headers=who.operator
        )
    return assets


async def _cleanup(
    client: httpx.AsyncClient,
    who: Principals,
    assets: Mapping[str, str],
    pending: Sequence[tuple[str, dict[str, str]]],
) -> None:
    """Leave nothing waiting and nothing active. Best effort, never fatal."""
    for invocation_id, headers in pending:
        with contextlib.suppress(httpx.HTTPError):
            await client.post(
                f"/tool-invocations/{invocation_id}/cancel",
                headers=headers,
                json={"reason": "Acceptance check finished."},
            )
    with contextlib.suppress(httpx.HTTPError):
        await client.post(
            "/tools/test.service.restart/enable",
            headers=who.admin,
            json={"tool_version": "1.0", "reason": "Acceptance check finished."},
        )
    for asset_id in assets.values():
        with contextlib.suppress(httpx.HTTPError):
            await client.post(f"/cmdb/assets/{asset_id}/retire", headers=who.operator)


async def verify(
    base_url: str, who: Principals, *, timeout: float, include_slow: bool
) -> int:
    check = Checker()
    run = uuid.uuid4().hex[:8]
    pending: list[tuple[str, dict[str, str]]] = []
    assets: dict[str, str] = {}

    async with httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=120.0) as client:
        if not await _check_contract(check, client):
            return 1
        await _check_registry(check, client, who)
        assets = await _make_assets(check, client, who, run)
        try:
            echo_id = await _check_read_only(check, client, who, run, assets)
            change_id = await _check_change_path(
                check,
                client,
                who,
                run,
                assets,
                timeout=timeout,
                include_slow=include_slow,
            )
            await _check_separation_of_duties(check, client, who, run, assets, pending)
            await _check_high_risk(check, client, who, run, assets, timeout=timeout)
            await _check_prohibition(check, client, who, assets)
            await _check_lifecycle(
                check, client, who, run, assets, pending, timeout=timeout
            )
            await _check_evidence(check, client, who, change_id)
            await _check_reconciliation(check, client, who, echo_id or change_id)
            await _check_idempotency(check, client, who, run, assets, pending)
        finally:
            await _cleanup(client, who, assets, pending)

    print()
    print(f"        {check.criteria} acceptance criteria checked.")
    if check.failures:
        print(
            f"{FAIL} Milestone 4 NOT met: {check.failures} failure(s), "
            f"{check.warnings} warning(s)."
        )
        return 1
    print(f"{PASS} Milestone 4 acceptance criteria met ({check.warnings} warning(s)).")
    print(f"        Test assets carry the suffix {run} and are retired.")
    return 0


async def _run(args: argparse.Namespace) -> int:
    supplied = (
        args.viewer_key,
        args.operator_key,
        args.requester_approver_key,
        args.approver_key,
        args.second_approver_key,
        args.admin_key,
    )
    if args.start_server or not all(supplied):
        check = Checker()
        who = Principals(
            viewer=_headers(str(FIXTURE_KEYS[0]["secret"])),
            operator=_headers(str(FIXTURE_KEYS[1]["secret"])),
            requester_approver=_headers(str(FIXTURE_KEYS[2]["secret"])),
            approver=_headers(str(FIXTURE_KEYS[3]["secret"])),
            second_approver=_headers(str(FIXTURE_KEYS[4]["secret"])),
            admin=_headers(str(FIXTURE_KEYS[5]["secret"])),
        )
        port = args.port or _free_port()
        async with _uvicorn(port, check) as base_url:
            return await verify(
                base_url,
                who,
                timeout=args.settle_timeout,
                include_slow=args.include_slow,
            )
    who = Principals(
        viewer=_headers(args.viewer_key),
        operator=_headers(args.operator_key),
        requester_approver=_headers(args.requester_approver_key),
        approver=_headers(args.approver_key),
        second_approver=_headers(args.second_approver_key),
        admin=_headers(args.admin_key),
    )
    return await verify(
        args.base_url,
        who,
        timeout=args.settle_timeout,
        include_slow=args.include_slow,
    )


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
    parser.add_argument(
        "--start-server",
        action="store_true",
        help=(
            "Start a Uvicorn server with the fixture principals. Implied when "
            "any key is missing."
        ),
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("ACOP_VERIFY_PORT", "0")),
        help="Port for the server this script starts. 0 picks a free one.",
    )
    parser.add_argument("--viewer-key", default=os.getenv("ACOP_VERIFY_VIEWER_KEY"))
    parser.add_argument(
        "--operator-key",
        default=os.getenv("ACOP_VERIFY_OPERATOR_KEY", os.getenv("ACOP_VERIFY_API_KEY")),
    )
    parser.add_argument(
        "--requester-approver-key",
        default=os.getenv("ACOP_VERIFY_REQUESTER_APPROVER_KEY"),
        help=(
            "A principal holding both operator and approver. Separation of "
            "duties cannot be proven without one."
        ),
    )
    parser.add_argument("--approver-key", default=os.getenv("ACOP_VERIFY_APPROVER_KEY"))
    parser.add_argument(
        "--second-approver-key",
        default=os.getenv("ACOP_VERIFY_SECOND_APPROVER_KEY"),
        help="A second, distinct approver. Class 3 requires two.",
    )
    parser.add_argument("--admin-key", default=os.getenv("ACOP_VERIFY_ADMIN_KEY"))
    parser.add_argument(
        "--include-slow",
        action="store_true",
        help="Also exercise the sim-slow timeout path, which takes about 35s.",
    )
    parser.add_argument(
        "--settle-timeout",
        type=float,
        default=90.0,
        help="Seconds to wait for an invocation to reach a terminal state.",
    )
    args = parser.parse_args()
    try:
        return asyncio.run(_run(args))
    except RuntimeError as exc:
        print(f"{FAIL} {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
