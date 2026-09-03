#!/usr/bin/env python3
"""Milestone 2 acceptance check against a running ACOP stack.

Exercises the CMDB end to end against the real service and reports what it
actually observed. Every assertion here corresponds to a property the design
promised, not to an implementation detail:

* identity resolves, and ambiguity is refused rather than guessed
* an unchanged re-assertion touches instead of writing history
* a changed value supersedes, and both intervals remain queryable
* a caller cannot assert its own trust level
* verification requires a higher role than assertion
* revocation preserves the attribution trail
* a secret-bearing predicate is rejected and never echoed
* relationships read correctly in both directions
* nothing is destructive - retirement preserves history

The script creates assets under a run-scoped name prefix and retires them at
the end. It never deletes anything, because the API has no way to.

Usage:
    python scripts/verify_milestone2.py
    python scripts/verify_milestone2.py --base-url http://acop-01:8000 \
        --operator-key KEY --approver-key KEY

Exit codes:
    0  all criteria met
    1  one or more criteria not met
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import uuid
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from acop.config import get_settings

PASS = "[ PASS ]"  # noqa: S105 - an output label, not a credential
FAIL = "[ FAIL ]"
WARN = "[ WARN ]"

#: The Milestone 2 REST contract, as (method, path) pairs. This is the
#: acceptance criterion: every operation here must be registered, and the check
#: names precisely which are missing. Counting paths - the previous form - was
#: brittle and, worse, uninformative: it could not say what was absent, and it
#: was compared against a total that silently included /health and /whoami.
#:
#: tests/unit/test_api_identity.py asserts the running application registers
#: exactly this set, so the verifier and the API cannot drift apart.
REQUIRED_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        # Assets and identity
        ("POST", "/cmdb/assets"),
        ("GET", "/cmdb/assets"),
        ("POST", "/cmdb/assets/resolve"),
        ("GET", "/cmdb/assets/{asset_id}"),
        ("PATCH", "/cmdb/assets/{asset_id}"),
        ("POST", "/cmdb/assets/{asset_id}/retire"),
        ("GET", "/cmdb/assets/{asset_id}/identifiers"),
        ("POST", "/cmdb/assets/{asset_id}/identifiers"),
        ("POST", "/cmdb/identifiers/{identifier_id}/retire"),
        # Facts, history and trust
        ("POST", "/cmdb/assets/{asset_id}/facts"),
        ("GET", "/cmdb/assets/{asset_id}/facts"),
        ("GET", "/cmdb/assets/{asset_id}/facts/{predicate}/history"),
        ("GET", "/cmdb/assets/{asset_id}/facts/{predicate}/effective"),
        ("GET", "/cmdb/assets/{asset_id}/conflicts"),
        ("POST", "/cmdb/assets/{asset_id}/desired-facts"),
        ("GET", "/cmdb/facts/{fact_id}/attestations"),
        ("POST", "/cmdb/facts/{fact_id}/verify"),
        ("POST", "/cmdb/facts/{fact_id}/revoke"),
        # Relationships
        ("POST", "/cmdb/relationships"),
        ("GET", "/cmdb/relationships"),
        ("POST", "/cmdb/relationships/{relationship_id}/retire"),
        ("GET", "/cmdb/assets/{asset_id}/related"),
    }
)

#: The provider-neutral Principal field every attestation carries. Named here
#: so the acceptance check and the unit test that guards it share one literal.
ATTESTATION_SUBJECT_FIELD = "principal_subject"

# RFC 5737 / RFC 7042 documentation values. Real identifiers in a verification
# script eventually get copied into something that dials them.
DOC_SERIAL_PREFIX = "DOC-M2-VERIFY"
MEM_16 = 17179869184
MEM_24 = 25769803776


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

    def expect(self, condition: bool, message: str, remedy: str | None = None) -> bool:
        if condition:
            self.ok(message)
        else:
            self.bad(message, remedy)
        return condition


def _memory_fact(value: int, source_id: str) -> dict[str, Any]:
    return {
        "predicate": "memory.total_bytes",
        "value_type": "NUMBER",
        "value_number": value,
        "source_type": "LIVE_DISCOVERY",
        "source_id": source_id,
    }


async def verify(
    base_url: str, operator_key: str | None, approver_key: str | None
) -> int:
    check = Checker()
    base_url = base_url.rstrip("/")
    run = uuid.uuid4().hex[:8]

    if not operator_key or not approver_key:
        print(
            f"{FAIL} Both --operator-key and --approver-key are required.\n"
            "        -> Milestone 2 separates asserting a fact from verifying one,\n"
            "           so the check needs two principals to prove the separation."
        )
        return 1

    operator = {"X-ACOP-API-Key": operator_key}
    approver = {"X-ACOP-API-Key": approver_key}

    async with httpx.AsyncClient(base_url=base_url, timeout=30.0) as client:
        # 0. Reachability ---------------------------------------------------
        try:
            live = await client.get("/health/live")
        except httpx.HTTPError as exc:
            check.bad(
                f"API unreachable at {base_url}: {type(exc).__name__}",
                "Start the stack with `make up`, then `make logs`.",
            )
            return 1
        if live.status_code != 200:
            check.bad(f"Liveness probe returned HTTP {live.status_code}.")
            return 1
        check.ok(f"API is live at {base_url}.")

        # 1. Required REST contract present -----------------------------------
        schema = await client.get("/openapi.json")
        paths = schema.json().get("paths", {})
        registered = {
            (method.upper(), path)
            for path, operations in paths.items()
            for method in operations
        }
        missing = sorted(REQUIRED_ROUTES - registered)
        check.expect(
            not missing,
            f"All {len(REQUIRED_ROUTES)} required Milestone 2 operations are registered.",
            (
                "Missing: "
                + ", ".join(f"{m} {p}" for m, p in missing)
                + ". These are route registrations, not schema objects - check "
                "src/acop/api/router.py and the cmdb route modules. A database "
                "migration cannot create a FastAPI route."
            )
            if missing
            else None,
        )
        extra_cmdb = sorted(
            {(m, p) for m, p in registered if p.startswith("/cmdb")} - REQUIRED_ROUTES
        )
        if extra_cmdb:
            check.warn(
                "CMDB operations present but not in the Milestone 2 contract: "
                + ", ".join(f"{m} {p}" for m, p in extra_cmdb)
                + ". Scope creep, or the contract needs updating deliberately."
            )
        check.expect(
            all("delete" not in ops for ops in paths.values()),
            "No DELETE verb exists anywhere in the API.",
        )

        # 2. Identity resolution is idempotent -------------------------------
        serial_a = f"{DOC_SERIAL_PREFIX}-{run}-A"
        create_body = {
            "asset_type": "VM",
            "display_name": f"acop-verify-{run}-a",
            "identifiers": [{"namespace": "serial", "value": serial_a}],
        }
        first = await client.post("/cmdb/assets", headers=operator, json=create_body)
        if first.status_code != 201:
            check.bad(
                f"Asset creation returned HTTP {first.status_code}: {first.text[:200]}",
                "Check the operator key has the 'operator' or 'admin' role.",
            )
            return 1
        asset_id = first.json()["id"]
        check.ok(f"Asset created and resolvable by identifier ({serial_a}).")

        again = await client.post("/cmdb/assets", headers=operator, json=create_body)
        check.expect(
            again.status_code == 200 and again.json()["id"] == asset_id,
            "Re-creating with the same identifier matched the existing asset "
            "instead of duplicating it.",
            "Identity resolution is not idempotent - see ADR-0006.",
        )

        # 3. Ambiguity is refused, not guessed --------------------------------
        serial_b = f"{DOC_SERIAL_PREFIX}-{run}-B"
        second = await client.post(
            "/cmdb/assets",
            headers=operator,
            json={
                "asset_type": "VM",
                "display_name": f"acop-verify-{run}-b",
                "identifiers": [{"namespace": "serial", "value": serial_b}],
            },
        )
        second_id = second.json()["id"] if second.status_code == 201 else None
        clash = await client.post(
            "/cmdb/assets/resolve",
            headers=operator,
            json={
                "asset_type": "VM",
                "display_name": f"acop-verify-{run}-merged",
                "identifiers": [
                    {"namespace": "serial", "value": serial_a},
                    {"namespace": "serial", "value": serial_b},
                ],
            },
        )
        check.expect(
            clash.status_code == 409,
            "Identifiers matching two assets are refused with 409 rather than merged.",
            "This is the unrecoverable failure ADR-0006 exists to prevent.",
        )

        # 4. Caller cannot assert its own trust -------------------------------
        smuggled = await client.post(
            f"/cmdb/assets/{asset_id}/facts",
            headers=operator,
            json={**_memory_fact(MEM_16, "verify:a"), "verification_status": "VERIFIED"},
        )
        check.expect(
            smuggled.status_code == 422,
            "A caller-supplied verification_status is rejected at the boundary.",
            "Trust must be derived from the source, never accepted as input.",
        )

        # 5. Assert, touch, supersede -----------------------------------------
        created = await client.post(
            f"/cmdb/assets/{asset_id}/facts",
            headers=operator,
            json=_memory_fact(MEM_16, "verify:a"),
        )
        if created.status_code != 201:
            check.bad(f"Fact assertion returned HTTP {created.status_code}.")
            return 1
        fact_id = created.json()["fact"]["id"]
        check.ok("Fact asserted (201 CREATED).")

        touched = await client.post(
            f"/cmdb/assets/{asset_id}/facts",
            headers=operator,
            json=_memory_fact(MEM_16, "verify:a"),
        )
        check.expect(
            touched.status_code == 200 and touched.json()["outcome"] == "TOUCHED",
            "An unchanged re-assertion returns TOUCHED and writes no history row.",
            "Without this a five-minute sweep floods the fact table.",
        )

        superseded = await client.post(
            f"/cmdb/assets/{asset_id}/facts",
            headers=operator,
            json=_memory_fact(MEM_24, "verify:a"),
        )
        check.expect(
            superseded.status_code == 201
            and superseded.json()["outcome"] == "SUPERSEDED"
            and superseded.json()["superseded_fact_id"] == fact_id,
            "A changed value supersedes the previous claim and points back at it.",
        )
        new_fact_id = superseded.json()["fact"]["id"]

        history = await client.get(
            f"/cmdb/assets/{asset_id}/facts/memory.total_bytes/history",
            headers=operator,
        )
        intervals = history.json().get("intervals", [])
        check.expect(
            len(intervals) == 2 and sum(1 for i in intervals if i["valid_to"]) == 1,
            f"History holds both intervals, exactly one of them closed "
            f"(saw {len(intervals)}).",
        )

        # 6. Separation of duties ----------------------------------------------
        self_verify = await client.post(
            f"/cmdb/facts/{new_fact_id}/verify", headers=operator, json={}
        )
        check.expect(
            self_verify.status_code == 403,
            "An operator cannot verify its own assertion (403).",
            "Separation of duties - NIST PR.AC-4. If this key holds the 'admin' "
            "role it legitimately passes both checks; supply an operator-only "
            "key to prove the separation.",
        )

        verified = await client.post(
            f"/cmdb/facts/{new_fact_id}/verify",
            headers=approver,
            json={"reason": "Milestone 2 acceptance check."},
        )
        check.expect(
            verified.status_code == 200
            and verified.json()["verification_status"] == "VERIFIED",
            "An approver can verify, and the value is unchanged by verification.",
        )
        check.expect(
            verified.status_code == 200 and verified.json()["value_number"] == MEM_24,
            "Verification changed trust only - the value is untouched.",
        )

        # 7. Revocation preserves the trail -------------------------------------
        revoked = await client.post(
            f"/cmdb/facts/{new_fact_id}/revoke",
            headers=approver,
            json={"reason": "Acceptance check - withdrawing test verification."},
        )
        check.expect(
            revoked.status_code == 200,
            "Verification is reversible (revoke returned 200).",
        )
        attestations = await client.get(
            f"/cmdb/facts/{new_fact_id}/attestations", headers=operator
        )
        actions = [row["action"] for row in attestations.json()]
        check.expect(
            "VERIFY" in actions and "REVOKE" in actions,
            f"Both the verification and its revocation survive as attestations "
            f"({actions}).",
            "Revocation must not erase historical accountability.",
        )
        subjects = {row.get(ATTESTATION_SUBJECT_FIELD) for row in attestations.json()}
        check.expect(
            bool(subjects) and all(subjects),
            f"Every attestation names the acting principal ({sorted(subjects)}).",
            f"Attestations must carry {ATTESTATION_SUBJECT_FIELD!r}, the "
            "provider-neutral Principal field used everywhere else.",
        )

        # 8. Secrets are refused, and never echoed -------------------------------
        secret = await client.post(
            f"/cmdb/assets/{asset_id}/facts",
            headers=operator,
            json={
                "predicate": "snmp.community",
                "value_type": "TEXT",
                "value_text": "acceptance-check-placeholder",
                "source_type": "LIVE_DISCOVERY",
                "source_id": "verify:a",
            },
        )
        check.expect(
            secret.status_code == 422,
            "A secret-bearing predicate is rejected (422).",
        )
        check.expect(
            "acceptance-check-placeholder" not in secret.text,
            "The rejected value is not echoed back to the caller.",
        )

        # 9. Relationships read correctly in both directions ----------------------
        if second_id:
            edge = await client.post(
                "/cmdb/relationships",
                headers=operator,
                json={
                    "relationship_type": "RUNS_ON",
                    "source_asset_id": asset_id,
                    "target_asset_id": second_id,
                    "source_type": "LIVE_DISCOVERY",
                    "source_id": "verify:a",
                },
            )
            if edge.status_code in (200, 201):
                forward = await client.get(
                    f"/cmdb/assets/{asset_id}/related", headers=operator
                )
                reverse = await client.get(
                    f"/cmdb/assets/{second_id}/related", headers=operator
                )
                # The endpoint returns NeighbourList - {asset_id, neighbours} -
                # not a bare array. Reading it as a list was the same class of
                # mistake as the attestation field name: the verifier assumed a
                # response shape instead of following the response model.
                forward_labels = {
                    n["label"] for n in forward.json().get("neighbours", [])
                }
                reverse_labels = {
                    n["label"] for n in reverse.json().get("neighbours", [])
                }
                check.expect(
                    "RUNS_ON" in forward_labels and "HOSTS" in reverse_labels,
                    f"One stored edge reads as RUNS_ON forward and HOSTS in reverse "
                    f"({sorted(forward_labels)} / {sorted(reverse_labels)}).",
                )
            else:
                check.warn(
                    f"Relationship creation returned HTTP {edge.status_code}; "
                    "the endpoint-type rules may not permit VM RUNS_ON VM."
                )

        # 10. Conflicting sources are reported, not resolved ----------------------
        await client.post(
            f"/cmdb/assets/{asset_id}/facts",
            headers=operator,
            json=_memory_fact(MEM_16, "verify:b"),
        )
        conflicts = await client.get(
            f"/cmdb/assets/{asset_id}/conflicts", headers=operator
        )
        predicates = {c["predicate"] for c in conflicts.json()}
        check.expect(
            "memory.total_bytes" in predicates,
            "Disagreeing sources are reported as a conflict rather than silently "
            "resolved.",
        )
        effective = await client.get(
            f"/cmdb/assets/{asset_id}/facts/memory.total_bytes/effective",
            headers=operator,
        )
        check.expect(
            effective.json().get("basis") == "UNRESOLVED",
            "The effective value reports UNRESOLVED instead of inventing a winner.",
            "Conflict resolution is Milestone 8 - see ADR-0007.",
        )

        # 11. Retirement preserves history -----------------------------------------
        retired = await client.post(f"/cmdb/assets/{asset_id}/retire", headers=operator)
        check.expect(
            retired.status_code == 200 and retired.json()["lifecycle_state"] == "RETIRED",
            "Retirement is a POST and returns the retired asset.",
        )
        after = await client.get(
            f"/cmdb/assets/{asset_id}/facts/memory.total_bytes/history",
            headers=operator,
        )
        check.expect(
            len(after.json().get("intervals", [])) >= 2,
            "Retiring the asset closed its claims without deleting history.",
        )
        gone = await client.delete(f"/cmdb/assets/{asset_id}")
        check.expect(
            gone.status_code == 405,
            "DELETE on an asset is not allowed (405) - nothing is destructive.",
        )

        if second_id:
            await client.post(f"/cmdb/assets/{second_id}/retire", headers=operator)

    print()
    if check.failures:
        print(
            f"{FAIL} Milestone 2 NOT met: {check.failures} failure(s), "
            f"{check.warnings} warning(s)."
        )
        return 1
    print(f"{PASS} Milestone 2 acceptance criteria met ({check.warnings} warning(s)).")
    print(f"        Test assets carry the prefix acop-verify-{run} and are retired.")
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
    parser.add_argument(
        "--operator-key",
        default=os.getenv("ACOP_VERIFY_OPERATOR_KEY", os.getenv("ACOP_VERIFY_API_KEY")),
        help="API key for a principal holding the operator (or admin) role.",
    )
    parser.add_argument(
        "--approver-key",
        default=os.getenv("ACOP_VERIFY_APPROVER_KEY"),
        help="API key for a principal holding the approver (or admin) role.",
    )
    args = parser.parse_args()
    return asyncio.run(verify(args.base_url, args.operator_key, args.approver_key))


if __name__ == "__main__":
    raise SystemExit(main())
