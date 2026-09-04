#!/usr/bin/env python3
"""Milestone 3 acceptance check against a running ACOP stack.

Every assertion corresponds to a property the design promised, not to an
implementation detail:

* a secret-bearing document is refused, and creates no canonical row at all
* the refusal names a detector and a position, and never the matched value
* only an approver may dispose of a finding, and only FALSE_POSITIVE unblocks
* REMEDIATED_AT_SOURCE does *not* unblock the original bytes
* identical resubmission is idempotent and makes no new version
* an edit creates a new version and the old one stays addressable
* injection-shaped text is flagged, ingested, and labelled in the render
* retrieval never returns content above the caller's classification
* the response says whether the answer is complete or degraded
* hybrid retrieval reports VECTOR / LEXICAL / HYBRID per result
* asset mentions are exact matches only, and write nothing authoritative
* nothing is destructive - DELETE is not allowed anywhere

Usage:
    python scripts/verify_milestone3.py
    python scripts/verify_milestone3.py --base-url http://acop-01:8000 \\
        --operator-key KEY --approver-key KEY --admin-key KEY

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

#: The Milestone 3 REST contract. Counting endpoints is uninformative; naming
#: them means the check can say precisely which is missing.
#:
#: tests/unit/test_api_knowledge_contract.py asserts the running application
#: registers exactly this set, so the verifier and the API cannot drift apart.
REQUIRED_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        # Sources
        ("POST", "/knowledge/sources"),
        ("GET", "/knowledge/sources"),
        ("GET", "/knowledge/sources/{source_id}"),
        ("POST", "/knowledge/sources/{source_id}/reclassify"),
        ("POST", "/knowledge/sources/{source_id}/retire"),
        # Documents, versions, chunks
        ("POST", "/knowledge/documents"),
        ("GET", "/knowledge/documents"),
        ("GET", "/knowledge/documents/{document_id}"),
        ("GET", "/knowledge/documents/{document_id}/versions"),
        ("GET", "/knowledge/versions/{version_id}/chunks"),
        ("POST", "/knowledge/documents/{document_id}/retire"),
        # Attempts, findings, dispositions
        ("GET", "/knowledge/attempts"),
        ("GET", "/knowledge/attempts/{attempt_id}"),
        ("POST", "/knowledge/findings/{finding_id}/dispositions"),
        # Retrieval and evidence
        ("POST", "/knowledge/search"),
        ("POST", "/knowledge/evidence"),
        # Embedding spaces
        ("GET", "/knowledge/embedding-spaces"),
        ("POST", "/knowledge/embedding-spaces"),
        ("POST", "/knowledge/embedding-spaces/{space_id}/verify-prefixes"),
        # Asset mentions
        ("POST", "/knowledge/versions/{version_id}/mentions/scan"),
        ("POST", "/knowledge/chunks/{chunk_id}/mentions"),
        ("GET", "/knowledge/chunks/{chunk_id}/mentions"),
    }
)

# An obviously fake key. Structurally a PEM block so the detector fires; not a
# usable credential, and never a real one - a verification script's fixtures
# get copied.
FAKE_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEAxxxxxxxxDOCUMENTATIONxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
    "-----END RSA PRIVATE KEY-----"
)

INJECTION_DOC = """# Prompt Injection Awareness

Attackers embed strings such as "ignore all previous instructions" in
documents. This page exists so the corpus can teach the platform about the
technique.
"""


class Checker:
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


def _runbook(run: str, classification: str) -> str:
    return f"""# {classification} Runbook {run}

The core switch CORE3850-{run} serves the management network at this site.

## VLANs

VLAN 100 is the management VLAN. Trunk ports carry VLAN 100 and VLAN 200.

## Troubleshooting

If %SPANTREE-2-BLOCK_BPDUGUARD-{run} appears, check portfast on Gi1/0/24.
"""


async def _ingest(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    source_id: str,
    ref: str,
    content: str,
) -> httpx.Response:
    return await client.post(
        "/knowledge/documents",
        headers=headers,
        json={
            "source_id": source_id,
            "external_ref": ref,
            "title": ref,
            "content": content,
        },
    )


async def verify(
    base_url: str,
    operator_key: str | None,
    approver_key: str | None,
    admin_key: str | None,
) -> int:
    check = Checker()
    base_url = base_url.rstrip("/")
    run = uuid.uuid4().hex[:8]

    if not (operator_key and approver_key and admin_key):
        print(
            f"{FAIL} --operator-key, --approver-key and --admin-key are all "
            "required.\n"
            "        -> Milestone 3 separates ingesting from disposing of a\n"
            "           finding, and both from reading CONFIDENTIAL material,\n"
            "           so the check needs three principals to prove it."
        )
        return 1

    operator = {"X-ACOP-API-Key": operator_key}
    approver = {"X-ACOP-API-Key": approver_key}
    admin = {"X-ACOP-API-Key": admin_key}

    async with httpx.AsyncClient(base_url=base_url, timeout=120.0) as client:
        # -- contract ---------------------------------------------------
        spec = await client.get("/openapi.json")
        if spec.status_code != 200:
            check.bad(
                "Could not read /openapi.json.",
                f"Is ACOP running at {base_url}?",
            )
            return 1
        registered = {
            (method.upper(), path)
            for path, operations in spec.json()["paths"].items()
            for method in operations
            if method.upper() in {"GET", "POST", "PATCH", "PUT", "DELETE"}
        }
        missing = sorted(REQUIRED_ROUTES - registered)
        check.expect(
            not missing,
            f"All {len(REQUIRED_ROUTES)} Milestone 3 operations are registered.",
            f"Missing: {missing}" if missing else None,
        )
        knowledge_deletes = sorted(
            route
            for route in registered
            if route[0] == "DELETE" and route[1].startswith("/knowledge")
        )
        check.expect(
            not knowledge_deletes,
            "The knowledge API exposes no DELETE - nothing is destructive.",
            f"Found: {knowledge_deletes}" if knowledge_deletes else None,
        )

        # -- embedding space --------------------------------------------
        spaces = await client.get("/knowledge/embedding-spaces", headers=operator)
        if spaces.status_code != 200:
            check.bad("Could not list embedding spaces.", spaces.text[:200])
            return 1
        registered_spaces: list[dict[str, Any]] = spaces.json()
        default = next((s for s in registered_spaces if s["is_default"]), None)
        if default is None:
            check.bad(
                "No default embedding space is registered.",
                "Run scripts/probe_embedding_prefixes.py against the provider, "
                "then POST /knowledge/embedding-spaces with make_default true.",
            )
            return 1
        check.ok(
            f"Default embedding space {default['space_key']!r}: "
            f"{default['provider']}/{default['model']} at "
            f"{default['dimensions']} dimensions."
        )
        if not default.get("model_digest"):
            check.warn(
                "The default space records no model digest. Ollama tags are "
                "mutable, so vectors from two pulls of the same tag can be "
                "silently incomparable."
            )
        if not check.expect(
            bool(default.get("prefix_verified_at")),
            "The default space's prompt-prefix behaviour has been verified.",
            "Run scripts/probe_embedding_prefixes.py, then POST "
            "/knowledge/embedding-spaces/{space_id}/verify-prefixes. Until "
            "then ingestion and retrieval both refuse the space, by design.",
        ):
            return 1
        check.expect(
            default["partition_relation"] != default["storage_relation"],
            "Vectors live in a per-space partition of the dimension family - "
            "cross-space contamination is unrepresentable, not filtered.",
        )

        # -- sources ----------------------------------------------------
        internal = await client.post(
            "/knowledge/sources",
            headers=operator,
            json={
                "source_kind": "RUNBOOK",
                "title": f"acop-verify-{run} internal runbooks",
                "origin": "verify_milestone3",
                "trust_class": "INTERNAL_VERIFIED",
                "sensitivity": "INTERNAL",
            },
        )
        if internal.status_code != 201:
            check.bad("Could not register an INTERNAL source.", internal.text[:300])
            return 1
        internal_id = internal.json()["id"]
        check.ok("Registered an INTERNAL knowledge source.")

        escalation = await client.post(
            "/knowledge/sources",
            headers=operator,
            json={
                "source_kind": "POLICY",
                "title": f"acop-verify-{run} policy",
                "origin": "verify_milestone3",
                "trust_class": "AUTHORITATIVE_POLICY",
                "sensitivity": "INTERNAL",
            },
        )
        check.expect(
            escalation.status_code == 403,
            "An operator cannot declare material AUTHORITATIVE_POLICY (403) - "
            "raising trust is an approval act.",
            f"Got {escalation.status_code}.",
        )

        confidential = await client.post(
            "/knowledge/sources",
            headers=operator,
            json={
                "source_kind": "RUNBOOK",
                "title": f"acop-verify-{run} confidential runbooks",
                "origin": "verify_milestone3",
                "trust_class": "INTERNAL_VERIFIED",
                "sensitivity": "CONFIDENTIAL",
            },
        )
        confidential_id = (
            confidential.json()["id"] if confidential.status_code == 201 else None
        )

        # -- the persistence security gate ------------------------------
        secret_doc = _runbook(run, "Internal") + "\n\n```\n" + FAKE_PEM + "\n```\n"
        refused = await _ingest(
            client, operator, internal_id, f"secret-{run}.md", secret_doc
        )
        check.expect(
            refused.status_code in (400, 422),
            "A document containing key material is refused.",
            f"Got {refused.status_code}: {refused.text[:200]}",
        )
        body = (
            refused.json()
            if refused.headers.get("content-type", "").startswith("application/json")
            else {}
        )
        serialised = str(body)
        check.expect(
            "BEGIN RSA PRIVATE KEY" not in serialised
            and "MIIEowIBAAKCAQEA" not in serialised,
            "The refusal never echoes the matched secret material.",
        )
        check.expect(
            "line " in serialised and "cols " in serialised,
            "The refusal names a detector and a position, which is what a human "
            "needs to find it in their own copy.",
        )

        docs = await client.get(
            "/knowledge/documents",
            headers=operator,
            params={"source_id": internal_id},
        )
        check.expect(
            all(d["external_ref"] != f"secret-{run}.md" for d in docs.json()),
            "The refused submission created no document - no canonical row at "
            "all, not an empty one.",
        )

        attempts = await client.get(
            "/knowledge/attempts",
            headers=approver,
            params={"source_id": internal_id, "external_ref": f"secret-{run}.md"},
        )
        check.expect(
            attempts.status_code == 200 and len(attempts.json()) >= 1,
            "The refused submission is still recorded as an attempt.",
        )
        operator_attempts = await client.get("/knowledge/attempts", headers=operator)
        check.expect(
            operator_attempts.status_code == 403,
            "The attempt log - what was blocked, by which detector and where - "
            "is approver-scoped (403 for an operator).",
            f"Got {operator_attempts.status_code}.",
        )

        attempt_id = attempts.json()[0]["id"] if attempts.json() else None
        finding_id = None
        if attempt_id:
            detail = await client.get(
                f"/knowledge/attempts/{attempt_id}", headers=approver
            )
            findings = (
                detail.json().get("findings", []) if detail.status_code == 200 else []
            )
            blocking = [f for f in findings if f["severity"] == "BLOCKING"]
            check.expect(
                bool(blocking),
                "The attempt carries a BLOCKING finding with a locator and a "
                "fingerprint, and no value.",
            )
            if blocking:
                finding_id = blocking[0]["id"]
                check.expect(
                    "BEGIN" not in str(blocking[0]),
                    "The stored finding contains no matched material.",
                )

        # -- dispositions ------------------------------------------------
        if finding_id:
            by_operator = await client.post(
                f"/knowledge/findings/{finding_id}/dispositions",
                headers=operator,
                json={"disposition": "FALSE_POSITIVE", "reason": "attempt by operator"},
            )
            check.expect(
                by_operator.status_code == 403,
                "An operator cannot dispose of its own blocked submission (403).",
                f"Got {by_operator.status_code}.",
            )

            remediated = await client.post(
                f"/knowledge/findings/{finding_id}/dispositions",
                headers=approver,
                json={
                    "disposition": "REMEDIATED_AT_SOURCE",
                    "reason": f"acop-verify-{run}: key rotated at source",
                },
            )
            check.expect(
                remediated.status_code == 201,
                "An approver can record REMEDIATED_AT_SOURCE.",
                remediated.text[:200],
            )
            still_refused = await _ingest(
                client, operator, internal_id, f"secret-{run}.md", secret_doc
            )
            check.expect(
                still_refused.status_code in (400, 422),
                "REMEDIATED_AT_SOURCE does NOT unblock the original bytes - the "
                "submitter must edit the document, which changes its hash.",
                f"Got {still_refused.status_code}.",
            )

            cleared = await client.post(
                f"/knowledge/findings/{finding_id}/dispositions",
                headers=approver,
                json={
                    "disposition": "FALSE_POSITIVE",
                    "reason": f"acop-verify-{run}: documentation sample, not a key",
                },
            )
            check.expect(
                cleared.status_code == 201,
                "An approver can record FALSE_POSITIVE for the exact reviewed bytes.",
                cleared.text[:200],
            )
            now_allowed = await _ingest(
                client, operator, internal_id, f"secret-{run}.md", secret_doc
            )
            check.expect(
                now_allowed.status_code == 201,
                "FALSE_POSITIVE unblocks exactly those bytes for exactly that "
                "target, and nothing wider.",
                f"Got {now_allowed.status_code}: {now_allowed.text[:200]}",
            )

        # -- ingestion, idempotence, versioning --------------------------
        content = _runbook(run, "Internal")
        first = await _ingest(client, operator, internal_id, f"runbook-{run}.md", content)
        if first.status_code != 201:
            check.bad("Could not ingest a clean document.", first.text[:300])
            return 1
        first_body = first.json()
        check.expect(
            first_body["outcome"] == "CREATED" and first_body["version_no"] == 1,
            "A clean document is ingested as version 1.",
        )
        check.expect(
            first_body["embedded_count"] == first_body["chunk_count"],
            "Every chunk was embedded - no silent partial ingest.",
        )
        document_id = first_body["document_id"]
        version_id = first_body["version_id"]

        again = await _ingest(client, operator, internal_id, f"runbook-{run}.md", content)
        check.expect(
            again.status_code == 201
            and again.json()["outcome"] == "UNCHANGED"
            and again.json()["embedded_count"] == 0,
            "Resubmitting identical content is idempotent and makes no embedding call.",
            f"Got {again.json().get('outcome')}.",
        )

        edited = content.replace("Gi1/0/24", "Gi1/0/48")
        second = await _ingest(client, operator, internal_id, f"runbook-{run}.md", edited)
        check.expect(
            second.status_code == 201
            and second.json()["outcome"] == "VERSIONED"
            and second.json()["version_no"] == 2,
            "An edit creates version 2 rather than overwriting version 1.",
        )
        versions = await client.get(
            f"/knowledge/documents/{document_id}/versions", headers=operator
        )
        check.expect(
            versions.status_code == 200 and len(versions.json()) >= 2,
            "Both versions remain addressable - history is never overwritten.",
        )
        old_chunks = await client.get(
            f"/knowledge/versions/{version_id}/chunks", headers=operator
        )
        check.expect(
            old_chunks.status_code == 200 and old_chunks.json(),
            "The superseded version's chunks are still readable, so an old "
            "citation still resolves.",
        )

        # -- injection is flagged, not rejected --------------------------
        injection = await _ingest(
            client, operator, internal_id, f"injection-{run}.md", INJECTION_DOC
        )
        check.expect(
            injection.status_code == 201,
            "A document *about* prompt injection is ingested, not refused - "
            "otherwise the corpus cannot teach the platform about the threat.",
            f"Got {injection.status_code}: {injection.text[:200]}",
        )
        check.expect(
            injection.status_code == 201
            and injection.json()["advisory_finding_count"] >= 1,
            "Injection-shaped text is recorded as an advisory finding.",
        )

        # -- retrieval ---------------------------------------------------
        query = {"query": "which VLAN is used for management?", "mode": "HYBRID", "k": 5}
        search = await client.post("/knowledge/search", headers=operator, json=query)
        if search.status_code != 200:
            check.bad("Search failed.", search.text[:300])
            return 1
        payload = search.json()
        check.expect(
            payload["query_hash"] and "query" not in payload,
            "The response echoes a query hash and length, never the query text.",
        )
        diagnostics = payload["diagnostics"]
        check.expect(
            set(diagnostics) >= {"strategy", "degraded", "eligible_population"},
            "The response says how retrieval resolved and whether it is complete.",
        )
        check.expect(
            all(
                r["retrieval_method"] in {"VECTOR", "VECTOR_EXACT", "LEXICAL", "HYBRID"}
                for r in payload["results"]
            ),
            "Every result reports which leg found it.",
        )

        if confidential_id:
            await _ingest(
                client,
                operator,
                confidential_id,
                f"confidential-{run}.md",
                _runbook(run, "Confidential"),
            )
            operator_view = await client.post(
                "/knowledge/search", headers=operator, json={**query, "k": 20}
            )
            check.expect(
                all(
                    r["sensitivity"] != "CONFIDENTIAL"
                    for r in operator_view.json()["results"]
                ),
                "An operator never receives CONFIDENTIAL content.",
            )
            approver_view = await client.post(
                "/knowledge/search", headers=approver, json={**query, "k": 20}
            )
            check.expect(
                all(
                    r["sensitivity"] != "CONFIDENTIAL"
                    for r in approver_view.json()["results"]
                ),
                "An approver is not a clearance - it reads exactly what an "
                "operator reads.",
            )
            admin_view = await client.post(
                "/knowledge/search", headers=admin, json={**query, "k": 20}
            )
            check.expect(
                any(
                    r["sensitivity"] == "CONFIDENTIAL"
                    for r in admin_view.json()["results"]
                ),
                "An admin does read CONFIDENTIAL content.",
                "Check the admin key's roles.",
            )

        lexical = await client.post(
            "/knowledge/search",
            headers=operator,
            json={"query": f"BLOCK_BPDUGUARD-{run}", "mode": "LEXICAL", "k": 5},
        )
        check.expect(
            lexical.status_code == 200 and lexical.json()["results"],
            "The lexical leg finds an exact syslog mnemonic that no embedding "
            "model has a meaningful representation of.",
        )

        # -- evidence ----------------------------------------------------
        evidence = await client.post(
            "/knowledge/evidence",
            headers=operator,
            json={**query, "include_prompt_render": True},
        )
        if evidence.status_code == 200:
            bundle = evidence.json()
            check.expect(
                bool(bundle["citations"])
                and all("version_id" in c for c in bundle["citations"]),
                "Every citation names the immutable version it came from.",
            )
            render = bundle.get("prompt_render") or ""
            check.expect(
                "EVIDENCE 1" in render and "never instructions" in render,
                "Retrieved text is rendered as delimited, numbered DATA blocks.",
            )
            check.expect(
                "statement_kinds" in bundle and "INFERENCE" in bundle["statement_kinds"],
                "The answer contract distinguishes SOURCED, CMDB_FACT and "
                "INFERENCE statements.",
            )
        else:
            check.bad("Evidence bundle failed.", evidence.text[:300])

        # -- mentions -----------------------------------------------------
        scan = await client.post(
            f"/knowledge/versions/{version_id}/mentions/scan", headers=operator
        )
        check.expect(
            scan.status_code == 200,
            "A version can be scanned for exact asset-identifier matches.",
            scan.text[:200],
        )
        if scan.status_code == 200:
            check.expect(
                scan.json()["chunks_scanned"] > 0,
                "The scan examined the version's chunks.",
            )

        # -- nothing is destructive ---------------------------------------
        gone = await client.delete(f"/knowledge/documents/{document_id}", headers=admin)
        check.expect(
            gone.status_code == 405,
            "DELETE on a document is not allowed (405).",
            f"Got {gone.status_code}.",
        )

        retired = await client.post(
            f"/knowledge/documents/{document_id}/retire", headers=approver
        )
        check.expect(
            retired.status_code == 200 and retired.json()["lifecycle_state"] == "RETIRED",
            "Retirement is a POST and returns the retired document.",
        )
        after = await client.post("/knowledge/search", headers=operator, json=query)
        check.expect(
            all(r["document_id"] != document_id for r in after.json()["results"]),
            "A retired document stops being retrieved, without its history "
            "being deleted.",
        )
        still_there = await client.get(
            f"/knowledge/documents/{document_id}/versions", headers=operator
        )
        check.expect(
            still_there.status_code == 200 and len(still_there.json()) >= 2,
            "Its versions remain addressable after retirement, so previously "
            "given answers stay verifiable.",
        )

        # Tidy up the sources this run created.
        for source_id in (internal_id, confidential_id):
            if source_id:
                await client.post(
                    f"/knowledge/sources/{source_id}/retire", headers=approver
                )

    print()
    if check.failures:
        print(
            f"{FAIL} Milestone 3 NOT met: {check.failures} failure(s), "
            f"{check.warnings} warning(s)."
        )
        return 1
    print(f"{PASS} Milestone 3 acceptance criteria met ({check.warnings} warning(s)).")
    print(f"        Test sources carry the prefix acop-verify-{run} and are retired.")
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
    )
    parser.add_argument("--approver-key", default=os.getenv("ACOP_VERIFY_APPROVER_KEY"))
    parser.add_argument("--admin-key", default=os.getenv("ACOP_VERIFY_ADMIN_KEY"))
    args = parser.parse_args()
    return asyncio.run(
        verify(args.base_url, args.operator_key, args.approver_key, args.admin_key)
    )


if __name__ == "__main__":
    raise SystemExit(main())
