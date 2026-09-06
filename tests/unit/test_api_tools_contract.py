"""The Milestone 4 HTTP contract, pinned so it cannot drift.

Most of what this milestone promises about its API is a property of the
*schema*, and that is the strongest place for it: a schema guarantee does not
depend on anyone remembering a check. There is no field a caller could use to
declare its own permission class, no field that could carry a command, no field
that could assert an exemption from separation of duties, and no DELETE for an
accident to hit.

These are asserted against the generated OpenAPI document, because that is the
thing an outside caller - or a future model integration - actually sees.
"""

from __future__ import annotations

import httpx

from acop.models.tool_vocabulary import (
    FORBIDDEN_APPROVAL_FIELDS,
    FORBIDDEN_INVOCATION_FIELDS,
)
from acop.schemas.tools import (
    ApprovalDecisionRequest,
    InvocationCreate,
    TargetSpec,
    ToolAdminView,
    ToolDescriptor,
)

#: Every operation the milestone declares. Sixteen, and the count is asserted:
#: an endpoint added without a design change should fail this test.
REQUIRED_ROUTES = {
    ("GET", "/tools"),
    ("GET", "/tools/{tool_name}"),
    ("GET", "/tools/{tool_name}/versions"),
    ("POST", "/tools/{tool_name}/disable"),
    ("POST", "/tools/{tool_name}/enable"),
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


async def _schema(client: httpx.AsyncClient) -> dict:
    return (await client.get("/openapi.json")).json()


class TestRouteContract:
    async def test_the_api_matches_the_contract_in_both_directions(
        self, client: httpx.AsyncClient
    ) -> None:
        schema = await _schema(client)
        registered = {
            (method.upper(), path)
            for path, operations in schema["paths"].items()
            for method in operations
            if path.startswith("/tool")
        }
        assert not REQUIRED_ROUTES - registered, "the API lacks required routes"
        assert not registered - REQUIRED_ROUTES, "the API exposes undeclared routes"

    def test_there_are_exactly_sixteen(self) -> None:
        assert len(REQUIRED_ROUTES) == 16

    async def test_no_delete_anywhere(self, client: httpx.AsyncClient) -> None:
        """Cancellation is a POST that leaves the record.

        Deleting an invocation would strand its approvals and its transition
        history, turning an auditable execution into an unexplained gap. The
        verb simply does not exist, so an accidental DELETE has nothing to hit.
        """
        schema = await _schema(client)
        for path, operations in schema["paths"].items():
            if path.startswith("/tool"):
                assert "delete" not in operations, path

    async def test_there_is_no_execute_endpoint(self, client: httpx.AsyncClient) -> None:
        """One entry point, and no per-class shortcut.

        A second way to run something is a second place for a gate to be
        missing.
        """
        schema = await _schema(client)
        for path in schema["paths"]:
            assert not path.endswith(("/execute", "/run", "/command"))


class TestNoRequestFieldCanWeakenPolicy:
    async def test_no_forbidden_field_appears_in_any_request_schema(
        self, client: httpx.AsyncClient
    ) -> None:
        """The complete list, checked against the published contract.

        A caller that could send ``approval_required: false`` or
        ``skip_validation: true`` would be setting its own policy. There is
        nowhere to put them.
        """
        schema = await _schema(client)
        by_model = {
            "InvocationCreate": FORBIDDEN_INVOCATION_FIELDS,
            "TargetSpec": FORBIDDEN_INVOCATION_FIELDS,
            "CancelRequest": FORBIDDEN_INVOCATION_FIELDS,
            "ReconcileRequest": FORBIDDEN_INVOCATION_FIELDS,
            "ToolLifecycleRequest": FORBIDDEN_INVOCATION_FIELDS,
            # An approval states the digest it reviewed, so the envelope names
            # are permitted here and only here. Everything that would let an
            # approver rewrite the policy it is measured against is not.
            "ApprovalDecisionRequest": FORBIDDEN_APPROVAL_FIELDS,
        }
        for name, model in schema.get("components", {}).get("schemas", {}).items():
            forbidden = by_model.get(name)
            if forbidden is None:
                continue
            for field in model.get("properties", {}):
                assert field not in forbidden, f"{name}.{field}"

    def test_an_invocation_cannot_name_its_own_class_or_policy(self) -> None:
        forbidden = {
            "permission_class",
            "approval_required",
            "validation_required",
            "min_approvals",
            "required_roles",
            "prohibited",
            "timeout_seconds",
            "skip_validation",
            "force",
            "adapter_id",
        }
        assert forbidden.isdisjoint(InvocationCreate.model_fields)

    def test_an_invocation_cannot_express_a_command(self) -> None:
        """The structural half of "no generic execution surface".

        An injected instruction that a model faithfully obeyed would have
        nowhere to put the result.
        """
        forbidden = {"command", "script", "shell", "sql", "raw", "exec", "cmd"}
        assert forbidden.isdisjoint(InvocationCreate.model_fields)

    def test_a_target_cannot_be_a_network_address(self) -> None:
        """No SSRF surface, by construction.

        Real addresses are resolved inside the adapter from the asset's
        registered identifiers. A caller has no way to name a destination.
        """
        forbidden = {"host", "hostname", "ip", "address", "url", "endpoint", "uri"}
        assert forbidden.isdisjoint(TargetSpec.model_fields)

    def test_an_approver_cannot_assert_self_approval(self) -> None:
        """Layer 1 of three.

        ``self_approval`` is derived server-side from configuration, the tool's
        policy, and whether the approver is the requester. A caller that could
        assert it would be asserting its own exemption from separation of
        duties.
        """
        assert "self_approval" not in ApprovalDecisionRequest.model_fields
        assert "envelope_digest" in ApprovalDecisionRequest.model_fields

    def test_tool_version_is_required(self) -> None:
        """No implicit "latest".

        An approval binds to a version; resolving "latest" at request time
        would let a deploy silently change which code a queued approval refers
        to.
        """
        assert InvocationCreate.model_fields["tool_version"].is_required()

    async def test_every_request_model_forbids_extra_fields(
        self, client: httpx.AsyncClient
    ) -> None:
        schema = await _schema(client)
        for name in (
            "InvocationCreate",
            "TargetSpec",
            "ApprovalDecisionRequest",
            "ReconcileRequest",
        ):
            model = schema["components"]["schemas"][name]
            assert model.get("additionalProperties") is False, name


class TestNoResponseDisclosesAnAdapter:
    def test_no_descriptor_names_an_adapter(self) -> None:
        """Knowing which adapter backs a tool tells an attacker where to aim.

        Absent from the admin view too: an admin who needs it can read the
        catalog source, which is the reviewable place for it to be.
        """
        assert "adapter_id" not in ToolDescriptor.model_fields
        assert "adapter_id" not in ToolAdminView.model_fields

    async def test_no_response_schema_mentions_an_adapter_or_a_credential(
        self, client: httpx.AsyncClient
    ) -> None:
        schema = await _schema(client)
        banned = ("adapter", "credential", "password", "secret", "private_key")
        for name, model in schema.get("components", {}).get("schemas", {}).items():
            if not name.startswith(("Tool", "Invocation", "Approval", "Envelope")):
                continue
            for field in model.get("properties", {}):
                assert not any(bad in field.lower() for bad in banned), f"{name}.{field}"
