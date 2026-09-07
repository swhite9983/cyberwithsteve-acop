"""The Proxmox read-only transport and the ten tools bound to it.

The tests here run the **real** client, identity and projection code against a
scripted upstream. Only the socket is replaced, by ``httpx.MockTransport``, so
request construction, the ``Authorization`` header, status mapping, streaming and
its size cap, envelope parsing and every projection are all exercised. A stub
that returned parsed objects would prove none of that, and every one of those
steps is where a security property lives.

Three groups are doing structural rather than behavioural work, and they are the
important ones:

* :class:`TestNothingReachesAPathFromOutside` proves the negative space - a
  caller cannot name a node, a VMID, a path or a method, because there is
  nowhere in the schema to say one and no parameter in the client to carry one.
* :class:`TestTheSecretStaysInside` searches whole rendered exceptions and whole
  stored results for the token, on every failure path, because a leak that lands
  in an unexpected field is still a leak.
* :class:`TestProjectionsMatchTheirDeclarations` runs each projection over the
  fixtures and validates the result against the tool's own ``output_model``.
  Under ADR-0023 a drifted projection is a *failed invocation*, so this is the
  test that keeps a rename in ``proxmox_schemas.py`` from becoming a tool that
  fails only in production.
"""

from __future__ import annotations

import ast
import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest

from acop.config import Environment
from acop.models.provenance import PermissionClass
from acop.models.tool_vocabulary import (
    COMMAND_FIELDS,
    NETWORK_LOCATOR_FIELDS,
    SECRET_FIELD_FRAGMENTS,
    AdapterOutcome,
    TargetKind,
    ToolErrorCategory,
)
from acop.models.vocabulary import AssetType
from acop.tools.adapters.base import AdapterRequest, AdapterServices, ResolvedTarget
from acop.tools.adapters.proxmox import SUPPORTED_TOOLS, ProxmoxAdapter
from acop.tools.adapters.proxmox.client import MAX_RESPONSE_BYTES, ProxmoxClient
from acop.tools.adapters.proxmox.endpoints import TOOL_ENDPOINTS
from acop.tools.adapters.proxmox.errors import (
    ProxmoxAmbiguousObjectError,
    ProxmoxAuthenticationError,
    ProxmoxAuthorizationError,
    ProxmoxConnectionError,
    ProxmoxError,
    ProxmoxHTTPStatusError,
    ProxmoxIdentifierError,
    ProxmoxInstanceMismatchError,
    ProxmoxNotConfiguredError,
    ProxmoxObjectNotFoundError,
    ProxmoxProtocolError,
    ProxmoxTimeoutError,
)
from acop.tools.catalog import PROXMOX_TOOLS
from acop.tools.catalog.schemas import EmptyInput
from acop.tools.errors import AdapterUnavailableError
from acop.tools.registry import CODE_REGISTRY, get_definition
from tests.proxmox_fixtures import (
    CLUSTER_STATUS_CLUSTERED,
    CT_VMID,
    INSTANCE_ID,
    NODE,
    NODE_B,
    NODE_LIST_ONE_OFFLINE,
    NODE_LIST_TWO,
    STORAGE_LIST,
    TOKEN_ID,
    TOKEN_SECRET,
    VM_GENID,
    VM_NAME,
    VM_UUID,
    VM_VMID,
    ScriptedProxmox,
    envelope,
    proxmox_settings,
    standalone_instance,
)

APPROVED_TOOLS = {
    "proxmox.cluster.status",
    "proxmox.node.list",
    "proxmox.node.status",
    "proxmox.node.network",
    "proxmox.guest.list",
    "proxmox.vm.status",
    "proxmox.vm.config",
    "proxmox.container.status",
    "proxmox.container.config",
    "proxmox.storage.list",
}

CLIENT_SOURCE = Path("src/acop/tools/adapters/proxmox/client.py")

_CLUSTER_IDS = {"proxmox:instance": INSTANCE_ID}
_NODE_IDS = {"proxmox:node": f"{INSTANCE_ID}/{NODE}"}
_VM_IDS = {"proxmox:guest": f"{INSTANCE_ID}/{VM_VMID}"}
_CT_IDS = {"proxmox:guest": f"{INSTANCE_ID}/{CT_VMID}"}

#: Which identifier set and asset type each tool's target carries.
TARGETS: dict[str, tuple[dict[str, str], AssetType]] = {
    "proxmox.cluster.status": (_CLUSTER_IDS, AssetType.CLUSTER),
    "proxmox.node.list": (_CLUSTER_IDS, AssetType.CLUSTER),
    "proxmox.guest.list": (_CLUSTER_IDS, AssetType.CLUSTER),
    "proxmox.storage.list": (_CLUSTER_IDS, AssetType.CLUSTER),
    "proxmox.node.status": (_NODE_IDS, AssetType.HOST),
    "proxmox.node.network": (_NODE_IDS, AssetType.HOST),
    "proxmox.vm.status": (_VM_IDS, AssetType.VM),
    "proxmox.vm.config": (_VM_IDS, AssetType.VM),
    "proxmox.container.status": (_CT_IDS, AssetType.CONTAINER),
    "proxmox.container.config": (_CT_IDS, AssetType.CONTAINER),
}

#: The final endpoint each tool reads, after any resolution requests.
FINAL_PATHS: dict[str, str] = {
    "proxmox.cluster.status": "/api2/json/cluster/status",
    "proxmox.node.list": "/api2/json/nodes",
    "proxmox.node.status": f"/api2/json/nodes/{NODE}/status",
    "proxmox.node.network": f"/api2/json/nodes/{NODE}/network",
    "proxmox.guest.list": "/api2/json/cluster/resources",
    "proxmox.vm.status": f"/api2/json/nodes/{NODE}/qemu/{VM_VMID}/status/current",
    "proxmox.vm.config": f"/api2/json/nodes/{NODE}/qemu/{VM_VMID}/config",
    "proxmox.container.status": f"/api2/json/nodes/{NODE}/lxc/{CT_VMID}/status/current",
    "proxmox.container.config": f"/api2/json/nodes/{NODE}/lxc/{CT_VMID}/config",
    "proxmox.storage.list": f"/api2/json/nodes/{NODE}/storage",
}


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


def _adapter(scripted: ScriptedProxmox) -> ProxmoxAdapter:
    """An adapter whose transport is scripted but whose client is the real one."""
    return ProxmoxAdapter(
        client_factory=lambda settings: ProxmoxClient(
            settings, transport=scripted.transport()
        )
    )


def _request(
    tool_name: str,
    *,
    identifiers: dict[str, str] | None = None,
    asset_type: AssetType | None = None,
    timeout_seconds: float = 30.0,
    settings: Any = None,
) -> AdapterRequest:
    default_ids, default_type = TARGETS.get(tool_name, (_CLUSTER_IDS, AssetType.CLUSTER))
    return AdapterRequest(
        invocation_id=uuid.uuid4(),
        tool_name=tool_name,
        tool_version="1.0",
        target=ResolvedTarget(
            kind=TargetKind.ASSET,
            asset_id=uuid.uuid4(),
            display_name="docs-target",
            asset_type=(asset_type or default_type).value,
            identifiers=dict(identifiers if identifiers is not None else default_ids),
        ),
        payload={},
        timeout_seconds=timeout_seconds,
        services=AdapterServices(settings=settings or proxmox_settings()),
    )


async def _run(tool_name: str, scripted: ScriptedProxmox, **kwargs: Any) -> Any:
    return await _adapter(scripted).execute(_request(tool_name, **kwargs))


def _rendered(error: BaseException) -> str:
    """Every string an exception carries, for leak assertions."""
    parts = [str(error), repr(error), str(getattr(error, "context", ""))]
    internal = getattr(error, "internal_message", None)
    if internal:
        parts.append(str(internal))
    return " ".join(parts)


# ---------------------------------------------------------------------------
# The declared surface
# ---------------------------------------------------------------------------
class TestTheApprovedSurfaceIsExactlyTen:
    def test_ten_tools_are_registered_under_exactly_the_approved_names(self) -> None:
        declared = {
            name for name, _version in CODE_REGISTRY if name.startswith("proxmox.")
        }
        assert declared == APPROVED_TOOLS
        assert len(PROXMOX_TOOLS) == 10

    def test_the_adapter_implements_exactly_those_names(self) -> None:
        """Exact, not a superset. A supported name with no declaration would be
        an implemented capability nobody could review in the catalog."""
        assert SUPPORTED_TOOLS == APPROVED_TOOLS

    def test_every_approved_name_has_exactly_one_endpoint(self) -> None:
        assert set(TOOL_ENDPOINTS) == APPROVED_TOOLS

    @pytest.mark.parametrize("tool_name", sorted(APPROVED_TOOLS))
    def test_each_is_class_one_read_only_bound_to_the_proxmox_adapter(
        self, tool_name: str
    ) -> None:
        definition = get_definition(tool_name, "1.0")
        assert definition is not None
        assert definition.permission_class is PermissionClass.CLASS_1_READ_ONLY
        assert definition.adapter_id == "proxmox"
        assert definition.target_type is TargetKind.ASSET
        assert definition.approval_policy.approval_required is False
        assert definition.validation_required is False
        assert definition.prohibited is False
        assert definition.allow_registration_for_testing is False

    @pytest.mark.parametrize(
        ("tool_name", "expected"),
        [
            ("proxmox.cluster.status", AssetType.CLUSTER),
            ("proxmox.node.list", AssetType.CLUSTER),
            ("proxmox.guest.list", AssetType.CLUSTER),
            ("proxmox.storage.list", AssetType.CLUSTER),
            ("proxmox.node.status", AssetType.HOST),
            ("proxmox.node.network", AssetType.HOST),
            ("proxmox.vm.status", AssetType.VM),
            ("proxmox.vm.config", AssetType.VM),
            ("proxmox.container.status", AssetType.CONTAINER),
            ("proxmox.container.config", AssetType.CONTAINER),
        ],
    )
    def test_target_asset_types_are_the_ratified_ones(
        self, tool_name: str, expected: AssetType
    ) -> None:
        definition = get_definition(tool_name, "1.0")
        assert definition is not None
        assert definition.target_asset_types == frozenset({expected.value})

    def test_no_generic_api_tool_exists(self) -> None:
        """Not "not yet". An arbitrary-path read would undo rules 9, 10 and 11."""
        for name, _version in CODE_REGISTRY:
            assert "api" not in name.split(".")
            assert not name.endswith(".get")

    def test_no_proxmox_tool_declares_a_mutating_capability(self) -> None:
        forbidden = {
            "start",
            "stop",
            "reboot",
            "shutdown",
            "create",
            "delete",
            "migrate",
            "snapshot",
            "clone",
            "write",
            "set",
            "update",
        }
        for definition in PROXMOX_TOOLS:
            verb = definition.tool_name.rsplit(".", 1)[-1]
            assert verb not in forbidden


# ---------------------------------------------------------------------------
# Negative space: what a caller cannot say
# ---------------------------------------------------------------------------
class TestNothingReachesAPathFromOutside:
    @pytest.mark.parametrize("tool_name", sorted(APPROVED_TOOLS))
    def test_the_input_model_has_no_fields_at_all(self, tool_name: str) -> None:
        """Stronger than "no forbidden field names".

        Rules 9, 10 and 11 refuse a schema that *names* a locator, a secret or a
        command. A schema with no fields cannot name anything, so there is
        nothing for a caller to steer and nothing for a future edit to widen
        without it being visible in the declaration.
        """
        definition = get_definition(tool_name, "1.0")
        assert definition is not None
        assert definition.input_model is EmptyInput
        assert definition.input_model.model_fields == {}

    @pytest.mark.parametrize(
        "field_name",
        [
            "host",
            "hostname",
            "ip",
            "url",
            "endpoint",
            "port",
            "username",
            "password",
            "token",
            "secret",
            "credential",
            "authorization",
            "api_path",
            "path",
            "command",
            "shell",
            "ssh",
            "node",
            "vmid",
        ],
    )
    def test_supplying_any_locator_or_credential_is_rejected(
        self, field_name: str
    ) -> None:
        """``extra="forbid"`` turns an injected field into a rejection.

        Not a redaction downstream: the request never becomes an invocation, so
        there is no canonical input carrying it and nothing to sanitize.
        """
        with pytest.raises(ValueError, match=r"[Ee]xtra"):
            EmptyInput.model_validate({field_name: "anything"})

    def test_the_forbidden_name_lists_would_have_caught_a_wider_schema(self) -> None:
        """The rules are real, and this is what they would refuse.

        Asserted so that the "no fields at all" decision above is understood as
        belt *and* braces rather than as a reason the rules stopped mattering.
        """
        assert {"host", "hostname", "url", "endpoint"} <= NETWORK_LOCATOR_FIELDS
        assert {"command", "shell", "script"} <= COMMAND_FIELDS
        assert any(fragment in "api_token" for fragment in SECRET_FIELD_FRAGMENTS)

    def test_the_client_exposes_no_method_and_no_path_parameter(self) -> None:
        """No write method is reachable, made structural rather than reviewed.

        ``get_data`` takes an endpoint *key*, not a path, and there is no method
        argument anywhere. A future contributor cannot POST by passing a
        different value; they would have to change this file, visibly.
        """
        source = CLIENT_SOURCE.read_text(encoding="utf-8")
        tree = ast.parse(source)
        methods = {"POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
        literals = {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        assert not literals & methods
        assert '"GET"' in source

        get_data = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "get_data"
        )
        parameters = {arg.arg for arg in get_data.args.args} | {
            arg.arg for arg in get_data.args.kwonlyargs
        }
        assert parameters == {"self", "endpoint_key", "deadline"}
        assert get_data.args.kwarg is not None  # **segments, and only that

    @pytest.mark.parametrize("tool_name", sorted(APPROVED_TOOLS))
    async def test_every_request_a_tool_makes_is_a_get(self, tool_name: str) -> None:
        scripted = standalone_instance()
        await _run(tool_name, scripted)
        assert set(scripted.methods) == {"GET"}

    async def test_every_path_stays_under_the_api_root(self) -> None:
        scripted = standalone_instance()
        for tool_name in sorted(APPROVED_TOOLS):
            await _run(tool_name, scripted)
        assert all(path.startswith("/api2/json/") for path in scripted.paths)
        assert not any(".." in path for path in scripted.paths)

    def test_a_hostile_node_name_cannot_escape_the_template(self) -> None:
        """Defence in depth over a value that came from a response body.

        The only way a node name reaches a template is from Proxmox's own
        inventory. If that were ever compromised, the pattern refuses first and
        the percent-encoder would refuse second.
        """
        endpoint = TOOL_ENDPOINTS["proxmox.node.status"]
        for hostile in ("../../cluster/status", "a/b", "node?x=1", "", "a" * 100):
            with pytest.raises(ProxmoxProtocolError):
                endpoint.build(node=hostile)

    def test_a_hostile_vmid_cannot_escape_the_template(self) -> None:
        endpoint = TOOL_ENDPOINTS["proxmox.vm.config"]
        for hostile in ("1;2", "../200", "0", "-1", ""):
            with pytest.raises(ProxmoxProtocolError):
                endpoint.build(node=NODE, vmid=hostile)


# ---------------------------------------------------------------------------
# Endpoint mapping
# ---------------------------------------------------------------------------
class TestEndpointMapping:
    @pytest.mark.parametrize("tool_name", sorted(APPROVED_TOOLS))
    async def test_each_tool_reads_its_declared_endpoint(self, tool_name: str) -> None:
        scripted = standalone_instance()
        await _run(tool_name, scripted)
        assert scripted.paths[-1] == FINAL_PATHS[tool_name]

    async def test_guest_list_uses_the_unified_cluster_resource_endpoint(self) -> None:
        """Cluster-scoped and valid on a standalone node, so no node iteration."""
        scripted = standalone_instance()
        await _run("proxmox.guest.list", scripted)
        assert scripted.paths == ["/api2/json/cluster/resources"]
        assert scripted.requests[0].url.params["type"] == "vm"

    async def test_a_guest_read_resolves_its_node_before_reading(self) -> None:
        """Two requests, in this order, and the node comes from the first."""
        scripted = standalone_instance()
        await _run("proxmox.vm.status", scripted)
        assert scripted.paths == [
            "/api2/json/cluster/resources",
            f"/api2/json/nodes/{NODE}/qemu/{VM_VMID}/status/current",
        ]

    async def test_a_node_read_resolves_its_spelling_from_live_inventory(self) -> None:
        """The identifier selects the node; Proxmox supplies how it is spelled.

        ``AssetIdentifier.value_normalized`` case-folds, and Proxmox node names
        appear literally in API paths, so an identifier whose stored value is
        lower-case must not be pasted into a URL.
        """
        scripted = standalone_instance()
        await _run(
            "proxmox.node.status",
            scripted,
            identifiers={"proxmox:node": f"{INSTANCE_ID}/{NODE.upper()}"},
        )
        assert scripted.paths == ["/api2/json/nodes", f"/api2/json/nodes/{NODE}/status"]


# ---------------------------------------------------------------------------
# Credentials and configuration
# ---------------------------------------------------------------------------
class TestCredentialsAreOwnedByTheAdapter:
    async def test_the_token_header_is_built_internally(self) -> None:
        scripted = standalone_instance()
        await _run("proxmox.cluster.status", scripted)
        header = scripted.requests[0].headers["authorization"]
        assert header == f"PVEAPIToken={TOKEN_ID}={TOKEN_SECRET}"

    async def test_only_token_authentication_is_attempted(self) -> None:
        """No ticket flow: no cookie, no CSRF header, no login request.

        A ticket flow would mean ACOP holds a user password, obtains a session
        and renews it - three more secrets and a lifecycle, in exchange for
        nothing a token does not already give a read.
        """
        scripted = standalone_instance()
        await _run("proxmox.cluster.status", scripted)
        request = scripted.requests[0]
        assert "cookie" not in request.headers
        assert not [name for name in request.headers if "csrf" in name.lower()]
        assert "/access/ticket" not in " ".join(scripted.paths)

    def test_the_tls_setting_is_honoured(self) -> None:
        assert ProxmoxClient(proxmox_settings()).verify_tls is True
        assert (
            ProxmoxClient(proxmox_settings(proxmox_verify_tls=False)).verify_tls is False
        )

    def test_unverified_tls_is_refused_outside_development(self) -> None:
        """The setting is honoured, and where it may be set is also honoured.

        Unverified TLS authenticates nothing: it encrypts to whoever answered,
        which is exactly the property an interception needs.
        """
        with pytest.raises(ValueError, match="ACOP_PROXMOX_VERIFY_TLS"):
            proxmox_settings(proxmox_verify_tls=False, environment=Environment.PRODUCTION)

    def test_the_tls_setting_is_what_httpx_receives(self) -> None:
        """A source assertion, because ``httpx`` exposes no ``verify`` back.

        Read the way the repository's other boundary assertions are read: the
        property is about what this module hands to a library, not about what it
        computes on a given input.
        """
        source = CLIENT_SOURCE.read_text(encoding="utf-8")
        assert "verify=self._verify_tls," in source

    def test_a_disabled_integration_refuses_to_build_a_client(self) -> None:
        with pytest.raises(ProxmoxNotConfiguredError):
            ProxmoxClient(proxmox_settings(proxmox_enabled=False))

    def test_a_plain_http_base_url_is_refused_at_the_point_of_use(self) -> None:
        """The settings validator refuses this too. Both, deliberately.

        This object is the one that would actually put a token on the wire, and
        a guarantee is worth having where it is used as well as where it is
        configured.
        """
        settings = proxmox_settings()
        object.__setattr__(settings, "proxmox_base_url", "http://pve.example.invalid")
        with pytest.raises(ProxmoxNotConfiguredError):
            ProxmoxClient(settings)

    async def test_redirects_are_not_followed(self) -> None:
        """A redirect is a server-controlled instruction to move the token."""
        scripted = standalone_instance()
        scripted.raw_route(
            "/api2/json/cluster/status",
            lambda _r: httpx.Response(
                302, headers={"location": "https://elsewhere.invalid/"}
            ),
        )
        with pytest.raises(ProxmoxHTTPStatusError):
            await _run("proxmox.cluster.status", scripted)
        assert scripted.paths == ["/api2/json/cluster/status"]


class TestTheSecretStaysInside:
    async def test_no_failure_path_renders_the_token(self) -> None:
        """Whole exceptions, on every failure shape ACOP defines.

        The message, the repr, the context and the internal message are all
        searched, because a leak that lands in an unexpected field is still a
        leak.
        """
        cases: list[tuple[ScriptedProxmox, str, dict[str, Any]]] = []

        unauthorised = standalone_instance()
        unauthorised.status_route("/api2/json/cluster/status", 401)
        cases.append((unauthorised, "proxmox.cluster.status", {}))

        forbidden = standalone_instance()
        forbidden.status_route("/api2/json/cluster/status", 403)
        cases.append((forbidden, "proxmox.cluster.status", {}))

        broken = standalone_instance()
        broken.raw_route(
            "/api2/json/cluster/status",
            lambda _r: httpx.Response(200, content=b"not json"),
        )
        cases.append((broken, "proxmox.cluster.status", {}))

        refused = standalone_instance()
        refused.error_route(
            "/api2/json/cluster/status",
            httpx.ConnectError("connection refused"),
        )
        cases.append((refused, "proxmox.cluster.status", {}))

        timed_out = standalone_instance()
        timed_out.error_route("/api2/json/cluster/status", httpx.ReadTimeout("too slow"))
        cases.append((timed_out, "proxmox.cluster.status", {}))

        mismatched = standalone_instance()
        cases.append(
            (
                mismatched,
                "proxmox.vm.status",
                {"identifiers": {"proxmox:guest": "other/200"}},
            )
        )

        missing = standalone_instance()
        cases.append((missing, "proxmox.vm.status", {"identifiers": {}}))

        for scripted, tool_name, kwargs in cases:
            with pytest.raises(ProxmoxError) as caught:
                await _run(tool_name, scripted, **kwargs)
            rendered = _rendered(caught.value)
            assert TOKEN_SECRET not in rendered
            assert "PVEAPIToken" not in rendered

    async def test_no_successful_result_carries_the_token(self) -> None:
        scripted = standalone_instance()
        for tool_name in sorted(APPROVED_TOOLS):
            result = await _run(tool_name, scripted)
            rendered = repr(result.payload)
            assert TOKEN_SECRET not in rendered
            assert TOKEN_ID not in rendered
            assert "PVEAPIToken" not in rendered

    def test_the_settings_object_does_not_render_the_token(self) -> None:
        settings = proxmox_settings()
        assert TOKEN_SECRET not in repr(settings)
        assert TOKEN_SECRET not in str(settings)

    async def test_an_http_error_body_is_never_carried(self) -> None:
        """An error body may quote the request, and the request carried a token."""
        scripted = standalone_instance()
        scripted.raw_route(
            "/api2/json/cluster/status",
            lambda _r: httpx.Response(
                500,
                content=f"upstream said PVEAPIToken={TOKEN_ID}={TOKEN_SECRET}".encode(),
            ),
        )
        with pytest.raises(ProxmoxHTTPStatusError) as caught:
            await _run("proxmox.cluster.status", scripted)
        assert TOKEN_SECRET not in _rendered(caught.value)


# ---------------------------------------------------------------------------
# Trusted identifier resolution
# ---------------------------------------------------------------------------
class TestTrustedIdentifierResolution:
    async def test_an_instance_mismatch_makes_zero_http_calls(self) -> None:
        """The ratified rule: fail before the request, not after it.

        A VMID that exists on two instances would otherwise return a confident
        answer about the wrong machine.
        """
        scripted = standalone_instance()
        with pytest.raises(ProxmoxInstanceMismatchError):
            await _run(
                "proxmox.vm.config",
                scripted,
                identifiers={"proxmox:guest": f"other-pve/{VM_VMID}"},
            )
        assert scripted.requests == []

    async def test_a_cluster_tool_also_verifies_the_instance_first(self) -> None:
        scripted = standalone_instance()
        with pytest.raises(ProxmoxInstanceMismatchError):
            await _run(
                "proxmox.guest.list",
                scripted,
                identifiers={"proxmox:instance": "other-pve"},
            )
        assert scripted.requests == []

    @pytest.mark.parametrize(
        "identifiers",
        [
            {},
            {"hostname": "docs-vm-01"},
            {"proxmox:uuid": VM_UUID},
        ],
    )
    async def test_a_missing_guest_identifier_is_refused_not_guessed(
        self, identifiers: dict[str, str]
    ) -> None:
        """No fallback to hostname, display name, or a UUID that names no VMID.

        Substituting one of those is precisely the shortcut this architecture
        exists to refuse.
        """
        scripted = standalone_instance()
        with pytest.raises(ProxmoxIdentifierError):
            await _run("proxmox.vm.status", scripted, identifiers=identifiers)
        assert scripted.requests == []

    @pytest.mark.parametrize(
        "value", ["docs-pve", "docs-pve/", "/200", "docs-pve/200/extra", "docs-pve/abc"]
    )
    async def test_a_malformed_composite_is_refused(self, value: str) -> None:
        scripted = standalone_instance()
        with pytest.raises(ProxmoxIdentifierError):
            await _run(
                "proxmox.vm.status", scripted, identifiers={"proxmox:guest": value}
            )
        assert scripted.requests == []

    async def test_a_guest_absent_from_live_inventory_is_not_found(self) -> None:
        scripted = standalone_instance()
        with pytest.raises(ProxmoxObjectNotFoundError) as caught:
            await _run(
                "proxmox.vm.status",
                scripted,
                identifiers={"proxmox:guest": f"{INSTANCE_ID}/999"},
            )
        assert caught.value.category is ToolErrorCategory.INVALID_TARGET

    async def test_two_guests_with_one_vmid_are_refused_rather_than_chosen(self) -> None:
        """Proxmox answering impossibly is not a licence to pick one."""
        scripted = standalone_instance()
        duplicate = [
            {"type": "qemu", "vmid": VM_VMID, "node": NODE, "name": "a"},
            {"type": "qemu", "vmid": VM_VMID, "node": NODE_B, "name": "b"},
        ]
        scripted.json_route("/api2/json/cluster/resources", duplicate)
        with pytest.raises(ProxmoxAmbiguousObjectError):
            await _run("proxmox.vm.status", scripted)

    async def test_a_container_is_not_read_through_the_qemu_endpoint(self) -> None:
        """QEMU and LXC share one VMID space, so type must match as well.

        The type is a constant of the tool, never caller input: reading the
        container's VMID as a VM must find nothing rather than route to
        ``/qemu/``.
        """
        scripted = standalone_instance()
        with pytest.raises(ProxmoxObjectNotFoundError):
            await _run(
                "proxmox.vm.status",
                scripted,
                identifiers={"proxmox:guest": f"{INSTANCE_ID}/{CT_VMID}"},
            )
        assert scripted.paths == ["/api2/json/cluster/resources"]

    async def test_the_node_comes_from_proxmox_not_from_the_cmdb(self) -> None:
        """Live routing, so a guest that migrated is read on its current node."""
        scripted = standalone_instance()
        # The guest has moved to the second node since the last discovery sweep.
        # Nothing in the CMDB knows that yet, and the read must still land.
        scripted.json_route(
            "/api2/json/cluster/resources",
            [{"type": "qemu", "vmid": VM_VMID, "node": NODE_B, "name": VM_NAME}],
        )
        scripted.json_route(
            f"/api2/json/nodes/{NODE_B}/qemu/{VM_VMID}/status/current",
            {"vmid": VM_VMID, "status": "running"},
        )
        result = await _run("proxmox.vm.status", scripted)
        assert scripted.paths[-1].startswith(f"/api2/json/nodes/{NODE_B}/")
        assert result.payload["node"] == NODE_B

    async def test_a_node_absent_from_live_inventory_is_not_found(self) -> None:
        scripted = standalone_instance()
        with pytest.raises(ProxmoxObjectNotFoundError):
            await _run(
                "proxmox.node.status",
                scripted,
                identifiers={"proxmox:node": f"{INSTANCE_ID}/pve-doc-99"},
            )


# ---------------------------------------------------------------------------
# Transport failure translation
# ---------------------------------------------------------------------------
class TestFailuresAreTranslatedNotAbsorbed:
    @pytest.mark.parametrize(
        ("status_code", "expected", "category"),
        [
            (401, ProxmoxAuthenticationError, ToolErrorCategory.AUTHENTICATION),
            (403, ProxmoxAuthorizationError, ToolErrorCategory.AUTHORIZATION),
            (404, ProxmoxHTTPStatusError, ToolErrorCategory.EXECUTION_FAILED),
            (500, ProxmoxHTTPStatusError, ToolErrorCategory.EXECUTION_FAILED),
            (503, ProxmoxHTTPStatusError, ToolErrorCategory.EXECUTION_FAILED),
        ],
    )
    async def test_http_status_maps_onto_the_framework_taxonomy(
        self, status_code: int, expected: type[ProxmoxError], category: ToolErrorCategory
    ) -> None:
        scripted = standalone_instance()
        scripted.status_route("/api2/json/cluster/status", status_code)
        with pytest.raises(expected) as caught:
            await _run("proxmox.cluster.status", scripted)
        assert caught.value.category is category

    async def test_authentication_and_timeout_are_not_retryable_categories(self) -> None:
        """Retrying a rejected token or an expired deadline cannot succeed.

        Import rule 8 already refuses a declaration that would retry outside
        ``RETRYABLE_CATEGORIES``; this asserts the categories these failures
        carry are outside it, which is what makes that rule bite here.
        """
        from acop.models.tool_vocabulary import RETRYABLE_CATEGORIES

        assert ToolErrorCategory.AUTHENTICATION not in RETRYABLE_CATEGORIES
        assert ToolErrorCategory.AUTHORIZATION not in RETRYABLE_CATEGORIES
        assert ToolErrorCategory.TIMEOUT not in RETRYABLE_CATEGORIES
        assert ToolErrorCategory.INVALID_TARGET not in RETRYABLE_CATEGORIES
        assert ToolErrorCategory.TARGET_UNAVAILABLE in RETRYABLE_CATEGORIES

    async def test_a_timeout_fails_as_a_timeout(self) -> None:
        scripted = standalone_instance()
        scripted.error_route("/api2/json/cluster/status", httpx.ReadTimeout("slow"))
        with pytest.raises(ProxmoxTimeoutError) as caught:
            await _run("proxmox.cluster.status", scripted)
        assert caught.value.category is ToolErrorCategory.TIMEOUT

    async def test_a_connection_failure_is_retryable_and_named(self) -> None:
        scripted = standalone_instance()
        scripted.error_route("/api2/json/cluster/status", httpx.ConnectError("refused"))
        with pytest.raises(ProxmoxConnectionError) as caught:
            await _run("proxmox.cluster.status", scripted)
        assert caught.value.category is ToolErrorCategory.TARGET_UNAVAILABLE

    async def test_a_tls_verification_failure_is_authentication_not_connectivity(
        self,
    ) -> None:
        """Told apart because they need opposite responses.

        A refused connection is retryable. A certificate that does not verify
        must never be retried: the server failed to prove it is the server, and
        if that is an interception, retrying is the one thing that must not
        happen.
        """
        import ssl

        scripted = standalone_instance()

        def raising(_request: httpx.Request) -> httpx.Response:
            # The shape httpx actually produces: a ConnectError whose cause is
            # an ssl error. Detected by walking the cause chain rather than by
            # matching message text, which is version-dependent and would fail
            # open the first time it changed.
            cause = ssl.SSLCertVerificationError("certificate verify failed")
            raise httpx.ConnectError("tls failure") from cause

        scripted.raw_route("/api2/json/cluster/status", raising)
        with pytest.raises(ProxmoxAuthenticationError) as caught:
            await _run("proxmox.cluster.status", scripted)
        assert caught.value.category is ToolErrorCategory.AUTHENTICATION

    @pytest.mark.parametrize(
        "body",
        [b"not json", b"[]", b'{"errors": {}}', b"null", b'{"result": []}'],
    )
    async def test_a_malformed_envelope_fails_rather_than_becoming_empty(
        self, body: bytes
    ) -> None:
        """The single most important failure in this file.

        An unreadable inventory answered as an empty one would be read by the
        discovery checkpoint as "every guest is gone", and its absence pass would
        retire the lot.
        """
        scripted = standalone_instance()
        scripted.raw_route(
            "/api2/json/cluster/resources", lambda _r: httpx.Response(200, content=body)
        )
        with pytest.raises(ProxmoxProtocolError):
            await _run("proxmox.guest.list", scripted)

    async def test_a_response_over_the_size_cap_is_refused(self) -> None:
        oversized = b'{"data": [' + b'{"x":1},' * 1_200_000 + b"{}]}"
        assert len(oversized) > MAX_RESPONSE_BYTES
        scripted = standalone_instance()
        scripted.raw_route(
            "/api2/json/cluster/status", lambda _r: httpx.Response(200, content=oversized)
        )
        with pytest.raises(ProxmoxProtocolError):
            await _run("proxmox.cluster.status", scripted)

    async def test_an_unsupported_tool_name_fails_loudly(self) -> None:
        scripted = standalone_instance()
        with pytest.raises(AdapterUnavailableError) as caught:
            await _run("proxmox.vm.start", scripted)
        assert "proxmox.vm.start" in str(caught.value)
        assert scripted.requests == []

    async def test_validate_still_refuses_permanently(self) -> None:
        """Every Milestone 5 tool is read-only; a read has nothing to confirm."""
        scripted = standalone_instance()
        with pytest.raises(AdapterUnavailableError) as caught:
            await _adapter(scripted).validate(_request("proxmox.vm.status"))
        assert "read-only" in str(caught.value)


# ---------------------------------------------------------------------------
# Timeout budget
# ---------------------------------------------------------------------------
class TestTheTimeoutIsABudget:
    async def test_a_request_never_exceeds_the_configured_per_request_timeout(
        self,
    ) -> None:
        scripted = standalone_instance()
        await _run("proxmox.cluster.status", scripted, timeout_seconds=300.0)
        applied = scripted.requests[0].extensions["timeout"]["read"]
        assert applied == pytest.approx(5.0)

    async def test_an_exhausted_budget_fails_before_any_request(self) -> None:
        scripted = standalone_instance()
        with pytest.raises(ProxmoxTimeoutError):
            await _run("proxmox.cluster.status", scripted, timeout_seconds=0.0)
        assert scripted.requests == []

    async def test_the_budget_is_shared_across_a_fan_out(self) -> None:
        """``storage.list`` makes ``1 + N`` requests inside one deadline.

        Each request gets what is left rather than the full configured timeout,
        so the tool cannot run for ``N`` times its declared deadline and be
        cancelled from outside with nothing to say about which call was slow.
        """
        scripted = standalone_instance()
        scripted.json_route("/api2/json/nodes", NODE_LIST_TWO)
        scripted.json_route(f"/api2/json/nodes/{NODE_B}/storage", STORAGE_LIST[:1])
        await _run("proxmox.storage.list", scripted, timeout_seconds=2.0)
        applied = [r.extensions["timeout"]["read"] for r in scripted.requests]
        assert len(applied) == 3
        assert all(value <= 2.0 for value in applied)
        assert applied == sorted(applied, reverse=True)

    def test_the_declared_timeouts_cover_their_fan_out(self) -> None:
        """The declaration is arithmetic, not taste. 15s per request by default."""
        assert get_definition("proxmox.cluster.status", "1.0").timeout_seconds == 20.0
        assert get_definition("proxmox.vm.config", "1.0").timeout_seconds == 35.0
        assert get_definition("proxmox.storage.list", "1.0").timeout_seconds == 90.0


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
class TestProjectionsMatchTheirDeclarations:
    @pytest.mark.parametrize("tool_name", sorted(APPROVED_TOOLS))
    async def test_every_projection_validates_against_its_output_model(
        self, tool_name: str
    ) -> None:
        """Closes the drift the Milestone 4 contract deliberately leaves open.

        The adapter returns a plain mapping and the *framework* validates it,
        which is what makes ADR-0023's failure mode work. The cost is that a
        renamed field is only caught at dispatch, so it is caught here instead.
        """
        definition = get_definition(tool_name, "1.0")
        assert definition is not None
        scripted = standalone_instance()
        result = await _run(tool_name, scripted)
        assert result.outcome is AdapterOutcome.SUCCESS
        validated = definition.output_model.model_validate(result.payload)
        assert set(result.payload) == set(validated.model_dump())

    @pytest.mark.parametrize("tool_name", sorted(APPROVED_TOOLS))
    async def test_no_upstream_field_leaks_through_unnamed(self, tool_name: str) -> None:
        """Extra upstream fields should not automatically become ACOP output."""
        definition = get_definition(tool_name, "1.0")
        assert definition is not None
        scripted = standalone_instance()
        result = await _run(tool_name, scripted)
        assert set(result.payload) <= set(definition.output_model.model_fields)


class TestOutputContent:
    async def test_cluster_status_reads_a_standalone_node_as_first_class(self) -> None:
        """No cluster name, no quorum, and a successful read all the same."""
        scripted = standalone_instance()
        result = await _run("proxmox.cluster.status", scripted)
        assert result.payload["standalone"] is True
        assert result.payload["cluster_name"] is None
        assert result.payload["quorate"] is None
        assert len(result.payload["members"]) == 1
        assert result.payload["members"][0]["online"] is True
        assert result.payload["members"][0]["local"] is True

    async def test_cluster_status_reads_a_real_cluster_too(self) -> None:
        scripted = standalone_instance()
        scripted.json_route("/api2/json/cluster/status", CLUSTER_STATUS_CLUSTERED)
        result = await _run("proxmox.cluster.status", scripted)
        assert result.payload["standalone"] is False
        assert result.payload["cluster_name"] == "docs-cluster"
        assert result.payload["quorate"] is True

    async def test_guest_list_carries_qemu_and_lxc_together(self) -> None:
        scripted = standalone_instance()
        result = await _run("proxmox.guest.list", scripted)
        by_type = {guest["guest_type"]: guest for guest in result.payload["guests"]}
        assert set(by_type) == {"qemu", "lxc"}
        assert by_type["qemu"]["vmid"] == VM_VMID
        assert by_type["lxc"]["vmid"] == CT_VMID
        assert all(guest["node"] == NODE for guest in result.payload["guests"])

    async def test_an_empty_inventory_is_a_success_not_a_failure(self) -> None:
        """The distinction the discovery checkpoint depends on.

        An empty list is a true statement about an instance with no guests. A
        malformed body is not a statement at all, and fails - see
        ``test_a_malformed_envelope_fails_rather_than_becoming_empty``.
        """
        scripted = standalone_instance()
        scripted.json_route("/api2/json/cluster/resources", [])
        result = await _run("proxmox.guest.list", scripted)
        assert result.outcome is AdapterOutcome.SUCCESS
        assert result.payload["guests"] == []

    async def test_a_guest_record_missing_its_node_fails_as_a_protocol_error(
        self,
    ) -> None:
        """Not an output-contract violation. ADR-0023 reserves that for ACOP."""
        scripted = standalone_instance()
        scripted.json_route(
            "/api2/json/cluster/resources", [{"type": "qemu", "vmid": VM_VMID}]
        )
        with pytest.raises(ProxmoxProtocolError):
            await _run("proxmox.guest.list", scripted)

    async def test_vm_config_parses_the_smbios_uuid_vmgenid_meta_and_digest(
        self,
    ) -> None:
        scripted = standalone_instance()
        result = await _run("proxmox.vm.config", scripted)
        assert result.payload["smbios_uuid"] == VM_UUID
        assert result.payload["vmgenid"] == VM_GENID
        assert result.payload["creation_qemu_version"] == "10.1.2"
        assert result.payload["created_at"] is not None
        assert result.payload["config_digest"].startswith("0123456789")

    @pytest.mark.parametrize(
        "smbios",
        ["", "uuid=", "uuid=not-a-uuid", "family=docs", "uuid=1234", "manufacturer=x"],
    )
    async def test_an_unreadable_smbios_uuid_becomes_none_never_a_guess(
        self, smbios: str
    ) -> None:
        """A VM with no readable UUID has no strong correlator, and says so.

        The identity design already accounts for that. It is not an invitation
        to fall back to something weaker.
        """
        scripted = standalone_instance()
        scripted.json_route(
            f"/api2/json/nodes/{NODE}/qemu/{VM_VMID}/config",
            {"name": VM_NAME, "smbios1": smbios, "digest": "abc"},
        )
        result = await _run("proxmox.vm.config", scripted)
        assert result.payload["smbios_uuid"] is None

    async def test_vm_output_carries_no_disk_or_nic_device_lines(self) -> None:
        """Storage volume paths and MAC addresses are not published here.

        Both belong to decisions this checkpoint explicitly does not make: the
        Checkpoint 3 storage-identity gate, and the ratified position that a MAC
        is not lifecycle identity.
        """
        scripted = standalone_instance()
        for tool_name in ("proxmox.vm.config", "proxmox.vm.status"):
            result = await _run(tool_name, scripted)
            rendered = repr(result.payload)
            assert "vm-200-disk" not in rendered
            assert "subvol-" not in rendered
            assert "00:00:5E" not in rendered
            assert "virtio=" not in rendered
            assert "bridge=vmbr0" not in rendered
            assert "size=64G" not in rendered
        # ``boot_order`` names device *slots* ("order=scsi0;net0") and carries
        # neither a volume path nor a MAC, so it is kept: it is cheap lifecycle
        # evidence. The device *definitions* those slots point at are what is
        # excluded, and the assertions above are written against those.
        config = await _run("proxmox.vm.config", standalone_instance())
        assert config.payload["boot_order"] == "order=scsi0;net0"

    async def test_container_config_fabricates_no_lifecycle_identity(self) -> None:
        """LXC has no durable lifecycle identifier and ACOP invents none.

        Asserted structurally - the model has no field that could hold one - as
        well as behaviourally, because a prose promise is not a control.
        """
        definition = get_definition("proxmox.container.config", "1.0")
        assert definition is not None
        fields = set(definition.output_model.model_fields)
        assert not [name for name in fields if "uuid" in name.lower()]
        assert not [name for name in fields if "mac" in name.lower()]
        assert "config_digest" in fields

        scripted = standalone_instance()
        result = await _run("proxmox.container.config", scripted)
        rendered = repr(result.payload)
        assert "00:00:5E" not in rendered
        assert "subvol-310-disk" not in rendered
        assert result.payload["config_digest"].startswith("fedcba")

    async def test_no_container_model_can_hold_a_uuid_at_all(self) -> None:
        for tool_name in ("proxmox.container.status", "proxmox.container.config"):
            definition = get_definition(tool_name, "1.0")
            assert definition is not None
            assert not [
                name
                for name in definition.output_model.model_fields
                if "uuid" in name.lower()
            ]

    async def test_a_node_status_field_proxmox_omits_becomes_none_not_a_failure(
        self,
    ) -> None:
        """``/nodes/{node}/status`` was never captured during Checkpoint 0.

        Every field but ``node`` is therefore optional, and a sparse response is
        a true statement rather than a failed invocation.
        """
        scripted = standalone_instance()
        scripted.json_route(f"/api2/json/nodes/{NODE}/status", {"uptime": 10})
        result = await _run("proxmox.node.status", scripted)
        assert result.payload["uptime_seconds"] == 10
        assert result.payload["cpu_model"] is None
        assert result.payload["memory_total_bytes"] is None

    async def test_network_output_carries_the_bridge_and_its_address(self) -> None:
        scripted = standalone_instance()
        result = await _run("proxmox.node.network", scripted)
        bridge = next(
            item for item in result.payload["interfaces"] if item["iface"] == "vmbr0"
        )
        assert bridge["type"] == "bridge"
        assert bridge["cidr"].endswith("/24")
        assert bridge["gateway"] == "192.0.2.1"
        assert bridge["bridge_ports"] == "nic0"
        assert bridge["active"] is True


class TestStorageIsAUnionCarryingItsNode:
    async def test_one_node_is_queried_on_a_standalone_instance(self) -> None:
        scripted = standalone_instance()
        result = await _run("proxmox.storage.list", scripted)
        assert result.payload["nodes_queried"] == [NODE]
        assert {row["node"] for row in result.payload["storages"]} == {NODE}
        assert len(result.payload["storages"]) == len(STORAGE_LIST)

    async def test_every_online_node_is_queried_and_the_union_returned(self) -> None:
        """The ratified rule. ``local`` on one node is not ``local`` on another.

        Choosing a single node would report that node's free space as the
        instance's - overstating shared capacity and understating local.
        """
        scripted = standalone_instance()
        scripted.json_route("/api2/json/nodes", NODE_LIST_TWO)
        scripted.json_route(f"/api2/json/nodes/{NODE_B}/storage", STORAGE_LIST[:2])
        result = await _run("proxmox.storage.list", scripted)
        assert result.payload["nodes_queried"] == [NODE, NODE_B]
        assert scripted.paths == [
            "/api2/json/nodes",
            f"/api2/json/nodes/{NODE}/storage",
            f"/api2/json/nodes/{NODE_B}/storage",
        ]
        pairs = {(row["node"], row["storage"]) for row in result.payload["storages"]}
        assert (NODE, "local") in pairs
        assert (NODE_B, "local") in pairs

    async def test_an_offline_node_is_skipped_rather_than_failing_the_read(self) -> None:
        scripted = standalone_instance()
        scripted.json_route("/api2/json/nodes", NODE_LIST_ONE_OFFLINE)
        result = await _run("proxmox.storage.list", scripted)
        assert result.payload["nodes_queried"] == [NODE]
        assert f"/api2/json/nodes/{NODE_B}/storage" not in scripted.paths

    async def test_no_online_node_is_distinguishable_from_no_storage(self) -> None:
        """``nodes_queried`` is what makes those two readings distinct."""
        scripted = standalone_instance()
        scripted.json_route("/api2/json/nodes", [])
        result = await _run("proxmox.storage.list", scripted)
        assert result.payload["nodes_queried"] == []
        assert result.payload["storages"] == []

    async def test_storage_output_is_typed_not_a_passthrough(self) -> None:
        scripted = standalone_instance()
        result = await _run("proxmox.storage.list", scripted)
        row = next(
            item for item in result.payload["storages"] if item["storage"] == "local"
        )
        assert row["storage_type"] == "dir"
        assert row["shared"] is False
        assert row["active"] is True
        assert isinstance(row["total_bytes"], int)
        assert isinstance(row["used_fraction"], float)
        # Proxmox's own key names are gone: the projection renamed them.
        assert "avail" not in row
        assert "type" not in row


class TestEnvelopeHandling:
    async def test_the_data_envelope_is_required(self) -> None:
        scripted = standalone_instance()
        scripted.raw_route(
            "/api2/json/nodes", lambda _r: httpx.Response(200, content=b'{"nodes": []}')
        )
        with pytest.raises(ProxmoxProtocolError):
            await _run("proxmox.node.list", scripted)

    async def test_an_envelope_holding_null_is_still_an_envelope(self) -> None:
        """``{"data": null}`` is a real Proxmox answer for an absent object.

        It must fail as a *shape* error at the projection, not be silently read
        as an empty collection.
        """
        scripted = standalone_instance()
        scripted.raw_route(
            "/api2/json/nodes", lambda _r: httpx.Response(200, content=envelope(None))
        )
        with pytest.raises(ProxmoxProtocolError):
            await _run("proxmox.node.list", scripted)
