"""The adapter boundary, asserted statically.

Two of these tests read source code rather than calling it, and that is
deliberate. "The simulated adapter cannot reach the host" and "adapter
resolution never consults the database" are properties of what the modules
*import*, not of what they happen to do on a given input, so an import check is
the honest way to assert them.
"""

from __future__ import annotations

import ast
import uuid
from pathlib import Path

import pytest

from acop.models.tool_vocabulary import PROHIBITED_CAPABILITIES, TargetKind
from acop.tools.adapters.base import (
    ADAPTER_REGISTRY,
    AdapterRequest,
    AdapterResult,
    ResolvedTarget,
    ToolAdapter,
    register_adapter,
    resolve_adapter,
)
from acop.tools.adapters.proxmox import PROXMOX_ADAPTER, ProxmoxAdapter
from acop.tools.errors import AdapterUnavailableError
from acop.tools.registry import CODE_REGISTRY

#: Anything that could reach a host, a process, or a network. A simulation that
#: needed one of these would no longer be a simulation.
FORBIDDEN_IMPORTS = {
    "subprocess",
    "socket",
    "asyncssh",
    "paramiko",
    "pexpect",
    "winrm",
    "telnetlib",
    "ftplib",
    "http.client",
    "httpx",
    "requests",
}


def _imports(path: str) -> set[str]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def _attribute_calls(path: str) -> set[str]:
    """Dotted call targets, e.g. ``os.system``."""
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            value = node.func.value
            if isinstance(value, ast.Name):
                calls.add(f"{value.id}.{node.func.attr}")
    return calls


class TestSimulatedAdapterCannotReachAnything:
    def test_it_imports_nothing_that_could_touch_a_host(self) -> None:
        imported = _imports("src/acop/tools/adapters/simulated.py")
        assert not imported & FORBIDDEN_IMPORTS

    def test_it_does_not_call_os_system_or_popen(self) -> None:
        calls = _attribute_calls("src/acop/tools/adapters/simulated.py")
        assert "os.system" not in calls
        assert "os.popen" not in calls

    def test_the_local_adapter_reaches_nothing_outside_the_process_either(
        self,
    ) -> None:
        imported = _imports("src/acop/tools/adapters/local.py")
        assert not imported & FORBIDDEN_IMPORTS

    def test_the_proxmox_adapter_reaches_nothing_yet_either(self) -> None:
        """Checkpoint 1C registers the binding and adds no connectivity.

        Read as an import check rather than a behavioural one for the same
        reason the two above are: "it cannot reach a host" is a property of
        what the module imports, not of what it happens to do on one input.
        When the client lands, ``httpx`` must be removed from this assertion
        deliberately and visibly, in the commit that earns it.
        """
        imported = _imports("src/acop/tools/adapters/proxmox.py")
        assert not imported & FORBIDDEN_IMPORTS


class TestAdapterResolutionIsCodeOnly:
    def test_the_adapter_module_does_not_import_the_orm(self) -> None:
        """Mechanism 1 of the Capability Binding Invariant.

        There is no function anywhere that resolves an adapter from a database
        value. A ``tool_registration`` row with no matching code declaration
        resolves to ``None``, and the invocation is refused before any adapter
        is reached.
        """
        imported = _imports("src/acop/tools/adapters/base.py")
        assert "acop.models.tool" not in imported
        assert not any(name.startswith("sqlalchemy") for name in imported)

    def test_an_unknown_adapter_resolves_to_none(self) -> None:
        assert resolve_adapter("not.registered") is None

    def test_registering_two_adapters_under_one_id_is_refused(self) -> None:
        """Import order must not decide which code executes."""

        class Impostor:
            adapter_id = "acop.local"

            async def execute(self, request: AdapterRequest) -> AdapterResult:
                raise NotImplementedError

            async def validate(self, request: AdapterRequest) -> AdapterResult:
                raise NotImplementedError

        with pytest.raises(ValueError, match="already registered"):
            register_adapter(Impostor())

    def test_every_declared_adapter_is_bound(self) -> None:
        """Exact, not a superset. An adapter nobody meant to ship shows up here."""
        assert set(ADAPTER_REGISTRY) == {"acop.local", "test.simulated", "proxmox"}

    def test_the_proxmox_id_resolves_to_the_proxmox_adapter(self) -> None:
        """What import rule 13 will consult when the first Proxmox tool lands.

        Registering now means a misspelt ``adapter_id`` in that declaration
        fails the build instead of surfacing later as a confusing denial.
        """
        assert resolve_adapter("proxmox") is PROXMOX_ADAPTER

    def test_a_second_adapter_cannot_take_the_proxmox_id(self) -> None:
        """The duplicate-registration guard still holds for the new id."""

        class Impostor:
            adapter_id = "proxmox"

            async def execute(self, request: AdapterRequest) -> AdapterResult:
                raise NotImplementedError

            async def validate(self, request: AdapterRequest) -> AdapterResult:
                raise NotImplementedError

        with pytest.raises(ValueError, match="already registered"):
            register_adapter(Impostor())
        assert resolve_adapter("proxmox") is PROXMOX_ADAPTER


class TestAdapterRequestCannotEscalate:
    def test_it_carries_no_policy_no_principal_and_no_credential(self) -> None:
        """G4: an adapter cannot escalate because the type has nowhere to say it.

        The same technique Milestone 3 used for ``KnowledgeAnswer``: the
        guarantee lives in the shape of the object, not in a check someone has
        to remember to run.
        """
        fields = set(AdapterRequest.__dataclass_fields__)
        forbidden = {
            "permission_class",
            "principal",
            "roles",
            "approval",
            "credentials",
            "password",
            "api_key",
            "command",
            "raw_input",
            "required_roles",
        }
        assert fields.isdisjoint(forbidden)

    def test_the_result_cannot_set_a_state(self) -> None:
        """An adapter reports an outcome; the framework decides the state.

        An adapter that could set the state could report success for a change
        that did not happen.
        """
        fields = set(AdapterResult.__dataclass_fields__)
        assert "state" not in fields
        assert "invocation_state" not in fields
        assert "outcome" in fields


class TestProhibitionRegistry:
    def test_every_category_a_shell_could_hide_behind_is_listed(self) -> None:
        for tag in (
            "arbitrary.shell",
            "arbitrary.ssh",
            "arbitrary.cli",
            "arbitrary.powershell",
            "arbitrary.sql",
            "arbitrary.winrm",
            "model.generated.command",
        ):
            assert tag in PROHIBITED_CAPABILITIES

    def test_secret_access_is_prohibited_as_a_category(self) -> None:
        assert {"secrets.read", "secrets.export"} <= PROHIBITED_CAPABILITIES

    def test_the_controls_that_would_hide_an_attack_are_prohibited(self) -> None:
        """Disabling audit or logging is the move that makes everything else
        invisible, so it is a category rather than a per-tool judgement."""
        assert {
            "audit.disable",
            "logging.disable",
            "monitoring.disable",
        } <= PROHIBITED_CAPABILITIES


class TestProxmoxAdapterSkeleton:
    """Milestone 5 Checkpoint 1C: bound, protocol-conformant, and inert.

    The point of these is that the adapter is *inert on purpose*, not merely
    unfinished. A skeleton that returned an empty success would be far worse
    than one that refuses: the dispatcher would record ``SUCCEEDED`` for a read
    that never happened.
    """

    def _request(self, tool_name: str = "proxmox.node.list") -> AdapterRequest:
        return AdapterRequest(
            invocation_id=uuid.uuid4(),
            tool_name=tool_name,
            tool_version="1.0",
            target=ResolvedTarget(kind=TargetKind.ASSET),
            payload={},
            timeout_seconds=5.0,
        )

    def test_it_satisfies_the_adapter_protocol(self) -> None:
        assert isinstance(PROXMOX_ADAPTER, ToolAdapter)

    def test_its_id_is_the_bare_name(self) -> None:
        assert ProxmoxAdapter.adapter_id == "proxmox"

    async def test_execute_refuses_every_tool_name(self) -> None:
        """Every tool name, because in this checkpoint every one is unimplemented."""
        with pytest.raises(AdapterUnavailableError) as caught:
            await PROXMOX_ADAPTER.execute(self._request())
        assert "proxmox.node.list" in str(caught.value)

    async def test_execute_names_the_tool_that_arrived_early(self) -> None:
        """The only way here is a declaration naming this adapter.

        If one appears before the client does, the error should say which tool
        it was rather than fail as a generic unavailability.
        """
        with pytest.raises(AdapterUnavailableError) as caught:
            await PROXMOX_ADAPTER.execute(self._request("proxmox.vm.config"))
        assert caught.value.context["tool_name"] == "proxmox.vm.config"
        assert caught.value.context["adapter_id"] == "proxmox"

    async def test_validate_always_refuses(self) -> None:
        """Not a placeholder. Every Milestone 5 tool is Class 1, read-only.

        Import rule 2 only forces ``validation_required`` for Class 2 and
        Class 3, so no read-only tool sets it and the dispatcher never calls
        this. A read makes no change, so there is nothing to confirm.
        """
        with pytest.raises(AdapterUnavailableError) as caught:
            await PROXMOX_ADAPTER.validate(self._request())
        assert "read-only" in str(caught.value)

    async def test_it_never_returns_a_result(self) -> None:
        """It raises rather than returning a falsy payload, and that matters.

        An ``AdapterResult`` with ``outcome=SUCCESS`` and an empty payload would
        be recorded by the dispatcher as a completed execution. Raising is what
        makes "not implemented" and "observed nothing" different states.
        """
        for method in (PROXMOX_ADAPTER.execute, PROXMOX_ADAPTER.validate):
            with pytest.raises(AdapterUnavailableError):
                await method(self._request())

    @pytest.mark.parametrize("method_name", ["execute", "validate"])
    async def test_the_refusal_carries_no_configuration(self, method_name: str) -> None:
        """A refusal message must not become a configuration disclosure channel.

        The whole rendered exception is searched - message, internal message and
        context - because a leak that lands in an unexpected field is still a
        leak.
        """
        method = getattr(PROXMOX_ADAPTER, method_name)
        with pytest.raises(AdapterUnavailableError) as caught:
            await method(self._request())

        error = caught.value
        rendered = f"{error} {error.context} {error.internal_message}".lower()
        for leak in ("http", "://", "token", "password", "secret", "verify"):
            assert leak not in rendered, f"{method_name} leaked {leak!r}"


class TestNoProxmoxToolsYet:
    """Checkpoint 1C adds a binding, not a capability."""

    def test_no_tool_is_declared_against_the_proxmox_adapter(self) -> None:
        bound = [
            definition.qualified_name
            for definition in CODE_REGISTRY.values()
            if definition.adapter_id == "proxmox"
        ]
        assert bound == []

    def test_no_tool_name_begins_with_proxmox(self) -> None:
        assert not [name for name, _ in CODE_REGISTRY if name.startswith("proxmox")]

    def test_the_catalog_is_unchanged_in_size(self) -> None:
        """Six test-and-system tools, exactly as Milestone 4 shipped."""
        assert len(CODE_REGISTRY) == 6
