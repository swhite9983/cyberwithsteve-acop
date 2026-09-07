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

    def test_only_the_proxmox_client_module_can_open_a_socket(self) -> None:
        """The Checkpoint 1C assertion, replaced deliberately and visibly.

        1C asserted that no Proxmox module imported ``httpx`` at all. That was
        the honest statement while the adapter was inert and it would be a false
        one now, so it is not weakened - it is made more specific. ``httpx``
        belongs to exactly one file, and every other module in the package still
        reaches nothing. "Which code can talk to a hypervisor" is then answered
        by reading one file rather than by trusting a convention.

        ``ssh``, ``subprocess`` and the rest stay forbidden everywhere,
        ``client.py`` included: this checkpoint added HTTP, not execution.
        """
        package = Path("src/acop/tools/adapters/proxmox")
        modules = sorted(path.name for path in package.glob("*.py"))
        assert modules == [
            "__init__.py",
            "adapter.py",
            "client.py",
            "endpoints.py",
            "errors.py",
            "identity.py",
            "projection.py",
        ]
        for name in modules:
            imported = _imports(str(package / name))
            allowed = FORBIDDEN_IMPORTS - ({"httpx"} if name == "client.py" else set())
            assert not imported & allowed, f"{name} imports something it may not"
        assert "httpx" in _imports(str(package / "client.py"))

    def test_no_proxmox_module_shells_out(self) -> None:
        for path in Path("src/acop/tools/adapters/proxmox").glob("*.py"):
            calls = _attribute_calls(str(path))
            assert "os.system" not in calls
            assert "os.popen" not in calls


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


class TestProxmoxAdapterBinding:
    """Milestone 5 Checkpoint 2: bound, protocol-conformant, and implemented.

    The behavioural coverage lives in ``tests/unit/test_proxmox_transport.py``,
    which runs the real client against a scripted upstream. What is left here is
    the binding itself and the two refusals that survive the checkpoint.
    """

    def _request(self, tool_name: str) -> AdapterRequest:
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

    async def test_an_undeclared_tool_name_is_refused_loudly_and_by_name(self) -> None:
        """Only the ten are reachable, and a wrong name says which one it was.

        A fall-through returning an empty success would be recorded by the
        dispatcher as a completed read that never happened.
        """
        with pytest.raises(AdapterUnavailableError) as caught:
            await PROXMOX_ADAPTER.execute(self._request("proxmox.vm.start"))
        assert caught.value.context["tool_name"] == "proxmox.vm.start"
        assert caught.value.context["adapter_id"] == "proxmox"

    async def test_validate_always_refuses(self) -> None:
        """Still not a placeholder. Every Milestone 5 tool is Class 1.

        Import rule 2 only forces ``validation_required`` for Class 2 and
        Class 3, so no read-only tool sets it and the dispatcher never calls
        this. A read makes no change, so there is nothing to confirm.
        """
        with pytest.raises(AdapterUnavailableError) as caught:
            await PROXMOX_ADAPTER.validate(self._request("proxmox.node.list"))
        assert "read-only" in str(caught.value)

    @pytest.mark.parametrize(
        ("method_name", "tool_name"),
        [("execute", "proxmox.vm.start"), ("validate", "proxmox.node.list")],
    )
    async def test_the_refusal_carries_no_configuration(
        self, method_name: str, tool_name: str
    ) -> None:
        """A refusal message must not become a configuration disclosure channel.

        The whole rendered exception is searched - message, internal message and
        context - because a leak that lands in an unexpected field is still a
        leak.
        """
        method = getattr(PROXMOX_ADAPTER, method_name)
        with pytest.raises(AdapterUnavailableError) as caught:
            await method(self._request(tool_name))

        error = caught.value
        rendered = f"{error} {error.context} {error.internal_message}".lower()
        for leak in ("http", "://", "token", "password", "secret", "verify"):
            assert leak not in rendered, f"{method_name} leaked {leak!r}"


class TestTheProxmoxCapabilitySurface:
    """Checkpoint 2 adds ten capabilities, and exactly ten."""

    def test_every_proxmox_tool_binds_to_the_proxmox_adapter(self) -> None:
        bound = sorted(
            definition.tool_name
            for definition in CODE_REGISTRY.values()
            if definition.adapter_id == "proxmox"
        )
        assert bound == sorted(
            name for name, _ in CODE_REGISTRY if name.startswith("proxmox.")
        )
        assert len(bound) == 10

    def test_no_other_adapter_gained_a_proxmox_tool(self) -> None:
        for name, version in CODE_REGISTRY:
            if name.startswith("proxmox."):
                assert CODE_REGISTRY[(name, version)].adapter_id == "proxmox"

    def test_the_catalog_is_the_six_from_milestone_four_plus_ten(self) -> None:
        assert len(CODE_REGISTRY) == 16
