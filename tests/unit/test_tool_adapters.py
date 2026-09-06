"""The adapter boundary, asserted statically.

Two of these tests read source code rather than calling it, and that is
deliberate. "The simulated adapter cannot reach the host" and "adapter
resolution never consults the database" are properties of what the modules
*import*, not of what they happen to do on a given input, so an import check is
the honest way to assert them.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from acop.models.tool_vocabulary import PROHIBITED_CAPABILITIES
from acop.tools.adapters.base import (
    ADAPTER_REGISTRY,
    AdapterRequest,
    AdapterResult,
    register_adapter,
    resolve_adapter,
)

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

    def test_both_declared_adapters_are_bound(self) -> None:
        assert set(ADAPTER_REGISTRY) == {"acop.local", "test.simulated"}


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
