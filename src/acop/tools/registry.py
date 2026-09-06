"""The code registry — the only thing that can make a capability executable.

This module holds one dict. Its importance is out of all proportion to its
size, because it is where the **Capability Binding Invariant (G5)** lives:

> A database row alone can never make anything executable.

Three mechanisms enforce that, and all three are required:

1. **Adapter resolution is code-only.** The dispatcher gets its callable from
   ``CODE_REGISTRY[(name, version)].adapter_id`` resolved through
   :mod:`acop.tools.adapters.base`. No function in ACOP resolves an adapter
   from a database value. A ``tool_registration`` row with no matching
   declaration resolves to ``None``, and the invocation is refused
   ``capability_not_bound`` before any adapter is reached.
2. **Policy reads code.** The policy engine takes a
   :class:`~acop.tools.contract.ToolDefinition`, never an ORM object. A unit
   test asserts :mod:`acop.tools.policy` does not import
   :mod:`acop.models.tool` at all, so the property is checked rather than
   merely intended.
3. **Reconciliation is one-directional.** Startup writes code into the
   database. It never reads a definition out. A row naming a tool that code
   does not declare is marked ``RETIRED``, never resurrected.

**Why the database is still needed.** During an incident an operator must be
able to take a misbehaving tool out of service immediately and attributably,
without a redeploy. That is an operational fact about a capability, not the
definition of one - which is exactly the line drawn in
:mod:`acop.models.tool`.

**Contract drift fails startup.** If a row exists for ``(name, version)`` with
a different ``contract_hash``, the process refuses to start. That looks harsh
until you consider what it prevents: editing a Class 2 tool's input schema in
place, in a release, while approvals bound to envelopes computed under the old
schema are still pending. The correct action is a version bump.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from acop.core.exceptions import ConfigurationError
from acop.core.logging import get_logger
from acop.models.tool import ToolRegistration
from acop.models.tool_vocabulary import ToolLifecycle
from acop.tools.contract import ToolDefinition, validate_declaration

logger = get_logger(__name__)

#: The authoritative capability set. Populated at import by :func:`register`,
#: and by nothing else, ever.
CODE_REGISTRY: dict[tuple[str, str], ToolDefinition] = {}


def register(definition: ToolDefinition) -> ToolDefinition:
    """Validate a declaration and add it to the registry.

    Raises:
        ToolDeclarationError: Any of the fourteen import rules is violated.
        AdapterBindingError: The named adapter is not registered.
    """
    validate_declaration(definition)
    existing = CODE_REGISTRY.get(definition.key)
    if existing is not None and existing is not definition:
        # Rule 14's uniqueness half. Only the registry can see two
        # declarations at once, so only the registry can check this.
        raise ConfigurationError(
            f"Tool {definition.qualified_name} is declared twice. A duplicate "
            "would let import order decide which contract applies."
        )
    CODE_REGISTRY[definition.key] = definition
    return definition


def get_definition(tool_name: str, tool_version: str) -> ToolDefinition | None:
    """Resolve a declaration, or ``None``.

    Returning ``None`` rather than raising is deliberate: the caller decides
    whether an unknown tool is a 404 or a policy denial, and both outcomes are
    reachable - an unknown name is a 404, while a name that exists as a row but
    not in code is ``capability_not_bound``.
    """
    return CODE_REGISTRY.get((tool_name, tool_version))


def all_definitions() -> tuple[ToolDefinition, ...]:
    """Every declared tool, ordered by name and version for stable output."""
    return tuple(
        sorted(CODE_REGISTRY.values(), key=lambda d: (d.tool_name, d.tool_version))
    )


class ToolRegistryReconciler:
    """Writes the code registry into the database, one direction only.

    Never reads a definition out of the database. The only thing it reads is
    lifecycle state and ``contract_hash``, which are facts *about* a
    declaration rather than the declaration itself.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def reconcile(self, *, allow_rehash: bool = False) -> ReconcileReport:
        """Bring ``tool_registration`` into step with the code registry.

        Args:
            allow_rehash: Accept a changed contract hash for an unchanged
                version, rewriting the stored hash. Development only, and the
                guard today is simply that **no caller opts in**: startup
                reconciliation runs inline in ``acop.main``'s lifespan and
                passes nothing, so the default refuses. The parameter exists
                for a development-only rehash path that is not wired to
                anything yet; until something calls it, adding a caller means
                deciding then how production is kept out.

        Raises:
            ConfigurationError: A stored contract hash differs from the code's
                and ``allow_rehash`` is false.
        """
        rows = list(
            (await self._session.execute(select(ToolRegistration))).scalars().all()
        )
        by_key = {(row.tool_name, row.tool_version): row for row in rows}
        report = ReconcileReport()

        for definition in all_definitions():
            digest = definition.contract_hash()
            row = by_key.pop(definition.key, None)
            if row is None:
                self._session.add(
                    ToolRegistration(
                        tool_name=definition.tool_name,
                        tool_version=definition.tool_version,
                        contract_hash=digest,
                        lifecycle_state=definition.lifecycle_default.value,
                    )
                )
                report.registered.append(definition.qualified_name)
                continue
            if row.contract_hash == digest:
                report.unchanged.append(definition.qualified_name)
                continue
            if not allow_rehash:
                raise ConfigurationError(
                    f"Tool {definition.qualified_name} changed without a "
                    "version bump. Approvals already given were bound to "
                    "envelopes computed under the previous contract, so the "
                    "correct action is a MAJOR or MINOR version increment, not "
                    "an in-place edit.",
                    context={
                        "tool": definition.qualified_name,
                        "stored_hash": row.contract_hash,
                        "code_hash": digest,
                    },
                )
            row.contract_hash = digest
            report.rehashed.append(definition.qualified_name)

        # Whatever is left has a row but no code. Retire it; never delete it,
        # because invocations still reference it.
        for key, row in by_key.items():
            if row.lifecycle_state == ToolLifecycle.RETIRED.value:
                continue
            row.lifecycle_state = ToolLifecycle.RETIRED.value
            row.retired_at = datetime.now(UTC)
            row.retired_reason = "No code declaration for this tool version."
            report.retired.append(f"{key[0]}@{key[1]}")

        await self._session.flush()
        logger.info(
            "tools.registry.reconciled",
            registered=len(report.registered),
            unchanged=len(report.unchanged),
            retired=len(report.retired),
            rehashed=len(report.rehashed),
        )
        return report


class ReconcileReport:
    """What reconciliation did. Plain object; logged and returned, not stored."""

    __slots__ = ("registered", "rehashed", "retired", "unchanged")

    def __init__(self) -> None:
        self.registered: list[str] = []
        self.unchanged: list[str] = []
        self.retired: list[str] = []
        self.rehashed: list[str] = []

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<ReconcileReport registered={len(self.registered)} "
            f"unchanged={len(self.unchanged)} retired={len(self.retired)} "
            f"rehashed={len(self.rehashed)}>"
        )


__all__ = [
    "CODE_REGISTRY",
    "ReconcileReport",
    "ToolRegistryReconciler",
    "all_definitions",
    "get_definition",
    "register",
]
