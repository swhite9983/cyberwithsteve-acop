"""The approval module's public surface, and the one name that must not return.

``raise_for_approval`` translated an insufficient approval into an exception. It
was written for a design in which the final gate *raised*; the implemented gate
**records** a ``DENY`` or ``EXPIRED`` outcome, because it runs on a background
worker with no caller to raise to. An exception thrown there is caught by the
worker loop and lost, leaving the invocation in ``READY`` with nothing on the
row saying why it never executed.

It shipped with no call site at all. Asserting its absence rather than deleting
it quietly is what stops it coming back: the helper reads like an obvious
missing piece to anyone who meets ``approval_failure`` returning a
``PolicyReason`` and assumes something upstream must turn that into an error.
"""

from __future__ import annotations

import ast
from pathlib import Path

from acop.services.tools import approval

_REMOVED = "raise_for_approval"

#: Everything the approval module is allowed to be to the rest of ACOP. Pinned
#: as a set rather than a membership check so re-adding a raising helper under
#: any other name is also a failing test.
_PUBLIC_SURFACE = {"ToolApprovalService", "approval_failure", "approved_rows"}

_SOURCE_ROOTS = (Path("src"), Path("tests"), Path("scripts"))


def _identifiers(node: ast.AST) -> list[str]:
    """Every name this node binds, references or imports."""
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        return [node.attr]
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
        return [node.name]
    if isinstance(node, ast.ImportFrom | ast.Import):
        return [alias.name for alias in node.names] + [
            alias.asname for alias in node.names if alias.asname
        ]
    return []


class TestTheRaisingApprovalGateIsGone:
    def test_the_module_neither_defines_nor_exports_it(self) -> None:
        assert not hasattr(approval, _REMOVED)
        assert _REMOVED not in approval.__all__
        assert set(approval.__all__) == _PUBLIC_SURFACE

    def test_nothing_in_the_tree_defines_imports_or_calls_it(self) -> None:
        """Asserted over the AST, not by text search.

        A comment or docstring explaining *why* the helper is gone - this one
        included - must not fail the test. Only a real definition, import,
        reference or call may.
        """
        offenders = [
            str(path)
            for root in _SOURCE_ROOTS
            for path in sorted(root.rglob("*.py"))
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
            if _REMOVED in _identifiers(node)
        ]
        assert not offenders
