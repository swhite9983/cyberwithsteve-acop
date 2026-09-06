"""The execution envelope — what an approver actually agreed to.

An approval that means "yes, run something called `test.service.restart`" is
worthless. An approval has to mean "yes, run *this* tool at *this* version,
under *this* permission class, against *this* target, with *these* arguments,
under *this* approval and execution policy" - and it has to be possible to
prove at execution time that none of those changed in between.

The envelope is that statement, and :func:`envelope_digest` is the proof. The
digest is computed once at request time, stored on the invocation, copied onto
every approval, and **recomputed** at the final execution gate. If the two
differ, the approval does not transfer: it is invalidated, not carried forward.

**Why the digest is recomputable at all.** Because import rule 9 forbids
secret-bearing fields in any tool input schema, the canonical input is safe to
persist verbatim - so the row holds the same bytes the digest was taken over.
An earlier draft persisted a redacted input and hashed the raw one, which meant
the final gate could not verify anything. That defect is the reason the secret
rule exists in the form it does.

**Canonicalisation rules**, all of which exist because a digest that varies
with something insignificant is a digest that fails randomly:

* Object keys are sorted. JSON preserves insertion order; a caller sending
  ``{"b":1,"a":2}`` and one sending ``{"a":2,"b":1}`` asked for the same thing.
* Separators are tight and non-ASCII is not escaped, so the encoding is one
  fixed choice rather than the interpreter's default.
* Values come from Pydantic's JSON mode, so a ``datetime`` or ``UUID`` has one
  representation rather than a repr that could change with a library version.
* Sets are sorted into lists. A ``frozenset`` has no stable iteration order.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from acop.models.tool_vocabulary import TargetKind
from acop.tools.contract import ToolDefinition


def canonical_json(value: Any) -> str:
    """Render ``value`` in the one canonical form ACOP hashes."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_encode,
    )


def _encode(value: Any) -> Any:
    """Fallback encoder for the few types JSON does not cover.

    Deliberately narrow. A type that reaches here and is not handled raises,
    which is the correct outcome: silently stringifying an unknown object would
    make the digest depend on that object's ``__str__``.
    """
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, frozenset | set):
        return sorted(value)
    raise TypeError(f"{type(value).__name__} has no canonical JSON form.")


def digest_of(value: Any) -> str:
    """SHA-256 of the canonical rendering of ``value``."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def build_target_block(
    kind: TargetKind,
    *,
    asset_id: uuid.UUID | None = None,
    target_ref: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The target, as the envelope sees it.

    Only the resolved identity goes in - an asset id, or a typed reference ACOP
    validated. A display name is deliberately absent: renaming an asset would
    otherwise invalidate every pending approval against it, which is a
    surprising failure with no security benefit.
    """
    return {
        "kind": kind.value,
        "asset_id": str(asset_id) if asset_id is not None else None,
        "target_ref": target_ref if target_ref else None,
    }


def build_envelope(
    definition: ToolDefinition,
    *,
    canonical_input: dict[str, Any],
    target: dict[str, Any],
) -> dict[str, Any]:
    """Assemble the envelope for one invocation.

    Everything in here is something a change to which should invalidate an
    approval. Everything an approver would not have cared about - the request
    id, the wall-clock time, the requester's display name - is deliberately
    outside it, so an approval is not invalidated by noise.
    """
    return {
        "tool": {
            "name": definition.tool_name,
            "version": definition.tool_version,
            "contract_hash": definition.contract_hash(),
        },
        "permission_class": definition.permission_class.value,
        "target": target,
        "input": canonical_input,
        "execution": definition.execution_parameters(),
        "approval": definition.approval_policy.as_snapshot(),
    }


def envelope_digest(envelope: dict[str, Any]) -> str:
    """The value an approval binds to and the final gate recomputes."""
    return digest_of(envelope)


def input_digest(canonical_input: dict[str, Any]) -> str:
    """A digest of the arguments alone.

    Separate from the envelope digest because the two answer different
    questions. "Did the arguments change?" is useful in an audit query and in
    an idempotency comparison; "did anything an approver agreed to change?"
    is what gates execution.
    """
    return digest_of(canonical_input)


__all__ = [
    "build_envelope",
    "build_target_block",
    "canonical_json",
    "digest_of",
    "envelope_digest",
    "input_digest",
]
