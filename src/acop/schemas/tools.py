"""The Milestone 4 HTTP contract.

Several of this milestone's guarantees are properties of the *schema* rather
than of any code path, and that is the strongest place for them to live because
a schema guarantee does not depend on anyone remembering a check:

* **No request model can weaken policy.** There is no ``permission_class``, no
  ``approval_required``, no ``min_approvals``, no ``timeout_seconds``, no
  ``skip_validation``, no ``force``, no ``adapter_id``, no ``self_approval``.
  A caller has nowhere to put them. The names are listed in
  :data:`~acop.models.tool_vocabulary.FORBIDDEN_INVOCATION_FIELDS` and
  :data:`~acop.models.tool_vocabulary.FORBIDDEN_APPROVAL_FIELDS`, and a
  contract test asserts none of them appears in the generated OpenAPI
  document. ``envelope_digest`` on an *approval* is the deliberate exception
  and does the opposite job: it binds the approver to the version of the
  request they were shown.
* **No request model can express a command.** No ``command``, ``script``,
  ``shell``, ``sql`` or ``raw``. An injected instruction that a model faithfully
  obeyed would have nowhere to go.
* **No response model discloses an adapter.** ``adapter_id`` is absent from
  every descriptor. Knowing which adapter backs a tool tells an attacker where
  to aim, and a caller never needs it.
* **``tool_version`` is required.** No implicit "latest": an approval binds to a
  version, and resolving "latest" at request time would let a deploy silently
  change which code a queued approval refers to.

Every model forbids extra fields, so an undeclared key is a 422 rather than
something quietly ignored.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

_FORBID = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------
# Tool catalog
# ---------------------------------------------------------------------------


class ToolDescriptor(BaseModel):
    """What a caller may know about a tool.

    An allow-list, built field by field from the declaration rather than dumped
    from it. ``adapter_id`` and the raw declaration object are deliberately
    absent - this is what an AI model would eventually be shown, and it must
    contain nothing that helps someone attack the thing behind the tool.
    """

    model_config = _FORBID

    tool_name: str
    tool_version: str
    description: str
    permission_class: str
    approval_required: bool
    min_approvals: int
    validation_required: bool
    target_type: str
    target_asset_types: list[str]
    required_roles: list[str]
    timeout_seconds: float
    idempotency: str
    lifecycle_state: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]


class ToolAdminView(ToolDescriptor):
    """Everything an administrator needs, and still no secrets.

    Adds the operational and provenance fields an admin needs to reason about
    a tool during an incident: why it is disabled, who disabled it, and what
    contract the running code declares. ``adapter_id`` stays absent even here -
    an admin who needs it can read the catalog source, which is the reviewable
    place for it to be.
    """

    model_config = _FORBID

    capability_tags: list[str]
    prohibited: bool
    contract_hash: str
    approval_ttl_seconds: int
    distinct_approvers_required: bool
    sensitivity: str
    first_registered_at: datetime | None = None
    disabled_at: datetime | None = None
    disabled_by_subject: str | None = None
    disabled_reason: str | None = None
    retired_at: datetime | None = None


class ToolLifecycleRequest(BaseModel):
    """Disable or enable one tool version.

    ``reason`` is required for a disable and free text for a human. A disable
    with no stated reason is an unexplained outage to whoever finds it next
    week, so the schema will not accept one.
    """

    model_config = _FORBID

    tool_version: str = Field(min_length=1, max_length=16)
    reason: str = Field(min_length=1, max_length=512)


# ---------------------------------------------------------------------------
# Invocation
# ---------------------------------------------------------------------------


class TargetSpec(BaseModel):
    """What to act on.

    A discriminated shape with exactly three cases and no free-form string.
    There is no ``host``, ``address`` or ``url`` field, because an
    unconstrained network target is the same class of hazard as an
    unconstrained command: policy cannot reason about it, audit cannot join it
    to inventory, and it is a server-side request forgery surface. Real
    addresses are resolved inside the adapter, from the asset's registered
    identifiers.
    """

    model_config = _FORBID

    kind: Literal["NONE", "ASSET", "EXTERNAL_REF"] = "NONE"
    asset_id: uuid.UUID | None = None
    reference: dict[str, Any] | None = Field(
        default=None,
        description=(
            "A typed locator for something that is genuinely not an asset. "
            "Schema-validated by the tool; never a raw address."
        ),
    )

    @model_validator(mode="after")
    def _kind_must_match_what_is_populated(self) -> TargetSpec:
        """``kind`` is honoured, not decorative.

        The service derives the kind it acts on from which field is populated,
        which meant a body declaring ``kind: "ASSET"`` with no ``asset_id``
        was silently treated as ``NONE``. This check makes the two agree by
        construction, so the derivation stays a one-line rule and the caller
        still cannot be quietly misread.

        It lives in the schema rather than in the policy engine because it is a
        *shape* error, not a policy decision: a 422 naming ``asset_id`` tells
        the caller which field to fix, where a target denial would name a
        target they never actually sent.
        """
        if self.kind == "ASSET" and self.asset_id is None:
            raise ValueError("target.kind is ASSET but no asset_id was given.")
        if self.kind == "EXTERNAL_REF" and not self.reference:
            raise ValueError("target.kind is EXTERNAL_REF but no reference was given.")
        if self.kind == "NONE" and (self.asset_id is not None or self.reference):
            raise ValueError(
                "target.kind is NONE but an asset_id or reference was given."
            )
        return self


class InvocationCreate(BaseModel):
    """The single execution entry point's body.

    ``justification`` is required for Class 2/3 by the endpoint, not by this
    model, because the class is a property of the tool rather than of the
    request - and asking the caller to tell us the class would be exactly the
    field this schema exists to refuse.
    """

    model_config = _FORBID

    tool_name: str = Field(min_length=1, max_length=128)
    tool_version: str = Field(min_length=1, max_length=16)
    target: TargetSpec = Field(default_factory=TargetSpec)
    input: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=128)
    justification: str | None = Field(default=None, max_length=2000)


class InvocationRead(BaseModel):
    """An invocation and the policy that applied to it.

    The security snapshot is included because it is the answer to the only
    interesting audit question: not "what does this tool require today" but
    "what did it require when this ran". ``input_canonical`` is safe to return
    because import rule 9 makes it incapable of holding a secret.
    """

    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: uuid.UUID
    tool_name: str
    tool_version: str
    permission_class: str
    state: str
    request_id: str | None = None
    idempotency_key: str | None = None

    approval_required: bool
    min_approvals: int
    approvals_received: int
    distinct_approvers_required: bool
    approval_ttl_seconds: int
    validation_required: bool

    principal_subject: str
    target_kind: str
    target_asset_id: uuid.UUID | None = None

    authorization_decision: str
    authorization_reason: str
    final_gate_decision: str | None = None
    final_gate_reason: str | None = None

    envelope_digest: str
    input_digest: str
    input_canonical: dict[str, Any]

    error_category: str | None = None
    error_detail_sanitized: str | None = None
    validation_outcome: str | None = None

    requested_at: datetime
    approved_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


class InvocationResultRead(BaseModel):
    """The sanitized outcome.

    ``result_summary`` has been through the output allow-list, so it contains
    only fields the tool declared. ``error_detail_sanitized`` is a fixed phrase
    from :data:`~acop.models.tool_vocabulary.ERROR_PHRASES`, never adapter text.
    """

    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: uuid.UUID
    state: str
    result_summary: dict[str, Any] | None = None
    result_digest: str | None = None
    validation_outcome: str | None = None
    validation_detail: dict[str, Any] | None = None
    rollback_hint: dict[str, Any] | None = None
    error_category: str | None = None
    error_detail_sanitized: str | None = None
    finished_at: datetime | None = None


class EnvelopeRead(BaseModel):
    """The approver's review surface.

    The whole envelope and its digest, so an approver can see precisely what
    they are agreeing to - and so they can quote the digest back when they
    approve, which is what proves they acted on this version of the request.
    """

    model_config = _FORBID

    invocation_id: uuid.UUID
    envelope: dict[str, Any]
    envelope_digest: str
    input_digest: str
    permission_class: str
    state: str


class InvocationEventRead(BaseModel):
    """One state transition."""

    model_config = ConfigDict(from_attributes=True, extra="forbid")

    sequence: int
    from_state: str | None = None
    to_state: str
    actor_subject: str | None = None
    reason: str
    detail: dict[str, Any]
    occurred_at: datetime


class ApprovalRead(BaseModel):
    """One approver's decision."""

    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: uuid.UUID
    decision: str
    approver_subject: str
    approver_issuer: str
    self_approval: bool
    justification: str
    approved_envelope_digest: str
    decided_at: datetime
    expires_at: datetime


class ApprovalDecisionRequest(BaseModel):
    """Approve or deny.

    Notice there is no ``self_approval`` field, and there never will be. That
    value is derived server-side from configuration, the tool's policy, and
    whether the approver is the requester. A caller that could assert it would
    be asserting its own exemption from separation of duties.

    ``envelope_digest`` is required, and is the caller stating what they
    reviewed.
    """

    model_config = _FORBID

    envelope_digest: str = Field(min_length=64, max_length=64)
    justification: str = Field(min_length=1, max_length=2000)


class CancelRequest(BaseModel):
    """Withdraw an invocation before it executes."""

    model_config = _FORBID

    reason: str = Field(min_length=1, max_length=512)


class ReconcileRequest(BaseModel):
    """What a human determined about an indeterminate execution.

    ``evidence_ref`` is references only - a ticket id, a log query, a knowledge
    document id. Not captured output, not a device response, not a credential.
    """

    model_config = _FORBID

    disposition: Literal["CONFIRMED_SUCCEEDED", "CONFIRMED_FAILED", "UNKNOWN"]
    justification: str = Field(min_length=1, max_length=2000)
    evidence_ref: dict[str, Any] = Field(default_factory=dict)


class ReconciliationRead(BaseModel):
    """A recorded determination."""

    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: uuid.UUID
    disposition: str
    justification: str
    evidence_ref: dict[str, Any]
    reconciled_by_subject: str
    reconciled_by_issuer: str
    reconciled_at: datetime


__all__ = [
    "ApprovalDecisionRequest",
    "ApprovalRead",
    "CancelRequest",
    "EnvelopeRead",
    "InvocationCreate",
    "InvocationEventRead",
    "InvocationRead",
    "InvocationResultRead",
    "ReconcileRequest",
    "ReconciliationRead",
    "TargetSpec",
    "ToolAdminView",
    "ToolDescriptor",
    "ToolLifecycleRequest",
]
