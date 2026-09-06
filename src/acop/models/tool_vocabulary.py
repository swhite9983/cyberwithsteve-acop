"""Milestone 4 tool-framework vocabulary and code registries.

**This module deliberately defines no permission enum.**
:class:`acop.models.provenance.PermissionClass` was declared in Milestone 1 for
exactly this purpose, and ``audit_event.permission_class`` has carried a column
for it since the first migration. Introducing a second enum here would orphan
every audit row written since M1, so a unit test asserts that nothing in this
module shadows those member names.

Everything here is either an enumerated value stored as ``VARCHAR`` (ADR-0004)
or a **code registry** - a frozen constant that policy reads and that no
database row can influence. The distinction matters: a value in this file is
part of the deployed artifact and changes only through a reviewed pull request.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Final

from acop.auth.principal import Role
from acop.core.redaction import SENSITIVE_KEY_FRAGMENTS
from acop.models.provenance import PermissionClass

# ---------------------------------------------------------------------------
# Tool identity
# ---------------------------------------------------------------------------

#: ``domain.object.verb``, three to five dot-separated segments. Enforced so a
#: tool name sorts usefully, reads well to a human, and makes the blast radius
#: of a namespace obvious at a glance.
TOOL_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){2,4}$"
)

#: ``MAJOR.MINOR``. A breaking input or output change is a MAJOR bump, because
#: an approval is bound to a version and resolving "latest" at request time
#: would let a deploy silently change what a queued approval refers to.
TOOL_VERSION_PATTERN: Final[re.Pattern[str]] = re.compile(r"^\d+\.\d+$")


class ToolLifecycle(StrEnum):
    """Operational state, owned by the database.

    This is the *only* thing the database owns about a tool. Capability
    identity, permission class, schemas, approval policy and adapter binding
    are owned by the Python declaration - see the Capability Binding Invariant
    in :mod:`acop.tools.registry`.
    """

    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    RETIRED = "RETIRED"


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------


class TargetKind(StrEnum):
    """What an invocation acts on.

    Deliberately three cases and no free-form string. An unconstrained network
    target is the same class of hazard as an unconstrained command: policy
    cannot reason about it, audit cannot join it to inventory, and it is a
    server-side request forgery surface.
    """

    NONE = "NONE"
    """ACOP-local. Class 0 only - nothing outside ACOP is touched."""

    ASSET = "ASSET"
    """A Milestone 2 CMDB asset, by id. The normal case."""

    EXTERNAL_REF = "EXTERNAL_REF"
    """A typed, schema-validated locator for something that is genuinely not an
    asset. Available to any permission class: the only constraints on it are
    rule 7's class/target agreement at import and gate 5's requirement that a
    reference actually be present.

    Restricting it by class is deliberately deferred. No catalog tool declares
    it today, so a flag gating Class 2/3 would guard nothing and no test could
    exercise it - and a documented control that nothing enforces is worse than
    an honest statement that the control does not exist yet."""


# ---------------------------------------------------------------------------
# Execution state machine
# ---------------------------------------------------------------------------


class InvocationState(StrEnum):
    """Where an invocation is.

    Two distinctions in here are load-bearing and were the subject of the
    design review:

    ``EXECUTED`` is **not** ``SUCCEEDED``. The adapter returning success and
    the change actually having happened are different facts. Collapsing them
    would make "the restart API returned 200" indistinguishable from "the
    service is running", which is precisely the failure the validation stage
    exists to catch.

    ``EXECUTION_INDETERMINATE`` is **not** ``FAILED``. When a worker is lost
    mid-execution the change may or may not have landed. Recording that as a
    failure is false and invites a retry that double-executes; recording it as
    success is false in the other direction. The honest answer is a state that
    says so, and it is never retried automatically.
    """

    REQUESTED = "REQUESTED"
    REJECTED = "REJECTED"
    AUTHORIZED = "AUTHORIZED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    READY = "READY"
    EXECUTING = "EXECUTING"
    EXECUTED = "EXECUTED"
    VALIDATING = "VALIDATING"
    SUCCEEDED = "SUCCEEDED"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    EXECUTION_INDETERMINATE = "EXECUTION_INDETERMINATE"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"
    SUPERSEDED = "SUPERSEDED"


#: States from which nothing further happens. ``EXECUTION_INDETERMINATE`` is
#: terminal *and* reconcilable: a human records what they determined in
#: ``tool_invocation_reconciliation``, which appends evidence beside the record
#: rather than rewriting a state ACOP did not know at execution time.
TERMINAL_STATES: Final[frozenset[InvocationState]] = frozenset(
    {
        InvocationState.REJECTED,
        InvocationState.DENIED,
        InvocationState.EXPIRED,
        InvocationState.CANCELLED,
        InvocationState.FAILED,
        InvocationState.TIMED_OUT,
        InvocationState.EXECUTION_INDETERMINATE,
        InvocationState.SUCCEEDED,
        InvocationState.VALIDATION_FAILED,
        InvocationState.SUPERSEDED,
    }
)

#: States in which the adapter has been asked to act. Used by the reaper to
#: decide what a lost lease means.
IN_FLIGHT_STATES: Final[frozenset[InvocationState]] = frozenset(
    {InvocationState.EXECUTING, InvocationState.VALIDATING}
)

#: Every legal transition, as ``(from, to)``. Enforced twice: by this constant
#: in the service layer, and by a ``WHERE state = :expected`` predicate on
#: every UPDATE, so an illegal transition is refused by PostgreSQL rather than
#: only by Python.
LEGAL_TRANSITIONS: Final[frozenset[tuple[InvocationState, InvocationState]]] = frozenset(
    {
        (InvocationState.REQUESTED, InvocationState.REJECTED),
        (InvocationState.REQUESTED, InvocationState.AUTHORIZED),
        (InvocationState.AUTHORIZED, InvocationState.AWAITING_APPROVAL),
        (InvocationState.AUTHORIZED, InvocationState.READY),
        (InvocationState.AWAITING_APPROVAL, InvocationState.APPROVED),
        (InvocationState.AWAITING_APPROVAL, InvocationState.DENIED),
        (InvocationState.AWAITING_APPROVAL, InvocationState.EXPIRED),
        (InvocationState.AWAITING_APPROVAL, InvocationState.CANCELLED),
        (InvocationState.APPROVED, InvocationState.READY),
        (InvocationState.READY, InvocationState.EXECUTING),
        (InvocationState.READY, InvocationState.EXPIRED),
        (InvocationState.READY, InvocationState.CANCELLED),
        (InvocationState.EXECUTING, InvocationState.EXECUTED),
        # The final execution gate refuses *after* the claim, because the claim
        # is what makes the row ours to decide about. A refusal there is
        # EXPIRED rather than FAILED: nothing was attempted, so recording a
        # failure would be a false statement about the target.
        (InvocationState.EXECUTING, InvocationState.EXPIRED),
        (InvocationState.EXECUTING, InvocationState.FAILED),
        (InvocationState.EXECUTING, InvocationState.TIMED_OUT),
        (InvocationState.EXECUTING, InvocationState.EXECUTION_INDETERMINATE),
        (InvocationState.EXECUTED, InvocationState.SUCCEEDED),
        (InvocationState.EXECUTED, InvocationState.VALIDATING),
        (InvocationState.VALIDATING, InvocationState.SUCCEEDED),
        # A lost validation lease is *not* indeterminate execution: the
        # adapter already reported success, so what is unknown is the
        # confirmation, not the change. ``validation_outcome`` carries the
        # difference between "we checked and it was wrong" and "we could
        # not check", and both require a human to look.
        (InvocationState.VALIDATING, InvocationState.VALIDATION_FAILED),
    }
    # Any non-terminal state may be superseded by an idempotent replacement.
    | {
        (state, InvocationState.SUPERSEDED)
        for state in InvocationState
        if state not in TERMINAL_STATES
    }
)


def is_legal_transition(source: InvocationState, target: InvocationState) -> bool:
    """Whether ``source -> target`` is permitted."""
    return (source, target) in LEGAL_TRANSITIONS


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------


class GateDecision(StrEnum):
    """The outcome of a policy gate.

    Recorded twice per invocation - once for the request-time authorization and
    once for the final execution gate - because "we allowed it then and refused
    it now" is a materially different record from "we refused it".
    """

    ALLOW = "ALLOW"
    DENY = "DENY"


class ApprovalDecision(StrEnum):
    APPROVED = "APPROVED"
    DENIED = "DENIED"


class ReconciliationDisposition(StrEnum):
    """What a human determined actually happened, after the fact.

    Recorded against an ``EXECUTION_INDETERMINATE`` invocation without altering
    it. The execution record stays as the truthful statement of what ACOP knew
    at the time; this is a later, separately attributed judgement.
    """

    CONFIRMED_SUCCEEDED = "CONFIRMED_SUCCEEDED"
    CONFIRMED_FAILED = "CONFIRMED_FAILED"
    UNKNOWN = "UNKNOWN"


class ValidationOutcome(StrEnum):
    """What an independent post-action observation saw.

    ``INDETERMINATE`` is distinct from ``NOT_CONFIRMED`` because "the service is
    down" and "we could not check" need different human responses. Both lead to
    ``VALIDATION_FAILED``, since both mean a human must look, but the column
    keeps the difference.
    """

    CONFIRMED = "CONFIRMED"
    NOT_CONFIRMED = "NOT_CONFIRMED"
    INDETERMINATE = "INDETERMINATE"


class AdapterOutcome(StrEnum):
    """What an adapter reported. Never a state - the framework decides that."""

    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    TIMEOUT = "TIMEOUT"
    UNAVAILABLE = "UNAVAILABLE"


class IdempotencyKind(StrEnum):
    """How safe it is to run a tool more than once."""

    NATURALLY_IDEMPOTENT = "NATURALLY_IDEMPOTENT"
    """Reading state. Repetition changes nothing."""

    KEYED = "KEYED"
    """Repetition is deduplicated by an idempotency key."""

    NON_IDEMPOTENT = "NON_IDEMPOTENT"
    """Repetition would act twice. ``max_attempts`` is pinned to 1."""


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ToolErrorCategory(StrEnum):
    """Normalized failure categories.

    This is what leaves the process boundary. The raw adapter exception goes to
    the structured log keyed by invocation id and is never persisted, never
    returned, and never shown to a model.
    """

    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    POLICY_DENIED = "POLICY_DENIED"
    CAPABILITY_NOT_BOUND = "CAPABILITY_NOT_BOUND"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVAL_DENIED = "APPROVAL_DENIED"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    APPROVAL_INVALID_ENVELOPE = "APPROVAL_INVALID_ENVELOPE"
    SELF_APPROVAL_FORBIDDEN = "SELF_APPROVAL_FORBIDDEN"
    INVALID_TARGET = "INVALID_TARGET"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    TIMEOUT = "TIMEOUT"
    ADAPTER_UNAVAILABLE = "ADAPTER_UNAVAILABLE"
    TARGET_UNAVAILABLE = "TARGET_UNAVAILABLE"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    EXECUTION_INDETERMINATE = "EXECUTION_INDETERMINATE"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    CANCELLED = "CANCELLED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


#: Categories a framework retry may be attempted for, and only when the tool
#: also declares ``adapter_idempotent``. Everything else is terminal on the
#: first attempt.
RETRYABLE_CATEGORIES: Final[frozenset[ToolErrorCategory]] = frozenset(
    {
        ToolErrorCategory.ADAPTER_UNAVAILABLE,
        ToolErrorCategory.TARGET_UNAVAILABLE,
    }
)

#: A fixed phrase per category. Constructed, not filtered - a deny-list over a
#: raw string fails open the first time an adapter returns something nobody
#: anticipated.
ERROR_PHRASES: Final[dict[ToolErrorCategory, str]] = {
    ToolErrorCategory.AUTHENTICATION: "The caller could not be authenticated.",
    ToolErrorCategory.AUTHORIZATION: "The caller is not permitted to invoke this tool.",
    ToolErrorCategory.POLICY_DENIED: "Policy refused this invocation.",
    ToolErrorCategory.CAPABILITY_NOT_BOUND: (
        "No executable capability is bound to this tool name and version."
    ),
    ToolErrorCategory.APPROVAL_REQUIRED: "This invocation requires human approval.",
    ToolErrorCategory.APPROVAL_DENIED: "An approver denied this invocation.",
    ToolErrorCategory.APPROVAL_EXPIRED: "The approval for this invocation expired.",
    ToolErrorCategory.APPROVAL_INVALID_ENVELOPE: (
        "The approval does not match this invocation's execution envelope."
    ),
    ToolErrorCategory.SELF_APPROVAL_FORBIDDEN: (
        "The requester may not approve their own invocation."
    ),
    ToolErrorCategory.INVALID_TARGET: "The target is unknown or out of scope.",
    ToolErrorCategory.VALIDATION_ERROR: "The request does not satisfy the tool's schema.",
    ToolErrorCategory.IDEMPOTENCY_CONFLICT: (
        "That idempotency key was already used for a different execution envelope."
    ),
    ToolErrorCategory.TIMEOUT: "The tool exceeded its execution deadline.",
    ToolErrorCategory.ADAPTER_UNAVAILABLE: "The adapter could not be reached.",
    ToolErrorCategory.TARGET_UNAVAILABLE: "The target could not be reached.",
    ToolErrorCategory.EXECUTION_FAILED: "The tool reported a failure.",
    ToolErrorCategory.EXECUTION_INDETERMINATE: (
        "Execution was interrupted and the outcome is unknown. "
        "A human must determine what happened."
    ),
    ToolErrorCategory.VALIDATION_FAILED: (
        "The tool executed but the intended change could not be confirmed."
    ),
    ToolErrorCategory.CANCELLED: "The invocation was cancelled.",
    ToolErrorCategory.INTERNAL_ERROR: "An internal error occurred.",
}


class PolicyReason(StrEnum):
    """Machine-readable reason for a gate decision.

    Stored on the invocation so a denial six months old is still explicable
    without reading logs that have rotated away.
    """

    ALLOWED = "allowed"
    CAPABILITY_NOT_BOUND = "capability_not_bound"
    TOOL_DISABLED = "tool_disabled"
    TOOL_RETIRED = "tool_retired"
    PROHIBITED_CAPABILITY = "prohibited_capability"
    SCHEMA_INVALID = "schema_invalid"
    TARGET_INVALID = "target_invalid"
    TARGET_OUT_OF_SCOPE = "target_out_of_scope"
    TARGET_RETIRED = "target_retired"
    ROLE_INSUFFICIENT = "role_insufficient"
    ENVIRONMENT_RESTRICTED = "environment_restricted"
    APPROVAL_MISSING = "approval_missing"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_ENVELOPE_MISMATCH = "approval_envelope_mismatch"
    ENVELOPE_INTEGRITY_FAILED = "envelope_integrity_failed"
    INTERNAL_ERROR = "internal_error"


# ---------------------------------------------------------------------------
# Prohibition — a code registry, unreachable by role, approval or database
# ---------------------------------------------------------------------------

#: Capability categories ACOP will not expose, ever, through any tool.
#:
#: This is a *category* registry rather than only a per-tool flag, and the
#: difference is the point. A flag denies what someone remembered to flag; a
#: category denies a shape of capability. When a future contributor writes
#: ``proxmox.vm.delete``, the honest tag set includes ``vm.delete`` and the
#: tool is refused at import - not at review, and not at 3am.
#:
#: Removing an entry requires an ADR. That is a documentation convention rather
#: than a code constraint, and it is named as such rather than pretended to be
#: enforcement.
PROHIBITED_CAPABILITIES: Final[frozenset[str]] = frozenset(
    {
        "arbitrary.shell",
        "arbitrary.ssh",
        "arbitrary.cli",
        "arbitrary.powershell",
        "arbitrary.sql",
        "arbitrary.winrm",
        "storage.format",
        "vm.delete",
        "container.delete",
        "audit.disable",
        "logging.disable",
        "monitoring.disable",
        "authn.bypass",
        "authz.bypass",
        "firewall.unrestricted",
        "routing.unrestricted",
        "secrets.read",
        "secrets.export",
        "model.generated.command",
    }
)


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------

#: Who may approve, for **every** permission class.
#:
#: ``admin`` is here because it is a superset role, **not** because high-risk
#: work needs an admin. Authorization/clearance and approval authority are
#: separate axes - the same ruling Milestone 3 made when it decided ``approver``
#: is not a clearance. Class 3 strength comes from approval *policy*
#: (``min_approvals``, distinct approvers, shorter TTL, environment
#: restrictions), never from role inflation.
APPROVAL_AUTHORITY_ROLES: Final[frozenset[Role]] = frozenset({Role.APPROVER, Role.ADMIN})

#: The floor a tool's ``required_roles`` must reach for its class. A tool may
#: raise above this; it may never declare below it.
CLASS_MINIMUM_ROLES: Final[dict[PermissionClass, frozenset[Role]]] = {
    PermissionClass.CLASS_0_INFORMATION: frozenset({Role.VIEWER}),
    PermissionClass.CLASS_1_READ_ONLY: frozenset({Role.VIEWER}),
    PermissionClass.CLASS_2_LOW_RISK_CHANGE: frozenset({Role.OPERATOR}),
    PermissionClass.CLASS_3_HIGH_RISK_CHANGE: frozenset({Role.OPERATOR}),
    PermissionClass.PROHIBITED: frozenset({Role.ADMIN}),
}

#: Roles that satisfy a requirement. ``admin`` satisfies everything because it
#: is a superset; nothing else is implied.
ROLE_IMPLICATIONS: Final[dict[Role, frozenset[Role]]] = {
    Role.ADMIN: frozenset({Role.ADMIN, Role.APPROVER, Role.OPERATOR, Role.VIEWER}),
    Role.APPROVER: frozenset({Role.APPROVER, Role.VIEWER}),
    Role.OPERATOR: frozenset({Role.OPERATOR, Role.VIEWER}),
    Role.VIEWER: frozenset({Role.VIEWER}),
}


def effective_roles(roles: frozenset[str]) -> frozenset[Role]:
    """Expand a principal's roles through :data:`ROLE_IMPLICATIONS`."""
    expanded: set[Role] = set()
    for name in roles:
        try:
            role = Role(name)
        except ValueError:
            continue
        expanded |= ROLE_IMPLICATIONS.get(role, frozenset({role}))
    return frozenset(expanded)


# ---------------------------------------------------------------------------
# Input-schema prohibitions — enforced at import, so they fail the build
# ---------------------------------------------------------------------------

#: A tool input field may not name a network locator. Resolving a real address
#: is the adapter's job, from the asset's registered identifiers plus the
#: adapter's own configuration - never from a caller's argument.
NETWORK_LOCATOR_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "host",
        "hostname",
        "ip",
        "ip_address",
        "address",
        "url",
        "uri",
        "endpoint",
        "dsn",
        "connection_string",
        "server",
        "target_host",
    }
)

#: A tool input field may not name a command. There is no generic execution
#: surface in ACOP, and this is one of the three static checks that prove it.
COMMAND_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "command",
        "cmd",
        "commands",
        "script",
        "shell",
        "exec",
        "execute",
        "query",
        "sql",
        "statement",
        "payload",
        "raw",
        "body",
        "powershell",
    }
)

#: A tool input field may not name a secret. This is what makes the persisted
#: canonical input safe to keep, and therefore what makes the execution-envelope
#: digest genuinely recomputable at the final gate. Reuses Milestone 1's
#: fragment list rather than duplicating it.
SECRET_FIELD_FRAGMENTS: Final[tuple[str, ...]] = SENSITIVE_KEY_FRAGMENTS

#: Field names that must never exist on an **invocation request** schema. A
#: caller supplying any of these could weaken policy, name its own class, or
#: smuggle a command, so the schema simply has nowhere to put them.
#:
#: ``envelope`` and ``envelope_digest`` are here because an invocation's
#: envelope is *computed*, never supplied. They are deliberately **not**
#: forbidden on an approval body, where a caller-stated digest does the
#: opposite job: it binds the approver to the version of the request they were
#: actually shown. See :data:`FORBIDDEN_APPROVAL_FIELDS`.
FORBIDDEN_INVOCATION_FIELDS: Final[frozenset[str]] = frozenset(
    {
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
        "self_approval",
        "envelope",
        "envelope_digest",
        "capability_tags",
        "command",
        "script",
        "shell",
        "sql",
        "raw",
    }
)


#: Field names that must never exist on an **approval** schema. Every one of
#: them would let an approver assert its own exemption or rewrite the policy it
#: is being measured against; ``self_approval`` is the one that matters most,
#: and it is derived server-side from configuration, the tool's policy, and
#: whether the approver is the requester.
FORBIDDEN_APPROVAL_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "self_approval",
        "approver_subject",
        "approver_roles",
        "requester_subject",
        "min_approvals",
        "distinct_approvers_required",
        "expires_at",
        "approval_ttl_seconds",
        "permission_class",
        "force",
    }
)


__all__ = [
    "APPROVAL_AUTHORITY_ROLES",
    "CLASS_MINIMUM_ROLES",
    "COMMAND_FIELDS",
    "ERROR_PHRASES",
    "FORBIDDEN_APPROVAL_FIELDS",
    "FORBIDDEN_INVOCATION_FIELDS",
    "IN_FLIGHT_STATES",
    "LEGAL_TRANSITIONS",
    "NETWORK_LOCATOR_FIELDS",
    "PROHIBITED_CAPABILITIES",
    "RETRYABLE_CATEGORIES",
    "ROLE_IMPLICATIONS",
    "SECRET_FIELD_FRAGMENTS",
    "TERMINAL_STATES",
    "TOOL_NAME_PATTERN",
    "TOOL_VERSION_PATTERN",
    "AdapterOutcome",
    "ApprovalDecision",
    "GateDecision",
    "IdempotencyKind",
    "InvocationState",
    "PolicyReason",
    "ReconciliationDisposition",
    "TargetKind",
    "ToolErrorCategory",
    "ToolLifecycle",
    "ValidationOutcome",
    "effective_roles",
    "is_legal_transition",
]
