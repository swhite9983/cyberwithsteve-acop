"""Tool registrations, invocations, approvals, events and reconciliations.

Five tables, and the boundary between them and the Python tool registry is the
most important thing in this file.

**What the database owns.** Exactly one thing about a tool: its operational
lifecycle - ``ACTIVE``/``DISABLED``/``RETIRED`` - plus who disabled or retired
it, when, and why. That is genuinely operational state: an on-call engineer
must be able to take a misbehaving tool out of service at 3am without a deploy.

**What the database must never own.** Capability identity, permission class,
input and output schemas, approval and validation policy, adapter binding, and
capability tags. Those live in the Python declaration and only there. This is
the Capability Binding Invariant (G5): *a database row alone can never mint an
executable capability.* An attacker with INSERT on ``tool_registration`` gains
the ability to name a tool that does not resolve to an adapter, and nothing
else - every such invocation is refused with ``CAPABILITY_NOT_BOUND``.

Consequently ``tool_registration`` carries **no** ``permission_class`` column.
An earlier draft kept one "for reporting only"; that was removed, because a
column that exists is a column something will eventually read, and a second
copy of a security-significant value is a second thing that can be wrong. The
authoritative class for *policy* is read from the code registry at request
time; the authoritative class for *history* is snapshotted onto the invocation,
which is what reporting queries should use anyway.

**Invocations are the historical evidence.** ``tool_invocation`` copies the
tool's name, version and full security policy at the moment of the request
rather than joining to the registration. A join would make a three-year-old
audit answer change when someone edits a tool declaration today. The columns
are denormalised on purpose, for the same reason the M1 audit log denormalises
principal identity.

**Append-only.** No table here has an UPDATE path except ``tool_invocation``
itself, which advances through its state machine and is never rewritten
otherwise. Approvals, events and reconciliations have no update or delete
method anywhere in the service layer, and every foreign key is
``ON DELETE RESTRICT``.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PostgresUuid  # noqa: N811
from sqlalchemy.orm import Mapped, mapped_column

from acop.models.base import Base, UUIDPrimaryKeyMixin
from acop.models.provenance import APPROVAL_REQUIRED_CLASSES, PermissionClass
from acop.models.tool_vocabulary import InvocationState, ToolLifecycle


def _sql_list(values: Iterable[str]) -> str:
    """Render an ordered SQL ``IN`` list, so a literal is never retyped."""
    return "(" + ",".join(f"'{value}'" for value in values) + ")"


#: Every permission class the platform defines, as a SQL list. Derived from
#: :class:`acop.models.provenance.PermissionClass` rather than transcribed, so
#: the database's idea of the domain cannot fall behind the code's.
_PERMISSION_CLASSES_SQL = _sql_list(cls.value for cls in PermissionClass)

#: The classes that do *not* require approval, validation and an idempotency
#: key - the complement of
#: :data:`acop.models.provenance.APPROVAL_REQUIRED_CLASSES`, written once so the
#: three class-agreement CHECK constraints below cannot drift apart.
#:
#: The constraints are phrased against this list in the *positive*
#: (``permission_class IN (...) OR approval_required IS TRUE``) rather than
#: against the change classes in the negative. The difference is what happens to
#: a value nobody anticipated: ``permission_class NOT IN
#: ('CLASS_2_LOW_RISK_CHANGE',...)`` is satisfied by ``'CLASS_2_LOW_RISK_CHANG'``,
#: so a single dropped character bought a change invocation a full exemption from
#: approval, validation and idempotency. The positive form makes an unknown class
#: *require* all three instead, and does so without depending on
#: ``ck_tool_invocation_permission_class`` existing.
_NON_CHANGE_CLASSES_SQL = _sql_list(
    cls.value for cls in PermissionClass if cls not in APPROVAL_REQUIRED_CLASSES
)

#: Every state the Milestone 4 machine implements, in enum order. Derived from
#: :class:`acop.models.tool_vocabulary.InvocationState` for the same reason as
#: the class list: a hand-copied spelling is a second place to be wrong.
_INVOCATION_STATES_SQL = _sql_list(state.value for state in InvocationState)

#: The states in which a worker holds a lease. Both ``EXECUTING`` and
#: ``VALIDATING`` are reaped, so both must carry one - see
#: :data:`acop.models.tool_vocabulary.IN_FLIGHT_STATES`.
_LEASED_STATES_SQL = "('EXECUTING','VALIDATING')"


class ToolRegistration(UUIDPrimaryKeyMixin, Base):
    """The operational lifecycle of one code-declared tool version.

    Rows are created by reconciliation at startup, from the code registry, and
    never by an API. Reconciliation inserts what code declares and marks
    ``RETIRED`` what code no longer declares; it never deletes, because a
    retired registration is still referenced by every invocation that used it.
    """

    __tablename__ = "tool_registration"

    tool_name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        doc="Dotted capability name, e.g. 'acop.diagnostic.echo'.",
    )
    tool_version: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        doc="MAJOR.MINOR. An approval binds to a version, so 'latest' does not exist.",
    )
    contract_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        doc=(
            "SHA-256 of the code declaration's canonical contract. Recorded so "
            "reconciliation can refuse a contract that changed without a version "
            "bump - which would silently redefine what a queued approval means. "
            "Never consulted by policy; policy reads the code registry."
        ),
    )
    lifecycle_state: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=ToolLifecycle.ACTIVE.value,
        server_default=ToolLifecycle.ACTIVE.value,
        doc="ACTIVE | DISABLED | RETIRED. The only tool attribute the database owns.",
    )
    first_registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    disabled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    disabled_by_subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    disabled_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    retired_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    retired_by_subject: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        doc="NULL when reconciliation retired it because code stopped declaring it.",
    )
    retired_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("tool_name", "tool_version", name="uq_tool_registration_nv"),
        CheckConstraint(
            "lifecycle_state IN ('ACTIVE','DISABLED','RETIRED')", name="lifecycle_state"
        ),
        CheckConstraint(
            "(lifecycle_state = 'DISABLED') = (disabled_at IS NOT NULL)",
            name="disabled_state",
        ),
        CheckConstraint(
            "(lifecycle_state = 'RETIRED') = (retired_at IS NOT NULL)",
            name="retired_state",
        ),
        # A disable without an attributed actor and a stated reason is an
        # unexplained outage six months later, so the schema will not accept one.
        CheckConstraint(
            "(disabled_at IS NULL) = (disabled_by_subject IS NULL)",
            name="disabled_attribution",
        ),
        CheckConstraint(
            "(disabled_at IS NULL) = (disabled_reason IS NULL)",
            name="disabled_reason_present",
        ),
        Index("ix_tool_registration_state", "lifecycle_state", "tool_name"),
        {
            "comment": (
                "Operational lifecycle of code-declared tools. Carries no "
                "permission class, schema or adapter binding: a row here cannot "
                "mint an executable capability."
            )
        },
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<ToolRegistration {self.tool_name}@{self.tool_version} "
            f"{self.lifecycle_state}>"
        )


class ToolInvocation(UUIDPrimaryKeyMixin, Base):
    """One request to execute one tool against one target.

    The security snapshot in the middle of this table is the point of the whole
    milestone. Everything policy decided at request time is frozen here, so
    that the record remains a truthful statement of what ACOP knew and applied
    at that moment, whatever the code declares later.
    """

    __tablename__ = "tool_invocation"

    # -- Identity and correlation ---------------------------------------
    request_id: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        doc="M1 request correlation id; joins this row to its audit events.",
    )
    idempotency_key: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        doc=(
            "Caller-supplied replay key. Mandatory for Class 2/3: without it a "
            "retried POST after a lost response would act twice."
        ),
    )

    # -- Security snapshot ----------------------------------------------
    # Copied, never joined. A three-year-old audit answer must not change
    # because someone edited a tool declaration this morning.
    tool_name: Mapped[str] = mapped_column(String(128), nullable=False)
    tool_version: Mapped[str] = mapped_column(String(16), nullable=False)
    tool_registration_id: Mapped[uuid.UUID] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "tool_registration.id",
            name="fk_tool_invocation_tool_registration_id_tool_registration",
            ondelete="RESTRICT",
        ),
        nullable=False,
        doc="Which lifecycle row was current. Convenience only; never a policy read.",
    )
    permission_class: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        doc=(
            "The effective class at request time, from the code registry. This "
            "column - not tool_registration - is the historical authority, and "
            "is what reporting should group by."
        ),
    )
    approval_required: Mapped[bool] = mapped_column(Boolean, nullable=False)
    min_approvals: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, default=1, server_default=text("1")
    )
    distinct_approvers_required: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    approval_ttl_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    validation_required: Mapped[bool] = mapped_column(Boolean, nullable=False)
    effective_approval_policy: Mapped[dict[str, Any]] = mapped_column(
        JSONB(none_as_null=True),
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
        doc="The whole approval policy as applied, including required roles.",
    )
    execution_parameters: Mapped[dict[str, Any]] = mapped_column(
        JSONB(none_as_null=True),
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
        doc="Timeout, max attempts, idempotency kind - as applied, not as declared now.",
    )
    registry_contract_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        doc="Contract hash of the declaration this invocation was validated against.",
    )
    envelope: Mapped[dict[str, Any]] = mapped_column(
        JSONB(none_as_null=True),
        nullable=False,
        doc=(
            "The canonical execution envelope: tool identity and version, "
            "permission class, target, canonical validated input, execution "
            "parameters and approval policy."
        ),
    )
    envelope_digest: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        doc=(
            "SHA-256 over the canonical envelope. An approval is bound to this "
            "value, and the final execution gate recomputes it - so a change "
            "between approval and execution invalidates the approval rather than "
            "riding along with it."
        ),
    )
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    input_canonical: Mapped[dict[str, Any]] = mapped_column(
        JSONB(none_as_null=True),
        nullable=False,
        doc=(
            "The validated input, canonically ordered. Safe to persist verbatim "
            "because import rule 9 forbids secret-bearing fields in any tool "
            "input schema; that is precisely what makes envelope_digest "
            "recomputable at the final gate."
        ),
    )

    # -- Principal (M1 four-field neutral identity) ---------------------
    principal_subject: Mapped[str] = mapped_column(String(255), nullable=False)
    principal_type: Mapped[str] = mapped_column(String(32), nullable=False)
    principal_issuer: Mapped[str] = mapped_column(String(255), nullable=False)
    auth_method: Mapped[str] = mapped_column(String(32), nullable=False)

    # -- Target ----------------------------------------------------------
    target_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    target_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "asset.id",
            name="fk_tool_invocation_target_asset_id_asset",
            ondelete="RESTRICT",
        ),
        nullable=True,
        doc="The only cross-milestone foreign key: M4 points at M2, never back.",
    )
    target_ref: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB(none_as_null=True),
        nullable=True,
        doc="Typed, schema-validated locator for a genuinely non-asset target.",
    )

    # -- Gate decisions ---------------------------------------------------
    # Two of them, because "we allowed it then and refused it now" is a
    # materially different record from "we refused it".
    authorization_decision: Mapped[str] = mapped_column(String(8), nullable=False)
    authorization_reason: Mapped[str] = mapped_column(String(128), nullable=False)
    authorized_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    final_gate_decision: Mapped[str | None] = mapped_column(String(8), nullable=True)
    final_gate_reason: Mapped[str | None] = mapped_column(String(128), nullable=True)
    final_gate_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    final_gate_event_id: Mapped[uuid.UUID | None] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "tool_invocation_event.id",
            name="fk_tool_invocation_final_gate_event_id_tool_invocation_event",
            ondelete="RESTRICT",
        ),
        nullable=True,
        doc=(
            "The append-only event that recorded this decision. A pointer rather "
            "than an event-sourcing framework: tool_invocation_event is already "
            "append-only and gap-free per invocation, so every gate evaluation - "
            "including a stale worker's - has left a durable row whether or not "
            "it won. This column names the one that produced the decision now on "
            "the row, and the RESTRICT foreign key makes that pointer "
            "unfalsifiable: nothing is deleted and no prior gate evidence is "
            "rewritten to make the current answer look inevitable."
        ),
    )

    # -- Execution --------------------------------------------------------
    state: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=InvocationState.REQUESTED.value,
        server_default=InvocationState.REQUESTED.value,
    )
    approvals_received: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, default=0, server_default=text("0")
    )
    executor_lease_id: Mapped[uuid.UUID | None] = mapped_column(
        PostgresUuid(as_uuid=True),
        nullable=True,
        doc="Identifies the worker holding the claim, so a reaper can tell whose.",
    )
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    attempt_count: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, default=0, server_default=text("0")
    )
    deadline_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # -- Outcome ----------------------------------------------------------
    result_summary: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB(none_as_null=True),
        nullable=True,
        doc="Sanitized, schema-validated adapter output. Never a raw response.",
    )
    result_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    validation_outcome: Mapped[str | None] = mapped_column(String(24), nullable=True)
    validation_detail: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB(none_as_null=True), nullable=True
    )
    rollback_hint: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB(none_as_null=True),
        nullable=True,
        doc="Advisory text for a human. ACOP performs no automatic rollback.",
    )
    error_category: Mapped[str | None] = mapped_column(String(40), nullable=True)
    error_detail_sanitized: Mapped[str | None] = mapped_column(
        String(1024),
        nullable=True,
        doc=(
            "A fixed phrase from ERROR_PHRASES, never adapter text. The raw "
            "exception goes to the structured log keyed by this row's id."
        ),
    )

    # -- Timestamps --------------------------------------------------------
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    validated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "target_kind IN ('NONE','ASSET','EXTERNAL_REF')", name="target_kind"
        ),
        CheckConstraint(
            "(target_kind = 'ASSET') = (target_asset_id IS NOT NULL)",
            name="target_asset",
        ),
        CheckConstraint(
            "(target_kind = 'EXTERNAL_REF') = (target_ref IS NOT NULL)",
            name="target_ref",
        ),
        CheckConstraint(
            "authorization_decision IN ('ALLOW','DENY')", name="authorization_decision"
        ),
        CheckConstraint(
            "final_gate_decision IS NULL OR final_gate_decision IN ('ALLOW','DENY')",
            name="final_gate_decision",
        ),
        CheckConstraint(
            "(final_gate_decision IS NULL) = (final_gate_at IS NULL)",
            name="final_gate_timing",
        ),
        # A decision with no event behind it is an assertion, not a record: the
        # row would say the gate ran without the append-only history to show it
        # ran, which is exactly the claim an incident review cannot check.
        CheckConstraint(
            "(final_gate_decision IS NULL) = (final_gate_event_id IS NULL)",
            name="final_gate_provenance",
        ),
        CheckConstraint("min_approvals >= 1", name="min_approvals"),
        CheckConstraint(
            "approvals_received >= 0 AND approvals_received <= min_approvals",
            name="approvals_received",
        ),
        # Asking two people and accepting the same person twice is not two
        # approvals, so the schema refuses to express it.
        CheckConstraint(
            "min_approvals = 1 OR distinct_approvers_required IS TRUE",
            name="distinct_approvers",
        ),
        CheckConstraint("approval_ttl_seconds > 0", name="approval_ttl"),
        CheckConstraint("attempt_count >= 0", name="attempt_count"),
        # A lease exists exactly while a worker holds the row. Both in-flight
        # states are reaped, so both must carry one; an EXECUTING row with no
        # lease would be invisible to the reaper and hang for ever.
        CheckConstraint(
            f"(state IN {_LEASED_STATES_SQL}) = (executor_lease_id IS NOT NULL)",
            name="lease_state",
        ),
        CheckConstraint(
            f"(state IN {_LEASED_STATES_SQL}) = (lease_expires_at IS NOT NULL)",
            name="lease_expiry",
        ),
        # The two domains. Transitions are already checked by the service layer
        # and again by the ``WHERE state = :expected`` predicate on every UPDATE,
        # but neither reaches this: the transition check is bypassed entirely by
        # direct SQL - a restored backup, a migration script, a compromised
        # credential - and it does not run at all for a typo in future service
        # code that writes a state string no enum member spells. A CAS predicate
        # refuses a wrong *transition*; only the database refuses a value that is
        # not a state.
        CheckConstraint(f"state IN {_INVOCATION_STATES_SQL}", name="state"),
        # All five classes are legitimate snapshots. PROHIBITED included: the
        # policy engine records it for an unbound capability, where there is no
        # declared class to copy and refusing to name one would lose the record.
        CheckConstraint(
            f"permission_class IN {_PERMISSION_CLASSES_SQL}", name="permission_class"
        ),
        # The three class agreements. Each is defence in depth behind the policy
        # engine: if a bug ever let a Class 3 invocation be written with
        # approval_required false, the transaction fails rather than executing.
        # Each is stated in the positive - see _NON_CHANGE_CLASSES_SQL - so an
        # unrecognised class is held to the requirement rather than escaping it.
        # ``IS TRUE`` rather than ``= TRUE`` so no comparison can return UNKNOWN;
        # the boolean columns are NOT NULL, so three-valued logic could not arise
        # from a NULL left-hand side either, and the real hazard was always the
        # unconstrained domain rather than NULLs.
        # A refused invocation is exempt from the key, and deliberately so: it
        # never reaches an adapter, so there is no repeated execution for a key
        # to prevent, and burning the caller's key on a refusal would stop them
        # fixing the request and retrying with it.
        CheckConstraint(
            f"permission_class IN {_NON_CHANGE_CLASSES_SQL} "
            "OR idempotency_key IS NOT NULL "
            "OR authorization_decision = 'DENY'",
            name="change_requires_idempotency_key",
        ),
        CheckConstraint(
            f"permission_class IN {_NON_CHANGE_CLASSES_SQL} OR approval_required IS TRUE",
            name="change_requires_approval",
        ),
        CheckConstraint(
            f"permission_class IN {_NON_CHANGE_CLASSES_SQL} "
            "OR validation_required IS TRUE",
            name="change_requires_validation",
        ),
        # Dispatcher hot path: one small index, always the same shape.
        Index(
            "ix_tool_invocation_ready",
            "state",
            "requested_at",
            postgresql_where=text("state = 'READY'"),
        ),
        # Reaper. Covers both leased states for the same reason the CHECK does.
        Index(
            "ix_tool_invocation_lease",
            "lease_expires_at",
            postgresql_where=text("state IN ('EXECUTING','VALIDATING')"),
        ),
        # Approval TTL sweeper.
        Index(
            "ix_tool_invocation_pending",
            "requested_at",
            postgresql_where=text("state = 'AWAITING_APPROVAL'"),
        ),
        Index(
            "ix_tool_invocation_principal",
            "principal_subject",
            text("requested_at DESC"),
        ),
        Index(
            "ix_tool_invocation_tool",
            "tool_name",
            "tool_version",
            text("requested_at DESC"),
        ),
        Index("ix_tool_invocation_class", "permission_class", text("requested_at DESC")),
        Index(
            "ix_tool_invocation_target",
            "target_asset_id",
            postgresql_where=text("target_asset_id IS NOT NULL"),
        ),
        # Idempotency. A superseded row is excluded so that replacing an
        # invocation does not permanently burn its key.
        Index(
            "uq_tool_invocation_idem",
            "idempotency_key",
            unique=True,
            postgresql_where=text(
                "idempotency_key IS NOT NULL AND state <> 'SUPERSEDED'"
            ),
        ),
        {
            "comment": (
                "One tool invocation and the full security policy that applied "
                "to it at request time. Advances through a fixed state machine; "
                "the snapshot columns are never rewritten."
            )
        },
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<ToolInvocation {self.tool_name}@{self.tool_version} state={self.state}>"


class ToolApproval(UUIDPrimaryKeyMixin, Base):
    """One approver's decision on one invocation. Append-only.

    ``requester_subject`` is denormalised from the invocation for one reason:
    it lets separation of duties be a database CHECK rather than only a service
    rule. That is the third of three layers - the API cannot express
    self-approval, the service refuses it, and the database rejects the row.
    """

    __tablename__ = "tool_approval"

    invocation_id: Mapped[uuid.UUID] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "tool_invocation.id",
            name="fk_tool_approval_invocation_id_tool_invocation",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    approved_envelope_digest: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        doc=(
            "What the approver actually agreed to. The final gate compares this "
            "against the invocation's recomputed envelope digest, so an approval "
            "cannot be carried over to a changed request."
        ),
    )
    requester_subject: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="Denormalised from the invocation so the SoD CHECK below can exist.",
    )
    approver_subject: Mapped[str] = mapped_column(String(255), nullable=False)
    approver_type: Mapped[str] = mapped_column(String(32), nullable=False)
    approver_issuer: Mapped[str] = mapped_column(String(255), nullable=False)
    approver_auth_method: Mapped[str] = mapped_column(String(32), nullable=False)
    self_approval: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
        doc=(
            "Derived server-side only, never accepted from a caller. True is "
            "possible solely in a non-production configuration that explicitly "
            "permits it; production refuses to start with it enabled."
        ),
    )
    justification: Mapped[str] = mapped_column(String(2000), nullable=False)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        doc="An approval that never expires is a standing grant, so every one has a TTL.",
    )

    __table_args__ = (
        CheckConstraint("decision IN ('APPROVED','DENIED')", name="decision"),
        CheckConstraint("length(trim(justification)) > 0", name="justification"),
        CheckConstraint("expires_at > decided_at", name="expiry_after_decision"),
        # Separation of duties as a database invariant.
        CheckConstraint(
            "approver_subject <> requester_subject OR self_approval IS TRUE",
            name="separation_of_duties",
        ),
        # Two approvals from one person are one approval.
        Index(
            "uq_tool_approval_distinct",
            "invocation_id",
            "approver_subject",
            unique=True,
            postgresql_where=text("decision = 'APPROVED'"),
        ),
        Index("ix_tool_approval_invocation", "invocation_id", "decided_at"),
        # Every self-approval, cheaply listable for review. It should be empty
        # in production; an index makes proving that a one-row scan.
        Index(
            "ix_tool_approval_self",
            "decided_at",
            postgresql_where=text("self_approval IS TRUE"),
        ),
        {
            "comment": (
                "Append-only approval decisions. No update or delete path "
                "exists in the application."
            )
        },
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<ToolApproval {self.decision} by={self.approver_subject}>"


class ToolInvocationEvent(UUIDPrimaryKeyMixin, Base):
    """One state transition. Append-only, gap-free, ordered.

    ``sequence`` is a per-invocation counter rather than a timestamp ordering
    because two transitions can share a millisecond, and "what happened first"
    must not depend on clock resolution. The unique constraint makes a
    concurrent double-write a constraint violation rather than a silently
    reordered history.
    """

    __tablename__ = "tool_invocation_event"

    invocation_id: Mapped[uuid.UUID] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "tool_invocation.id",
            name="fk_tool_invocation_event_invocation_id_tool_invocation",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    from_state: Mapped[str | None] = mapped_column(
        String(32), nullable=True, doc="NULL on creation."
    )
    to_state: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_subject: Mapped[str | None] = mapped_column(
        String(255), nullable=True, doc="NULL for system and reaper transitions."
    )
    reason: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        doc="A PolicyReason or a fixed system reason. Never free text from an adapter.",
    )
    detail: Mapped[dict[str, Any]] = mapped_column(
        JSONB(none_as_null=True),
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
        doc="Redacted structured detail. Never secrets, never raw adapter output.",
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "invocation_id", "sequence", name="uq_tool_invocation_event_sequence"
        ),
        CheckConstraint("sequence >= 1", name="sequence"),
        Index("ix_tool_invocation_event_lookup", "invocation_id", "sequence"),
        {"comment": "Append-only state-transition history for a tool invocation."},
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<ToolInvocationEvent {self.sequence} {self.from_state}->{self.to_state}>"


class ToolInvocationReconciliation(UUIDPrimaryKeyMixin, Base):
    """A human's after-the-fact determination about an indeterminate execution.

    This table exists because ``EXECUTION_INDETERMINATE`` must stay truthful.
    When a worker is lost mid-execution, ACOP genuinely does not know whether
    the change landed, and rewriting that record later - once a human has gone
    and looked - would replace what ACOP knew at execution time with something
    it did not know. So the determination is *appended beside* the execution
    record and attributed to whoever made it. ``tool_invocation.state`` is not
    modified, ever, by anything in this table's service.

    It is deliberately not a workflow system. There is no assignment, no
    status, no queue, no notification: one row, one attributed judgement, one
    justification, and an optional reference to whatever evidence the person
    looked at.
    """

    __tablename__ = "tool_invocation_reconciliation"

    invocation_id: Mapped[uuid.UUID] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "tool_invocation.id",
            name="fk_tool_invocation_reconciliation_invocation_id_tool_invocation",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    disposition: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        doc="CONFIRMED_SUCCEEDED | CONFIRMED_FAILED | UNKNOWN.",
    )
    justification: Mapped[str] = mapped_column(String(2000), nullable=False)
    evidence_ref: Mapped[dict[str, Any]] = mapped_column(
        JSONB(none_as_null=True),
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
        doc=(
            "Safe reference metadata for what was examined - a ticket id, a "
            "log query, a knowledge document id. References only: no captured "
            "output, no credentials, no raw device response."
        ),
    )
    # Full M1 four-field attribution: who decided, and on whose authority.
    reconciled_by_subject: Mapped[str] = mapped_column(String(255), nullable=False)
    reconciled_by_type: Mapped[str] = mapped_column(String(32), nullable=False)
    reconciled_by_issuer: Mapped[str] = mapped_column(String(255), nullable=False)
    reconciled_by_auth_method: Mapped[str] = mapped_column(String(32), nullable=False)
    reconciled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "disposition IN ('CONFIRMED_SUCCEEDED','CONFIRMED_FAILED','UNKNOWN')",
            name="disposition",
        ),
        CheckConstraint("length(trim(justification)) > 0", name="justification"),
        Index("ix_tool_reconciliation_invocation", "invocation_id", "reconciled_at"),
        {
            "comment": (
                "Append-only human determinations about indeterminate "
                "executions. Never modifies tool_invocation.state."
            )
        },
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<ToolInvocationReconciliation {self.disposition} "
            f"by={self.reconciled_by_subject}>"
        )


__all__ = [
    "ToolApproval",
    "ToolInvocation",
    "ToolInvocationEvent",
    "ToolInvocationReconciliation",
    "ToolRegistration",
]
