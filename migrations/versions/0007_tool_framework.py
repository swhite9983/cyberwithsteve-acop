"""Milestone 4: the tool framework — registrations, invocations, approvals.

Five tables. Four of them are append-only; the fifth, ``tool_invocation``,
advances through a fixed state machine and is never otherwise rewritten.

Three things in here are load-bearing enough to say out loud:

1. **``tool_registration`` has no ``permission_class`` column.** The permission
   class is owned by the Python declaration and snapshotted onto each
   invocation. A second copy on the lifecycle row would be a second thing that
   can be wrong, and a column that exists is a column something eventually
   reads. This is the database half of the Capability Binding Invariant: a row
   here names a tool's operational state and nothing else, so INSERT on this
   table cannot mint an executable capability.

2. **The CHECK constraints on ``tool_invocation`` are defence in depth, not the
   policy.** Policy lives in the engine. These exist so that a bug which
   somehow produced a Class 3 invocation with ``approval_required`` false
   aborts the transaction instead of executing.

3. **No ``ON DELETE CASCADE`` anywhere, and no DELETE path.** Every foreign key
   is ``RESTRICT``. Deleting an invocation would strand its approvals and its
   transition history, turning an auditable execution into an unexplained one.

The only cross-milestone foreign key is
``tool_invocation.target_asset_id -> asset.id``. It points M4 at M2 and never
back, so M2 remains independently deployable.

Revision ID: 0007
Revises: 0006
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | None = None
depends_on: str | None = None

#: Every permission class. Kept in step with
#: ``acop.models.provenance.PermissionClass``. ``PROHIBITED`` belongs here: the
#: policy engine records it on an invocation for an unbound capability, where
#: there is no declared class to copy.
_PERMISSION_CLASSES = (
    "('CLASS_0_INFORMATION','CLASS_1_READ_ONLY','CLASS_2_LOW_RISK_CHANGE',"
    "'CLASS_3_HIGH_RISK_CHANGE','PROHIBITED')"
)

#: The classes that do *not* require approval, validation and an idempotency
#: key - the complement of
#: ``acop.models.provenance.APPROVAL_REQUIRED_CLASSES``.
#:
#: The three class-agreement CHECKs below are stated against this list in the
#: positive rather than against the change classes in the negative, because
#: ``permission_class NOT IN ('CLASS_2_LOW_RISK_CHANGE',...)`` is satisfied by
#: every string that is not exactly one of them - ``'CLASS_2_LOW_RISK_CHANG'``
#: included. That form accepted a change invocation carrying
#: ``approval_required`` false. The positive form holds an unrecognised class to
#: the requirement instead, and does so without depending on the domain CHECK
#: above existing.
_NON_CHANGE_CLASSES = "('CLASS_0_INFORMATION','CLASS_1_READ_ONLY','PROHIBITED')"

#: Every state the Milestone 4 machine implements, in the order
#: ``acop.models.tool_vocabulary.InvocationState`` declares them.
_STATES = (
    "('REQUESTED','REJECTED','AUTHORIZED','AWAITING_APPROVAL','APPROVED','DENIED',"
    "'READY','EXECUTING','EXECUTED','VALIDATING','SUCCEEDED','VALIDATION_FAILED',"
    "'FAILED','TIMED_OUT','EXECUTION_INDETERMINATE','EXPIRED','CANCELLED',"
    "'SUPERSEDED')"
)

#: The states in which a worker holds a lease. Both are reaped, so both must
#: carry one; an EXECUTING row with no lease would be invisible to the reaper.
_LEASED = "('EXECUTING','VALIDATING')"


def upgrade() -> None:
    _create_tool_registration()
    _create_tool_invocation()
    _create_tool_approval()
    _create_tool_invocation_event()
    _create_tool_invocation_reconciliation()
    # Added after the event table exists, because the reference runs the other
    # way round from every other foreign key here: the invocation points at one
    # of its own events.
    op.create_foreign_key(
        "fk_tool_invocation_final_gate_event_id_tool_invocation_event",
        "tool_invocation",
        "tool_invocation_event",
        ["final_gate_event_id"],
        ["id"],
        ondelete="RESTRICT",
    )


def downgrade() -> None:
    # The cycle has to be broken before either end can be dropped.
    op.drop_constraint(
        "fk_tool_invocation_final_gate_event_id_tool_invocation_event",
        "tool_invocation",
        type_="foreignkey",
    )
    # Reverse dependency order. Children first, because every foreign key is
    # RESTRICT and nothing cascades.
    op.drop_table("tool_invocation_reconciliation")
    op.drop_table("tool_invocation_event")
    op.drop_table("tool_approval")
    op.drop_table("tool_invocation")
    op.drop_table("tool_registration")


# ---------------------------------------------------------------------------
# tool_registration
# ---------------------------------------------------------------------------


def _create_tool_registration() -> None:
    op.create_table(
        "tool_registration",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tool_name", sa.String(128), nullable=False),
        sa.Column("tool_version", sa.String(16), nullable=False),
        sa.Column("contract_hash", sa.String(64), nullable=False),
        sa.Column(
            "lifecycle_state", sa.String(16), nullable=False, server_default="ACTIVE"
        ),
        sa.Column(
            "first_registered_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disabled_by_subject", sa.String(255), nullable=True),
        sa.Column("disabled_reason", sa.String(512), nullable=True),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retired_by_subject", sa.String(255), nullable=True),
        sa.Column("retired_reason", sa.String(512), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tool_name", "tool_version", name="uq_tool_registration_nv"),
        sa.CheckConstraint(
            "lifecycle_state IN ('ACTIVE','DISABLED','RETIRED')", name="lifecycle_state"
        ),
        sa.CheckConstraint(
            "(lifecycle_state = 'DISABLED') = (disabled_at IS NOT NULL)",
            name="disabled_state",
        ),
        sa.CheckConstraint(
            "(lifecycle_state = 'RETIRED') = (retired_at IS NOT NULL)",
            name="retired_state",
        ),
        sa.CheckConstraint(
            "(disabled_at IS NULL) = (disabled_by_subject IS NULL)",
            name="disabled_attribution",
        ),
        sa.CheckConstraint(
            "(disabled_at IS NULL) = (disabled_reason IS NULL)",
            name="disabled_reason_present",
        ),
        comment=(
            "Operational lifecycle of code-declared tools. Carries no permission "
            "class, schema or adapter binding: a row here cannot mint an "
            "executable capability."
        ),
    )
    op.create_index(
        "ix_tool_registration_state",
        "tool_registration",
        ["lifecycle_state", "tool_name"],
    )


# ---------------------------------------------------------------------------
# tool_invocation
# ---------------------------------------------------------------------------


def _create_tool_invocation() -> None:
    op.create_table(
        "tool_invocation",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        # -- identity and correlation ----------------------------------
        sa.Column("request_id", sa.String(128), nullable=True),
        sa.Column("idempotency_key", sa.String(128), nullable=True),
        # -- security snapshot -----------------------------------------
        sa.Column("tool_name", sa.String(128), nullable=False),
        sa.Column("tool_version", sa.String(16), nullable=False),
        sa.Column("tool_registration_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("permission_class", sa.String(32), nullable=False),
        sa.Column("approval_required", sa.Boolean(), nullable=False),
        sa.Column(
            "min_approvals",
            sa.SmallInteger(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column(
            "distinct_approvers_required",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("approval_ttl_seconds", sa.Integer(), nullable=False),
        sa.Column("validation_required", sa.Boolean(), nullable=False),
        sa.Column(
            "effective_approval_policy",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "execution_parameters",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("registry_contract_hash", sa.String(64), nullable=False),
        sa.Column("envelope", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("envelope_digest", sa.String(64), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column(
            "input_canonical", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        # -- principal (M1 four-field neutral identity) ----------------
        sa.Column("principal_subject", sa.String(255), nullable=False),
        sa.Column("principal_type", sa.String(32), nullable=False),
        sa.Column("principal_issuer", sa.String(255), nullable=False),
        sa.Column("auth_method", sa.String(32), nullable=False),
        # -- target -----------------------------------------------------
        sa.Column("target_kind", sa.String(16), nullable=False),
        sa.Column("target_asset_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("target_ref", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        # -- gate decisions ---------------------------------------------
        sa.Column("authorization_decision", sa.String(8), nullable=False),
        sa.Column("authorization_reason", sa.String(128), nullable=False),
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("final_gate_decision", sa.String(8), nullable=True),
        sa.Column("final_gate_reason", sa.String(128), nullable=True),
        sa.Column("final_gate_at", sa.DateTime(timezone=True), nullable=True),
        # The append-only event that recorded the decision. A pointer rather
        # than an event-sourcing framework: tool_invocation_event is already
        # append-only and gap-free per invocation, so every gate evaluation -
        # including a stale worker's - has left a durable row whether or not it
        # won. This column names the one that produced the decision currently on
        # the row; the RESTRICT foreign key, added at the end of upgrade(),
        # makes that pointer unfalsifiable. Nothing is deleted and no prior gate
        # evidence is rewritten.
        sa.Column("final_gate_event_id", postgresql.UUID(as_uuid=True), nullable=True),
        # -- execution ---------------------------------------------------
        sa.Column("state", sa.String(32), nullable=False, server_default="REQUESTED"),
        sa.Column(
            "approvals_received",
            sa.SmallInteger(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("executor_lease_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "attempt_count",
            sa.SmallInteger(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=True),
        # -- outcome ------------------------------------------------------
        sa.Column(
            "result_summary", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
        sa.Column("result_digest", sa.String(64), nullable=True),
        sa.Column("validation_outcome", sa.String(24), nullable=True),
        sa.Column(
            "validation_detail", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
        sa.Column(
            "rollback_hint", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
        sa.Column("error_category", sa.String(40), nullable=True),
        sa.Column("error_detail_sanitized", sa.String(1024), nullable=True),
        # -- timestamps ----------------------------------------------------
        sa.Column(
            "requested_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["tool_registration_id"],
            ["tool_registration.id"],
            name="fk_tool_invocation_tool_registration_id_tool_registration",
            ondelete="RESTRICT",
        ),
        # The only cross-milestone foreign key. M4 -> M2, never back.
        sa.ForeignKeyConstraint(
            ["target_asset_id"],
            ["asset.id"],
            name="fk_tool_invocation_target_asset_id_asset",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "target_kind IN ('NONE','ASSET','EXTERNAL_REF')", name="target_kind"
        ),
        sa.CheckConstraint(
            "(target_kind = 'ASSET') = (target_asset_id IS NOT NULL)",
            name="target_asset",
        ),
        sa.CheckConstraint(
            "(target_kind = 'EXTERNAL_REF') = (target_ref IS NOT NULL)",
            name="target_ref",
        ),
        sa.CheckConstraint(
            "authorization_decision IN ('ALLOW','DENY')", name="authorization_decision"
        ),
        sa.CheckConstraint(
            "final_gate_decision IS NULL OR final_gate_decision IN ('ALLOW','DENY')",
            name="final_gate_decision",
        ),
        sa.CheckConstraint(
            "(final_gate_decision IS NULL) = (final_gate_at IS NULL)",
            name="final_gate_timing",
        ),
        # A decision with no event behind it is an assertion, not a record: the
        # row would say the gate ran without the append-only history to show it
        # ran, which is precisely the claim an incident review cannot check.
        sa.CheckConstraint(
            "(final_gate_decision IS NULL) = (final_gate_event_id IS NULL)",
            name="final_gate_provenance",
        ),
        sa.CheckConstraint("min_approvals >= 1", name="min_approvals"),
        sa.CheckConstraint(
            "approvals_received >= 0 AND approvals_received <= min_approvals",
            name="approvals_received",
        ),
        # Asking two people and accepting the same person twice is not two
        # approvals, so the schema refuses to express it.
        sa.CheckConstraint(
            "min_approvals = 1 OR distinct_approvers_required IS TRUE",
            name="distinct_approvers",
        ),
        sa.CheckConstraint("approval_ttl_seconds > 0", name="approval_ttl"),
        sa.CheckConstraint("attempt_count >= 0", name="attempt_count"),
        sa.CheckConstraint(
            f"(state IN {_LEASED}) = (executor_lease_id IS NOT NULL)",
            name="lease_state",
        ),
        sa.CheckConstraint(
            f"(state IN {_LEASED}) = (lease_expires_at IS NOT NULL)",
            name="lease_expiry",
        ),
        # The two domains. Transitions are already checked in the service layer
        # and again by the ``WHERE state = :expected`` predicate on every UPDATE,
        # but neither reaches this: the transition check is bypassed entirely by
        # direct SQL - a restored backup, a repair script, a compromised
        # credential - and it does not run at all for a typo in future service
        # code that writes a state string no enum member spells. A CAS predicate
        # refuses a wrong *transition*; only the database refuses a value that is
        # not a state at all.
        sa.CheckConstraint(f"state IN {_STATES}", name="state"),
        sa.CheckConstraint(
            f"permission_class IN {_PERMISSION_CLASSES}", name="permission_class"
        ),
        # Defence in depth behind the policy engine, stated in the positive so
        # an unrecognised class is held to the requirement rather than escaping
        # it - see _NON_CHANGE_CLASSES. ``IS TRUE`` rather than ``= TRUE`` so no
        # comparison can return UNKNOWN; both boolean columns are NOT NULL, so
        # three-valued logic could not arise from a NULL left-hand side either,
        # and the hazard was always the unconstrained domain rather than NULLs.
        # A refused invocation is exempt from the key: it never reaches an
        # adapter, so there is no repeated execution for a key to prevent, and
        # burning the caller's key on a refusal would stop them fixing the
        # request and retrying with it.
        sa.CheckConstraint(
            f"permission_class IN {_NON_CHANGE_CLASSES} "
            "OR idempotency_key IS NOT NULL "
            "OR authorization_decision = 'DENY'",
            name="change_requires_idempotency_key",
        ),
        sa.CheckConstraint(
            f"permission_class IN {_NON_CHANGE_CLASSES} OR approval_required IS TRUE",
            name="change_requires_approval",
        ),
        sa.CheckConstraint(
            f"permission_class IN {_NON_CHANGE_CLASSES} OR validation_required IS TRUE",
            name="change_requires_validation",
        ),
        comment=(
            "One tool invocation and the full security policy that applied to it "
            "at request time. Advances through a fixed state machine; the "
            "snapshot columns are never rewritten."
        ),
    )
    # Dispatcher hot path.
    op.create_index(
        "ix_tool_invocation_ready",
        "tool_invocation",
        ["state", "requested_at"],
        postgresql_where=sa.text("state = 'READY'"),
    )
    # Reaper. Covers both leased states, for the same reason the CHECK does.
    op.create_index(
        "ix_tool_invocation_lease",
        "tool_invocation",
        ["lease_expires_at"],
        postgresql_where=sa.text("state IN ('EXECUTING','VALIDATING')"),
    )
    # Approval TTL sweeper.
    op.create_index(
        "ix_tool_invocation_pending",
        "tool_invocation",
        ["requested_at"],
        postgresql_where=sa.text("state = 'AWAITING_APPROVAL'"),
    )
    op.create_index(
        "ix_tool_invocation_principal",
        "tool_invocation",
        ["principal_subject", sa.literal_column("requested_at DESC")],
    )
    op.create_index(
        "ix_tool_invocation_tool",
        "tool_invocation",
        ["tool_name", "tool_version", sa.literal_column("requested_at DESC")],
    )
    op.create_index(
        "ix_tool_invocation_class",
        "tool_invocation",
        ["permission_class", sa.literal_column("requested_at DESC")],
    )
    op.create_index(
        "ix_tool_invocation_target",
        "tool_invocation",
        ["target_asset_id"],
        postgresql_where=sa.text("target_asset_id IS NOT NULL"),
    )
    # Idempotency. A superseded row is excluded so that replacing an invocation
    # does not permanently burn its key.
    op.create_index(
        "uq_tool_invocation_idem",
        "tool_invocation",
        ["idempotency_key"],
        unique=True,
        postgresql_where=sa.text("idempotency_key IS NOT NULL AND state <> 'SUPERSEDED'"),
    )


# ---------------------------------------------------------------------------
# tool_approval
# ---------------------------------------------------------------------------


def _create_tool_approval() -> None:
    op.create_table(
        "tool_approval",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("invocation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("decision", sa.String(16), nullable=False),
        sa.Column("approved_envelope_digest", sa.String(64), nullable=False),
        sa.Column("requester_subject", sa.String(255), nullable=False),
        sa.Column("approver_subject", sa.String(255), nullable=False),
        sa.Column("approver_type", sa.String(32), nullable=False),
        sa.Column("approver_issuer", sa.String(255), nullable=False),
        sa.Column("approver_auth_method", sa.String(32), nullable=False),
        sa.Column(
            "self_approval",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("justification", sa.String(2000), nullable=False),
        sa.Column(
            "decided_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["invocation_id"],
            ["tool_invocation.id"],
            name="fk_tool_approval_invocation_id_tool_invocation",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("decision IN ('APPROVED','DENIED')", name="decision"),
        sa.CheckConstraint("length(trim(justification)) > 0", name="justification"),
        sa.CheckConstraint("expires_at > decided_at", name="expiry_after_decision"),
        # Separation of duties as a database invariant - the third of three
        # layers, behind a schema that cannot express self-approval and a
        # service that refuses it.
        sa.CheckConstraint(
            "approver_subject <> requester_subject OR self_approval IS TRUE",
            name="separation_of_duties",
        ),
        comment=(
            "Append-only approval decisions. No update or delete path exists in "
            "the application."
        ),
    )
    # Two approvals from one person are one approval.
    op.create_index(
        "uq_tool_approval_distinct",
        "tool_approval",
        ["invocation_id", "approver_subject"],
        unique=True,
        postgresql_where=sa.text("decision = 'APPROVED'"),
    )
    op.create_index(
        "ix_tool_approval_invocation", "tool_approval", ["invocation_id", "decided_at"]
    )
    # Every self-approval, cheaply listable for review. Should be empty in
    # production; the index makes proving that a one-row scan.
    op.create_index(
        "ix_tool_approval_self",
        "tool_approval",
        ["decided_at"],
        postgresql_where=sa.text("self_approval IS TRUE"),
    )


# ---------------------------------------------------------------------------
# tool_invocation_event
# ---------------------------------------------------------------------------


def _create_tool_invocation_event() -> None:
    op.create_table(
        "tool_invocation_event",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("invocation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("from_state", sa.String(32), nullable=True),
        sa.Column("to_state", sa.String(32), nullable=False),
        sa.Column("actor_subject", sa.String(255), nullable=True),
        sa.Column("reason", sa.String(128), nullable=False),
        sa.Column(
            "detail",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["invocation_id"],
            ["tool_invocation.id"],
            name="fk_tool_invocation_event_invocation_id_tool_invocation",
            ondelete="RESTRICT",
        ),
        # A per-invocation counter rather than timestamp ordering: two
        # transitions can share a millisecond, and "what happened first" must
        # not depend on clock resolution.
        sa.UniqueConstraint(
            "invocation_id", "sequence", name="uq_tool_invocation_event_sequence"
        ),
        sa.CheckConstraint("sequence >= 1", name="sequence"),
        comment="Append-only state-transition history for a tool invocation.",
    )
    op.create_index(
        "ix_tool_invocation_event_lookup",
        "tool_invocation_event",
        ["invocation_id", "sequence"],
    )


# ---------------------------------------------------------------------------
# tool_invocation_reconciliation
# ---------------------------------------------------------------------------


def _create_tool_invocation_reconciliation() -> None:
    op.create_table(
        "tool_invocation_reconciliation",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("invocation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("disposition", sa.String(24), nullable=False),
        sa.Column("justification", sa.String(2000), nullable=False),
        sa.Column(
            "evidence_ref",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("reconciled_by_subject", sa.String(255), nullable=False),
        sa.Column("reconciled_by_type", sa.String(32), nullable=False),
        sa.Column("reconciled_by_issuer", sa.String(255), nullable=False),
        sa.Column("reconciled_by_auth_method", sa.String(32), nullable=False),
        sa.Column(
            "reconciled_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["invocation_id"],
            ["tool_invocation.id"],
            name="fk_tool_invocation_reconciliation_invocation_id_tool_invocation",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "disposition IN ('CONFIRMED_SUCCEEDED','CONFIRMED_FAILED','UNKNOWN')",
            name="disposition",
        ),
        sa.CheckConstraint("length(trim(justification)) > 0", name="justification"),
        comment=(
            "Append-only human determinations about indeterminate executions. "
            "Never modifies tool_invocation.state."
        ),
    )
    op.create_index(
        "ix_tool_reconciliation_invocation",
        "tool_invocation_reconciliation",
        ["invocation_id", "reconciled_at"],
    )
