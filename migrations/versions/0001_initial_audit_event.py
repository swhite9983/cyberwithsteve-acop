"""Initial schema: audit_event.

Milestone 1 creates exactly one table. The CMDB arrives in Milestone 2 and is
not anticipated here with empty tables.

Revision ID: 0001
Revises:
Create Date: 2026-09-03

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_event",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
            comment="When the audited event happened, in UTC.",
        ),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
            comment="When ACOP persisted the record.",
        ),
        sa.Column("principal_subject", sa.String(length=255), nullable=False),
        sa.Column("principal_type", sa.String(length=32), nullable=False),
        sa.Column("principal_issuer", sa.String(length=255), nullable=False),
        sa.Column("auth_method", sa.String(length=32), nullable=False),
        sa.Column("source_address", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=True),
        sa.Column("resource_id", sa.String(length=255), nullable=True),
        sa.Column("permission_class", sa.String(length=32), nullable=True),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("message", sa.String(length=1024), nullable=True),
        sa.Column("request_id", sa.String(length=128), nullable=True),
        sa.Column(
            "context",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_event")),
        comment=(
            "Append-only audit log. No UPDATE or DELETE path exists in the "
            "application; the acop_app database role should not hold those "
            "privileges on this table."
        ),
    )
    op.create_index("ix_audit_event_occurred_at", "audit_event", ["occurred_at"])
    op.create_index(
        "ix_audit_event_principal_occurred",
        "audit_event",
        ["principal_subject", "occurred_at"],
    )
    op.create_index("ix_audit_event_request_id", "audit_event", ["request_id"])
    op.create_index(
        "ix_audit_event_action_occurred", "audit_event", ["action", "occurred_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_audit_event_action_occurred", table_name="audit_event")
    op.drop_index("ix_audit_event_request_id", table_name="audit_event")
    op.drop_index("ix_audit_event_principal_occurred", table_name="audit_event")
    op.drop_index("ix_audit_event_occurred_at", table_name="audit_event")
    op.drop_table("audit_event")
