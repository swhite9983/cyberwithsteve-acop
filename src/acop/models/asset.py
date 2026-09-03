"""Assets and their external identifiers.

The ``asset`` table holds only identity and lifecycle. Everything disputable -
hostname, memory, VLAN membership - is a fact, because in ACOP an attribute is
a claim with a source, a confidence and a verification state, and a claim
cannot be a column.

There is deliberately **no free-form JSONB attribute bag** here. That column
would be unqueryable, unauditable and unscreened, and would become the secrets
dumping ground the requirements forbid.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Numeric,
    String,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID as PostgresUuid  # noqa: N811
from sqlalchemy.orm import Mapped, mapped_column

from acop.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from acop.models.vocabulary import LifecycleState


class Asset(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A thing ACOP knows about.

    Durable identity is ``id`` and nothing else. Every natural key - serial,
    MAC, hostname, Proxmox VMID - is a *correlator* in
    :class:`AssetIdentifier`, because every one of them is reused, reassigned,
    absent or spoofable in a real lab.
    """

    __tablename__ = "asset"

    asset_type: Mapped[str] = mapped_column(String(32), nullable=False)
    lifecycle_state: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=LifecycleState.ACTIVE.value,
        server_default=LifecycleState.ACTIVE.value,
    )
    display_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc=(
            "ACOP's own label for the thing, equivalent to a CI name. NOT the "
            "hostname - that is a discovered fact two sources may disagree "
            "about, whereas this is how a human finds the asset in a list."
        ),
    )
    description: Mapped[str | None] = mapped_column(String(2000), nullable=True)

    merged_into_id: Mapped[uuid.UUID | None] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey("asset.id", name="fk_asset_merged_into_id_asset"),
        nullable=True,
        doc="Set when this asset turned out to be a duplicate of another.",
    )

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    retired_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        CheckConstraint(
            "(lifecycle_state = 'MERGED') = (merged_into_id IS NOT NULL)",
            name="merged_state",
        ),
        CheckConstraint(
            "(lifecycle_state = 'RETIRED') = (retired_at IS NOT NULL)",
            name="retired_state",
        ),
        CheckConstraint(
            "merged_into_id IS DISTINCT FROM id",
            name="no_self_merge",
        ),
        Index("ix_asset_type_state", "asset_type", "lifecycle_state"),
        Index("ix_asset_last_seen", text("last_seen_at DESC")),
        Index("ix_asset_display_name_lower", text("lower(display_name)")),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Asset {self.asset_type} {self.display_name!r} {self.lifecycle_state}>"


class AssetIdentifier(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """An external or hardware identifier correlating a source's view to an asset.

    ``unique_in_namespace`` is denormalised from the code registry so that one
    partial unique index can enforce global uniqueness for the namespaces that
    have it (serial, smbios:uuid) while leaving those that genuinely do not
    (hostname, proxmox:vmid) unconstrained.
    """

    __tablename__ = "asset_identifier"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        PostgresUuid(as_uuid=True),
        ForeignKey(
            "asset.id",
            name="fk_asset_identifier_asset_id_asset",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    namespace: Mapped[str] = mapped_column(String(48), nullable=False)
    value_raw: Mapped[str] = mapped_column(
        String(255), nullable=False, doc="Exactly as the source reported it."
    )
    value_normalized: Mapped[str] = mapped_column(
        String(255), nullable=False, doc="Case- and delimiter-normalised for matching."
    )
    unique_in_namespace: Mapped[bool] = mapped_column(nullable=False)

    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source_id: Mapped[str] = mapped_column(String(255), nullable=False)
    confidence: Mapped[float] = mapped_column(
        Numeric(4, 3, asdecimal=False),
        nullable=False,
        default=1.000,
        server_default="1.000",
    )

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    retired_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="Retiring frees the value for legitimate reuse elsewhere.",
    )

    __table_args__ = (
        CheckConstraint(
            r"namespace ~ '^[a-z0-9]+(:[a-z0-9_-]+)*$'",
            name="namespace_format",
        ),
        CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="confidence",
        ),
        # The deduplication guarantee, enforced by PostgreSQL rather than hope.
        Index(
            "uq_asset_identifier_live_unique",
            "namespace",
            "value_normalized",
            unique=True,
            postgresql_where=text("retired_at IS NULL AND unique_in_namespace"),
        ),
        Index(
            "uq_asset_identifier_asset_ns_value",
            "asset_id",
            "namespace",
            "value_normalized",
            unique=True,
            postgresql_where=text("retired_at IS NULL"),
        ),
        Index(
            "ix_asset_identifier_asset",
            "asset_id",
            postgresql_where=text("retired_at IS NULL"),
        ),
        Index("ix_asset_identifier_lookup", "namespace", "value_normalized"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<AssetIdentifier {self.namespace}={self.value_normalized!r}>"
