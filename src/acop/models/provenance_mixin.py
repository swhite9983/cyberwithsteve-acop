"""Columns shared by every claim ACOP stores.

Facts and relationships are different shapes - a fact has a value, an edge has
two endpoints - but they make the same kind of statement: *this source says
this, with this much confidence, and we trust it this much.* Those columns are
defined once here so the two tables cannot drift apart, and so
:mod:`acop.services.provenance` can implement the trust rules once.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Numeric, String, func
from sqlalchemy.orm import Mapped, mapped_column


class ProvenanceMixin:
    """Where a claim came from and how far it is trusted."""

    statement_class: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        doc="FACT | OBSERVATION | INFERENCE. Derived from source_type, never chosen.",
    )
    source_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        doc="acop.models.provenance.SourceType",
    )
    source_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc=(
            "Which instance of that source, e.g. 'proxmox:pve-01' or "
            "'acop:user:steve'. Part of the live-claim key, so two sources may "
            "hold contradictory live claims simultaneously."
        ),
    )
    confidence: Mapped[float] = mapped_column(
        # asdecimal=False: confidence is inherently approximate, and a float
        # keeps the type annotations honest without a Decimal round-trip.
        Numeric(4, 3, asdecimal=False),
        nullable=False,
        default=1.000,
        server_default="1.000",
    )

    verification_status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        doc="acop.models.provenance.VerificationStatus",
    )

    # Current attribution only. The immutable lineage of every verify, approve
    # and revoke lives in fact_attestation - clearing these on revoke is safe
    # precisely because that record exists.
    verified_by_subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    approved_by_subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class ValidityIntervalMixin:
    """Append-only history via a validity interval.

    ``valid_to IS NULL`` means live. Superseding a claim closes the old
    interval and inserts a new row; nothing is ever rewritten.
    """

    valid_from: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    valid_to: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        doc="NULL means this is the live claim.",
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        doc="When this particular value was first asserted.",
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        doc=(
            "When it was last confirmed. Kept separate from valid_to so the gap "
            "between last confirmation and supersession stays visible."
        ),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
