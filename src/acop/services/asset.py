"""Asset lifecycle and identifier management."""

from __future__ import annotations

import base64
import binascii
import uuid
from datetime import UTC, datetime

from sqlalchemy import func, or_, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from acop.core.exceptions import ConflictError, NotFoundError, ValidationError
from acop.core.logging import get_logger
from acop.models.asset import Asset, AssetIdentifier
from acop.models.fact import AssetFact
from acop.models.provenance import VerificationStatus
from acop.models.relationship import AssetRelationship
from acop.models.vocabulary import TERMINAL_LIFECYCLE_STATES, LifecycleState
from acop.schemas.asset import AssetUpdate, IdentifierInput
from acop.services.identity_resolver import normalise

logger = get_logger(__name__)

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200


def _encode_cursor(created_at: datetime, asset_id: uuid.UUID) -> str:
    raw = f"{created_at.isoformat()}|{asset_id}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def _decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        stamp, ident = raw.split("|", 1)
        return datetime.fromisoformat(stamp), uuid.UUID(ident)
    except (ValueError, binascii.Error) as exc:
        raise ValidationError("Malformed pagination cursor.") from exc


class AssetService:
    """Create, read, update and retire assets."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, asset_id: uuid.UUID) -> Asset:
        asset = await self._session.get(Asset, asset_id)
        if asset is None:
            raise NotFoundError(f"Asset {asset_id} does not exist.")
        return asset

    async def identifiers(
        self, asset_id: uuid.UUID, *, include_retired: bool = True
    ) -> list[AssetIdentifier]:
        query = select(AssetIdentifier).where(AssetIdentifier.asset_id == asset_id)
        if not include_retired:
            query = query.where(AssetIdentifier.retired_at.is_(None))
        query = query.order_by(
            AssetIdentifier.namespace, AssetIdentifier.value_normalized
        )
        return list((await self._session.execute(query)).scalars())

    async def counts(self, asset_id: uuid.UUID) -> tuple[int, int]:
        """Live fact count and live relationship count, for the detail view."""
        facts = await self._session.scalar(
            select(func.count())
            .select_from(AssetFact)
            .where(AssetFact.asset_id == asset_id, AssetFact.valid_to.is_(None))
        )
        edges = await self._session.scalar(
            select(func.count())
            .select_from(AssetRelationship)
            .where(
                or_(
                    AssetRelationship.source_asset_id == asset_id,
                    AssetRelationship.target_asset_id == asset_id,
                ),
                AssetRelationship.valid_to.is_(None),
            )
        )
        return int(facts or 0), int(edges or 0)

    async def list_assets(
        self,
        *,
        asset_type: str | None = None,
        lifecycle_state: str | None = None,
        query_text: str | None = None,
        identifier: str | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        cursor: str | None = None,
    ) -> tuple[list[Asset], str | None]:
        """Keyset-paginated listing.

        Keyset rather than OFFSET so that a page boundary stays stable while
        collectors are inserting - OFFSET silently skips or repeats rows under
        concurrent writes.
        """
        limit = max(1, min(limit, MAX_PAGE_SIZE))
        statement = select(Asset)

        if asset_type:
            statement = statement.where(Asset.asset_type == asset_type)
        if lifecycle_state:
            statement = statement.where(Asset.lifecycle_state == lifecycle_state)
        if query_text:
            statement = statement.where(
                func.lower(Asset.display_name).like(f"{query_text.lower()}%")
            )
        if identifier:
            if ":" not in identifier:
                raise ValidationError(
                    "identifier filter must be 'namespace:value', e.g. 'serial:ABC123'."
                )
            namespace, _, value = identifier.partition(":")
            # A namespace may itself contain ':' (proxmox:vmid). Split on the
            # last colon so 'proxmox:vmid:200' resolves correctly.
            if identifier.count(":") > 1:
                namespace, _, value = identifier.rpartition(":")
            normalised = normalise(
                IdentifierInput(namespace=namespace, value=value)
            ).value_normalized
            statement = statement.where(
                Asset.id.in_(
                    select(AssetIdentifier.asset_id).where(
                        AssetIdentifier.namespace == namespace,
                        AssetIdentifier.value_normalized == normalised,
                        AssetIdentifier.retired_at.is_(None),
                    )
                )
            )

        if cursor:
            after_time, after_id = _decode_cursor(cursor)
            # tuple_() emits a SQL row-value comparison. A plain Python
            # tuple here would compare column objects in Python, not rows in
            # SQL, and silently return the wrong page.
            statement = statement.where(
                tuple_(Asset.created_at, Asset.id) > (after_time, after_id)
            )

        statement = statement.order_by(Asset.created_at, Asset.id).limit(limit + 1)
        rows = list((await self._session.execute(statement)).scalars())

        next_cursor = None
        if len(rows) > limit:
            rows = rows[:limit]
            next_cursor = _encode_cursor(rows[-1].created_at, rows[-1].id)
        return rows, next_cursor

    async def update(self, asset_id: uuid.UUID, payload: AssetUpdate) -> Asset:
        asset = await self.get(asset_id)
        if asset.lifecycle_state in {s.value for s in TERMINAL_LIFECYCLE_STATES}:
            raise ConflictError(
                f"Asset is {asset.lifecycle_state} and cannot be modified.",
                context={"lifecycle_state": asset.lifecycle_state},
            )
        if payload.display_name is not None:
            asset.display_name = payload.display_name
        if payload.description is not None:
            asset.description = payload.description
        if payload.lifecycle_state is not None:
            asset.lifecycle_state = str(payload.lifecycle_state)
        await self._session.flush()
        return asset

    async def retire(self, asset_id: uuid.UUID) -> tuple[Asset, int, int]:
        """Retire an asset, closing its live claims.

        Nothing is deleted. Facts and relationships have their intervals
        closed, so history remains queryable - "what did we know about this
        switch before it was decommissioned" must still answer.
        """
        asset = await self.get(asset_id)
        if asset.lifecycle_state == LifecycleState.RETIRED.value:
            raise ConflictError("Asset is already retired.")
        if asset.lifecycle_state == LifecycleState.MERGED.value:
            raise ConflictError("A merged asset cannot be retired separately.")

        now = datetime.now(UTC)
        closed_facts = 0
        for fact in (
            await self._session.execute(
                select(AssetFact).where(
                    AssetFact.asset_id == asset_id, AssetFact.valid_to.is_(None)
                )
            )
        ).scalars():
            fact.valid_to = now
            # A retired asset's last known claims are stale, not wrong. Only
            # non-authoritative rows are relabelled: overwriting a human's
            # VERIFIED standing would erase attribution the row still carries.
            if fact.verification_status not in {
                VerificationStatus.VERIFIED.value,
                VerificationStatus.APPROVED.value,
            }:
                fact.verification_status = VerificationStatus.STALE.value
            closed_facts += 1

        closed_edges = 0
        for edge in (
            await self._session.execute(
                select(AssetRelationship).where(
                    or_(
                        AssetRelationship.source_asset_id == asset_id,
                        AssetRelationship.target_asset_id == asset_id,
                    ),
                    AssetRelationship.valid_to.is_(None),
                )
            )
        ).scalars():
            edge.valid_to = now
            closed_edges += 1

        asset.lifecycle_state = LifecycleState.RETIRED.value
        asset.retired_at = now
        await self._session.flush()
        return asset, closed_facts, closed_edges

    async def attach_identifier(
        self, asset_id: uuid.UUID, payload: IdentifierInput
    ) -> AssetIdentifier:
        asset = await self.get(asset_id)
        item = normalise(payload)
        now = datetime.now(UTC)

        existing = (
            (
                await self._session.execute(
                    select(AssetIdentifier).where(
                        AssetIdentifier.asset_id == asset.id,
                        AssetIdentifier.namespace == item.namespace,
                        AssetIdentifier.value_normalized == item.value_normalized,
                        AssetIdentifier.retired_at.is_(None),
                    )
                )
            )
            .scalars()
            .first()
        )
        if existing is not None:
            existing.last_seen_at = now
            await self._session.flush()
            return existing

        if item.unique_in_namespace:
            clash = (
                (
                    await self._session.execute(
                        select(AssetIdentifier).where(
                            AssetIdentifier.namespace == item.namespace,
                            AssetIdentifier.value_normalized == item.value_normalized,
                            AssetIdentifier.retired_at.is_(None),
                        )
                    )
                )
                .scalars()
                .first()
            )
            if clash is not None:
                raise ConflictError(
                    f"{item.namespace}:{item.value_normalized} is already "
                    "attached to another asset. Retire it there first.",
                    context={"existing_asset_id": str(clash.asset_id)},
                )

        identifier = AssetIdentifier(
            asset_id=asset.id,
            namespace=item.namespace,
            value_raw=item.value_raw,
            value_normalized=item.value_normalized,
            unique_in_namespace=item.unique_in_namespace,
            source_type=item.source_type,
            source_id=item.source_id,
            confidence=item.confidence,
            first_seen_at=now,
            last_seen_at=now,
        )
        self._session.add(identifier)
        await self._session.flush()
        return identifier

    async def retire_identifier(self, identifier_id: uuid.UUID) -> AssetIdentifier:
        identifier = await self._session.get(AssetIdentifier, identifier_id)
        if identifier is None:
            raise NotFoundError(f"Identifier {identifier_id} does not exist.")
        if identifier.retired_at is not None:
            raise ConflictError("Identifier is already retired.")
        identifier.retired_at = datetime.now(UTC)
        await self._session.flush()
        return identifier


__all__ = ["DEFAULT_PAGE_SIZE", "MAX_PAGE_SIZE", "AssetService"]
