"""Relationship assertion, retirement and depth-1 traversal."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from acop.core.exceptions import ConflictError, NotFoundError, VocabularyError
from acop.core.logging import get_logger
from acop.models.asset import Asset
from acop.models.provenance import SourceType
from acop.models.relationship import AssetRelationship
from acop.models.vocabulary import RELATIONSHIP_SPECS, AssetType, RelationshipType
from acop.schemas.relationship import Neighbour, RelationshipAssert
from acop.services.provenance import default_status_for, statement_class_for

logger = get_logger(__name__)

CREATED = "CREATED"
TOUCHED = "TOUCHED"


class RelationshipService:
    """The write and read path for edges between assets."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def assert_relationship(
        self, payload: RelationshipAssert
    ) -> tuple[str, AssetRelationship, bool]:
        """Assert an edge, canonicalising symmetric endpoints.

        Returns ``(outcome, relationship, canonicalised)``.
        """
        rel_type = RelationshipType(str(payload.relationship_type))
        spec = RELATIONSHIP_SPECS[rel_type]

        if payload.source_asset_id == payload.target_asset_id:
            raise VocabularyError(
                "An asset cannot be related to itself.",
                context={"relationship_type": rel_type.value},
            )

        source = await self._require_asset(payload.source_asset_id)
        target = await self._require_asset(payload.target_asset_id)

        if not spec.permits(AssetType(source.asset_type), AssetType(target.asset_type)):
            raise VocabularyError(
                f"{rel_type.value} does not join {source.asset_type} to "
                f"{target.asset_type}.",
                context={
                    "relationship_type": rel_type.value,
                    "source_asset_type": source.asset_type,
                    "target_asset_type": target.asset_type,
                },
            )

        source_id, target_id = payload.source_asset_id, payload.target_asset_id
        canonicalised = False
        if spec.symmetric and source_id > target_id:
            # One physical link, one row. Canonical UUID order makes the
            # swapped duplicate impossible rather than merely discouraged.
            source_id, target_id = target_id, source_id
            canonicalised = True

        source_type = SourceType(str(payload.source_type))
        now = datetime.now(UTC)

        live = (
            (
                await self._session.execute(
                    select(AssetRelationship).where(
                        AssetRelationship.source_asset_id == source_id,
                        AssetRelationship.target_asset_id == target_id,
                        AssetRelationship.relationship_type == rel_type.value,
                        AssetRelationship.source_id == payload.source_id,
                        AssetRelationship.valid_to.is_(None),
                    )
                )
            )
            .scalars()
            .first()
        )

        if live is not None and (live.qualifier or "") == (payload.qualifier or ""):
            live.last_seen_at = now
            live.confidence = payload.confidence
            await self._session.flush()
            return TOUCHED, live, canonicalised

        supersedes = None
        if live is not None:
            live.valid_to = now
            supersedes = live.id
            await self._session.flush()

        edge = AssetRelationship(
            relationship_type=rel_type.value,
            source_asset_id=source_id,
            target_asset_id=target_id,
            is_symmetric=spec.symmetric,
            qualifier=payload.qualifier,
            statement_class=statement_class_for(source_type).value,
            source_type=source_type.value,
            source_id=payload.source_id,
            confidence=payload.confidence,
            verification_status=default_status_for(source_type).value,
            supersedes_rel_id=supersedes,
            valid_from=now,
            first_seen_at=now,
            last_seen_at=now,
        )
        self._session.add(edge)
        await self._session.flush()
        return CREATED, edge, canonicalised

    async def retire(self, relationship_id: uuid.UUID) -> AssetRelationship:
        edge = await self._session.get(AssetRelationship, relationship_id)
        if edge is None:
            raise NotFoundError(f"Relationship {relationship_id} does not exist.")
        if edge.valid_to is not None:
            raise ConflictError("Relationship is already closed.")
        edge.valid_to = datetime.now(UTC)
        await self._session.flush()
        return edge

    async def list_relationships(
        self,
        *,
        asset_id: uuid.UUID | None = None,
        relationship_type: str | None = None,
        direction: str = "both",
        include_closed: bool = False,
    ) -> list[AssetRelationship]:
        query = select(AssetRelationship)
        if not include_closed:
            query = query.where(AssetRelationship.valid_to.is_(None))
        if relationship_type:
            query = query.where(AssetRelationship.relationship_type == relationship_type)
        if asset_id is not None:
            if direction == "out":
                query = query.where(AssetRelationship.source_asset_id == asset_id)
            elif direction == "in":
                query = query.where(AssetRelationship.target_asset_id == asset_id)
            else:
                query = query.where(
                    or_(
                        AssetRelationship.source_asset_id == asset_id,
                        AssetRelationship.target_asset_id == asset_id,
                    )
                )
        query = query.order_by(AssetRelationship.relationship_type)
        return list((await self._session.execute(query)).scalars())

    async def neighbours(self, asset_id: uuid.UUID) -> list[Neighbour]:
        """Directly related assets, both directions, depth 1 only.

        The inverse label is applied when this asset is the target, so a VM
        shows ``RUNS_ON`` its host and the host shows ``HOSTS`` the VM - from
        the same single stored row. Multi-hop traversal is Milestone 8.
        """
        await self._require_asset(asset_id)
        edges = await self.list_relationships(asset_id=asset_id)
        if not edges:
            return []

        other_ids = {
            edge.target_asset_id
            if edge.source_asset_id == asset_id
            else edge.source_asset_id
            for edge in edges
        }
        assets = {
            row.id: row
            for row in (
                await self._session.execute(select(Asset).where(Asset.id.in_(other_ids)))
            ).scalars()
        }

        neighbours: list[Neighbour] = []
        for edge in edges:
            outbound = edge.source_asset_id == asset_id
            other_id = edge.target_asset_id if outbound else edge.source_asset_id
            other = assets.get(other_id)
            if other is None:  # pragma: no cover - FK makes this unreachable
                continue
            spec = RELATIONSHIP_SPECS[RelationshipType(edge.relationship_type)]
            label = (
                edge.relationship_type
                if outbound or spec.symmetric
                else spec.inverse_label
            )
            neighbours.append(
                Neighbour(
                    relationship_id=edge.id,
                    label=label,
                    direction="out" if outbound else "in",
                    qualifier=edge.qualifier,
                    asset_id=other.id,
                    asset_type=other.asset_type,
                    display_name=other.display_name,
                    lifecycle_state=other.lifecycle_state,
                    verification_status=edge.verification_status,
                    source_id=edge.source_id,
                )
            )
        neighbours.sort(key=lambda item: (item.label, item.display_name))
        return neighbours

    async def _require_asset(self, asset_id: uuid.UUID) -> Asset:
        asset = await self._session.get(Asset, asset_id)
        if asset is None:
            raise NotFoundError(f"Asset {asset_id} does not exist.")
        return asset


__all__ = ["CREATED", "TOUCHED", "RelationshipService"]
