"""Identity resolution and deduplication.

The single entry point every future discovery source uses. Its contract has
three outcomes, and the third is the important one:

* exactly one asset matched  -> MATCHED
* nothing matched            -> CREATED (when permitted)
* two or more assets matched -> refuse, write nothing, raise

A resolver that picks one on a multi-match silently welds two real machines
into one record, and there is no way back once facts have accumulated against
the merged row. Refusing is recoverable; guessing is not.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from acop.auth.principal import Principal
from acop.core.exceptions import IdentityConflictError, VocabularyError
from acop.core.logging import get_logger
from acop.models.asset import Asset, AssetIdentifier
from acop.models.vocabulary import IDENTIFIER_NAMESPACES, AssetType, LifecycleState
from acop.schemas.asset import IdentifierInput

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class NormalisedIdentifier:
    """An identifier after registry normalisation."""

    namespace: str
    value_raw: str
    value_normalized: str
    unique_in_namespace: bool
    source_type: str
    source_id: str
    confidence: float


@dataclass(frozen=True, slots=True)
class Resolution:
    """What resolution decided."""

    outcome: str
    asset: Asset
    matched_on: tuple[str, ...] = ()


def normalise(identifier: IdentifierInput) -> NormalisedIdentifier:
    """Apply the registry's normaliser and uniqueness policy.

    An unregistered namespace is accepted but never treated as unique - it
    cannot be trusted to identify anything on its own, and asserting otherwise
    would let an unknown source collapse two assets.
    """
    spec = IDENTIFIER_NAMESPACES.get(identifier.namespace)
    if spec is None:
        normalised = identifier.value.strip().lower()
        unique = False
    else:
        normalised = spec.normalise(identifier.value)
        unique = spec.unique
    if not normalised:
        raise VocabularyError(
            f"Identifier value for namespace {identifier.namespace!r} is empty "
            "after normalisation.",
            context={"namespace": identifier.namespace},
        )
    return NormalisedIdentifier(
        namespace=identifier.namespace,
        value_raw=identifier.value,
        value_normalized=normalised,
        unique_in_namespace=unique,
        source_type=str(identifier.source_type),
        source_id=identifier.source_id,
        confidence=identifier.confidence,
    )


class IdentityResolver:
    """Resolves presented identifiers to exactly one asset, or refuses."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def find_matches(
        self, identifiers: list[NormalisedIdentifier]
    ) -> dict[uuid.UUID, list[str]]:
        """Map each matching asset id to the namespaces that matched it.

        Only namespaces declared unique participate. A hostname or a Proxmox
        VMID is a correlation hint, not an identity - matching on one alone
        would merge two assets the first time a name is reused.
        """
        unique_ids = [item for item in identifiers if item.unique_in_namespace]
        if not unique_ids:
            return {}

        clauses = [
            (AssetIdentifier.namespace == item.namespace)
            & (AssetIdentifier.value_normalized == item.value_normalized)
            for item in unique_ids
        ]
        combined = clauses[0]
        for clause in clauses[1:]:
            combined = combined | clause

        rows = (
            await self._session.execute(
                select(AssetIdentifier).where(
                    combined, AssetIdentifier.retired_at.is_(None)
                )
            )
        ).scalars()

        matches: dict[uuid.UUID, list[str]] = {}
        for row in rows:
            matches.setdefault(row.asset_id, []).append(row.namespace)
        return matches

    async def resolve(
        self,
        *,
        asset_type: AssetType | str,
        display_name: str,
        identifiers: list[IdentifierInput],
        principal: Principal,
        create_if_missing: bool = True,
    ) -> Resolution:
        """Resolve to one asset, creating it when nothing matched.

        Raises:
            IdentityConflictError: More than one asset matched. Nothing is
                written; the caller gets both candidates and decides.
        """
        normalised = [normalise(item) for item in identifiers]
        matches = await self.find_matches(normalised)

        if len(matches) > 1:
            candidates = [
                {"asset_id": str(asset_id), "matched_on": sorted(namespaces)}
                for asset_id, namespaces in matches.items()
            ]
            logger.warning(
                "cmdb.identity.conflict",
                candidate_count=len(candidates),
                subject=principal.subject,
            )
            raise IdentityConflictError(
                "Presented identifiers match more than one existing asset. ACOP "
                "will not guess which is correct.",
                context={"candidates": candidates},
            )

        now = datetime.now(UTC)

        if len(matches) == 1:
            asset_id, matched_on = next(iter(matches.items()))
            asset = await self._session.get(Asset, asset_id)
            if asset is None:  # pragma: no cover - FK makes this unreachable
                raise IdentityConflictError("Matched asset disappeared mid-resolution.")
            asset.last_seen_at = now
            await self._attach_missing(asset, normalised, now)
            return Resolution("MATCHED", asset, tuple(sorted(matched_on)))

        if not create_if_missing:
            raise IdentityConflictError(
                "No existing asset matched and creation was not requested.",
                context={"candidates": []},
            )

        asset = Asset(
            asset_type=str(asset_type),
            display_name=display_name,
            lifecycle_state=LifecycleState.ACTIVE.value,
            first_seen_at=now,
            last_seen_at=now,
        )
        self._session.add(asset)
        await self._session.flush()
        await self._attach_missing(asset, normalised, now)
        return Resolution("CREATED", asset)

    async def _attach_missing(
        self,
        asset: Asset,
        identifiers: list[NormalisedIdentifier],
        now: datetime,
    ) -> None:
        """Attach any identifier the asset does not already carry.

        An identifier already present has its ``last_seen_at`` advanced rather
        than being duplicated, mirroring the touch semantics of facts.
        """
        existing = {
            (row.namespace, row.value_normalized): row
            for row in (
                await self._session.execute(
                    select(AssetIdentifier).where(
                        AssetIdentifier.asset_id == asset.id,
                        AssetIdentifier.retired_at.is_(None),
                    )
                )
            ).scalars()
        }
        for item in identifiers:
            key = (item.namespace, item.value_normalized)
            found = existing.get(key)
            if found is not None:
                found.last_seen_at = now
                continue
            self._session.add(
                AssetIdentifier(
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
            )
        await self._session.flush()


__all__ = ["IdentityResolver", "NormalisedIdentifier", "Resolution", "normalise"]
