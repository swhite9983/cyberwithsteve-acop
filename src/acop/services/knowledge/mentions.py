"""Linking document text to CMDB assets, without inventing anything.

**The boundary this module sits on.** Milestone 3 holds evidence; Milestone 2
holds authoritative state. A mention is a one-way reference from a chunk to an
asset and nothing more: it never creates an asset, never adds an identifier,
never writes a fact, never touches an attestation. The foreign key points from
knowledge into the CMDB and no Milestone 2 table points back, so retiring
knowledge can never orphan or invalidate an authoritative row.

**Two sources, and no third.** A mention exists because either

* ``IDENTIFIER_MATCH`` - the chunk literally contains a string that normalises,
  under a registered namespace's own normaliser, to an identifier already
  recorded against a live asset; or
* ``EXPLICIT`` - a human or an API call said so, and their subject is recorded.

There is no entity extraction, no NLP, no fuzzy or approximate matching, no
model in the loop. That is not an efficiency decision. A probabilistic linker
attaches a runbook to the wrong machine some fraction of the time, silently,
and the error then propagates into every answer that cites that runbook while
looking exactly like a confident correct one. An exact match either holds or it
does not, and a human can check it in a second.

**Ambiguity is recorded, not resolved.** A value matching two assets produces
one row with both candidates and ``asset_id`` NULL - the same rule as
Milestone 2's ``IdentityConflictError``. Refusing is recoverable; guessing is
not.
"""

from __future__ import annotations

import re
import uuid
from collections import defaultdict
from dataclasses import dataclass
from typing import Final

from sqlalchemy import select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from acop.auth.principal import Principal
from acop.core.exceptions import NotFoundError, ValidationError
from acop.core.logging import get_logger
from acop.models.asset import Asset, AssetIdentifier
from acop.models.knowledge import KnowledgeAssetMention, KnowledgeChunk
from acop.models.knowledge_vocabulary import (
    MENTIONABLE_NAMESPACES,
    MIN_MENTION_TOKEN_LENGTH,
    MentionResolution,
    MentionSource,
)
from acop.models.vocabulary import (
    IDENTIFIER_NAMESPACES,
    TERMINAL_LIFECYCLE_STATES,
    LifecycleState,
)

logger = get_logger(__name__)

#: Candidate tokens. Deliberately greedy about the characters that appear
#: *inside* real identifiers - dots, colons, hyphens, underscores, slashes -
#: because splitting ``core3850.lab.local`` or ``00:1a:2b:3c:4d:5e`` on those
#: would leave fragments that match nothing, or worse, match something else.
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:\-/]{1,126}[A-Za-z0-9]|[A-Za-z0-9]+")

#: A token is also tried with trailing punctuation stripped, so ``core3850.``
#: at the end of a sentence still matches.
_TRAILING = ".,:;)/-"

MAX_TOKENS_PER_CHUNK: Final[int] = 4000


@dataclass(frozen=True, slots=True)
class MentionCandidate:
    """One (namespace, normalised value) pair worth asking the database about."""

    namespace: str
    value_normalized: str
    surface: str


@dataclass(frozen=True, slots=True)
class MentionReport:
    """What a scan did, for the caller and the audit trail."""

    chunks_scanned: int
    candidates_considered: int
    mentions_created: int
    ambiguous: int


def candidates(text: str) -> list[MentionCandidate]:
    """Every (namespace, value) pair the text could exactly match.

    Pure and deterministic: the same text always yields the same candidates in
    the same order, which is what makes a re-scan a no-op rather than a source
    of churn.

    Each token is normalised through *each* eligible namespace's own
    normaliser, because "exact match" means exact under the rules that
    namespace already uses - a MAC written with dashes in a document and with
    colons in the CMDB is the same MAC, and pretending otherwise would be a
    different kind of guessing.
    """
    seen: set[tuple[str, str]] = set()
    found: list[MentionCandidate] = []
    for index, match in enumerate(_TOKEN.finditer(text)):
        if index >= MAX_TOKENS_PER_CHUNK:
            break
        surface = match.group(0)
        for token in {surface, surface.rstrip(_TRAILING)}:
            if len(token) < MIN_MENTION_TOKEN_LENGTH or token.isdigit():
                # A bare number is never evidence. See MENTIONABLE_NAMESPACES.
                continue
            for namespace in MENTIONABLE_NAMESPACES:
                spec = IDENTIFIER_NAMESPACES.get(namespace)
                if spec is None:  # pragma: no cover - registry is static
                    continue
                try:
                    normalised = spec.normalise(token)
                except (ValueError, TypeError):  # pragma: no cover - defensive
                    continue
                if not normalised or len(normalised) < MIN_MENTION_TOKEN_LENGTH:
                    continue
                key = (namespace, normalised)
                if key in seen:
                    continue
                seen.add(key)
                found.append(
                    MentionCandidate(
                        namespace=namespace,
                        value_normalized=normalised,
                        surface=token,
                    )
                )
    return found


class AssetMentionService:
    """Creates and reads mentions. Writes to exactly one table."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def link_version(
        self, version_id: uuid.UUID, principal: Principal
    ) -> MentionReport:
        """Scan every chunk of one version and record its exact matches.

        Run per *version* rather than per chunk because a version is the unit
        that is immutable: rescanning it later, after new assets have been
        registered, is legitimate and idempotent, whereas rescanning "a
        document" would silently mean rescanning whichever version happens to
        be current.
        """
        chunks = list(
            (
                await self._session.execute(
                    select(KnowledgeChunk)
                    .where(KnowledgeChunk.version_id == version_id)
                    .order_by(KnowledgeChunk.ordinal)
                )
            ).scalars()
        )
        if not chunks:
            raise NotFoundError(
                f"Document version {version_id} has no chunks to scan.",
                context={"version_id": str(version_id)},
            )

        considered = 0
        created = 0
        ambiguous = 0
        existing = await self._existing_keys([chunk.id for chunk in chunks])

        for chunk in chunks:
            found = candidates(chunk.content)
            considered += len(found)
            if not found:
                continue
            matches = await self._match(found)
            for candidate, asset_ids in matches.items():
                key = (chunk.id, candidate.value_normalized, candidate.namespace)
                if key in existing:
                    # Idempotent: a re-scan adds nothing it has already added.
                    continue
                resolved = len(asset_ids) == 1
                self._session.add(
                    KnowledgeAssetMention(
                        id=uuid.uuid4(),
                        chunk_id=chunk.id,
                        asset_id=asset_ids[0] if resolved else None,
                        mention_text=candidate.surface[:255],
                        mention_source=MentionSource.IDENTIFIER_MATCH.value,
                        resolution=(
                            MentionResolution.RESOLVED.value
                            if resolved
                            else MentionResolution.AMBIGUOUS.value
                        ),
                        candidate_asset_ids=list(asset_ids),
                        matched_namespace=candidate.namespace,
                        created_by_subject=principal.subject,
                    )
                )
                existing.add(key)
                created += 1
                if not resolved:
                    ambiguous += 1

        await self._session.flush()
        report = MentionReport(
            chunks_scanned=len(chunks),
            candidates_considered=considered,
            mentions_created=created,
            ambiguous=ambiguous,
        )
        logger.info(
            "knowledge.mentions.scanned",
            version_id=str(version_id),
            chunks_scanned=report.chunks_scanned,
            candidates_considered=report.candidates_considered,
            mentions_created=report.mentions_created,
            ambiguous=report.ambiguous,
        )
        return report

    async def associate(
        self,
        *,
        chunk_id: uuid.UUID,
        asset_id: uuid.UUID,
        principal: Principal,
        mention_text: str | None = None,
    ) -> KnowledgeAssetMention:
        """Record a human's or an API caller's explicit association.

        The escape hatch for everything exact matching cannot see - a runbook
        that calls a switch "the core switch" and never writes its serial. It is
        an *assertion by a named subject*, which is why the subject is stored
        and why nothing here tries to validate the claim: the accountability is
        the control.

        Raises:
            NotFoundError: The chunk or the asset does not exist.
            ValidationError: The asset is in a terminal lifecycle state.
        """
        chunk = await self._session.get(KnowledgeChunk, chunk_id)
        if chunk is None:
            raise NotFoundError(f"Knowledge chunk {chunk_id} does not exist.")
        asset = await self._session.get(Asset, asset_id)
        if asset is None:
            raise NotFoundError(f"Asset {asset_id} does not exist.")
        if LifecycleState(asset.lifecycle_state) in TERMINAL_LIFECYCLE_STATES:
            # A retired or merged asset is not something live to attach evidence
            # to; a MERGED one in particular would attach it to a row that has
            # already been superseded by the surviving asset.
            raise ValidationError(
                "Cannot associate knowledge with a retired or merged asset.",
                context={
                    "asset_id": str(asset_id),
                    "lifecycle_state": asset.lifecycle_state,
                },
            )

        mention = KnowledgeAssetMention(
            id=uuid.uuid4(),
            chunk_id=chunk_id,
            asset_id=asset_id,
            mention_text=(mention_text or chunk.section_label or "explicit")[:255],
            mention_source=MentionSource.EXPLICIT.value,
            resolution=MentionResolution.RESOLVED.value,
            candidate_asset_ids=[asset_id],
            matched_namespace=None,
            created_by_subject=principal.subject,
        )
        self._session.add(mention)
        await self._session.flush()
        logger.info(
            "knowledge.mentions.associated",
            chunk_id=str(chunk_id),
            asset_id=str(asset_id),
            subject=principal.subject,
        )
        return mention

    async def for_chunks(
        self, chunk_ids: list[uuid.UUID]
    ) -> dict[uuid.UUID, list[KnowledgeAssetMention]]:
        """Mentions grouped by chunk, for attaching to retrieval results."""
        if not chunk_ids:
            return {}
        rows = (
            await self._session.execute(
                select(KnowledgeAssetMention)
                .where(KnowledgeAssetMention.chunk_id.in_(chunk_ids))
                .order_by(KnowledgeAssetMention.created_at)
            )
        ).scalars()
        grouped: dict[uuid.UUID, list[KnowledgeAssetMention]] = defaultdict(list)
        for row in rows:
            grouped[row.chunk_id].append(row)
        return dict(grouped)

    # -- internals ------------------------------------------------------

    async def _existing_keys(
        self, chunk_ids: list[uuid.UUID]
    ) -> set[tuple[uuid.UUID, str, str | None]]:
        """What a previous scan already recorded, so a re-scan is a no-op.

        Keyed on the *normalised* value rather than the surface text, because
        two spellings of one MAC are one mention, not two.
        """
        rows = (
            await self._session.execute(
                select(KnowledgeAssetMention).where(
                    KnowledgeAssetMention.chunk_id.in_(chunk_ids),
                    KnowledgeAssetMention.mention_source
                    == MentionSource.IDENTIFIER_MATCH.value,
                )
            )
        ).scalars()
        keys: set[tuple[uuid.UUID, str, str | None]] = set()
        for row in rows:
            namespace = row.matched_namespace
            spec = IDENTIFIER_NAMESPACES.get(namespace or "")
            value = spec.normalise(row.mention_text) if spec else row.mention_text
            keys.add((row.chunk_id, value, namespace))
        return keys

    async def _match(
        self, found: list[MentionCandidate]
    ) -> dict[MentionCandidate, list[uuid.UUID]]:
        """One query for every candidate in a chunk.

        A row-at-a-time lookup would be N round trips per chunk, which on a
        thousand-chunk document is the difference between a scan that runs and
        one that times out. Retired identifiers are excluded so that a value
        legitimately reassigned to another machine stops linking to the old one.
        """
        pairs = [(c.namespace, c.value_normalized) for c in found]
        rows = (
            await self._session.execute(
                select(
                    AssetIdentifier.namespace,
                    AssetIdentifier.value_normalized,
                    AssetIdentifier.asset_id,
                ).where(
                    tuple_(
                        AssetIdentifier.namespace, AssetIdentifier.value_normalized
                    ).in_(pairs),
                    AssetIdentifier.retired_at.is_(None),
                )
            )
        ).all()

        by_key: dict[tuple[str, str], list[uuid.UUID]] = defaultdict(list)
        for namespace, value, asset_id in rows:
            bucket = by_key[(namespace, value)]
            if asset_id not in bucket:
                bucket.append(asset_id)

        matched: dict[MentionCandidate, list[uuid.UUID]] = {}
        for candidate in found:
            asset_ids = by_key.get((candidate.namespace, candidate.value_normalized))
            if asset_ids:
                matched[candidate] = sorted(asset_ids, key=str)
        return matched


__all__ = [
    "MAX_TOKENS_PER_CHUNK",
    "AssetMentionService",
    "MentionCandidate",
    "MentionReport",
    "candidates",
]
