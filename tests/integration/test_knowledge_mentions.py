"""Asset mentions, and the boundary they are not allowed to cross.

Two properties are load-bearing here and neither is about matching quality.

The first is that a mention is *evidence*: the strongest assertion in this file
is that scanning a document changes no row in ``asset``, ``asset_identifier``,
``asset_fact``, ``asset_relationship`` or ``fact_attestation``. Knowledge may
point at the CMDB; it may never become it.

The second is that linking is exact. There is no entity extractor to tune, so
the tests are about what must *not* match - a bare VLAN number that collides
with a Proxmox VMID, a hostname prefix, a retired identifier - as much as about
what must.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import func, select, text

from acop.auth import AuthMethod, Principal, PrincipalType
from acop.config import Settings
from acop.core.exceptions import NotFoundError, ValidationError
from acop.db import Database
from acop.models.asset import Asset, AssetIdentifier
from acop.models.knowledge import (
    KnowledgeAssetMention,
    KnowledgeChunk,
    KnowledgeSource,
)
from acop.models.knowledge_vocabulary import (
    MentionResolution,
    MentionSource,
    Sensitivity,
    SourceKind,
    TrustClass,
)
from acop.models.vocabulary import AssetType, LifecycleState
from acop.services.knowledge.embedding_provider import DeterministicEmbeddingProvider
from acop.services.knowledge.ingest import IngestRequest, KnowledgeIngestService
from acop.services.knowledge.mentions import AssetMentionService, candidates
from acop.services.knowledge.screening import DocumentScreen
from acop.services.knowledge.spaces import EmbeddingSpaceService, SpaceRegistration
from tests.conftest import requires_database

pytestmark = [pytest.mark.integration, requires_database]

REPO_ROOT = Path(__file__).resolve().parents[2]

OPERATOR = Principal(
    subject="acop:user:operator",
    principal_type=PrincipalType.HUMAN,
    issuer="acop:api-key",
    auth_method=AuthMethod.API_KEY,
    roles=frozenset({"operator"}),
)

SERIAL = "FDO2145X0AB"
MAC = "00:1a:2b:3c:4d:5e"

RUNBOOK = f"""# Core Switch Runbook

The core switch (serial {SERIAL}) is reachable at core3850.lab.local.
Its management interface MAC is {MAC.replace(":", "-").upper()}.

## VLANs

VLAN 100 is the management VLAN. Trunk ports carry VLAN 100 and VLAN 200.
"""


@pytest.fixture
async def mdb(settings: Settings) -> AsyncIterator[Database]:
    database = Database(settings)
    async with database.engine.begin() as connection:
        await connection.execute(text("DROP SCHEMA public CASCADE"))
        await connection.execute(text("CREATE SCHEMA public"))
    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", settings.database_url)
    await asyncio.to_thread(command.upgrade, config, "head")
    try:
        yield database
    finally:
        await database.dispose()


async def _space(database: Database):
    async with database.session() as session:
        service = EmbeddingSpaceService(session)
        space = await service.register(
            SpaceRegistration(
                space_key="mentions_768",
                provider="deterministic",
                model="deterministic-test",
                dimensions=768,
                make_default=True,
            )
        )
        await service.mark_prefixes_verified(space.id, OPERATOR.subject)
        space_id = space.id
    async with database.session() as session:
        return await EmbeddingSpaceService(session).get(space_id)


async def _asset(
    database: Database,
    *,
    name: str,
    identifiers: list[tuple[str, str, bool]],
    lifecycle: LifecycleState = LifecycleState.ACTIVE,
    retired_identifiers: bool = False,
) -> uuid.UUID:
    from datetime import UTC, datetime

    from acop.schemas.asset import IdentifierInput
    from acop.services.identity_resolver import normalise

    async with database.session() as session:
        asset = Asset(
            id=uuid.uuid4(),
            asset_type=AssetType.DEVICE.value,
            lifecycle_state=lifecycle.value,
            display_name=name,
            retired_at=(
                datetime.now(UTC) if lifecycle is LifecycleState.RETIRED else None
            ),
        )
        session.add(asset)
        await session.flush()

        for namespace, value, unique in identifiers:
            normalised = normalise(
                IdentifierInput(
                    namespace=namespace,
                    value=value,
                    source_type="MANUAL_ENTRY",
                    source_id="test",
                )
            )
            session.add(
                AssetIdentifier(
                    id=uuid.uuid4(),
                    asset_id=asset.id,
                    namespace=namespace,
                    value_raw=value,
                    value_normalized=normalised.value_normalized,
                    unique_in_namespace=unique,
                    source_type="MANUAL_ENTRY",
                    source_id="test",
                    retired_at=datetime.now(UTC) if retired_identifiers else None,
                )
            )
        await session.flush()
        return asset.id


async def _ingest(database: Database, space, content: str = RUNBOOK) -> uuid.UUID:
    async with database.session() as session:
        source = KnowledgeSource(
            id=uuid.uuid4(),
            source_kind=SourceKind.RUNBOOK.value,
            title="Runbooks",
            origin="steve",
            trust_class=TrustClass.INTERNAL_VERIFIED.value,
            sensitivity=Sensitivity.INTERNAL.value,
        )
        session.add(source)
        await session.flush()
        source_id = source.id

    async with database.session() as session:
        service = KnowledgeIngestService(
            session,
            screen=DocumentScreen("test-salt"),
            embedder=DeterministicEmbeddingProvider(),
            database=database,
        )
        result = await service.ingest(
            IngestRequest(
                source_id=source_id,
                external_ref="core-switch.md",
                title="Core Switch Runbook",
                content=content,
            ),
            OPERATOR,
            space=space,
        )
        assert result.version_id is not None
        return result.version_id


async def _cmdb_snapshot(database: Database) -> dict[str, int]:
    """Row counts for every authoritative table Milestone 3 must not write."""
    tables = (
        "asset",
        "asset_identifier",
        "asset_fact",
        "asset_relationship",
        "fact_attestation",
    )
    async with database.session() as session:
        return {
            table: int(
                (
                    await session.execute(text(f'SELECT count(*) FROM "{table}"'))  # noqa: S608
                ).scalar_one()
            )
            for table in tables
        }


class TestCandidateExtraction:
    """Pure, and therefore testable without a database."""

    def test_a_bare_number_is_never_a_candidate(self) -> None:
        """The failure this guard exists for.

        ``proxmox:vmid`` and ``cisco:if-index`` are bare integers. "VLAN 100" in
        a runbook would otherwise link the document to VMID 100 - textually
        exact, factually absurd.
        """
        found = candidates("VLAN 100 is the management VLAN. Port 24 is trunked.")
        assert all(not c.value_normalized.isdigit() for c in found)

    def test_identifier_shaped_tokens_survive_intact(self) -> None:
        found = {c.value_normalized for c in candidates(RUNBOOK)}
        assert "core3850.lab.local" in found
        assert SERIAL.upper() in found

    def test_a_mac_matches_across_spellings(self) -> None:
        """Exact means exact under the namespace's own normaliser.

        The document writes the MAC with dashes and in upper case; the CMDB
        holds it with colons and in lower case. They are one MAC, and treating
        them as different would be a different kind of guessing.
        """
        dashed = {c.value_normalized for c in candidates("MAC is 00-1A-2B-3C-4D-5E")}
        colons = {c.value_normalized for c in candidates("MAC is 00:1a:2b:3c:4d:5e")}
        assert "001a2b3c4d5e" in dashed
        assert "001a2b3c4d5e" in colons

    def test_extraction_is_deterministic(self) -> None:
        assert candidates(RUNBOOK) == candidates(RUNBOOK)


class TestIdentifierMatching:
    async def test_an_exact_serial_creates_a_resolved_mention(
        self, mdb: Database
    ) -> None:
        space = await _space(mdb)
        asset_id = await _asset(
            mdb, name="core3850", identifiers=[("serial", SERIAL, True)]
        )
        version_id = await _ingest(mdb, space)

        async with mdb.session() as session:
            report = await AssetMentionService(session).link_version(version_id, OPERATOR)
        assert report.mentions_created >= 1

        async with mdb.session() as session:
            rows = list(
                (
                    await session.execute(
                        select(KnowledgeAssetMention).where(
                            KnowledgeAssetMention.matched_namespace == "serial"
                        )
                    )
                ).scalars()
            )
        assert len(rows) == 1
        assert rows[0].asset_id == asset_id
        assert rows[0].resolution == MentionResolution.RESOLVED.value
        assert rows[0].mention_source == MentionSource.IDENTIFIER_MATCH.value
        assert rows[0].created_by_subject == OPERATOR.subject

    async def test_a_value_matching_two_assets_is_recorded_ambiguous(
        self, mdb: Database
    ) -> None:
        """Milestone 2's refusal rule, applied to knowledge.

        Two assets sharing a hostname is an ordinary consequence of a name being
        reused. Picking one would attach the runbook to whichever row happened
        to sort first.
        """
        space = await _space(mdb)
        first = await _asset(
            mdb, name="a", identifiers=[("hostname", "core3850.lab.local", False)]
        )
        second = await _asset(
            mdb, name="b", identifiers=[("hostname", "core3850.lab.local", False)]
        )
        version_id = await _ingest(mdb, space)

        async with mdb.session() as session:
            await AssetMentionService(session).link_version(version_id, OPERATOR)

        async with mdb.session() as session:
            row = (
                (
                    await session.execute(
                        select(KnowledgeAssetMention).where(
                            KnowledgeAssetMention.matched_namespace == "hostname"
                        )
                    )
                )
                .scalars()
                .one()
            )
        assert row.resolution == MentionResolution.AMBIGUOUS.value
        assert row.asset_id is None
        assert set(row.candidate_asset_ids) == {first, second}

    async def test_a_retired_identifier_does_not_link(self, mdb: Database) -> None:
        """A value reassigned to another machine must stop linking to the old one."""
        space = await _space(mdb)
        await _asset(
            mdb,
            name="old",
            identifiers=[("serial", SERIAL, True)],
            retired_identifiers=True,
        )
        version_id = await _ingest(mdb, space)

        async with mdb.session() as session:
            report = await AssetMentionService(session).link_version(version_id, OPERATOR)
        assert report.mentions_created == 0

    async def test_a_vlan_number_never_links_to_a_vmid(self, mdb: Database) -> None:
        """The concrete false positive MENTIONABLE_NAMESPACES exists to prevent."""
        space = await _space(mdb)
        async with mdb.session() as session:
            asset = Asset(
                id=uuid.uuid4(),
                asset_type=AssetType.VM.value,
                lifecycle_state=LifecycleState.ACTIVE.value,
                display_name="vm100",
            )
            session.add(asset)
            await session.flush()
            session.add(
                AssetIdentifier(
                    id=uuid.uuid4(),
                    asset_id=asset.id,
                    namespace="proxmox:vmid",
                    value_raw="100",
                    value_normalized="100",
                    unique_in_namespace=False,
                    source_type="MANUAL_ENTRY",
                    source_id="test",
                )
            )
            await session.flush()
        version_id = await _ingest(mdb, space)

        async with mdb.session() as session:
            report = await AssetMentionService(session).link_version(version_id, OPERATOR)
        assert report.mentions_created == 0

    async def test_rescanning_is_idempotent(self, mdb: Database) -> None:
        space = await _space(mdb)
        await _asset(mdb, name="core3850", identifiers=[("serial", SERIAL, True)])
        version_id = await _ingest(mdb, space)

        async with mdb.session() as session:
            first = await AssetMentionService(session).link_version(version_id, OPERATOR)
        async with mdb.session() as session:
            second = await AssetMentionService(session).link_version(version_id, OPERATOR)
        assert first.mentions_created > 0
        assert second.mentions_created == 0

        async with mdb.session() as session:
            total = int(
                (
                    await session.execute(
                        select(func.count()).select_from(KnowledgeAssetMention)
                    )
                ).scalar_one()
            )
        assert total == first.mentions_created

    async def test_rescanning_picks_up_assets_registered_later(
        self, mdb: Database
    ) -> None:
        """The reason a scan is a separate, repeatable operation.

        A runbook ingested before the switch was inventoried should link once
        the switch exists, without the document having to be re-submitted.
        """
        space = await _space(mdb)
        version_id = await _ingest(mdb, space)

        async with mdb.session() as session:
            assert (
                await AssetMentionService(session).link_version(version_id, OPERATOR)
            ).mentions_created == 0

        await _asset(mdb, name="core3850", identifiers=[("serial", SERIAL, True)])

        async with mdb.session() as session:
            assert (
                await AssetMentionService(session).link_version(version_id, OPERATOR)
            ).mentions_created >= 1

    async def test_a_missing_version_is_refused(self, mdb: Database) -> None:
        async with mdb.session() as session:
            with pytest.raises(NotFoundError):
                await AssetMentionService(session).link_version(uuid.uuid4(), OPERATOR)


class TestExplicitAssociation:
    async def test_a_human_may_associate_what_matching_cannot_see(
        self, mdb: Database
    ) -> None:
        space = await _space(mdb)
        asset_id = await _asset(mdb, name="core3850", identifiers=[])
        version_id = await _ingest(mdb, space)

        async with mdb.session() as session:
            chunk_id = (
                (
                    await session.execute(
                        select(KnowledgeChunk.id).where(
                            KnowledgeChunk.version_id == version_id
                        )
                    )
                )
                .scalars()
                .first()
            )
            assert chunk_id is not None
            mention = await AssetMentionService(session).associate(
                chunk_id=chunk_id,
                asset_id=asset_id,
                principal=OPERATOR,
                mention_text="the core switch",
            )
            assert mention.mention_source == MentionSource.EXPLICIT.value
            assert mention.resolution == MentionResolution.RESOLVED.value
            assert mention.created_by_subject == OPERATOR.subject
            assert mention.matched_namespace is None

    async def test_association_with_a_retired_asset_is_refused(
        self, mdb: Database
    ) -> None:
        space = await _space(mdb)
        asset_id = await _asset(
            mdb, name="gone", identifiers=[], lifecycle=LifecycleState.RETIRED
        )
        version_id = await _ingest(mdb, space)

        async with mdb.session() as session:
            chunk_id = (
                (
                    await session.execute(
                        select(KnowledgeChunk.id).where(
                            KnowledgeChunk.version_id == version_id
                        )
                    )
                )
                .scalars()
                .first()
            )
            assert chunk_id is not None
            with pytest.raises(ValidationError):
                await AssetMentionService(session).associate(
                    chunk_id=chunk_id, asset_id=asset_id, principal=OPERATOR
                )

    async def test_unknown_chunk_or_asset_is_refused(self, mdb: Database) -> None:
        async with mdb.session() as session:
            with pytest.raises(NotFoundError):
                await AssetMentionService(session).associate(
                    chunk_id=uuid.uuid4(),
                    asset_id=uuid.uuid4(),
                    principal=OPERATOR,
                )


class TestEvidenceBoundary:
    """The milestone's central invariant, asserted rather than assumed."""

    async def test_scanning_writes_nothing_authoritative(self, mdb: Database) -> None:
        space = await _space(mdb)
        await _asset(
            mdb,
            name="core3850",
            identifiers=[
                ("serial", SERIAL, True),
                ("hostname", "core3850.lab.local", False),
                ("mac", MAC, True),
            ],
        )
        version_id = await _ingest(mdb, space)
        before = await _cmdb_snapshot(mdb)

        async with mdb.session() as session:
            report = await AssetMentionService(session).link_version(version_id, OPERATOR)
        assert report.mentions_created >= 2

        after = await _cmdb_snapshot(mdb)
        assert before == after

    async def test_explicit_association_writes_nothing_authoritative(
        self, mdb: Database
    ) -> None:
        space = await _space(mdb)
        asset_id = await _asset(mdb, name="core3850", identifiers=[])
        version_id = await _ingest(mdb, space)
        before = await _cmdb_snapshot(mdb)

        async with mdb.session() as session:
            chunk_id = (
                (
                    await session.execute(
                        select(KnowledgeChunk.id).where(
                            KnowledgeChunk.version_id == version_id
                        )
                    )
                )
                .scalars()
                .first()
            )
            assert chunk_id is not None
            await AssetMentionService(session).associate(
                chunk_id=chunk_id, asset_id=asset_id, principal=OPERATOR
            )

        assert await _cmdb_snapshot(mdb) == before

    async def test_the_module_contains_no_write_to_a_cmdb_table(self) -> None:
        """A static check, because a runtime one can only prove what it ran.

        The row-count assertions above prove these particular paths write
        nothing. This proves no path does, by reading the source: the only
        Milestone 2 classes the module may name are the two it *reads*.
        """
        import inspect

        from acop.services.knowledge import mentions

        source = inspect.getsource(mentions)
        for forbidden in (
            "AssetFact",
            "AssetRelationship",
            "FactAttestation",
            "AssetIdentifier(",
            "Asset(",
        ):
            assert forbidden not in source, forbidden
