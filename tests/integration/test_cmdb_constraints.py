"""Database-level constraint proofs.

Every assertion here bypasses the service layer and writes raw SQL. A
service-level test proves the service is polite; only a raw insert proves that
a future collector with a bug, a bad migration or a careless ``psql`` session
cannot corrupt the store.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from acop.config import Settings
from acop.db import Database
from tests.conftest import DOC_MAC, DOC_SERIAL, MEM_12, MEM_16, requires_database

pytestmark = [pytest.mark.integration, requires_database]

REPO_ROOT = Path(__file__).resolve().parents[2]

ASSET_A = uuid.UUID("aaaaaaaa-0000-0000-0000-000000000001")
ASSET_B = uuid.UUID("bbbbbbbb-0000-0000-0000-000000000002")


def at(hour: int, minute: int = 0) -> datetime:
    """A timestamp on the walkthrough day.

    asyncpg binds parameters by type and will not coerce an ISO string to
    timestamptz, so tests pass real datetimes.
    """
    return datetime(2026, 9, 3, hour, minute, tzinfo=UTC)


def _alembic_config(settings: Settings) -> Config:
    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", settings.database_url)
    return config


@pytest.fixture
async def db(settings: Settings):
    """A migrated database with two assets, for raw-SQL constraint probing."""
    database = Database(settings)
    async with database.engine.begin() as connection:
        await connection.execute(text("DROP SCHEMA public CASCADE"))
        await connection.execute(text("CREATE SCHEMA public"))
    await asyncio.to_thread(command.upgrade, _alembic_config(settings), "head")

    async with database.session() as session:
        await session.execute(
            text(
                "INSERT INTO asset (id, asset_type, lifecycle_state, display_name) "
                "VALUES (:a, 'VM', 'ACTIVE', 'vm-doc-200'), "
                "(:b, 'HOST', 'ACTIVE', 'host-doc-01')"
            ),
            {"a": ASSET_A, "b": ASSET_B},
        )
    try:
        yield database
    finally:
        await database.dispose()


FACT_INSERT = text(
    """
    INSERT INTO asset_fact (
        id, asset_id, predicate, fact_kind, statement_class, value_type,
        value_number, source_type, source_id, verification_status,
        verified_by_subject, verified_at, valid_from, valid_to,
        first_seen_at, last_seen_at
    ) VALUES (
        :id, :asset_id, :predicate, :fact_kind, :statement_class, 'NUMBER',
        :value, :source_type, :source_id, :status,
        :verified_by, :verified_at, :valid_from, :valid_to,
        :valid_from, :valid_from
    )
    """
)


def _fact_params(**overrides: object) -> dict[str, object]:
    params: dict[str, object] = {
        "id": uuid.uuid4(),
        "asset_id": ASSET_A,
        "predicate": "memory.total_bytes",
        "fact_kind": "OBSERVED_STATE",
        "statement_class": "OBSERVATION",
        "value": Decimal(MEM_12),
        "source_type": "LIVE_DISCOVERY",
        "source_id": "proxmox:pve-doc-01",
        "status": "DISCOVERED",
        "verified_by": None,
        "verified_at": None,
        "valid_from": at(10),
        "valid_to": None,
    }
    params.update(overrides)
    return params


class TestOverlappingHistoryRejected:
    """Requirement 1: two overlapping intervals for one claim lineage."""

    async def test_overlapping_intervals_raise(self, db) -> None:
        async with db.session() as session:
            await session.execute(
                FACT_INSERT,
                _fact_params(valid_from=at(10), valid_to=at(11)),
            )

        with pytest.raises(IntegrityError, match="ex_asset_fact_no_overlap"):
            async with db.session() as session:
                await session.execute(
                    FACT_INSERT,
                    _fact_params(
                        value=Decimal(MEM_16),
                        valid_from=at(10, 30),
                        valid_to=at(11, 30),
                    ),
                )

    async def test_adjacent_intervals_are_allowed(self, db) -> None:
        """Closed-open ranges: [10:00, 11:00) and [11:00, 12:00) do not overlap."""
        async with db.session() as session:
            await session.execute(
                FACT_INSERT,
                _fact_params(valid_from=at(10), valid_to=at(11)),
            )
            await session.execute(
                FACT_INSERT,
                _fact_params(
                    value=Decimal(MEM_16),
                    valid_from=at(11),
                    valid_to=at(12),
                ),
            )

    async def test_repeated_value_after_a_gap_is_allowed(self, db) -> None:
        """History must permit 12 -> 16 -> 12 again. Any uniqueness on closed
        rows would reject a legitimate rollback."""
        async with db.session() as session:
            for start, end, value in (
                (at(10), at(11), Decimal(MEM_12)),
                (at(11), at(12), Decimal(MEM_16)),
                (at(12), None, Decimal(MEM_12)),
            ):
                await session.execute(
                    FACT_INSERT,
                    _fact_params(value=value, valid_from=start, valid_to=end),
                )
            count = await session.scalar(
                text("SELECT count(*) FROM asset_fact WHERE asset_id = :a"),
                {"a": ASSET_A},
            )
        assert count == 3


class TestSingleLiveAuthority:
    """Requirement 2: two live authoritative facts for one key."""

    async def test_second_authoritative_claim_raises(self, db) -> None:
        async with db.session() as session:
            await session.execute(
                FACT_INSERT,
                _fact_params(
                    status="VERIFIED",
                    verified_by="acop:user:approver-a",
                    verified_at=at(11, 45),
                ),
            )

        with pytest.raises(IntegrityError, match="uq_asset_fact_live_authority"):
            async with db.session() as session:
                await session.execute(
                    FACT_INSERT,
                    _fact_params(
                        source_id="acop:user:steve",
                        source_type="MANUAL_ENTRY",
                        statement_class="FACT",
                        value=Decimal(MEM_16),
                        status="VERIFIED",
                        verified_by="acop:user:approver-b",
                        verified_at=at(12),
                    ),
                )

    async def test_observed_and_desired_authority_coexist(self, db) -> None:
        """The two axes are independent: fact_kind is in the key."""
        async with db.session() as session:
            await session.execute(
                FACT_INSERT,
                _fact_params(
                    status="VERIFIED",
                    verified_by="acop:user:approver-a",
                    verified_at=at(11, 45),
                ),
            )
            await session.execute(
                text(
                    """
                    INSERT INTO asset_fact (
                        id, asset_id, predicate, fact_kind, statement_class,
                        value_type, value_number, source_type, source_id,
                        verification_status, approved_by_subject, approved_at,
                        valid_from, first_seen_at, last_seen_at
                    ) VALUES (
                        :id, :asset_id, 'memory.total_bytes', 'DESIRED_STATE',
                        'FACT', 'NUMBER', :value, 'MANUAL_ENTRY',
                        'acop:user:steve', 'APPROVED', 'acop:user:steve',
                        now(), now(), now(), now()
                    )
                    """
                ),
                {"id": uuid.uuid4(), "asset_id": ASSET_A, "value": Decimal(24 * 1024**3)},
            )
            live = await session.scalar(
                text(
                    "SELECT count(*) FROM asset_fact WHERE asset_id = :a "
                    "AND valid_to IS NULL AND verification_status IN "
                    "('VERIFIED','APPROVED')"
                ),
                {"a": ASSET_A},
            )
        assert live == 2


class TestInferenceNeverAuthoritative:
    """Requirements 3 and 4: AI promoted to VERIFIED or APPROVED."""

    @pytest.mark.parametrize("status", ["VERIFIED", "APPROVED"])
    async def test_ai_inference_cannot_hold_authority(self, db, status: str) -> None:
        with pytest.raises(
            IntegrityError, match="ck_asset_fact_inference_not_authoritative"
        ):
            async with db.session() as session:
                await session.execute(
                    text(
                        """
                        INSERT INTO asset_fact (
                            id, asset_id, predicate, fact_kind, statement_class,
                            value_type, value_number, source_type, source_id,
                            verification_status, verified_by_subject, verified_at,
                            approved_by_subject, approved_at,
                            valid_from, first_seen_at, last_seen_at
                        ) VALUES (
                            :id, :asset_id, 'memory.total_bytes', 'OBSERVED_STATE',
                            'INFERENCE', 'NUMBER', :value, 'AI_INFERENCE',
                            'acop:agent:noc', :status, 'acop:user:approver-a',
                            now(), 'acop:user:approver-a', now(),
                            now(), now(), now()
                        )
                        """
                    ),
                    {
                        "id": uuid.uuid4(),
                        "asset_id": ASSET_A,
                        "value": Decimal(MEM_16),
                        "status": status,
                    },
                )

    async def test_updating_an_ai_row_to_verified_also_raises(self, db) -> None:
        """Neither field alone can be edited to escape the constraint."""
        fact_id = uuid.uuid4()
        async with db.session() as session:
            await session.execute(
                FACT_INSERT,
                _fact_params(
                    id=fact_id,
                    statement_class="INFERENCE",
                    source_type="AI_INFERENCE",
                    source_id="acop:agent:noc",
                    status="UNVERIFIED",
                ),
            )

        with pytest.raises(
            IntegrityError, match="ck_asset_fact_inference_not_authoritative"
        ):
            async with db.session() as session:
                await session.execute(
                    text(
                        "UPDATE asset_fact SET verification_status = 'VERIFIED', "
                        "verified_by_subject = 'x', verified_at = now() "
                        "WHERE id = :id"
                    ),
                    {"id": fact_id},
                )

    async def test_ai_row_may_stand_as_an_unverified_parallel_claim(self, db) -> None:
        async with db.session() as session:
            await session.execute(FACT_INSERT, _fact_params())
            await session.execute(
                FACT_INSERT,
                _fact_params(
                    value=Decimal(MEM_16),
                    statement_class="INFERENCE",
                    source_type="AI_INFERENCE",
                    source_id="acop:agent:noc",
                    status="UNVERIFIED",
                ),
            )
            live = await session.scalar(
                text(
                    "SELECT count(*) FROM asset_fact WHERE asset_id = :a "
                    "AND valid_to IS NULL"
                ),
                {"a": ASSET_A},
            )
        assert live == 2


class TestSymmetricRelationshipOrdering:
    """Requirement 5: invalid symmetric relationship ordering."""

    REL_INSERT = text(
        """
        INSERT INTO asset_relationship (
            id, relationship_type, source_asset_id, target_asset_id,
            is_symmetric, statement_class, source_type, source_id,
            verification_status, valid_from, first_seen_at, last_seen_at
        ) VALUES (
            :id, 'CONNECTED_TO', :source, :target, true, 'OBSERVATION',
            'LIVE_DISCOVERY', 'cisco:doc-switch-01', 'DISCOVERED',
            now(), now(), now()
        )
        """
    )

    async def test_reversed_symmetric_endpoints_raise(self, db) -> None:
        """One physical link, one row. ASSET_B > ASSET_A, so this is backwards."""
        with pytest.raises(IntegrityError, match="ck_asset_relationship_symmetric_order"):
            async with db.session() as session:
                await session.execute(
                    self.REL_INSERT,
                    {"id": uuid.uuid4(), "source": ASSET_B, "target": ASSET_A},
                )

    async def test_canonical_order_is_accepted(self, db) -> None:
        async with db.session() as session:
            await session.execute(
                self.REL_INSERT,
                {"id": uuid.uuid4(), "source": ASSET_A, "target": ASSET_B},
            )

    async def test_self_edge_raises(self, db) -> None:
        with pytest.raises(IntegrityError, match="ck_asset_relationship_no_self"):
            async with db.session() as session:
                await session.execute(
                    self.REL_INSERT,
                    {"id": uuid.uuid4(), "source": ASSET_A, "target": ASSET_A},
                )


class TestDuplicateLiveIdentifiers:
    """Requirement 6: duplicate live unique identifiers."""

    IDENT_INSERT = text(
        """
        INSERT INTO asset_identifier (
            id, asset_id, namespace, value_raw, value_normalized,
            unique_in_namespace, source_type, source_id
        ) VALUES (
            :id, :asset_id, :ns, :raw, :norm, :unique, 'LIVE_DISCOVERY', 'test'
        )
        """
    )

    async def test_same_unique_value_on_two_assets_raises(self, db) -> None:
        async with db.session() as session:
            await session.execute(
                self.IDENT_INSERT,
                {
                    "id": uuid.uuid4(),
                    "asset_id": ASSET_A,
                    "ns": "serial",
                    "raw": DOC_SERIAL,
                    "norm": DOC_SERIAL,
                    "unique": True,
                },
            )

        with pytest.raises(IntegrityError, match="uq_asset_identifier_live_unique"):
            async with db.session() as session:
                await session.execute(
                    self.IDENT_INSERT,
                    {
                        "id": uuid.uuid4(),
                        "asset_id": ASSET_B,
                        "ns": "serial",
                        "raw": DOC_SERIAL,
                        "norm": DOC_SERIAL,
                        "unique": True,
                    },
                )

    async def test_non_unique_namespace_may_repeat(self, db) -> None:
        """Two assets may legitimately share a hostname."""
        async with db.session() as session:
            for asset in (ASSET_A, ASSET_B):
                await session.execute(
                    self.IDENT_INSERT,
                    {
                        "id": uuid.uuid4(),
                        "asset_id": asset,
                        "ns": "hostname",
                        "raw": "web01",
                        "norm": "web01",
                        "unique": False,
                    },
                )

    async def test_retiring_frees_the_value_for_reuse(self, db) -> None:
        """A replaced NIC's MAC, or a reissued Proxmox VMID."""
        first = uuid.uuid4()
        async with db.session() as session:
            await session.execute(
                self.IDENT_INSERT,
                {
                    "id": first,
                    "asset_id": ASSET_A,
                    "ns": "mac",
                    "raw": DOC_MAC,
                    "norm": "00005e005301",
                    "unique": True,
                },
            )
            await session.execute(
                text("UPDATE asset_identifier SET retired_at = now() WHERE id = :id"),
                {"id": first},
            )
            await session.execute(
                self.IDENT_INSERT,
                {
                    "id": uuid.uuid4(),
                    "asset_id": ASSET_B,
                    "ns": "mac",
                    "raw": DOC_MAC,
                    "norm": "00005e005301",
                    "unique": True,
                },
            )
            total = await session.scalar(text("SELECT count(*) FROM asset_identifier"))
        assert total == 2  # the retired row is kept as history


class TestValueTypingConstraints:
    async def test_two_value_columns_raise(self, db) -> None:
        with pytest.raises(IntegrityError, match="ck_asset_fact_value_exclusive"):
            async with db.session() as session:
                await session.execute(
                    text(
                        "INSERT INTO asset_fact (id, asset_id, predicate, fact_kind,"
                        " statement_class, value_type, value_number, value_text,"
                        " source_type, source_id, verification_status) VALUES"
                        " (:id, :a, 'memory.total_bytes', 'OBSERVED_STATE',"
                        " 'OBSERVATION', 'NUMBER', 1, 'also', 'LIVE_DISCOVERY',"
                        " 's', 'DISCOVERED')"
                    ),
                    {"id": uuid.uuid4(), "a": ASSET_A},
                )

    async def test_value_type_mismatch_raises(self, db) -> None:
        with pytest.raises(IntegrityError, match="ck_asset_fact_value_type_matches"):
            async with db.session() as session:
                await session.execute(
                    text(
                        "INSERT INTO asset_fact (id, asset_id, predicate, fact_kind,"
                        " statement_class, value_type, value_text, source_type,"
                        " source_id, verification_status) VALUES"
                        " (:id, :a, 'os.name', 'OBSERVED_STATE', 'OBSERVATION',"
                        " 'NUMBER', 'ubuntu', 'LIVE_DISCOVERY', 's', 'DISCOVERED')"
                    ),
                    {"id": uuid.uuid4(), "a": ASSET_A},
                )

    async def test_verified_without_a_verifier_raises(self, db) -> None:
        with pytest.raises(IntegrityError, match="ck_asset_fact_verified_attribution"):
            async with db.session() as session:
                await session.execute(FACT_INSERT, _fact_params(status="VERIFIED"))

    async def test_desired_state_must_be_approved(self, db) -> None:
        with pytest.raises(IntegrityError, match="ck_asset_fact_desired_is_approved"):
            async with db.session() as session:
                await session.execute(
                    FACT_INSERT,
                    _fact_params(fact_kind="DESIRED_STATE", status="DISCOVERED"),
                )

    async def test_malformed_predicate_raises(self, db) -> None:
        with pytest.raises(IntegrityError, match="ck_asset_fact_predicate_format"):
            async with db.session() as session:
                await session.execute(
                    FACT_INSERT, _fact_params(predicate="Memory Total Bytes")
                )


class TestAssetLifecycleConstraints:
    async def test_merged_without_target_raises(self, db) -> None:
        with pytest.raises(IntegrityError, match="ck_asset_merged_state"):
            async with db.session() as session:
                await session.execute(
                    text("UPDATE asset SET lifecycle_state = 'MERGED' WHERE id = :a"),
                    {"a": ASSET_A},
                )

    async def test_retired_without_timestamp_raises(self, db) -> None:
        with pytest.raises(IntegrityError, match="ck_asset_retired_state"):
            async with db.session() as session:
                await session.execute(
                    text("UPDATE asset SET lifecycle_state = 'RETIRED' WHERE id = :a"),
                    {"a": ASSET_A},
                )

    async def test_hard_delete_of_a_referenced_asset_is_blocked(self, db) -> None:
        """ON DELETE RESTRICT: history cannot be destroyed by deleting the asset."""
        async with db.session() as session:
            await session.execute(FACT_INSERT, _fact_params())

        with pytest.raises(IntegrityError):
            async with db.session() as session:
                await session.execute(
                    text("DELETE FROM asset WHERE id = :a"), {"a": ASSET_A}
                )
