"""The approved lifecycle walkthrough, executed through the service layer.

Follows the seven events from the design document exactly, then covers
resolution, relationships, retirement and audit. If this file passes, the
behaviours the design promised are the behaviours the code has.
"""

from __future__ import annotations

import asyncio
from decimal import Decimal
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import func, select, text

from acop.config import Settings
from acop.core.exceptions import (
    ConflictError,
    IdentityConflictError,
    SecretRejectedError,
)
from acop.db import Database
from acop.models.asset import Asset
from acop.models.audit import AuditEvent
from acop.models.fact import AssetFact, FactAttestation
from acop.models.provenance import SourceType, VerificationStatus
from acop.models.vocabulary import (
    AssetType,
    AttestationAction,
    FactKind,
    LifecycleState,
    RelationshipType,
    ValueType,
)
from acop.schemas.asset import IdentifierInput
from acop.schemas.audit import AuditEventCreate
from acop.schemas.fact import DesiredFactCreate, FactAssert
from acop.schemas.relationship import RelationshipAssert
from acop.services import (
    AssetService,
    AuditService,
    FactService,
    IdentityResolver,
    RelationshipService,
)
from acop.services.fact import (
    AUTHORITATIVE_SINGLE,
    CREATED,
    SUPERSEDED,
    TOUCHED,
    UNANIMOUS,
    UNRESOLVED,
)
from tests.conftest import (
    DOC_MAC,
    DOC_SERIAL,
    MEM_12,
    MEM_16,
    MEM_24,
    requires_database,
)

pytestmark = [pytest.mark.integration, requires_database]

REPO_ROOT = Path(__file__).resolve().parents[2]
PREDICATE = "memory.total_bytes"
PROXMOX = "proxmox:pve-doc-01"


def _alembic_config(settings: Settings) -> Config:
    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", settings.database_url)
    return config


@pytest.fixture
async def db(settings: Settings):
    database = Database(settings)
    async with database.engine.begin() as connection:
        await connection.execute(text("DROP SCHEMA public CASCADE"))
        await connection.execute(text("CREATE SCHEMA public"))
    await asyncio.to_thread(command.upgrade, _alembic_config(settings), "head")
    try:
        yield database
    finally:
        await database.dispose()


async def _make_vm(session, principal, name: str = "vm-doc-200") -> Asset:
    resolution = await IdentityResolver(session).resolve(
        asset_type=AssetType.VM,
        display_name=name,
        identifiers=[IdentifierInput(namespace="serial", value=f"{DOC_SERIAL}-{name}")],
        principal=principal,
    )
    return resolution.asset


def _assert_memory(value: int, source_id: str, source_type: SourceType) -> FactAssert:
    return FactAssert(
        predicate=PREDICATE,
        value_type=ValueType.NUMBER,
        value_number=value,
        source_type=source_type,
        source_id=source_id,
    )


class TestFactLifecycle:
    """The seven approved events, in order."""

    async def test_full_walkthrough(
        self, db, operator_principal, approver_principal, second_approver_principal
    ) -> None:
        async with db.session() as session:
            facts = FactService(session)
            asset = await _make_vm(session, operator_principal)

            # Event 1 - Proxmox reports 12 GiB.
            outcome, f1, superseded, _ = await facts.assert_fact(
                asset.id, _assert_memory(MEM_12, PROXMOX, SourceType.LIVE_DISCOVERY)
            )
            assert outcome == CREATED
            assert superseded is None
            assert f1.verification_status == VerificationStatus.DISCOVERED.value
            assert f1.statement_class == "OBSERVATION"
            assert f1.valid_to is None
            first_seen = f1.first_seen_at

            # Event 2 - same value again: touch only, no new row.
            outcome, touched, _, _ = await facts.assert_fact(
                asset.id, _assert_memory(MEM_12, PROXMOX, SourceType.LIVE_DISCOVERY)
            )
            assert outcome == TOUCHED
            assert touched.id == f1.id
            assert touched.first_seen_at == first_seen
            assert touched.last_seen_at > first_seen
            assert touched.valid_to is None
            row_count = await session.scalar(select(func.count()).select_from(AssetFact))
            assert row_count == 1

            # Event 3 - new value: close the old interval, insert with a
            # BACKWARD supersedes pointer.
            outcome, f3, superseded, _ = await facts.assert_fact(
                asset.id, _assert_memory(MEM_16, PROXMOX, SourceType.LIVE_DISCOVERY)
            )
            assert outcome == SUPERSEDED
            assert superseded == f1.id
            assert f3.supersedes_fact_id == f1.id
            await session.refresh(f1)
            assert f1.valid_to is not None
            assert f1.value_number == Decimal(MEM_12)  # history intact

            # Event 4 - a different source disagrees. Nothing is closed.
            outcome, _f4, superseded, _ = await facts.assert_fact(
                asset.id,
                _assert_memory(MEM_12, "acop:user:steve", SourceType.MANUAL_ENTRY),
            )
            assert outcome == CREATED
            assert superseded is None
            await session.refresh(f3)
            assert f3.valid_to is None  # the Proxmox claim was NOT overwritten

            # Event 5 - AI inference, forced UNVERIFIED.
            _, f5, _, _ = await facts.assert_fact(
                asset.id,
                _assert_memory(MEM_16, "acop:agent:noc", SourceType.AI_INFERENCE),
            )
            assert f5.statement_class == "INFERENCE"
            assert f5.verification_status == VerificationStatus.UNVERIFIED.value

            live = await facts.live_facts(asset.id)
            assert len(live) == 3

            # Before verification: three live claims, two distinct values, and
            # the AI row cannot break the tie.
            effective = await facts.effective(
                asset.id, PREDICATE, FactKind.OBSERVED_STATE.value
            )
            assert effective.basis == UNRESOLVED
            assert effective.conflict_present
            assert effective.resolution_required

            # Event 6 - verify the Proxmox claim. In place, value unchanged.
            verified = await facts.transition(
                f3.id, AttestationAction.VERIFY, approver_principal
            )
            assert verified.verification_status == VerificationStatus.VERIFIED.value
            assert verified.verified_by_subject == "acop:user:approver-a"
            assert verified.value_number == Decimal(MEM_16)
            assert verified.valid_to is None

            effective = await facts.effective(
                asset.id, PREDICATE, FactKind.OBSERVED_STATE.value
            )
            assert effective.basis == AUTHORITATIVE_SINGLE
            assert effective.fact is not None
            assert effective.conflict_present  # honest about both
            assert not effective.resolution_required

            # Event 7 - desired state on the other axis. Observed untouched.
            desired = await facts.create_desired(
                asset.id,
                DesiredFactCreate(
                    predicate=PREDICATE,
                    value_type=ValueType.NUMBER,
                    value_number=MEM_24,
                ),
                second_approver_principal,
            )
            assert desired.fact_kind == FactKind.DESIRED_STATE.value
            assert desired.verification_status == VerificationStatus.APPROVED.value
            await session.refresh(f3)
            assert f3.valid_to is None

            # Five rows, one closed, nothing deleted.
            total = await session.scalar(select(func.count()).select_from(AssetFact))
            assert total == 5
            closed = await session.scalar(
                select(func.count())
                .select_from(AssetFact)
                .where(AssetFact.valid_to.is_not(None))
            )
            assert closed == 1

            # Drift is now a plain query, with no new schema.
            drift = (
                await session.execute(
                    text(
                        """
                        SELECT d.value_number, o.value_number
                        FROM asset_fact d
                        JOIN asset_fact o
                          ON o.asset_id = d.asset_id AND o.predicate = d.predicate
                         AND o.fact_kind = 'OBSERVED_STATE' AND o.valid_to IS NULL
                         AND o.verification_status IN ('VERIFIED','APPROVED')
                        WHERE d.fact_kind = 'DESIRED_STATE' AND d.valid_to IS NULL
                          AND d.value_number IS DISTINCT FROM o.value_number
                        """
                    )
                )
            ).all()
            assert drift == [(Decimal(MEM_24), Decimal(MEM_16))]

    async def test_history_is_queryable_at_a_past_instant(
        self, db, operator_principal
    ) -> None:
        async with db.session() as session:
            facts = FactService(session)
            asset = await _make_vm(session, operator_principal, "vm-doc-history")
            await facts.assert_fact(
                asset.id, _assert_memory(MEM_12, PROXMOX, SourceType.LIVE_DISCOVERY)
            )
            await facts.assert_fact(
                asset.id, _assert_memory(MEM_16, PROXMOX, SourceType.LIVE_DISCOVERY)
            )
            history = await facts.history(asset.id, PREDICATE)
        assert len(history) == 2
        assert history[0].valid_to is None
        assert history[1].valid_to is not None
        assert history[0].supersedes_fact_id == history[1].id


class TestSingleAuthorityAndRevocation:
    async def test_second_verification_is_refused_with_a_clean_conflict(
        self, db, operator_principal, approver_principal
    ) -> None:
        async with db.session() as session:
            facts = FactService(session)
            asset = await _make_vm(session, operator_principal, "vm-doc-auth")
            _, f_a, _, _ = await facts.assert_fact(
                asset.id, _assert_memory(MEM_16, PROXMOX, SourceType.LIVE_DISCOVERY)
            )
            _, f_b, _, _ = await facts.assert_fact(
                asset.id,
                _assert_memory(MEM_12, "acop:user:steve", SourceType.MANUAL_ENTRY),
            )
            await facts.transition(f_a.id, AttestationAction.VERIFY, approver_principal)

            with pytest.raises(ConflictError, match="already authoritative"):
                await facts.transition(
                    f_b.id, AttestationAction.VERIFY, approver_principal
                )

    async def test_ai_inference_cannot_be_verified_through_the_service(
        self, db, operator_principal, approver_principal
    ) -> None:
        async with db.session() as session:
            facts = FactService(session)
            asset = await _make_vm(session, operator_principal, "vm-doc-ai")
            _, ai_fact, _, _ = await facts.assert_fact(
                asset.id,
                _assert_memory(MEM_16, "acop:agent:noc", SourceType.AI_INFERENCE),
            )
            with pytest.raises(ConflictError, match="never be verified"):
                await facts.transition(
                    ai_fact.id, AttestationAction.VERIFY, approver_principal
                )

    async def test_revocation_preserves_full_historical_attribution(
        self, db, operator_principal, approver_principal, second_approver_principal
    ) -> None:
        """The scenario from the approved requirement.

        Principal A verifies; Principal B revokes. ACOP must still be able to
        show that the fact existed, that A verified it and when, that B revoked
        it and when, and the fact's value and provenance.
        """
        async with db.session() as session:
            facts = FactService(session)
            asset = await _make_vm(session, operator_principal, "vm-doc-revoke")
            _, fact, _, _ = await facts.assert_fact(
                asset.id, _assert_memory(MEM_16, PROXMOX, SourceType.LIVE_DISCOVERY)
            )

            await facts.transition(
                fact.id,
                AttestationAction.VERIFY,
                approver_principal,
                reason="Checked against the hypervisor.",
            )
            await facts.transition(
                fact.id,
                AttestationAction.REVOKE,
                second_approver_principal,
                reason="Reading was taken during a migration.",
            )

            await session.refresh(fact)
            trail = await facts.attestations([fact.id])

        # 1. The fact still exists, with its value and provenance intact.
        assert fact.value_number == Decimal(MEM_16)
        assert fact.source_id == PROXMOX
        assert fact.source_type == SourceType.LIVE_DISCOVERY.value
        assert fact.valid_to is None

        # 2. It is no longer authoritative, and carries no stale verifier.
        assert fact.verification_status == VerificationStatus.DISCOVERED.value
        assert fact.verified_by_subject is None
        assert fact.verified_at is None

        # 3. The immutable lineage holds both acts, both actors, both times.
        assert len(trail) == 2
        revoke, verify = trail  # newest first
        assert verify.action == AttestationAction.VERIFY.value
        assert verify.principal_subject == "acop:user:approver-a"
        assert verify.from_status == VerificationStatus.DISCOVERED.value
        assert verify.to_status == VerificationStatus.VERIFIED.value
        assert verify.reason == "Checked against the hypervisor."
        assert revoke.action == AttestationAction.REVOKE.value
        assert revoke.principal_subject == "acop:user:approver-b"
        assert revoke.from_status == VerificationStatus.VERIFIED.value
        assert revoke.occurred_at >= verify.occurred_at
        # Provider-neutral identity, the same four fields the audit log uses.
        assert verify.principal_issuer == "acop:api-key"
        assert verify.auth_method == "api_key"

    async def test_revocation_frees_the_authority_slot(
        self, db, operator_principal, approver_principal
    ) -> None:
        """Without this, a mistaken verification would be permanent."""
        async with db.session() as session:
            facts = FactService(session)
            asset = await _make_vm(session, operator_principal, "vm-doc-slot")
            _, f_a, _, _ = await facts.assert_fact(
                asset.id, _assert_memory(MEM_16, PROXMOX, SourceType.LIVE_DISCOVERY)
            )
            _, f_b, _, _ = await facts.assert_fact(
                asset.id,
                _assert_memory(MEM_12, "acop:user:steve", SourceType.MANUAL_ENTRY),
            )
            await facts.transition(f_a.id, AttestationAction.VERIFY, approver_principal)
            await facts.transition(f_a.id, AttestationAction.REVOKE, approver_principal)
            promoted = await facts.transition(
                f_b.id, AttestationAction.VERIFY, approver_principal
            )
        assert promoted.verification_status == VerificationStatus.VERIFIED.value

    async def test_cannot_revoke_a_claim_that_holds_no_authority(
        self, db, operator_principal, approver_principal
    ) -> None:
        async with db.session() as session:
            facts = FactService(session)
            asset = await _make_vm(session, operator_principal, "vm-doc-norev")
            _, fact, _, _ = await facts.assert_fact(
                asset.id, _assert_memory(MEM_16, PROXMOX, SourceType.LIVE_DISCOVERY)
            )
            with pytest.raises(ConflictError, match="Only a VERIFIED or APPROVED"):
                await facts.transition(
                    fact.id, AttestationAction.REVOKE, approver_principal
                )


class TestEffectiveValueBases:
    async def test_unanimous_excludes_inference_from_the_vote(
        self, db, operator_principal
    ) -> None:
        """An inference agreeing with an observation is echo, not corroboration."""
        async with db.session() as session:
            facts = FactService(session)
            asset = await _make_vm(session, operator_principal, "vm-doc-unanimous")
            await facts.assert_fact(
                asset.id, _assert_memory(MEM_16, PROXMOX, SourceType.LIVE_DISCOVERY)
            )
            await facts.assert_fact(
                asset.id,
                _assert_memory(MEM_16, "acop:user:steve", SourceType.MANUAL_ENTRY),
            )
            await facts.assert_fact(
                asset.id,
                _assert_memory(MEM_12, "acop:agent:noc", SourceType.AI_INFERENCE),
            )
            effective = await facts.effective(
                asset.id, PREDICATE, FactKind.OBSERVED_STATE.value
            )
        assert effective.basis == UNANIMOUS
        assert effective.conflict_present  # the AI row still disagrees
        assert len(effective.dissenting_claims) == 1

    async def test_inference_only_is_never_a_resolved_value(
        self, db, operator_principal
    ) -> None:
        async with db.session() as session:
            facts = FactService(session)
            asset = await _make_vm(session, operator_principal, "vm-doc-aionly")
            await facts.assert_fact(
                asset.id,
                _assert_memory(MEM_16, "acop:agent:noc", SourceType.AI_INFERENCE),
            )
            effective = await facts.effective(
                asset.id, PREDICATE, FactKind.OBSERVED_STATE.value
            )
        assert effective.basis == UNRESOLVED
        assert effective.inference_only
        assert effective.fact is None


class TestSecretRejection:
    async def test_secret_predicate_is_rejected_at_the_service_boundary(
        self, db, operator_principal
    ) -> None:
        async with db.session() as session:
            facts = FactService(session)
            asset = await _make_vm(session, operator_principal, "vm-doc-secret")
            with pytest.raises(SecretRejectedError):
                await facts.assert_fact(
                    asset.id,
                    FactAssert(
                        predicate="snmp.community",
                        value_type=ValueType.TEXT,
                        value_text="public",
                        source_type=SourceType.LIVE_DISCOVERY,
                        source_id=PROXMOX,
                    ),
                )
            stored = await session.scalar(select(func.count()).select_from(AssetFact))
        assert stored == 0

    async def test_nested_secret_in_json_is_redacted_before_persistence(
        self, db, operator_principal
    ) -> None:
        async with db.session() as session:
            facts = FactService(session)
            asset = await _make_vm(session, operator_principal, "vm-doc-json")
            _, fact, _, redacted = await facts.assert_fact(
                asset.id,
                FactAssert(
                    predicate="interface.lldp_neighbour",
                    value_type=ValueType.JSON,
                    value_json={
                        "device": "switch-doc-01",
                        "password": "hunter2",
                    },
                    source_type=SourceType.LIVE_DISCOVERY,
                    source_id=PROXMOX,
                ),
            )
        assert "hunter2" not in str(fact.value_json)
        assert "switch-doc-01" in str(fact.value_json)
        assert redacted == ["password"]


class TestIdentityResolution:
    async def test_two_sources_converge_on_one_asset(
        self, db, operator_principal
    ) -> None:
        async with db.session() as session:
            resolver = IdentityResolver(session)
            first = await resolver.resolve(
                asset_type=AssetType.HOST,
                display_name="host-doc-01",
                identifiers=[IdentifierInput(namespace="serial", value=DOC_SERIAL)],
                principal=operator_principal,
            )
            second = await resolver.resolve(
                asset_type=AssetType.HOST,
                display_name="host-doc-01-alias",
                identifiers=[
                    IdentifierInput(namespace="serial", value=DOC_SERIAL.lower()),
                    IdentifierInput(namespace="mac", value=DOC_MAC),
                ],
                principal=operator_principal,
            )
            total = await session.scalar(select(func.count()).select_from(Asset))
        assert first.outcome == "CREATED"
        assert second.outcome == "MATCHED"
        assert second.asset.id == first.asset.id
        assert total == 1

    async def test_multi_match_refuses_and_writes_nothing(
        self, db, operator_principal
    ) -> None:
        """Refusing is recoverable; guessing welds two machines together."""
        async with db.session() as session:
            resolver = IdentityResolver(session)
            await resolver.resolve(
                asset_type=AssetType.HOST,
                display_name="host-doc-a",
                identifiers=[IdentifierInput(namespace="serial", value="DOCSERIAL-A")],
                principal=operator_principal,
            )
            await resolver.resolve(
                asset_type=AssetType.HOST,
                display_name="host-doc-b",
                identifiers=[
                    IdentifierInput(namespace="smbios:uuid", value="doc-uuid-b")
                ],
                principal=operator_principal,
            )
            before = await session.scalar(select(func.count()).select_from(Asset))

            with pytest.raises(IdentityConflictError) as excinfo:
                await resolver.resolve(
                    asset_type=AssetType.HOST,
                    display_name="host-doc-merged",
                    identifiers=[
                        IdentifierInput(namespace="serial", value="DOCSERIAL-A"),
                        IdentifierInput(namespace="smbios:uuid", value="doc-uuid-b"),
                    ],
                    principal=operator_principal,
                )
            after = await session.scalar(select(func.count()).select_from(Asset))

        assert after == before
        assert len(excinfo.value.context["candidates"]) == 2
        assert excinfo.value.http_status == 409

    async def test_non_unique_namespace_alone_never_matches(
        self, db, operator_principal
    ) -> None:
        """A hostname is a correlation hint, not an identity."""
        async with db.session() as session:
            resolver = IdentityResolver(session)
            await resolver.resolve(
                asset_type=AssetType.HOST,
                display_name="host-doc-1",
                identifiers=[IdentifierInput(namespace="hostname", value="web01")],
                principal=operator_principal,
            )
            second = await resolver.resolve(
                asset_type=AssetType.HOST,
                display_name="host-doc-2",
                identifiers=[IdentifierInput(namespace="hostname", value="web01")],
                principal=operator_principal,
            )
            total = await session.scalar(select(func.count()).select_from(Asset))
        assert second.outcome == "CREATED"
        assert total == 2


class TestRelationships:
    async def test_symmetric_edge_is_canonicalised_and_deduplicated(
        self, db, operator_principal
    ) -> None:
        async with db.session() as session:
            resolver = IdentityResolver(session)
            nic = (
                await resolver.resolve(
                    asset_type=AssetType.NETWORK_INTERFACE,
                    display_name="nic-doc-eth0",
                    identifiers=[IdentifierInput(namespace="mac", value=DOC_MAC)],
                    principal=operator_principal,
                )
            ).asset
            port = (
                await resolver.resolve(
                    asset_type=AssetType.SWITCH_PORT,
                    display_name="Gi1/0/24",
                    identifiers=[
                        IdentifierInput(namespace="serial", value="DOC-PORT-24")
                    ],
                    principal=operator_principal,
                )
            ).asset

            service = RelationshipService(session)
            outcome_a, edge_a, canon_a = await service.assert_relationship(
                RelationshipAssert(
                    relationship_type=RelationshipType.CONNECTED_TO,
                    source_asset_id=nic.id,
                    target_asset_id=port.id,
                    source_type=SourceType.LIVE_DISCOVERY,
                    source_id="cisco:doc-switch-01",
                )
            )
            # The same cable, asserted from the other end.
            _outcome_b, edge_b, canon_b = await service.assert_relationship(
                RelationshipAssert(
                    relationship_type=RelationshipType.CONNECTED_TO,
                    source_asset_id=port.id,
                    target_asset_id=nic.id,
                    source_type=SourceType.LIVE_DISCOVERY,
                    source_id="cisco:doc-switch-01",
                )
            )
            total = await session.scalar(text("SELECT count(*) FROM asset_relationship"))

        assert outcome_a == "CREATED"
        assert edge_b.id == edge_a.id  # one physical link, one row
        assert total == 1
        assert canon_a or canon_b  # exactly one direction needed swapping

    async def test_depth_one_traversal_applies_inverse_labels(
        self, db, operator_principal
    ) -> None:
        async with db.session() as session:
            resolver = IdentityResolver(session)
            vm = (
                await resolver.resolve(
                    asset_type=AssetType.VM,
                    display_name="vm-doc-guest",
                    identifiers=[IdentifierInput(namespace="serial", value="DOC-VM-1")],
                    principal=operator_principal,
                )
            ).asset
            host = (
                await resolver.resolve(
                    asset_type=AssetType.HOST,
                    display_name="host-doc-hv",
                    identifiers=[IdentifierInput(namespace="serial", value="DOC-HV-1")],
                    principal=operator_principal,
                )
            ).asset
            service = RelationshipService(session)
            await service.assert_relationship(
                RelationshipAssert(
                    relationship_type=RelationshipType.RUNS_ON,
                    source_asset_id=vm.id,
                    target_asset_id=host.id,
                    source_type=SourceType.LIVE_DISCOVERY,
                    source_id=PROXMOX,
                )
            )
            from_vm = await service.neighbours(vm.id)
            from_host = await service.neighbours(host.id)

        assert [n.label for n in from_vm] == ["RUNS_ON"]
        assert from_vm[0].direction == "out"
        # The same stored row, read from the other end.
        assert [n.label for n in from_host] == ["HOSTS"]
        assert from_host[0].direction == "in"

    async def test_invalid_endpoint_types_are_rejected(
        self, db, operator_principal
    ) -> None:
        async with db.session() as session:
            resolver = IdentityResolver(session)
            vlan = (
                await resolver.resolve(
                    asset_type=AssetType.VLAN,
                    display_name="vlan-400",
                    identifiers=[IdentifierInput(namespace="serial", value="DOC-V400")],
                    principal=operator_principal,
                )
            ).asset
            gpu = (
                await resolver.resolve(
                    asset_type=AssetType.GPU,
                    display_name="gpu-doc-0",
                    identifiers=[IdentifierInput(namespace="serial", value="DOC-GPU-0")],
                    principal=operator_principal,
                )
            ).asset
            with pytest.raises(Exception, match="does not join"):
                await RelationshipService(session).assert_relationship(
                    RelationshipAssert(
                        relationship_type=RelationshipType.RUNS_ON,
                        source_asset_id=vlan.id,
                        target_asset_id=gpu.id,
                        source_type=SourceType.LIVE_DISCOVERY,
                        source_id=PROXMOX,
                    )
                )


class TestRetirement:
    async def test_retirement_closes_claims_and_destroys_nothing(
        self, db, operator_principal, approver_principal
    ) -> None:
        async with db.session() as session:
            facts = FactService(session)
            assets = AssetService(session)
            asset = await _make_vm(session, operator_principal, "vm-doc-retire")
            _, fact, _, _ = await facts.assert_fact(
                asset.id, _assert_memory(MEM_16, PROXMOX, SourceType.LIVE_DISCOVERY)
            )
            await facts.transition(fact.id, AttestationAction.VERIFY, approver_principal)

            retired, closed_facts, closed_edges = await assets.retire(asset.id)
            await session.refresh(fact)
            surviving = await session.scalar(select(func.count()).select_from(AssetFact))

        assert retired.lifecycle_state == LifecycleState.RETIRED.value
        assert retired.retired_at is not None
        assert closed_facts == 1
        assert closed_edges == 0
        assert surviving == 1  # nothing deleted
        assert fact.valid_to is not None
        # A human's verification is not overwritten by retirement.
        assert fact.verification_status == VerificationStatus.VERIFIED.value
        assert fact.verified_by_subject == "acop:user:approver-a"

    async def test_unverified_claims_become_stale_on_retirement(
        self, db, operator_principal
    ) -> None:
        async with db.session() as session:
            facts = FactService(session)
            assets = AssetService(session)
            asset = await _make_vm(session, operator_principal, "vm-doc-stale")
            _, fact, _, _ = await facts.assert_fact(
                asset.id, _assert_memory(MEM_16, PROXMOX, SourceType.LIVE_DISCOVERY)
            )
            await assets.retire(asset.id)
            await session.refresh(fact)
        assert fact.verification_status == VerificationStatus.STALE.value


class TestAuditIntegration:
    async def test_cmdb_write_and_audit_row_share_one_transaction(
        self, db, operator_principal
    ) -> None:
        """The atomicity is inherited from get_session, not built."""
        async with db.session() as session:
            facts = FactService(session)
            audit = AuditService(session)
            asset = await _make_vm(session, operator_principal, "vm-doc-audit")
            _, fact, _, _ = await facts.assert_fact(
                asset.id, _assert_memory(MEM_16, PROXMOX, SourceType.LIVE_DISCOVERY)
            )
            await audit.record(
                AuditEventCreate(
                    action="cmdb.fact.assert",
                    outcome="SUCCESS",
                    resource_type="cmdb.fact",
                    resource_id=str(fact.id),
                    context={"predicate": fact.predicate},
                ),
                operator_principal,
            )

        async with db.session() as session:
            row = (
                (
                    await session.execute(
                        select(AuditEvent).where(AuditEvent.action == "cmdb.fact.assert")
                    )
                )
                .scalars()
                .one()
            )

        assert row.resource_id == str(fact.id)
        assert row.principal_subject == "acop:user:operator"
        assert row.principal_issuer == "acop:api-key"
        assert row.auth_method == "api_key"
        # The value is deliberately absent: it lives in asset_fact with full
        # history, so copying it doubles the leak surface.
        assert "value" not in str(row.context)

    async def test_a_failed_mutation_leaves_no_orphan_row(
        self, db, operator_principal
    ) -> None:
        asset_id = None
        with pytest.raises(SecretRejectedError):
            async with db.session() as session:
                asset = await _make_vm(session, operator_principal, "vm-doc-orphan")
                asset_id = asset.id
                await FactService(session).assert_fact(
                    asset.id,
                    FactAssert(
                        predicate="bmc.password",
                        value_type=ValueType.TEXT,
                        value_text="x",
                        source_type=SourceType.LIVE_DISCOVERY,
                        source_id=PROXMOX,
                    ),
                )

        async with db.session() as session:
            # The whole transaction rolled back, asset included.
            remaining = await session.scalar(
                select(func.count()).select_from(Asset).where(Asset.id == asset_id)
            )
            facts = await session.scalar(select(func.count()).select_from(AssetFact))
        assert remaining == 0
        assert facts == 0

    async def test_attestations_are_append_only_in_the_domain(
        self, db, operator_principal, approver_principal
    ) -> None:
        async with db.session() as session:
            facts = FactService(session)
            asset = await _make_vm(session, operator_principal, "vm-doc-attest")
            _, fact, _, _ = await facts.assert_fact(
                asset.id, _assert_memory(MEM_16, PROXMOX, SourceType.LIVE_DISCOVERY)
            )
            await facts.transition(fact.id, AttestationAction.VERIFY, approver_principal)
            await facts.transition(fact.id, AttestationAction.REVOKE, approver_principal)
            await facts.transition(fact.id, AttestationAction.VERIFY, approver_principal)
            await facts.transition(fact.id, AttestationAction.REVOKE, approver_principal)
            count = await session.scalar(
                select(func.count()).select_from(FactAttestation)
            )
        # Four transitions, four immutable records. Columns on the fact row
        # would have retained only the most recent pair.
        assert count == 4


class TestPagination:
    async def test_keyset_pagination_walks_every_asset_exactly_once(
        self, db, operator_principal
    ) -> None:
        """Keyset, not OFFSET: a page boundary must stay stable while
        collectors insert. This also guards the SQL row-value comparison -
        a Python tuple comparison there silently returns the wrong page.
        """
        async with db.session() as session:
            resolver = IdentityResolver(session)
            for index in range(7):
                await resolver.resolve(
                    asset_type=AssetType.VM,
                    display_name=f"vm-doc-page-{index:02d}",
                    identifiers=[
                        IdentifierInput(namespace="serial", value=f"DOC-PAGE-{index}")
                    ],
                    principal=operator_principal,
                )

            assets = AssetService(session)
            seen: list[str] = []
            cursor: str | None = None
            for _ in range(10):
                rows, cursor = await assets.list_assets(limit=3, cursor=cursor)
                seen.extend(row.display_name for row in rows)
                if cursor is None:
                    break

            # The contract is (created_at, id) order, not name order. Rows
            # created in one transaction share now(), so the UUID tiebreaker
            # decides intra-batch order - arbitrary, but total and stable,
            # which is all keyset pagination requires.
            expected = [
                row.display_name
                for row in (
                    await session.execute(
                        select(Asset).order_by(Asset.created_at, Asset.id)
                    )
                ).scalars()
            ]

        assert len(seen) == 7
        assert len(set(seen)) == 7  # nothing repeated across page boundaries
        assert seen == expected  # nothing skipped, order preserved
