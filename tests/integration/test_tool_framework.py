"""The tool framework against real PostgreSQL.

The properties proved here are the ones no unit test can reach, because they
are properties of *the database*: compare-and-set concurrency, the separation
of duties CHECK, the distinct-approver partial unique index, the idempotency
index, and the fact that a refusal survives the rollback of the request that
caused it.

The adversarial test at the end is the important one. It inserts a
``tool_registration`` row by raw SQL for a tool no code declares, marks it
ACTIVE and Class 1, and attempts to invoke it. Nothing may execute. That is the
Capability Binding Invariant tested the way an attacker would test it.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from acop.api.routes import tool_invocations as tool_routes
from acop.auth import AuthMethod, Principal, PrincipalType
from acop.config import Settings
from acop.db import Database
from acop.main import create_app
from acop.models.asset import Asset
from acop.models.provenance import PermissionClass
from acop.models.tool import (
    ToolApproval,
    ToolInvocation,
    ToolInvocationEvent,
    ToolInvocationReconciliation,
    ToolRegistration,
)
from acop.models.tool_vocabulary import (
    AdapterOutcome,
    ApprovalDecision,
    InvocationState,
    PolicyReason,
    ReconciliationDisposition,
    ToolErrorCategory,
    ToolLifecycle,
    ValidationOutcome,
)
from acop.models.vocabulary import AssetType, LifecycleState
from acop.services.audit import AuditService
from acop.services.tools import reaper as sweeper_module
from acop.services.tools.approval import ToolApprovalService
from acop.services.tools.dispatcher import ExecutionDispatcher
from acop.services.tools.invocation import InvocationRequest, ToolInvocationService
from acop.services.tools.reaper import ApprovalSweeper, InvocationReaper
from acop.services.tools.reconciliation import ReconciliationService
from acop.services.tools.state import claim_for_execution, release_lease, transition
from acop.tools.adapters.base import AdapterRequest, AdapterResult
from acop.tools.adapters.simulated import (
    SIM_SLOW,
    SIM_STAYS_DOWN,
    SIM_UNREACHABLE,
    SIMULATED_ADAPTER,
    reset_simulation,
)
from acop.tools.errors import (
    ApprovalEnvelopeMismatchError,
    DuplicateApprovalError,
    IdempotencyConflictError,
    InvalidTargetError,
    PolicyEngineFailureError,
    ProhibitedCapabilityError,
    SelfApprovalForbiddenError,
    StaleTransitionError,
    ToolAuthorizationError,
    ToolNotFoundError,
    ToolPolicyDeniedError,
)
from acop.tools.policy import ToolPolicyEngine
from acop.tools.registry import CODE_REGISTRY, ToolRegistryReconciler
from tests.conftest import TEST_API_SECRET, TEST_SUBJECT, requires_database
from tests.integration.conftest import reset_test_database

pytestmark = [pytest.mark.integration, requires_database]

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Shaped like the worst thing a gate could be holding when it dies. Nothing of
#: it may reach a response, an audit record or an invocation row.
_LEAKY_MESSAGE = "policy store unreachable: postgresql://acop:hunter2@db.internal/acop"


def _principal(subject: str, *roles: str) -> Principal:
    return Principal(
        subject=subject,
        principal_type=PrincipalType.HUMAN,
        issuer="acop:api-key",
        auth_method=AuthMethod.API_KEY,
        roles=frozenset(roles),
    )


VIEWER = _principal("acop:user:viewer", "viewer")
OPERATOR = _principal("acop:user:operator", "operator")
APPROVER_A = _principal("acop:user:approver-a", "approver")
APPROVER_B = _principal("acop:user:approver-b", "approver")
ADMIN = _principal("acop:user:admin", "admin")


@pytest.fixture
async def tdb(settings: Settings) -> AsyncIterator[Database]:
    database = Database(settings)
    await reset_test_database(settings)
    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", settings.alembic_database_url)
    await asyncio.to_thread(command.upgrade, config, "head")
    async with database.session() as session:
        await ToolRegistryReconciler(session).reconcile()
    await reset_simulation()
    try:
        yield database
    finally:
        await database.dispose()


async def _asset(
    database: Database,
    *,
    display_name: str,
    asset_type: AssetType = AssetType.SERVICE,
    lifecycle: LifecycleState = LifecycleState.ACTIVE,
) -> uuid.UUID:
    async with database.session() as session:
        asset = Asset(
            asset_type=asset_type.value,
            display_name=display_name,
            lifecycle_state=lifecycle.value,
            retired_at=(
                datetime.now(UTC) if lifecycle is LifecycleState.RETIRED else None
            ),
        )
        session.add(asset)
        await session.flush()
        return asset.id


def _services(
    database: Database, settings: Settings
) -> tuple[ToolInvocationService, ToolApprovalService, ExecutionDispatcher]:
    return (
        ToolInvocationService(database, settings),
        ToolApprovalService(database, settings),
        ExecutionDispatcher(database, settings),
    )


async def _reload(database: Database, invocation_id: uuid.UUID) -> ToolInvocation:
    async with database.session() as session:
        row = await session.get(ToolInvocation, invocation_id)
        assert row is not None
        return row


async def _denial_audit(database: Database) -> list[tuple[str, str]]:
    """Every ``DENIED`` audit row as ``(action, severity)``, oldest first.

    The whole list rather than a count, because what F4 is about is that two
    refusals which used to be one row shape are now two - and a count cannot
    tell them apart any better than the dashboard could.
    """
    async with database.session() as session:
        rows = await session.execute(
            text(
                "SELECT action, severity FROM audit_event "
                "WHERE outcome = 'DENIED' ORDER BY occurred_at"
            )
        )
        return [(str(action), str(severity)) for action, severity in rows]


async def _only_invocation(database: Database) -> ToolInvocation:
    """The single invocation this test wrote. The schema is fresh per test."""
    async with database.session() as session:
        rows = (await session.execute(select(ToolInvocation))).scalars().all()
    assert len(rows) == 1
    return rows[0]


# ---------------------------------------------------------------------------
# Registry reconciliation
# ---------------------------------------------------------------------------
class TestRegistryReconciliation:
    async def test_every_declared_tool_gets_an_active_row(self, tdb: Database) -> None:
        async with tdb.session() as session:
            rows = (await session.execute(select(ToolRegistration))).scalars().all()
        assert {row.tool_name for row in rows} == {
            "acop.system.health",
            "acop.test.echo_metadata",
            "test.device.status",
            "test.service.restart",
            "test.security.rotate_key",
            "test.prohibited.shell_exec",
            # Milestone 5 Checkpoint 2. Ten read-only Proxmox capabilities, and
            # exactly ten: the set is asserted rather than the count, so a tool
            # nobody meant to ship shows up here as a name.
            "proxmox.cluster.status",
            "proxmox.node.list",
            "proxmox.node.status",
            "proxmox.node.network",
            "proxmox.guest.list",
            "proxmox.vm.status",
            "proxmox.vm.config",
            "proxmox.container.status",
            "proxmox.container.config",
            "proxmox.storage.list",
        }
        assert all(row.lifecycle_state == ToolLifecycle.ACTIVE.value for row in rows)

    async def test_no_row_carries_a_permission_class(self, tdb: Database) -> None:
        """F3: the database owns lifecycle and nothing else about a tool.

        A second copy of a security-significant value is a second thing that
        can be wrong, and a column that exists is a column something eventually
        reads.
        """
        async with tdb.session() as session:
            columns = (
                (
                    await session.execute(
                        text(
                            "SELECT column_name FROM information_schema.columns "
                            "WHERE table_name = 'tool_registration'"
                        )
                    )
                )
                .scalars()
                .all()
            )
        assert "permission_class" not in columns
        assert "adapter_id" not in columns
        assert "input_schema" not in columns

    async def test_reconciliation_is_idempotent(self, tdb: Database) -> None:
        async with tdb.session() as session:
            report = await ToolRegistryReconciler(session).reconcile()
        assert not report.registered
        assert not report.retired
        assert len(report.unchanged) == 16

    async def test_a_row_with_no_code_declaration_is_retired_not_deleted(
        self, tdb: Database
    ) -> None:
        """History is preserved: invocations still reference it."""
        async with tdb.session() as session:
            session.add(
                ToolRegistration(
                    tool_name="ghost.tool.read",
                    tool_version="1.0",
                    contract_hash="0" * 64,
                )
            )
        async with tdb.session() as session:
            report = await ToolRegistryReconciler(session).reconcile()
        assert report.retired == ["ghost.tool.read@1.0"]
        async with tdb.session() as session:
            row = (
                (
                    await session.execute(
                        select(ToolRegistration).where(
                            ToolRegistration.tool_name == "ghost.tool.read"
                        )
                    )
                )
                .scalars()
                .one()
            )
        assert row.lifecycle_state == ToolLifecycle.RETIRED.value
        assert row.retired_at is not None


# ---------------------------------------------------------------------------
# Class 0 / Class 1 â€” the shared execution path, run inline
# ---------------------------------------------------------------------------
class TestReadOnlyExecution:
    async def test_a_class_zero_tool_runs_through_the_shared_dispatcher(
        self, tdb: Database, settings: Settings
    ) -> None:
        invocations, _, dispatcher = _services(tdb, settings)
        invocation = await invocations.create(
            InvocationRequest(
                tool_name="acop.test.echo_metadata",
                tool_version="1.0",
                arguments={"note": "hello"},
            ),
            VIEWER,
        )
        assert invocation.state == InvocationState.READY.value
        state = await dispatcher.execute_once(invocation.id)
        assert state is InvocationState.SUCCEEDED

        row = await _reload(tdb, invocation.id)
        # The final gate ran even for Class 0. There is no fast path.
        assert row.final_gate_decision == "ALLOW"
        assert row.final_gate_reason == PolicyReason.ALLOWED.value
        assert row.result_summary is not None
        assert row.result_summary["note"] == "hello"
        assert row.result_digest is not None

    async def test_a_class_one_tool_reads_the_real_cmdb(
        self, tdb: Database, settings: Settings
    ) -> None:
        asset_id = await _asset(
            tdb, display_name="core-switch", asset_type=AssetType.DEVICE
        )
        invocations, _, dispatcher = _services(tdb, settings)
        invocation = await invocations.create(
            InvocationRequest(
                tool_name="test.device.status",
                tool_version="1.0",
                arguments={"include_facts": False},
                target_asset_id=asset_id,
            ),
            VIEWER,
        )
        assert await dispatcher.execute_once(invocation.id) is InvocationState.SUCCEEDED
        row = await _reload(tdb, invocation.id)
        assert row.result_summary is not None
        assert row.result_summary["display_name"] == "core-switch"

    async def test_a_retired_asset_is_refused_before_execution(
        self, tdb: Database, settings: Settings
    ) -> None:
        asset_id = await _asset(
            tdb,
            display_name="decommissioned",
            asset_type=AssetType.DEVICE,
            lifecycle=LifecycleState.RETIRED,
        )
        invocations, _, _ = _services(tdb, settings)
        # A stale target is the caller's target being wrong, so it is a 422
        # naming the target rather than a 403 about who they are.
        with pytest.raises(InvalidTargetError):
            await invocations.create(
                InvocationRequest(
                    tool_name="test.device.status",
                    tool_version="1.0",
                    arguments={},
                    target_asset_id=asset_id,
                ),
                VIEWER,
            )

    async def test_a_refusal_survives_the_rollback_of_its_request(
        self, tdb: Database, settings: Settings
    ) -> None:
        """The record of an attempt must outlive the attempt.

        The invocation row is written on its own transaction precisely so that
        a denial - which raises - is still there afterwards.
        """
        invocations, _, _ = _services(tdb, settings)
        with pytest.raises(ToolAuthorizationError):
            await invocations.create(
                InvocationRequest(
                    tool_name="test.service.restart",
                    tool_version="1.0",
                    arguments={},
                    target_asset_id=await _asset(tdb, display_name="svc"),
                    idempotency_key="k1",
                ),
                VIEWER,  # not an operator
            )
        async with tdb.session() as session:
            rows = (
                (
                    await session.execute(
                        select(ToolInvocation).where(
                            ToolInvocation.state == InvocationState.REJECTED.value
                        )
                    )
                )
                .scalars()
                .all()
            )
        assert len(rows) == 1
        assert rows[0].authorization_decision == "DENY"
        assert rows[0].authorization_reason == PolicyReason.ROLE_INSUFFICIENT.value


# ---------------------------------------------------------------------------
# Class 2 â€” the complete change path
# ---------------------------------------------------------------------------
class TestChangeClassPath:
    async def test_request_approve_gate_execute_validate(
        self, tdb: Database, settings: Settings
    ) -> None:
        asset_id = await _asset(tdb, display_name="sim-ok")
        invocations, approvals, dispatcher = _services(tdb, settings)
        invocation = await invocations.create(
            InvocationRequest(
                tool_name="test.service.restart",
                tool_version="1.0",
                arguments={"graceful": True, "drain_seconds": 0},
                target_asset_id=asset_id,
                idempotency_key="restart-1",
            ),
            OPERATOR,
        )
        assert invocation.state == InvocationState.AWAITING_APPROVAL.value
        digest = invocation.envelope_digest

        await approvals.decide(
            invocation.id,
            APPROVER_A,
            decision=ApprovalDecision.APPROVED,
            justification="Change ticket CHG-1.",
            expected_envelope_digest=digest,
        )
        assert (await _reload(tdb, invocation.id)).state == InvocationState.READY.value

        assert await dispatcher.execute_once(invocation.id) is InvocationState.SUCCEEDED
        row = await _reload(tdb, invocation.id)
        assert row.validation_outcome == ValidationOutcome.CONFIRMED.value
        assert row.final_gate_decision == "ALLOW"
        assert row.rollback_hint is not None

    async def test_executed_is_not_succeeded_when_validation_disagrees(
        self, tdb: Database, settings: Settings
    ) -> None:
        """The whole reason the two states are separate.

        The adapter reports success and the service is nevertheless not
        running. Collapsing EXECUTED into SUCCEEDED would make "the restart API
        returned 200" indistinguishable from "the service is running".
        """
        asset_id = await _asset(tdb, display_name=SIM_STAYS_DOWN)
        invocations, approvals, dispatcher = _services(tdb, settings)
        invocation = await invocations.create(
            InvocationRequest(
                tool_name="test.service.restart",
                tool_version="1.0",
                arguments={},
                target_asset_id=asset_id,
                idempotency_key="restart-down",
            ),
            OPERATOR,
        )
        await approvals.decide(
            invocation.id,
            APPROVER_A,
            decision=ApprovalDecision.APPROVED,
            justification="Change ticket CHG-2.",
            expected_envelope_digest=invocation.envelope_digest,
        )
        state = await dispatcher.execute_once(invocation.id)
        assert state is InvocationState.VALIDATION_FAILED
        row = await _reload(tdb, invocation.id)
        assert row.validation_outcome == ValidationOutcome.NOT_CONFIRMED.value

    async def test_an_unreachable_adapter_fails_without_pretending(
        self, tdb: Database, settings: Settings
    ) -> None:
        asset_id = await _asset(tdb, display_name=SIM_UNREACHABLE)
        invocations, approvals, dispatcher = _services(tdb, settings)
        invocation = await invocations.create(
            InvocationRequest(
                tool_name="test.service.restart",
                tool_version="1.0",
                arguments={},
                target_asset_id=asset_id,
                idempotency_key="restart-unreachable",
            ),
            OPERATOR,
        )
        await approvals.decide(
            invocation.id,
            APPROVER_A,
            decision=ApprovalDecision.APPROVED,
            justification="Change ticket CHG-3.",
            expected_envelope_digest=invocation.envelope_digest,
        )
        assert await dispatcher.execute_once(invocation.id) is InvocationState.FAILED
        row = await _reload(tdb, invocation.id)
        assert row.error_category == "ADAPTER_UNAVAILABLE"
        # A fixed phrase, never adapter text.
        assert row.error_detail_sanitized == "The adapter could not be reached."

    async def test_an_adapter_cannot_extend_its_own_deadline(
        self, tdb: Database, settings: Settings
    ) -> None:
        asset_id = await _asset(tdb, display_name=SIM_SLOW)
        invocations, approvals, dispatcher = _services(tdb, settings)
        invocation = await invocations.create(
            InvocationRequest(
                tool_name="test.service.restart",
                tool_version="1.0",
                arguments={},
                target_asset_id=asset_id,
                idempotency_key="restart-slow",
            ),
            OPERATOR,
        )
        await approvals.decide(
            invocation.id,
            APPROVER_A,
            decision=ApprovalDecision.APPROVED,
            justification="Change ticket CHG-4.",
            expected_envelope_digest=invocation.envelope_digest,
        )
        # The tool declares 30s; the adapter sleeps past it. The dispatcher
        # cancels from outside, so the sleep never completes.
        row_definition_timeout = 30.0
        state = await asyncio.wait_for(
            dispatcher.execute_once(invocation.id),
            timeout=row_definition_timeout + 15,
        )
        assert state is InvocationState.TIMED_OUT
        row = await _reload(tdb, invocation.id)
        assert row.error_category == "TIMEOUT"


# ---------------------------------------------------------------------------
# Approvals: separation of duties and envelope binding
# ---------------------------------------------------------------------------
class TestApprovals:
    async def _pending(
        self, tdb: Database, settings: Settings, *, key: str = "sod-1"
    ) -> ToolInvocation:
        asset_id = await _asset(tdb, display_name="sim-ok")
        invocations, _, _ = _services(tdb, settings)
        return await invocations.create(
            InvocationRequest(
                tool_name="test.service.restart",
                tool_version="1.0",
                arguments={},
                target_asset_id=asset_id,
                idempotency_key=key,
            ),
            OPERATOR,
        )

    async def test_the_requester_cannot_approve_their_own_invocation(
        self, tdb: Database, settings: Settings
    ) -> None:
        invocation = await self._pending(tdb, settings)
        _, approvals, _ = _services(tdb, settings)
        operator_who_can_approve = _principal(OPERATOR.subject, "operator", "approver")
        with pytest.raises(SelfApprovalForbiddenError):
            await approvals.decide(
                invocation.id,
                operator_who_can_approve,
                decision=ApprovalDecision.APPROVED,
                justification="I am sure it is fine.",
                expected_envelope_digest=invocation.envelope_digest,
            )

    async def test_the_database_refuses_a_self_approval_row_directly(
        self, tdb: Database, settings: Settings
    ) -> None:
        """Layer 3, tested by going around layers 1 and 2.

        If the API and the service were both wrong, the INSERT still aborts.
        """
        invocation = await self._pending(tdb, settings, key="sod-db")
        with pytest.raises(IntegrityError):
            async with tdb.session() as session:
                session.add(
                    ToolApproval(
                        invocation_id=invocation.id,
                        decision=ApprovalDecision.APPROVED.value,
                        approved_envelope_digest=invocation.envelope_digest,
                        requester_subject=OPERATOR.subject,
                        approver_subject=OPERATOR.subject,
                        approver_type="human",
                        approver_issuer="acop:api-key",
                        approver_auth_method="api_key",
                        self_approval=False,
                        justification="Should be impossible.",
                        expires_at=datetime.now(UTC) + timedelta(hours=1),
                    )
                )

    async def test_an_admin_gets_no_separation_of_duties_bypass(
        self, tdb: Database, settings: Settings
    ) -> None:
        asset_id = await _asset(tdb, display_name="sim-ok")
        invocations, approvals, _ = _services(tdb, settings)
        invocation = await invocations.create(
            InvocationRequest(
                tool_name="test.service.restart",
                tool_version="1.0",
                arguments={},
                target_asset_id=asset_id,
                idempotency_key="admin-sod",
            ),
            ADMIN,
        )
        with pytest.raises(SelfApprovalForbiddenError):
            await approvals.decide(
                invocation.id,
                ADMIN,
                decision=ApprovalDecision.APPROVED,
                justification="Admin override.",
                expected_envelope_digest=invocation.envelope_digest,
            )

    async def test_a_viewer_holds_no_approval_authority(
        self, tdb: Database, settings: Settings
    ) -> None:
        invocation = await self._pending(tdb, settings, key="authority")
        _, approvals, _ = _services(tdb, settings)
        with pytest.raises(ToolAuthorizationError):
            await approvals.decide(
                invocation.id,
                VIEWER,
                decision=ApprovalDecision.APPROVED,
                justification="Looks fine to me.",
                expected_envelope_digest=invocation.envelope_digest,
            )

    async def test_an_approver_must_state_the_digest_they_reviewed(
        self, tdb: Database, settings: Settings
    ) -> None:
        invocation = await self._pending(tdb, settings, key="digest")
        _, approvals, _ = _services(tdb, settings)
        with pytest.raises(ApprovalEnvelopeMismatchError):
            await approvals.decide(
                invocation.id,
                APPROVER_A,
                decision=ApprovalDecision.APPROVED,
                justification="Approving something else.",
                expected_envelope_digest="f" * 64,
            )

    async def test_class_three_needs_two_distinct_approvers(
        self, tdb: Database, settings: Settings
    ) -> None:
        """Strength through policy, not role.

        An operator requests it and two approvers agree. No admin is involved
        anywhere, which is the R2 correction made observable.
        """
        asset_id = await _asset(tdb, display_name="key-store", asset_type=AssetType.HOST)
        invocations, approvals, dispatcher = _services(tdb, settings)
        invocation = await invocations.create(
            InvocationRequest(
                tool_name="test.security.rotate_key",
                tool_version="1.0",
                arguments={"key_slot": "primary"},
                target_asset_id=asset_id,
                idempotency_key="rotate-1",
            ),
            OPERATOR,
        )
        digest = invocation.envelope_digest

        await approvals.decide(
            invocation.id,
            APPROVER_A,
            decision=ApprovalDecision.APPROVED,
            justification="First approval.",
            expected_envelope_digest=digest,
        )
        # One is not enough.
        assert (
            await _reload(tdb, invocation.id)
        ).state == InvocationState.AWAITING_APPROVAL.value

        await approvals.decide(
            invocation.id,
            APPROVER_B,
            decision=ApprovalDecision.APPROVED,
            justification="Second approval.",
            expected_envelope_digest=digest,
        )
        assert (await _reload(tdb, invocation.id)).state == InvocationState.READY.value
        assert await dispatcher.execute_once(invocation.id) is InvocationState.SUCCEEDED

        row = await _reload(tdb, invocation.id)
        assert row.result_summary is not None
        # An opaque handle, and nothing that could be key material.
        assert set(row.result_summary) == {
            "asset_id",
            "key_slot",
            "key_identifier",
            "rotated_at",
        }

    async def test_the_same_approver_cannot_supply_both_approvals(
        self, tdb: Database, settings: Settings
    ) -> None:
        """Enforced by a partial unique index, not only by the service.

        The index is still the authority; what changed is only how its refusal
        is reported. A duplicate submission is a foreseeable client action, so
        it is a 409 rather than the 500 the escaping ``IntegrityError``
        produced - and the invocation is left exactly as it was, still one
        approval short.
        """
        asset_id = await _asset(
            tdb, display_name="key-store-2", asset_type=AssetType.HOST
        )
        invocations, approvals, _ = _services(tdb, settings)
        invocation = await invocations.create(
            InvocationRequest(
                tool_name="test.security.rotate_key",
                tool_version="1.0",
                arguments={"key_slot": "secondary"},
                target_asset_id=asset_id,
                idempotency_key="rotate-2",
            ),
            OPERATOR,
        )
        digest = invocation.envelope_digest
        await approvals.decide(
            invocation.id,
            APPROVER_A,
            decision=ApprovalDecision.APPROVED,
            justification="First.",
            expected_envelope_digest=digest,
        )
        with pytest.raises(DuplicateApprovalError):
            await approvals.decide(
                invocation.id,
                APPROVER_A,
                decision=ApprovalDecision.APPROVED,
                justification="And again.",
                expected_envelope_digest=digest,
            )
        row = await _reload(tdb, invocation.id)
        assert row.state == InvocationState.AWAITING_APPROVAL.value
        assert row.approvals_received == 1

    async def test_a_denial_is_terminal_immediately(
        self, tdb: Database, settings: Settings
    ) -> None:
        """No "one more approver might say yes".

        A provisional denial would let an approver who objected be outvoted by
        attrition.
        """
        invocation = await self._pending(tdb, settings, key="deny-1")
        _, approvals, _ = _services(tdb, settings)
        await approvals.decide(
            invocation.id,
            APPROVER_A,
            decision=ApprovalDecision.DENIED,
            justification="Not during the freeze.",
            expected_envelope_digest=invocation.envelope_digest,
        )
        assert (await _reload(tdb, invocation.id)).state == InvocationState.DENIED.value
        with pytest.raises(ToolPolicyDeniedError):
            await approvals.decide(
                invocation.id,
                APPROVER_B,
                decision=ApprovalDecision.APPROVED,
                justification="I disagree.",
                expected_envelope_digest=invocation.envelope_digest,
            )


# ---------------------------------------------------------------------------
# The final execution gate
# ---------------------------------------------------------------------------
class TestFinalGate:
    async def _approved(
        self, tdb: Database, settings: Settings, key: str
    ) -> ToolInvocation:
        asset_id = await _asset(tdb, display_name="sim-ok")
        invocations, approvals, _ = _services(tdb, settings)
        invocation = await invocations.create(
            InvocationRequest(
                tool_name="test.service.restart",
                tool_version="1.0",
                arguments={},
                target_asset_id=asset_id,
                idempotency_key=key,
            ),
            OPERATOR,
        )
        await approvals.decide(
            invocation.id,
            APPROVER_A,
            decision=ApprovalDecision.APPROVED,
            justification="Approved.",
            expected_envelope_digest=invocation.envelope_digest,
        )
        return invocation

    async def test_disabling_a_tool_stops_work_already_approved(
        self, tdb: Database, settings: Settings
    ) -> None:
        """Request-time authorization is necessary and not sufficient.

        This is the control's whole purpose: disabling a misbehaving tool has
        to stop what is already queued, or it is useless during the incident it
        exists for.
        """
        invocation = await self._approved(tdb, settings, "gate-disable")
        async with tdb.session() as session:
            row = (
                (
                    await session.execute(
                        select(ToolRegistration).where(
                            ToolRegistration.tool_name == "test.service.restart"
                        )
                    )
                )
                .scalars()
                .one()
            )
            row.lifecycle_state = ToolLifecycle.DISABLED.value
            row.disabled_at = datetime.now(UTC)
            row.disabled_by_subject = ADMIN.subject
            row.disabled_reason = "Misbehaving during the incident."

        _, _, dispatcher = _services(tdb, settings)
        assert await dispatcher.execute_once(invocation.id) is InvocationState.EXPIRED
        final = await _reload(tdb, invocation.id)
        assert final.final_gate_decision == "DENY"
        assert final.final_gate_reason == PolicyReason.TOOL_DISABLED.value
        # A refusal is a gate evaluation too, and carries the same provenance.
        assert final.final_gate_event_id is not None
        # Nothing was attempted, so it is not a failure of the target.
        assert final.started_at is not None
        assert final.result_summary is None

    async def test_a_tampered_canonical_input_fails_envelope_integrity(
        self, tdb: Database, settings: Settings
    ) -> None:
        """The check that makes an approval mean something.

        The digest is recomputed from what was stored. Changing the stored
        input by raw SQL - the shape a database compromise would take - is
        refused before any adapter is reached.
        """
        invocation = await self._approved(tdb, settings, "gate-tamper")
        async with tdb.session() as session:
            await session.execute(
                text(
                    "UPDATE tool_invocation SET input_canonical = "
                    '\'{"graceful": false, "drain_seconds": 30}\'::jsonb '
                    "WHERE id = :id"
                ),
                {"id": invocation.id},
            )
        _, _, dispatcher = _services(tdb, settings)
        assert await dispatcher.execute_once(invocation.id) is InvocationState.EXPIRED
        final = await _reload(tdb, invocation.id)
        assert final.final_gate_reason == PolicyReason.ENVELOPE_INTEGRITY_FAILED.value

    async def test_an_expired_approval_is_refused_by_the_gate_not_the_sweeper(
        self, tdb: Database, settings: Settings
    ) -> None:
        """The gate is authoritative; the sweeper is tidiness.

        A sweeper alone would let a dispatcher paused for a week execute last
        week's approval the moment it came back.
        """
        invocation = await self._approved(tdb, settings, "gate-expiry")
        async with tdb.session() as session:
            # The whole approval is moved into the past, not only its expiry:
            # CHECK (expires_at > decided_at) means an approval that was born
            # already expired is not a row the schema can hold, so backdating
            # the decision too is what "time passed" actually looks like.
            await session.execute(
                text(
                    "UPDATE tool_approval SET "
                    "decided_at = now() - interval '2 hours', "
                    "expires_at = now() - interval '1 hour' "
                    "WHERE invocation_id = :id"
                ),
                {"id": invocation.id},
            )
        _, _, dispatcher = _services(tdb, settings)
        assert await dispatcher.execute_once(invocation.id) is InvocationState.EXPIRED
        final = await _reload(tdb, invocation.id)
        assert final.final_gate_reason == PolicyReason.APPROVAL_EXPIRED.value


# ---------------------------------------------------------------------------
# Concurrency, idempotency, reaping and reconciliation
# ---------------------------------------------------------------------------
class TestConcurrencyAndRecovery:
    async def test_only_one_worker_can_claim_a_ready_invocation(
        self, tdb: Database, settings: Settings
    ) -> None:
        """PostgreSQL decides, not a lock ACOP takes by hand.

        Under READ COMMITTED, the second UPDATE blocks on the row lock and then
        re-evaluates ``state = 'READY'`` against the new committed version. It
        matches zero rows.
        """
        invocations, _, _ = _services(tdb, settings)
        invocation = await invocations.create(
            InvocationRequest(
                tool_name="acop.test.echo_metadata",
                tool_version="1.0",
                arguments={"note": "race"},
            ),
            VIEWER,
        )
        now = datetime.now(UTC)

        async def claim() -> bool:
            async with tdb.session() as session:
                return await claim_for_execution(
                    session,
                    invocation.id,
                    lease_id=uuid.uuid4(),
                    lease_expires_at=now + timedelta(minutes=5),
                    deadline_at=now + timedelta(seconds=30),
                )

        results = await asyncio.gather(claim(), claim(), claim())
        assert sum(results) == 1

    async def test_replaying_an_idempotency_key_returns_the_original(
        self, tdb: Database, settings: Settings
    ) -> None:
        asset_id = await _asset(tdb, display_name="sim-ok")
        invocations, _, _ = _services(tdb, settings)
        request = InvocationRequest(
            tool_name="test.service.restart",
            tool_version="1.0",
            arguments={"graceful": True},
            target_asset_id=asset_id,
            idempotency_key="idem-same",
        )
        first = await invocations.create(request, OPERATOR)
        second = await invocations.create(request, OPERATOR)
        assert first.id == second.id

    async def test_reusing_a_key_for_a_different_request_is_refused(
        self, tdb: Database, settings: Settings
    ) -> None:
        asset_id = await _asset(tdb, display_name="sim-ok")
        invocations, _, _ = _services(tdb, settings)
        await invocations.create(
            InvocationRequest(
                tool_name="test.service.restart",
                tool_version="1.0",
                arguments={"graceful": True},
                target_asset_id=asset_id,
                idempotency_key="idem-clash",
            ),
            OPERATOR,
        )
        with pytest.raises(IdempotencyConflictError):
            await invocations.create(
                InvocationRequest(
                    tool_name="test.service.restart",
                    tool_version="1.0",
                    arguments={"graceful": False},
                    target_asset_id=asset_id,
                    idempotency_key="idem-clash",
                ),
                OPERATOR,
            )

    async def test_a_lost_worker_produces_indeterminate_not_failed(
        self, tdb: Database, settings: Settings
    ) -> None:
        """The one genuinely hard case, recorded honestly.

        FAILED would invite a retry that double-executes; SUCCEEDED would be
        false in the other direction.
        """
        invocations, _, _ = _services(tdb, settings)
        invocation = await invocations.create(
            InvocationRequest(
                tool_name="acop.test.echo_metadata",
                tool_version="1.0",
                arguments={"note": "lost"},
            ),
            VIEWER,
        )
        async with tdb.session() as session:
            await claim_for_execution(
                session,
                invocation.id,
                lease_id=uuid.uuid4(),
                lease_expires_at=datetime.now(UTC) - timedelta(minutes=1),
                deadline_at=datetime.now(UTC) + timedelta(seconds=30),
            )
        assert await InvocationReaper(tdb).reap_expired_leases() == 1
        row = await _reload(tdb, invocation.id)
        assert row.state == InvocationState.EXECUTION_INDETERMINATE.value
        assert row.executor_lease_id is None

    async def test_a_worker_that_lost_its_lease_never_reaches_the_adapter(
        self, tdb: Database, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """F-3: the claim is committed, so it has to be re-asserted before use.

        Worker A claims the row and pauses at the final gate. Its lease expires
        and the reaper takes the invocation to ``EXECUTION_INDETERMINATE``.
        A then resumes holding a lease that is no longer its own.

        The assertion that matters is the **adapter call count**, not the final
        state: a state assertion passes just as well when the adapter ran and
        the reaper's row happened to be written over afterwards, which is the
        exact corruption this closes. Zero calls is the proof.
        """
        asset_id = await _asset(tdb, display_name="raced", asset_type=AssetType.DEVICE)
        invocations, _, dispatcher = _services(tdb, settings)
        invocation = await invocations.create(
            InvocationRequest(
                tool_name="test.device.status",
                tool_version="1.0",
                arguments={"include_facts": False},
                target_asset_id=asset_id,
            ),
            VIEWER,
        )

        dispatched: list[uuid.UUID] = []
        adapter_execute = SIMULATED_ADAPTER.execute

        async def counting_execute(request: AdapterRequest) -> AdapterResult:
            dispatched.append(request.invocation_id)
            return await adapter_execute(request)

        monkeypatch.setattr(SIMULATED_ADAPTER, "execute", counting_execute)

        # The pause point: the gate is the last thing that happens before the
        # ownership assertion, and therefore where a paused worker is stalest.
        gate = dispatcher._final_gate

        async def gate_while_the_lease_is_taken(
            session: object, row: ToolInvocation
        ) -> object:
            """Worker A's pause: everything below happens while A is here."""
            async with tdb.session() as other:
                await other.execute(
                    text(
                        "UPDATE tool_invocation SET lease_expires_at = "
                        "now() - interval '1 minute' WHERE id = :id"
                    ),
                    {"id": row.id},
                )
            assert await InvocationReaper(tdb).reap_expired_leases() == 1
            return await gate(session, row)  # type: ignore[arg-type]

        monkeypatch.setattr(dispatcher, "_final_gate", gate_while_the_lease_is_taken)

        state = await dispatcher.execute_once(invocation.id)

        # Nothing was dispatched, by either worker: the reaper does not execute
        # and the stale worker must not.
        assert dispatched == []
        # The caller is told what the row actually says now.
        assert state is InvocationState.EXECUTION_INDETERMINATE

        row = await _reload(tdb, invocation.id)
        # The stale worker wrote none of it. Overwriting the reaper's honest
        # record with an outcome nobody observed is the corruption being
        # prevented, and a decision written under a lost lease would be one.
        assert row.state == InvocationState.EXECUTION_INDETERMINATE.value
        assert row.final_gate_decision is None
        assert row.final_gate_event_id is None
        assert row.result_summary is None

        async with tdb.session() as session:
            events = (
                (
                    await session.execute(
                        select(ToolInvocationEvent)
                        .where(ToolInvocationEvent.invocation_id == invocation.id)
                        .order_by(ToolInvocationEvent.sequence)
                    )
                )
                .scalars()
                .all()
            )
        assert [e.to_state for e in events] == [
            "REQUESTED",
            "AUTHORIZED",
            "READY",
            "EXECUTING",
            "EXECUTION_INDETERMINATE",
            # The stale evaluation, appended after the reap. Evidence that a
            # second worker looked at this invocation and was refused - which a
            # silent return would have left nowhere.
            "EXECUTING",
        ]
        stale = events[-1]
        assert stale.from_state == stale.to_state == InvocationState.EXECUTING.value
        assert stale.detail["gate"] == "final"
        # And it was worker A's evaluation: the lease it minted at the claim.
        assert stale.detail["lease_id"] == events[3].detail["lease_id"]

    async def test_reconciliation_appends_and_never_rewrites(
        self, tdb: Database, settings: Settings
    ) -> None:
        """The execution record stays as ACOP wrote it.

        Rewriting it later would replace what ACOP knew at execution time with
        something it did not know.
        """
        invocations, _, _ = _services(tdb, settings)
        invocation = await invocations.create(
            InvocationRequest(
                tool_name="acop.test.echo_metadata",
                tool_version="1.0",
                arguments={"note": "reconcile"},
            ),
            VIEWER,
        )
        async with tdb.session() as session:
            await claim_for_execution(
                session,
                invocation.id,
                lease_id=uuid.uuid4(),
                lease_expires_at=datetime.now(UTC) - timedelta(minutes=1),
                deadline_at=datetime.now(UTC) + timedelta(seconds=30),
            )
        await InvocationReaper(tdb).reap_expired_leases()

        await ReconciliationService(tdb).record(
            invocation.id,
            APPROVER_A,
            disposition=ReconciliationDisposition.CONFIRMED_FAILED,
            justification="Checked the service manager; it never restarted.",
            evidence_ref={"ticket": "INC-42"},
        )
        row = await _reload(tdb, invocation.id)
        assert row.state == InvocationState.EXECUTION_INDETERMINATE.value

        async with tdb.session() as session:
            records = (
                (
                    await session.execute(
                        select(ToolInvocationReconciliation).where(
                            ToolInvocationReconciliation.invocation_id == invocation.id
                        )
                    )
                )
                .scalars()
                .all()
            )
        assert len(records) == 1
        assert records[0].disposition == "CONFIRMED_FAILED"
        assert records[0].reconciled_by_subject == APPROVER_A.subject

    async def test_only_an_indeterminate_execution_can_be_reconciled(
        self, tdb: Database, settings: Settings
    ) -> None:
        invocations, _, dispatcher = _services(tdb, settings)
        invocation = await invocations.create(
            InvocationRequest(
                tool_name="acop.test.echo_metadata",
                tool_version="1.0",
                arguments={"note": "fine"},
            ),
            VIEWER,
        )
        await dispatcher.execute_once(invocation.id)
        with pytest.raises(ToolPolicyDeniedError):
            await ReconciliationService(tdb).record(
                invocation.id,
                APPROVER_A,
                disposition=ReconciliationDisposition.CONFIRMED_FAILED,
                justification="Trying to correct a settled outcome.",
            )

    async def test_the_sweeper_expires_a_never_approved_invocation(
        self, tdb: Database, settings: Settings
    ) -> None:
        asset_id = await _asset(tdb, display_name="sim-ok")
        invocations, _, _ = _services(tdb, settings)
        invocation = await invocations.create(
            InvocationRequest(
                tool_name="test.service.restart",
                tool_version="1.0",
                arguments={},
                target_asset_id=asset_id,
                idempotency_key="sweeper-1",
            ),
            OPERATOR,
        )
        async with tdb.session() as session:
            await session.execute(
                text(
                    "UPDATE tool_invocation SET requested_at = now() - "
                    "interval '2 hours' WHERE id = :id"
                ),
                {"id": invocation.id},
            )
        assert await ApprovalSweeper(tdb).expire_stale() == 1
        assert (await _reload(tdb, invocation.id)).state == InvocationState.EXPIRED.value


# ---------------------------------------------------------------------------
# Compare-and-set on every transition
# ---------------------------------------------------------------------------
async def _events(
    database: Database, invocation_id: uuid.UUID
) -> list[ToolInvocationEvent]:
    async with database.session() as session:
        return list(
            (
                await session.execute(
                    select(ToolInvocationEvent)
                    .where(ToolInvocationEvent.invocation_id == invocation_id)
                    .order_by(ToolInvocationEvent.sequence)
                )
            )
            .scalars()
            .all()
        )


async def _executing_with_an_expired_lease(
    database: Database, settings: Settings, *, note: str
) -> uuid.UUID:
    """An invocation the reaper's candidate query will pick up."""
    invocations, _, _ = _services(database, settings)
    invocation = await invocations.create(
        InvocationRequest(
            tool_name="acop.test.echo_metadata",
            tool_version="1.0",
            arguments={"note": note},
        ),
        VIEWER,
    )
    async with database.session() as session:
        claimed = await claim_for_execution(
            session,
            invocation.id,
            lease_id=uuid.uuid4(),
            lease_expires_at=datetime.now(UTC) - timedelta(minutes=1),
            deadline_at=datetime.now(UTC) + timedelta(seconds=30),
        )
    assert claimed
    return invocation.id


async def _complete_as_a_dispatcher_would(
    database: Database, invocation_id: uuid.UUID
) -> None:
    """The dispatcher's own two writes - ``EXECUTED`` then ``SUCCEEDED``.

    What makes this the hard case is that it is entirely legitimate: the
    adapter ran, the change landed, validation confirmed it. It simply commits
    after the lease the reaper is judging has already elapsed.
    """
    now = datetime.now(UTC)
    async with database.session() as session:
        row = await session.get(ToolInvocation, invocation_id)
        assert row is not None
        await release_lease(
            session,
            row,
            to_state=InvocationState.EXECUTED,
            reason=PolicyReason.ALLOWED.value,
            result_summary={"restarted": True},
        )
        await transition(
            session,
            row,
            to_state=InvocationState.SUCCEEDED,
            reason=PolicyReason.ALLOWED.value,
            validation_outcome=ValidationOutcome.CONFIRMED.value,
            validated_at=now,
            finished_at=now,
        )


class _RacingReaper(InvocationReaper):
    """A reaper stopped in the window where the defect lived.

    The candidate query takes no lock, so there is a gap between selecting an
    expired ``EXECUTING`` row and writing over it. This makes that gap
    deterministic: the completion commits after the reaper has read the row and
    before it writes. Two real tasks and a sleep would test the same thing
    intermittently, which is not a test of anything.
    """

    def __init__(
        self, database: Database, completion: Callable[[], Awaitable[None]]
    ) -> None:
        super().__init__(database)
        self._completion = completion
        self._raced = False

    async def _reap_one(
        self,
        session: AsyncSession,
        audit: AuditService,
        invocation: ToolInvocation,
        now: datetime,
    ) -> bool:
        if not self._raced:
            self._raced = True
            await self._completion()
        return await super()._reap_one(session, audit, invocation, now)


class TestTransitionCompareAndSet:
    """Every UPDATE asserts the state it expects, so a stale writer loses.

    Without that predicate the emitted SQL is ``UPDATE ... WHERE id = :id``,
    and the last writer wins regardless of what it knew - which is how a
    validated ``SUCCEEDED`` gets relabelled ``EXECUTION_INDETERMINATE`` by a
    reaper that was already wrong about the row.
    """

    async def test_the_reaper_loses_to_a_legitimate_completion(
        self, tdb: Database, settings: Settings
    ) -> None:
        """The corruption this closes, reproduced end to end.

        ``EXECUTION_INDETERMINATE`` is terminal and never retried, so writing it
        over a real outcome does not merely lose information: it strands the
        record for a manual reconciliation that nothing needs.
        """
        invocation_id = await _executing_with_an_expired_lease(
            tdb, settings, note="reaper-loses"
        )

        async def completion() -> None:
            await _complete_as_a_dispatcher_would(tdb, invocation_id)

        # Zero, not one: the row was closed by the worker, not by this sweep,
        # and a count that claimed it would report the overwrite as work done.
        assert await _RacingReaper(tdb, completion).reap_expired_leases() == 0

        row = await _reload(tdb, invocation_id)
        assert row.state == InvocationState.SUCCEEDED.value
        assert row.result_summary == {"restarted": True}
        assert row.validation_outcome == ValidationOutcome.CONFIRMED.value
        # The reaper's failure columns are the tell: it writes both of these
        # together with the state, so either one surviving means it wrote.
        assert row.error_category is None
        assert row.error_detail_sanitized is None

        events = await _events(tdb, invocation_id)
        assert InvocationState.EXECUTION_INDETERMINATE.value not in {
            event.to_state for event in events
        }
        # The attempt is still on the record, as a move from a state to itself.
        # A reaper that skipped silently would be indistinguishable from one
        # that was never running.
        stale = events[-1]
        assert stale.from_state == stale.to_state == InvocationState.SUCCEEDED.value
        assert stale.detail["stale_transition"] is True
        assert stale.detail["expected_state"] == InvocationState.EXECUTING.value
        assert (
            stale.detail["attempted_to_state"]
            == InvocationState.EXECUTION_INDETERMINATE.value
        )

    async def test_the_reaper_still_wins_when_nothing_completed(
        self, tdb: Database, settings: Settings
    ) -> None:
        """The other half of the pair: the predicate must not disarm the reaper."""
        invocation_id = await _executing_with_an_expired_lease(
            tdb, settings, note="reaper-wins"
        )
        assert await InvocationReaper(tdb).reap_expired_leases() == 1
        row = await _reload(tdb, invocation_id)
        assert row.state == InvocationState.EXECUTION_INDETERMINATE.value
        assert row.executor_lease_id is None
        assert row.lease_expires_at is None
        assert row.error_category == ToolErrorCategory.EXECUTION_INDETERMINATE.value

    async def test_two_callers_racing_one_transition_leave_exactly_one_write(
        self, tdb: Database, settings: Settings
    ) -> None:
        """The loser is told, and leaves nothing behind.

        Both read ``READY`` and both believe ``READY -> CANCELLED`` is legal,
        which it is. Only the database can break the tie, and it does so by
        matching zero rows for the second writer.
        """
        invocations, _, _ = _services(tdb, settings)
        invocation = await invocations.create(
            InvocationRequest(
                tool_name="acop.test.echo_metadata",
                tool_version="1.0",
                arguments={"note": "two-callers"},
            ),
            VIEWER,
        )
        # Both must hold READY before either writes; without this the second
        # caller would read the row after the first committed and never attempt
        # the losing write the test exists to observe.
        both_have_read = asyncio.Barrier(2)

        async def cancel(subject: str) -> None:
            async with tdb.session() as session:
                row = await session.get(ToolInvocation, invocation.id)
                assert row is not None
                await both_have_read.wait()
                await transition(
                    session,
                    row,
                    to_state=InvocationState.CANCELLED,
                    reason=PolicyReason.ALLOWED.value,
                    actor_subject=subject,
                )

        outcomes = await asyncio.gather(
            cancel("acop:user:first"),
            cancel("acop:user:second"),
            return_exceptions=True,
        )
        failures = [outcome for outcome in outcomes if isinstance(outcome, BaseException)]
        assert len(failures) == 1
        assert isinstance(failures[0], StaleTransitionError)

        assert (
            await _reload(tdb, invocation.id)
        ).state == InvocationState.CANCELLED.value
        # Nothing of the loser survived: its stale-attempt event was rolled back
        # with the transaction it raised out of, which is the right trade on a
        # request path where a stale write is a defect rather than a race the
        # caller expected to lose.
        assert [event.to_state for event in await _events(tdb, invocation.id)] == [
            "REQUESTED",
            "AUTHORIZED",
            "READY",
            "CANCELLED",
        ]


# ---------------------------------------------------------------------------
# The two callers that are *expected* to lose a transition race
# ---------------------------------------------------------------------------
#: The requester's own key. Cancellation is restricted to the requester or an
#: admin, so the invocation under test must be created by this subject for the
#: HTTP call to reach the race at all rather than stopping at 403.
REQUESTER = _principal(TEST_SUBJECT, "operator")


async def _cancel_audit(database: Database) -> list[tuple[str, str, str]]:
    """Every ``tool.cancel`` audit row as ``(outcome, severity, message)``."""
    async with database.session() as session:
        rows = await session.execute(
            text(
                "SELECT outcome, severity, message FROM audit_event "
                "WHERE action = 'tool.cancel' ORDER BY occurred_at"
            )
        )
        return [
            (str(outcome), str(severity), str(message))
            for outcome, severity, message in rows
        ]


async def _ready_change_invocation(
    database: Database,
    settings: Settings,
    *,
    principal: Principal,
    key: str,
) -> ToolInvocation:
    """A Class 2 invocation approved and sitting in ``READY``."""
    asset_id = await _asset(database, display_name="sim-ok")
    invocations, approvals, _ = _services(database, settings)
    invocation = await invocations.create(
        InvocationRequest(
            tool_name="test.service.restart",
            tool_version="1.0",
            arguments={"graceful": True, "drain_seconds": 0},
            target_asset_id=asset_id,
            idempotency_key=key,
        ),
        principal,
    )
    await approvals.decide(
        invocation.id,
        APPROVER_A,
        decision=ApprovalDecision.APPROVED,
        justification="Change ticket CHG-race.",
        expected_envelope_digest=invocation.envelope_digest,
    )
    assert (await _reload(database, invocation.id)).state == InvocationState.READY.value
    return invocation


class TestCancellationLosesTheRace:
    """Cancellation is the one request that a race against it is not a defect.

    Everywhere else on the router, a stale transition means something touched an
    invocation that nothing should have been touching, and 500 is the honest
    report. Here the competing writer - a worker claiming a ``READY`` row - is
    doing exactly its job, and so is the person clicking cancel. Neither is
    wrong, so the answer is 409: the current state conflicts with the request.
    """

    @pytest.fixture
    async def api(self, tdb: Database, make_settings) -> AsyncIterator[httpx.AsyncClient]:
        """The real HTTP surface over the schema ``tdb`` just migrated.

        ``tools_dispatcher_enabled=False`` stands the background worker down.
        The race under test is injected deterministically below; a worker also
        polling for ``READY`` rows would sometimes claim and finish the
        invocation before the request even reached its pre-check, and the test
        would pass or fail by timing.
        """
        app = create_app(make_settings(tools_dispatcher_enabled=False))
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://acop.test"
            ) as client:
                yield client

    async def test_a_cancel_that_loses_to_a_worker_is_409_and_writes_nothing(
        self,
        tdb: Database,
        settings: Settings,
        api: httpx.AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The whole correction, end to end over HTTP.

        The endpoint reads ``READY``, a worker claims the row, and only then
        does the endpoint write. Patching the endpoint's own reference to
        ``transition`` is what makes that ordering exact rather than probable;
        the write it wraps is the real one, so the compare-and-set, the refusal
        and the status mapping under test are all the production code paths.
        """
        invocation = await _ready_change_invocation(
            tdb, settings, principal=REQUESTER, key="cancel-race"
        )
        lease_id = uuid.uuid4()
        real_transition = tool_routes.transition
        claimed = False

        async def claim_then_transition(*args: object, **kwargs: object) -> None:
            nonlocal claimed
            if not claimed:
                claimed = True
                now = datetime.now(UTC)
                async with tdb.session() as worker_session:
                    won = await claim_for_execution(
                        worker_session,
                        invocation.id,
                        lease_id=lease_id,
                        lease_expires_at=now + timedelta(minutes=5),
                        deadline_at=now + timedelta(seconds=30),
                    )
                assert won, "the worker must win, or the test proves nothing"
            await real_transition(*args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(tool_routes, "transition", claim_then_transition)

        response = await api.post(
            f"/tool-invocations/{invocation.id}/cancel",
            headers={"X-ACOP-API-Key": TEST_API_SECRET},
            json={"reason": "Withdrawn by the requester."},
        )

        # 409, not the 500 a stale transition means anywhere else.
        assert response.status_code == 409, response.text
        body = response.json()["error"]
        assert body["code"] == "invocation_state_conflict"
        # Sanitized: a fixed phrase, and nothing of the state, the identifier or
        # the internal exception that produced it.
        assert body["message"] == (
            "The invocation changed state before this request was applied. "
            "Nothing was changed."
        )
        for leaked in (
            str(invocation.id),
            InvocationState.EXECUTING.value,
            str(lease_id),
            "StaleTransitionError",
            "transition",
        ):
            assert leaked not in response.text

        # The worker's state stands, untouched and complete.
        row = await _reload(tdb, invocation.id)
        assert row.state == InvocationState.EXECUTING.value
        assert row.executor_lease_id == lease_id
        assert row.finished_at is None

        # Nothing of the cancellation reached the history. The stale-attempt
        # event was rolled back with the request, which is the request-path
        # trade the state module documents.
        events = await _events(tdb, invocation.id)
        assert InvocationState.CANCELLED.value not in {event.to_state for event in events}
        assert events[-1].from_state == InvocationState.READY.value
        assert events[-1].to_state == InvocationState.EXECUTING.value

        # The attempt survives the rollback, because it was written on an
        # independent connection. Somebody tried to withdraw an invocation that
        # is now executing, and whoever reads this row's history needs that.
        audited = await _cancel_audit(tdb)
        assert len(audited) == 1
        outcome, severity, message = audited[0]
        assert (outcome, severity) == ("FAILURE", "NOTICE")
        assert "already EXECUTING" in message

    async def test_a_cancel_that_wins_is_unaffected(
        self, tdb: Database, settings: Settings, api: httpx.AsyncClient
    ) -> None:
        """The other half of the pair: 409 must not become the ordinary answer."""
        invocation = await _ready_change_invocation(
            tdb, settings, principal=REQUESTER, key="cancel-clean"
        )
        response = await api.post(
            f"/tool-invocations/{invocation.id}/cancel",
            headers={"X-ACOP-API-Key": TEST_API_SECRET},
            json={"reason": "Withdrawn by the requester."},
        )
        assert response.status_code == 200, response.text
        assert response.json()["state"] == InvocationState.CANCELLED.value
        assert (
            await _reload(tdb, invocation.id)
        ).state == InvocationState.CANCELLED.value
        assert [outcome for outcome, _, _ in await _cancel_audit(tdb)] == ["SUCCESS"]


class TestApprovalSweeperLosesTheRace:
    """The sweeper's per-row tolerance, which nothing else covers.

    ``ApprovalSweeper`` reads its candidates without a lock, so an approval can
    land on one between the read and the write. It catches
    ``StaleTransitionError`` per candidate for the same reason the reaper does,
    and the consequence of getting it wrong is worse here than a bad count: an
    unguarded sweeper would expire an invocation a human had just approved,
    revoking a decision that was actually made.

    The tolerance is deliberately *per row*. A sweep that aborted on the first
    such candidate would leave every later expired request in the queue, and the
    queue filling up is the only thing the sweeper exists to prevent.
    """

    async def test_an_approval_landing_mid_sweep_survives_and_the_sweep_continues(
        self, tdb: Database, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asset_id = await _asset(tdb, display_name="sim-ok")
        invocations, approvals, _ = _services(tdb, settings)
        pending = []
        for key in ("sweeper-race-a", "sweeper-race-b"):
            pending.append(
                await invocations.create(
                    InvocationRequest(
                        tool_name="test.service.restart",
                        tool_version="1.0",
                        arguments={"graceful": True, "drain_seconds": 0},
                        target_asset_id=asset_id,
                        idempotency_key=key,
                    ),
                    OPERATOR,
                )
            )
        assert all(
            row.state == InvocationState.AWAITING_APPROVAL.value for row in pending
        )
        async with tdb.session() as session:
            await session.execute(
                text(
                    "UPDATE tool_invocation SET requested_at = now() - interval '2 hours'"
                )
            )

        real_transition = sweeper_module.transition
        raced: uuid.UUID | None = None

        async def approve_then_transition(
            session: AsyncSession, invocation: ToolInvocation, **kwargs: object
        ) -> None:
            """Approve the row the sweeper is about to expire, then let it try.

            Ordering, not luck: the approval commits on its own connection while
            the sweeper still holds the ``AWAITING_APPROVAL`` it read, which is
            precisely the window the tolerance exists for.
            """
            nonlocal raced
            if raced is None:
                raced = invocation.id
                await approvals.decide(
                    invocation.id,
                    APPROVER_A,
                    decision=ApprovalDecision.APPROVED,
                    justification="Approved while the sweeper was mid-batch.",
                    expected_envelope_digest=invocation.envelope_digest,
                )
            await real_transition(session, invocation, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(sweeper_module, "transition", approve_then_transition)

        # One, not two: the raced row was not expired by this sweep, and a count
        # that claimed it would report a revoked approval as work done.
        assert await ApprovalSweeper(tdb).expire_stale() == 1
        assert raced is not None

        # The approval stands. This is the corruption the tolerance prevents:
        # EXPIRED is terminal, so writing it here would discard a decision a
        # human actually made and force the change to be requested again.
        approved = await _reload(tdb, raced)
        assert approved.state == InvocationState.READY.value
        assert approved.approved_at is not None

        # The batch continued. One live approval must not strand every other
        # expired request in the queue.
        other = next(row.id for row in pending if row.id != raced)
        assert (await _reload(tdb, other)).state == InvocationState.EXPIRED.value

        # Tolerated, not skipped silently. The sweeper commits, so unlike the
        # request path its stale attempt is on the record.
        events = await _events(tdb, raced)
        assert InvocationState.EXPIRED.value not in {event.to_state for event in events}
        stale = events[-1]
        assert stale.from_state == stale.to_state == InvocationState.READY.value
        assert stale.detail["stale_transition"] is True
        assert stale.detail["expected_state"] == InvocationState.AWAITING_APPROVAL.value
        assert stale.detail["attempted_to_state"] == InvocationState.EXPIRED.value

    async def test_the_sweeper_still_expires_when_nothing_was_approved(
        self, tdb: Database, settings: Settings
    ) -> None:
        """The predicate must not disarm the sweeper, exactly as for the reaper."""
        asset_id = await _asset(tdb, display_name="sim-ok")
        invocations, _, _ = _services(tdb, settings)
        invocation = await invocations.create(
            InvocationRequest(
                tool_name="test.service.restart",
                tool_version="1.0",
                arguments={},
                target_asset_id=asset_id,
                idempotency_key="sweeper-uncontested",
            ),
            OPERATOR,
        )
        async with tdb.session() as session:
            await session.execute(
                text(
                    "UPDATE tool_invocation SET requested_at = now() - "
                    "interval '2 hours' WHERE id = :id"
                ),
                {"id": invocation.id},
            )
        assert await ApprovalSweeper(tdb).expire_stale() == 1
        assert (await _reload(tdb, invocation.id)).state == InvocationState.EXPIRED.value


# ---------------------------------------------------------------------------
# The declared output contract (B-M5-4)
# ---------------------------------------------------------------------------
class TestOutputContractViolation:
    """An adapter that breaks its own declared contract must fail the invocation.

    The old behaviour published ``{}`` and let the state machine carry the row
    to ``SUCCEEDED``. That is a false statement about an execution written into
    an append-only table: a reader cannot tell it from a tool that genuinely
    returned nothing, and a consumer reading ``result_summary`` sees an empty
    collection rather than a failure. See ADR-0023.
    """

    @staticmethod
    def _returning(payload: dict[str, object]) -> Callable[..., Awaitable[object]]:
        """An adapter that reports SUCCESS and hands back ``payload``.

        SUCCESS is the point. A failing adapter was already handled; what was
        not handled is an adapter that believes it succeeded and returns
        something its tool never declared.
        """

        async def execute(request: AdapterRequest) -> AdapterResult:
            return AdapterResult(outcome=AdapterOutcome.SUCCESS, payload=dict(payload))

        return execute

    async def _run(
        self,
        tdb: Database,
        settings: Settings,
        monkeypatch: pytest.MonkeyPatch,
        payload: dict[str, object],
    ) -> ToolInvocation:
        asset_id = await _asset(
            tdb, display_name="contract-target", asset_type=AssetType.DEVICE
        )
        invocations, _, dispatcher = _services(tdb, settings)
        invocation = await invocations.create(
            InvocationRequest(
                tool_name="test.device.status",
                tool_version="1.0",
                arguments={"include_facts": False},
                target_asset_id=asset_id,
            ),
            VIEWER,
        )
        monkeypatch.setattr(SIMULATED_ADAPTER, "execute", self._returning(payload))
        state = await dispatcher.execute_once(invocation.id)
        assert state is InvocationState.FAILED, state
        return await _reload(tdb, invocation.id)

    async def test_a_malformed_declared_output_fails_the_invocation(
        self, tdb: Database, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test C. The whole correction, end to end against PostgreSQL."""
        row = await self._run(
            tdb, settings, monkeypatch, {"this_field_is_not_declared": True}
        )

        assert row.state == InvocationState.FAILED.value
        assert row.error_category == ToolErrorCategory.OUTPUT_CONTRACT_VIOLATION.value
        assert row.error_detail_sanitized == (
            "The tool returned a result that does not match its declared output."
        )
        # Nothing unvalidated was published, and no digest claims otherwise.
        assert row.result_summary is None
        assert row.result_digest is None
        # It failed after execution, so the lease is released like any other
        # terminal state - the CHECK constraints tie those together.
        assert row.executor_lease_id is None
        assert row.lease_expires_at is None
        assert row.finished_at is not None
        # It never reached validation, and it never claimed success.
        assert row.validation_outcome is None

        states = [event.to_state for event in await _events(tdb, row.id)]
        assert InvocationState.FAILED.value in states
        assert InvocationState.SUCCEEDED.value not in states
        assert InvocationState.EXECUTED.value not in states
        # The final gate still ran and still allowed it: the tool was permitted,
        # the adapter was simply wrong afterwards.
        assert row.final_gate_decision == "ALLOW"

    async def test_the_failure_is_audited_as_a_failure(
        self, tdb: Database, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``_run_claimed`` audits anything that is not SUCCEEDED as FAILURE.

        Asserted rather than assumed, because the correction relies on that
        existing branch instead of adding an audit call of its own.
        """
        row = await self._run(tdb, settings, monkeypatch, {"undeclared": 1})

        async with tdb.session() as session:
            rows = await session.execute(
                text(
                    "SELECT action, outcome, severity FROM audit_event "
                    "WHERE resource_id = :rid ORDER BY occurred_at"
                ),
                {"rid": str(row.id)},
            )
            audited = [
                (str(action), str(outcome), str(severity))
                for action, outcome, severity in rows
            ]
        # Two records, and the distinction between them is the point. The
        # request was accepted - that is ``tool.invoke``, and it did succeed.
        # The execution then failed, which is ``tool.execute``. Collapsing the
        # two would either hide an accepted request or misreport it.
        assert ("tool.invoke", "SUCCESS", "INFO") in audited
        assert ("tool.execute", "FAILURE", "WARNING") in audited

    async def test_a_contract_violation_discloses_no_adapter_output(
        self, tdb: Database, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The canary, following the pattern already used for adapter text.

        The payload is rejected precisely because it is undeclared, so it must
        not survive anywhere - not in the invocation, not in its event history,
        not in the audit record that describes the failure.
        """
        row = await self._run(
            tdb, settings, monkeypatch, {"connection_string": _LEAKY_MESSAGE}
        )

        async with tdb.session() as session:
            for table, column in (
                ("tool_invocation", "result_summary::text"),
                ("tool_invocation", "error_detail_sanitized"),
                ("tool_invocation_event", "detail::text"),
                ("audit_event", "message"),
                ("audit_event", "context::text"),
            ):
                found = await session.scalar(
                    text(
                        f"SELECT count(*) FROM {table} "  # noqa: S608 - fixed literals
                        f"WHERE {column} ILIKE '%hunter2%'"
                    )
                )
                assert found == 0, f"{table}.{column} leaked adapter text"
        assert row.result_summary is None

    async def test_a_contract_violation_is_never_retried(
        self, tdb: Database, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test D, proved from the existing machinery rather than new code.

        ``test.device.status`` declares ``max_attempts=2``, so this tool *is*
        retried for the categories it names. A contract violation is not one of
        them, and structurally cannot be: the retry loop wraps
        ``adapter.execute``, and the output model is checked after that loop has
        already exited. The adapter is therefore called exactly once.
        """
        asset_id = await _asset(
            tdb, display_name="retry-target", asset_type=AssetType.DEVICE
        )
        invocations, _, dispatcher = _services(tdb, settings)
        invocation = await invocations.create(
            InvocationRequest(
                tool_name="test.device.status",
                tool_version="1.0",
                arguments={"include_facts": False},
                target_asset_id=asset_id,
            ),
            VIEWER,
        )
        definition = CODE_REGISTRY[("test.device.status", "1.0")]
        assert definition.retry_policy.max_attempts == 2, "the tool must be retryable"
        assert (
            ToolErrorCategory.OUTPUT_CONTRACT_VIOLATION
            not in definition.retry_policy.retry_on
        )

        calls = 0

        async def counting(request: AdapterRequest) -> AdapterResult:
            nonlocal calls
            calls += 1
            return AdapterResult(
                outcome=AdapterOutcome.SUCCESS, payload={"undeclared": True}
            )

        monkeypatch.setattr(SIMULATED_ADAPTER, "execute", counting)
        assert await dispatcher.execute_once(invocation.id) is InvocationState.FAILED

        assert calls == 1, "a contract violation must not be retried"
        row = await _reload(tdb, invocation.id)
        assert row.attempt_count == 1

    async def test_a_valid_output_still_succeeds(
        self, tdb: Database, settings: Settings
    ) -> None:
        """Test E. The correction must not cost the ordinary path.

        Deliberately unpatched: the real adapter, the real output model, a real
        asset. If the new branch could be reached by a well-behaved tool, this
        is what would catch it.
        """
        asset_id = await _asset(
            tdb, display_name="healthy-target", asset_type=AssetType.DEVICE
        )
        invocations, _, dispatcher = _services(tdb, settings)
        invocation = await invocations.create(
            InvocationRequest(
                tool_name="test.device.status",
                tool_version="1.0",
                arguments={"include_facts": False},
                target_asset_id=asset_id,
            ),
            VIEWER,
        )
        assert await dispatcher.execute_once(invocation.id) is InvocationState.SUCCEEDED

        row = await _reload(tdb, invocation.id)
        assert row.result_summary is not None
        assert row.result_summary["display_name"] == "healthy-target"
        assert row.result_digest is not None
        assert row.error_category is None


# ---------------------------------------------------------------------------
# Prohibition and the Capability Binding Invariant
# ---------------------------------------------------------------------------
class TestProhibitionAndBinding:
    @pytest.mark.parametrize(
        "principal", [VIEWER, OPERATOR, APPROVER_A, ADMIN], ids=lambda p: p.subject
    )
    async def test_a_prohibited_tool_is_denied_for_every_role(
        self, tdb: Database, settings: Settings, principal: Principal
    ) -> None:
        asset_id = await _asset(tdb, display_name="a-host", asset_type=AssetType.HOST)
        invocations, _, _ = _services(tdb, settings)
        with pytest.raises(ProhibitedCapabilityError) as caught:
            await invocations.create(
                InvocationRequest(
                    tool_name="test.prohibited.shell_exec",
                    tool_version="1.0",
                    arguments={"intent": "have a look around"},
                    target_asset_id=asset_id,
                    idempotency_key=f"prohibited-{principal.subject}",
                ),
                principal,
            )
        assert "prohibited_capability" in str(caught.value)
        # Identical for every role, and never reported as an authorization
        # problem: an answer that varied by role would tell an attacker which
        # role would have worked.
        assert caught.value.http_status == 403
        assert caught.value.code == "prohibited_capability"
        assert caught.value.category is ToolErrorCategory.POLICY_DENIED

    async def test_the_final_gate_refuses_a_prohibited_tool_driven_to_ready(
        self, tdb: Database, settings: Settings
    ) -> None:
        """Belt and braces, because the first test only proves gate 3 exists.

        A row is forced into READY by raw SQL - the shape a policy bug would
        take - and the final gate must still refuse it. The adapter raises if
        it is ever reached, so a pass here means it was not.
        """
        asset_id = await _asset(tdb, display_name="a-host-2", asset_type=AssetType.HOST)
        async with tdb.session() as session:
            registration = (
                (
                    await session.execute(
                        select(ToolRegistration).where(
                            ToolRegistration.tool_name == "test.prohibited.shell_exec"
                        )
                    )
                )
                .scalars()
                .one()
            )
            invocation = ToolInvocation(
                tool_name="test.prohibited.shell_exec",
                tool_version="1.0",
                tool_registration_id=registration.id,
                permission_class="CLASS_1_READ_ONLY",
                approval_required=False,
                min_approvals=1,
                approval_ttl_seconds=300,
                validation_required=False,
                effective_approval_policy={},
                execution_parameters={"timeout_seconds": 5.0},
                registry_contract_hash="0" * 64,
                envelope={},
                envelope_digest="0" * 64,
                input_digest="0" * 64,
                input_canonical={"intent": "escalate"},
                principal_subject=ADMIN.subject,
                principal_type="human",
                principal_issuer="acop:api-key",
                auth_method="api_key",
                target_kind="ASSET",
                target_asset_id=asset_id,
                authorization_decision="ALLOW",
                authorization_reason="allowed",
                state=InvocationState.READY.value,
            )
            session.add(invocation)
            await session.flush()
            invocation_id = invocation.id

        _, _, dispatcher = _services(tdb, settings)
        assert await dispatcher.execute_once(invocation_id) is InvocationState.EXPIRED
        final = await _reload(tdb, invocation_id)
        assert final.final_gate_reason == PolicyReason.PROHIBITED_CAPABILITY.value

    async def test_a_registration_row_alone_cannot_mint_a_capability(
        self, tdb: Database, settings: Settings
    ) -> None:
        """The adversarial test for G5.

        A row inserted by raw SQL - the shape a SQL injection, a compromised
        admin credential or a restored backup would take - names a tool no code
        declares. It resolves to no adapter and is refused.
        """
        async with tdb.session() as session:
            await session.execute(
                text(
                    "INSERT INTO tool_registration "
                    "(id, tool_name, tool_version, contract_hash, lifecycle_state) "
                    "VALUES (:id, 'evil.shell.exec', '1.0', :hash, 'ACTIVE')"
                ),
                {"id": uuid.uuid4(), "hash": "0" * 64},
            )

        invocations, _, _ = _services(tdb, settings)
        # From the outside an unbound capability does not exist, so the answer
        # is 404 rather than a policy denial that would confirm the row.
        with pytest.raises(ToolNotFoundError) as caught:
            await invocations.create(
                InvocationRequest(
                    tool_name="evil.shell.exec",
                    tool_version="1.0",
                    arguments={"anything": "at all"},
                ),
                ADMIN,
            )
        assert "capability_not_bound" in str(caught.value)

        async with tdb.session() as session:
            row = (
                (
                    await session.execute(
                        select(ToolInvocation).where(
                            ToolInvocation.tool_name == "evil.shell.exec"
                        )
                    )
                )
                .scalars()
                .one()
            )
        assert row.state == InvocationState.REJECTED.value
        assert row.authorization_reason == PolicyReason.CAPABILITY_NOT_BOUND.value
        # It never reached a lease, so it never reached an adapter.
        assert row.executor_lease_id is None
        assert row.started_at is None


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------
class TestEvidence:
    async def test_every_transition_is_recorded_in_order(
        self, tdb: Database, settings: Settings
    ) -> None:
        invocations, _, dispatcher = _services(tdb, settings)
        invocation = await invocations.create(
            InvocationRequest(
                tool_name="acop.test.echo_metadata",
                tool_version="1.0",
                arguments={"note": "history"},
            ),
            VIEWER,
        )
        await dispatcher.execute_once(invocation.id)
        async with tdb.session() as session:
            events = (
                (
                    await session.execute(
                        select(ToolInvocationEvent)
                        .where(ToolInvocationEvent.invocation_id == invocation.id)
                        .order_by(ToolInvocationEvent.sequence)
                    )
                )
                .scalars()
                .all()
            )
        assert [(e.from_state, e.to_state) for e in events] == [
            (None, "REQUESTED"),
            ("REQUESTED", "AUTHORIZED"),
            ("AUTHORIZED", "READY"),
            ("READY", "EXECUTING"),
            # The final gate. Recorded in place - the same state on both sides -
            # because evaluating the gate is evidence, not a transition.
            ("EXECUTING", "EXECUTING"),
            ("EXECUTING", "EXECUTED"),
            ("EXECUTED", "SUCCEEDED"),
        ]
        # Gap-free, starting at 1.
        assert [e.sequence for e in events] == list(range(1, len(events) + 1))

    async def test_the_final_gate_decision_names_the_event_that_produced_it(
        self, tdb: Database, settings: Settings
    ) -> None:
        """F-6: a decision with no event behind it is an assertion, not a record.

        The pointer must resolve to a real event on this same invocation, and
        that event must carry the decision - otherwise the row says the gate ran
        without the append-only history to show what it saw.
        """
        invocations, _, dispatcher = _services(tdb, settings)
        invocation = await invocations.create(
            InvocationRequest(
                tool_name="acop.test.echo_metadata",
                tool_version="1.0",
                arguments={"note": "provenance"},
            ),
            VIEWER,
        )
        assert await dispatcher.execute_once(invocation.id) is InvocationState.SUCCEEDED

        row = await _reload(tdb, invocation.id)
        assert row.final_gate_decision == "ALLOW"
        assert row.final_gate_at is not None
        assert row.final_gate_event_id is not None

        async with tdb.session() as session:
            event = await session.get(ToolInvocationEvent, row.final_gate_event_id)
        assert event is not None
        assert event.invocation_id == invocation.id
        assert event.reason == PolicyReason.ALLOWED.value
        assert event.detail["gate"] == "final"
        assert event.detail["decision"] == "ALLOW"
        assert event.detail["reason"] == row.final_gate_reason
        # Evaluating the gate moves nothing, so the event names one state twice.
        assert event.from_state == InvocationState.EXECUTING.value
        assert event.to_state == InvocationState.EXECUTING.value

    async def test_the_security_snapshot_survives_a_change_to_the_tool(
        self, tdb: Database, settings: Settings
    ) -> None:
        """A three-year-old audit answer must not change today.

        The snapshot is a copy of what policy applied, not a join to what the
        tool currently declares.
        """
        asset_id = await _asset(tdb, display_name="sim-ok")
        invocations, _, _ = _services(tdb, settings)
        invocation = await invocations.create(
            InvocationRequest(
                tool_name="test.service.restart",
                tool_version="1.0",
                arguments={},
                target_asset_id=asset_id,
                idempotency_key="snapshot-1",
            ),
            OPERATOR,
        )
        row = await _reload(tdb, invocation.id)
        assert row.permission_class == "CLASS_2_LOW_RISK_CHANGE"
        assert row.approval_required is True
        assert row.validation_required is True
        assert row.approval_ttl_seconds == 3600
        assert row.effective_approval_policy["approver_roles"] == ["admin", "approver"]
        assert row.registry_contract_hash

    async def test_no_audit_record_carries_adapter_text(
        self, tdb: Database, settings: Settings
    ) -> None:
        """Only fixed phrases leave the process boundary."""
        asset_id = await _asset(tdb, display_name=SIM_UNREACHABLE)
        invocations, approvals, dispatcher = _services(tdb, settings)
        invocation = await invocations.create(
            InvocationRequest(
                tool_name="test.service.restart",
                tool_version="1.0",
                arguments={},
                target_asset_id=asset_id,
                idempotency_key="audit-phrase",
            ),
            OPERATOR,
        )
        await approvals.decide(
            invocation.id,
            APPROVER_A,
            decision=ApprovalDecision.APPROVED,
            justification="Approved.",
            expected_envelope_digest=invocation.envelope_digest,
        )
        await dispatcher.execute_once(invocation.id)
        async with tdb.session() as session:
            count = await session.scalar(
                text(
                    "SELECT count(*) FROM audit_event WHERE "
                    "message ILIKE '%simulated service manager%'"
                )
            )
        assert count == 0

    async def test_a_denial_is_audited_at_critical_for_a_prohibited_tool(
        self, tdb: Database, settings: Settings
    ) -> None:
        asset_id = await _asset(tdb, display_name="a-host-3", asset_type=AssetType.HOST)
        invocations, _, _ = _services(tdb, settings)
        with pytest.raises(ProhibitedCapabilityError):
            await invocations.create(
                InvocationRequest(
                    tool_name="test.prohibited.shell_exec",
                    tool_version="1.0",
                    arguments={"intent": "escalate"},
                    target_asset_id=asset_id,
                    idempotency_key="prohibited-audit",
                ),
                ADMIN,
            )
        async with tdb.session() as session:
            count = await session.scalar(
                select(func.count()).select_from(
                    text(
                        "(SELECT 1 FROM audit_event WHERE action = 'tool.invoke' "
                        "AND outcome = 'DENIED' AND severity = 'CRITICAL') s"
                    )
                )
            )
        assert count == 1

    async def test_an_ordinary_role_denial_is_audited_as_a_routine_refusal(
        self, tdb: Database, settings: Settings
    ) -> None:
        """The baseline the engine-failure test below is measured against."""
        asset_id = await _asset(tdb, display_name="a-service")
        invocations, _, _ = _services(tdb, settings)
        with pytest.raises(ToolAuthorizationError) as caught:
            await invocations.create(
                InvocationRequest(
                    tool_name="test.service.restart",
                    tool_version="1.0",
                    arguments={},
                    target_asset_id=asset_id,
                ),
                VIEWER,
            )
        assert caught.value.code == "tool_not_authorized"
        assert await _denial_audit(tdb) == [("tool.invoke", "WARNING")]

        row = await _only_invocation(tdb)
        assert row.state == InvocationState.REJECTED.value
        assert row.authorization_decision == "DENY"
        assert row.authorization_reason == PolicyReason.ROLE_INSUFFICIENT.value

    async def test_a_policy_engine_failure_is_audited_apart_from_a_denial(
        self, tdb: Database, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """F4: "the engine is broken" must not arrive as "denials are up".

        Every channel an operator watches used to group a malfunctioning engine
        with ordinary refusals - same status, same code, same phrase, same
        audit action, same severity - so a bad deploy read as a permissions
        misconfiguration. The reason lived on the invocation row, where nobody
        looks at 03:00.

        The exception is injected into a gate ``_evaluate`` really calls, so the
        engine's own ``except`` clause is what produces this refusal rather than
        a decision object built by the test.
        """

        def _explode(*_: object, **__: object) -> None:
            raise RuntimeError(_LEAKY_MESSAGE)

        monkeypatch.setattr(ToolPolicyEngine, "_check_target", staticmethod(_explode))
        asset_id = await _asset(tdb, display_name="a-service-2")
        invocations, _, _ = _services(tdb, settings)
        with pytest.raises(PolicyEngineFailureError) as caught:
            await invocations.create(
                InvocationRequest(
                    tool_name="test.device.status",
                    tool_version="1.0",
                    arguments={},
                    target_asset_id=asset_id,
                ),
                OPERATOR,
            )
        # Distinguishable to the caller, and still a 403: the engine did decide,
        # and it decided to refuse.
        assert caught.value.code == "policy_engine_error"
        assert caught.value.http_status == 403
        assert caught.value.category is ToolErrorCategory.INTERNAL_ERROR
        for leak in ("hunter2", "RuntimeError", "Traceback", _LEAKY_MESSAGE):
            assert leak not in caught.value.public_message

        # Distinguishable in the durable record, without querying the row.
        assert await _denial_audit(tdb) == [("tool.policy_failure", "CRITICAL")]
        async with tdb.session() as session:
            leaked = await session.scalar(
                text("SELECT count(*) FROM audit_event WHERE message ILIKE '%hunter2%'")
            )
        assert leaked == 0

        # And still closed. An engine that has not decided never means "go on".
        row = await _only_invocation(tdb)
        assert row.state == InvocationState.REJECTED.value
        assert row.authorization_decision == "DENY"
        assert row.authorization_reason == PolicyReason.INTERNAL_ERROR.value


# ---------------------------------------------------------------------------
# Schema domains
# ---------------------------------------------------------------------------
#: A complete, valid ``tool_invocation`` row with every column the tests below
#: vary left as a bind parameter. Spelled out as SQL rather than built through
#: the ORM because what is under test is PostgreSQL's opinion of the row: a
#: mapped class that refuses a value says nothing about a repair script, a
#: restored backup, or a future service that writes the column directly.
_INVOCATION_INSERT = text(
    "INSERT INTO tool_invocation ("
    "id, tool_name, tool_version, tool_registration_id, permission_class, "
    "approval_required, approval_ttl_seconds, validation_required, "
    "registry_contract_hash, envelope, envelope_digest, input_digest, "
    "input_canonical, principal_subject, principal_type, principal_issuer, "
    "auth_method, target_kind, authorization_decision, authorization_reason, "
    "state, idempotency_key, executor_lease_id, lease_expires_at, "
    "final_gate_decision, final_gate_at, final_gate_event_id"
    ") VALUES ("
    ":id, 'test.domain.probe', '1.0', :registration_id, :permission_class, "
    ":approval_required, 3600, :validation_required, "
    ":digest, '{}'::jsonb, :digest, :digest, "
    "'{}'::jsonb, 'acop:user:probe', 'human', 'acop:api-key', "
    "'api_key', 'NONE', 'ALLOW', 'allowed', "
    ":state, :idempotency_key, :lease_id, :lease_expires_at, "
    ":final_gate_decision, :final_gate_at, :final_gate_event_id"
    ")"
)


async def _registration_id(database: Database) -> uuid.UUID:
    """Any reconciled registration. The invocation's foreign key must resolve."""
    async with database.session() as session:
        value = await session.scalar(text("SELECT id FROM tool_registration LIMIT 1"))
    assert value is not None
    return uuid.UUID(str(value))


async def _insert_invocation(
    database: Database,
    registration_id: uuid.UUID,
    *,
    permission_class: str = PermissionClass.CLASS_0_INFORMATION.value,
    state: str = InvocationState.REQUESTED.value,
    approval_required: bool = False,
    validation_required: bool = False,
    idempotency_key: str | None = None,
    final_gate_decision: str | None = None,
    final_gate_event_id: uuid.UUID | None = None,
) -> uuid.UUID:
    """Insert one otherwise-valid invocation, varying only what is passed.

    Each call gets its own session, and therefore its own transaction, because
    PostgreSQL aborts the whole transaction on the first constraint violation:
    two rejections asserted inside one transaction would prove only that the
    first one failed.
    """
    invocation_id = uuid.uuid4()
    leased = state in {
        InvocationState.EXECUTING.value,
        InvocationState.VALIDATING.value,
    }
    async with database.session() as session:
        await session.execute(
            _INVOCATION_INSERT,
            {
                "id": invocation_id,
                "registration_id": registration_id,
                "permission_class": permission_class,
                "approval_required": approval_required,
                "validation_required": validation_required,
                "digest": "0" * 64,
                "state": state,
                "idempotency_key": idempotency_key,
                "lease_id": uuid.uuid4() if leased else None,
                "lease_expires_at": (
                    datetime.now(UTC) + timedelta(minutes=5) if leased else None
                ),
                "final_gate_decision": final_gate_decision,
                "final_gate_at": datetime.now(UTC) if final_gate_decision else None,
                "final_gate_event_id": final_gate_event_id,
            },
        )
    return invocation_id


async def _insert_event(database: Database, invocation_id: uuid.UUID) -> uuid.UUID:
    """Append one transition event and return its id."""
    event_id = uuid.uuid4()
    async with database.session() as session:
        await session.execute(
            text(
                "INSERT INTO tool_invocation_event "
                "(id, invocation_id, sequence, to_state, reason) "
                "VALUES (:id, :invocation_id, 1, 'REQUESTED', 'requested')"
            ),
            {"id": event_id, "invocation_id": invocation_id},
        )
    return event_id


class TestSchemaDomainConstraints:
    """The invocation domain as PostgreSQL enforces it, reached by raw SQL.

    The service layer checks transitions and the CAS predicate on every UPDATE
    checks them again, but neither is reachable from a repair script, a restored
    backup or a compromised credential - and neither runs at all for a typo in
    future service code that writes a state string no enum member spells. These
    tests therefore go around the ORM entirely.

    :meth:`test_a_misspelt_change_class_cannot_escape_approval` is the F-2
    regression and the most important assertion in the class. The three class
    agreements were once written as ``permission_class NOT IN
    ('CLASS_2_LOW_RISK_CHANGE','CLASS_3_HIGH_RISK_CHANGE')``, which every string
    outside that list satisfies vacuously - so ``'CLASS_2_LOW_RISK_CHANG'``, one
    character short, was accepted with ``approval_required`` false. That silent
    fail-open must stay closed.
    """

    async def test_every_declared_state_is_accepted(self, tdb: Database) -> None:
        registration_id = await _registration_id(tdb)
        for state in InvocationState:
            await _insert_invocation(tdb, registration_id, state=state.value)
        async with tdb.session() as session:
            count = await session.scalar(text("SELECT count(*) FROM tool_invocation"))
        assert count == len(InvocationState)

    async def test_a_state_no_enum_spells_is_rejected(self, tdb: Database) -> None:
        """Including the plausible typo, which is the case that would ship."""
        registration_id = await _registration_id(tdb)
        for state in ("TOTALLY_MADE_UP", "SUCEEDED", "succeeded", ""):
            with pytest.raises(IntegrityError):
                await _insert_invocation(tdb, registration_id, state=state)

    async def test_every_declared_permission_class_is_accepted(
        self, tdb: Database
    ) -> None:
        """PROHIBITED included: the policy engine writes it for an unbound tool."""
        registration_id = await _registration_id(tdb)
        for index, permission_class in enumerate(PermissionClass):
            await _insert_invocation(
                tdb,
                registration_id,
                permission_class=permission_class.value,
                approval_required=True,
                validation_required=True,
                idempotency_key=f"domain-class-{index}",
            )
        async with tdb.session() as session:
            count = await session.scalar(text("SELECT count(*) FROM tool_invocation"))
        assert count == len(PermissionClass)

    async def test_a_permission_class_no_enum_spells_is_rejected(
        self, tdb: Database
    ) -> None:
        registration_id = await _registration_id(tdb)
        for permission_class in ("CLASS_4_UNLIMITED", "class_1_read_only", ""):
            with pytest.raises(IntegrityError):
                await _insert_invocation(
                    tdb,
                    registration_id,
                    permission_class=permission_class,
                    approval_required=True,
                    validation_required=True,
                    idempotency_key=f"unknown-{permission_class}",
                )

    async def test_a_misspelt_change_class_cannot_escape_approval(
        self, tdb: Database
    ) -> None:
        """F-2 regression: the fail-open the negative form left open.

        ``'CLASS_2_LOW_RISK_CHANG'`` is not in the change list, so the old
        ``NOT IN`` phrasing accepted this row with no approval, no validation
        and no idempotency key. It must now abort.
        """
        registration_id = await _registration_id(tdb)
        with pytest.raises(IntegrityError):
            await _insert_invocation(
                tdb,
                registration_id,
                permission_class="CLASS_2_LOW_RISK_CHANG",
                approval_required=False,
                validation_required=False,
            )

    async def test_a_final_gate_decision_cannot_exist_without_its_event(
        self, tdb: Database
    ) -> None:
        registration_id = await _registration_id(tdb)
        with pytest.raises(IntegrityError):
            await _insert_invocation(tdb, registration_id, final_gate_decision="ALLOW")

    async def test_a_final_gate_event_cannot_exist_without_its_decision(
        self, tdb: Database
    ) -> None:
        registration_id = await _registration_id(tdb)
        invocation_id = await _insert_invocation(tdb, registration_id)
        event_id = await _insert_event(tdb, invocation_id)
        with pytest.raises(IntegrityError):
            await _insert_invocation(tdb, registration_id, final_gate_event_id=event_id)

    async def test_a_final_gate_decision_may_only_name_a_real_event(
        self, tdb: Database
    ) -> None:
        """The pointer is unfalsifiable: an invented event id is refused."""
        registration_id = await _registration_id(tdb)
        with pytest.raises(IntegrityError):
            await _insert_invocation(
                tdb,
                registration_id,
                final_gate_decision="ALLOW",
                final_gate_event_id=uuid.uuid4(),
            )

    async def test_a_decision_recorded_with_its_event_is_accepted(
        self, tdb: Database
    ) -> None:
        registration_id = await _registration_id(tdb)
        invocation_id = await _insert_invocation(tdb, registration_id)
        event_id = await _insert_event(tdb, invocation_id)
        async with tdb.session() as session:
            await session.execute(
                text(
                    "UPDATE tool_invocation SET final_gate_decision = 'ALLOW', "
                    "final_gate_at = now(), final_gate_event_id = :event_id "
                    "WHERE id = :id"
                ),
                {"event_id": event_id, "id": invocation_id},
            )
        async with tdb.session() as session:
            stored = await session.scalar(
                text("SELECT final_gate_event_id FROM tool_invocation WHERE id = :id"),
                {"id": invocation_id},
            )
        assert stored == event_id
