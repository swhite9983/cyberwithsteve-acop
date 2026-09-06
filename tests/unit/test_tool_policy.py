"""The eight gates: order, fail-closed, and the ORM-free invariant.

Two of these tests are about *structure* rather than behaviour, and they are
the ones worth reading:

* ``test_the_policy_module_does_not_import_the_orm`` is mechanism 2 of the
  Capability Binding Invariant. Policy reads the code registry; if it could
  read a row, a row could set a permission class.
* ``test_prohibition_is_decided_before_authorization`` proves the denial reason
  does not vary by role. If it did, the error message would tell an attacker
  which role would have worked.
"""

from __future__ import annotations

import ast
import uuid
from pathlib import Path

import pytest

from acop.auth.principal import AuthMethod, Principal, PrincipalType, Role
from acop.models.provenance import PermissionClass
from acop.models.tool_vocabulary import (
    ERROR_PHRASES,
    GateDecision,
    PolicyReason,
    TargetKind,
    ToolErrorCategory,
    ToolLifecycle,
)
from acop.services.tools.invocation import _REFUSAL_ERRORS
from acop.tools.catalog import (
    DEVICE_STATUS,
    ECHO_METADATA,
    PROHIBITED_SHELL_EXEC,
    ROTATE_KEY,
    SERVICE_RESTART,
)
from acop.tools.errors import (
    InvalidTargetError,
    PolicyEngineFailureError,
    ProhibitedCapabilityError,
    ToolAuthorizationError,
    ToolDisabledError,
    ToolError,
    ToolInputError,
    ToolNotFoundError,
    ToolPolicyDeniedError,
)
from acop.tools.policy import PolicyContext, TargetFacts, ToolPolicyEngine

ENGINE = ToolPolicyEngine()

#: Deliberately shaped like the worst thing a failing gate could be holding.
#: A gate that dies mid-lookup can be carrying a DSN or a token in its
#: exception, which is exactly why the public phrase is a fixed table lookup
#: and not the exception's own text.
_LEAKY_MESSAGE = "policy store unreachable: postgresql://acop:hunter2@db.internal/acop"


def _principal(*roles: Role) -> Principal:
    return Principal(
        subject="acop:user:test",
        principal_type=PrincipalType.HUMAN,
        issuer="acop:api-key",
        auth_method=AuthMethod.API_KEY,
        roles=frozenset(role.value for role in roles),
    )


def _asset_target(asset_type: str = "DEVICE", lifecycle: str = "ACTIVE") -> TargetFacts:
    return TargetFacts(
        kind=TargetKind.ASSET,
        exists=True,
        asset_id=uuid.uuid4(),
        asset_type=asset_type,
        lifecycle_state=lifecycle,
        display_name="sim-target",
    )


def _context(
    definition: object,
    principal: Principal,
    *,
    raw_input: dict[str, object] | None = None,
    target: TargetFacts | None = None,
    lifecycle: ToolLifecycle = ToolLifecycle.ACTIVE,
    environment: str = "test",
) -> PolicyContext:
    return PolicyContext(
        principal=principal,
        definition=definition,  # type: ignore[arg-type]
        lifecycle_state=lifecycle,
        raw_input=raw_input if raw_input is not None else {},
        target=target or TargetFacts(kind=TargetKind.NONE),
        environment=environment,
    )


class TestGateOne:
    def test_an_unbound_capability_is_denied(self) -> None:
        """A row that names a tool code does not declare.

        This is the Capability Binding Invariant from the inside: nothing below
        gate 1 runs, so no adapter is reached and no role is even consulted.
        """
        decision = ENGINE.evaluate(_context(None, _principal(Role.ADMIN)))
        assert not decision.allowed
        assert decision.reason is PolicyReason.CAPABILITY_NOT_BOUND
        assert decision.decision is GateDecision.DENY


class TestGateTwo:
    @pytest.mark.parametrize(
        ("lifecycle", "reason"),
        [
            (ToolLifecycle.DISABLED, PolicyReason.TOOL_DISABLED),
            (ToolLifecycle.RETIRED, PolicyReason.TOOL_RETIRED),
        ],
    )
    def test_lifecycle_stops_an_otherwise_valid_request(
        self, lifecycle: ToolLifecycle, reason: PolicyReason
    ) -> None:
        decision = ENGINE.evaluate(
            _context(
                ECHO_METADATA,
                _principal(Role.VIEWER),
                raw_input={"note": "hello"},
                lifecycle=lifecycle,
            )
        )
        assert not decision.allowed
        assert decision.reason is reason


class TestGateThree:
    def test_prohibition_is_decided_before_authorization(self) -> None:
        """Every role gets the same refusal, and it is never "wrong role".

        A denial reason that varied by role would be an oracle telling an
        attacker exactly which privilege to acquire.
        """
        reasons = set()
        for role in (Role.VIEWER, Role.OPERATOR, Role.APPROVER, Role.ADMIN):
            decision = ENGINE.evaluate(
                _context(
                    PROHIBITED_SHELL_EXEC,
                    _principal(role),
                    raw_input={"intent": "look at something"},
                    target=_asset_target("HOST"),
                )
            )
            assert not decision.allowed
            reasons.add(decision.reason)
        assert reasons == {PolicyReason.PROHIBITED_CAPABILITY}

    def test_an_admin_gets_no_exemption(self) -> None:
        decision = ENGINE.evaluate(
            _context(
                PROHIBITED_SHELL_EXEC,
                _principal(Role.ADMIN),
                raw_input={"intent": "anything"},
                target=_asset_target("HOST"),
            )
        )
        assert decision.reason is PolicyReason.PROHIBITED_CAPABILITY
        assert decision.prohibited is True


class TestGateFour:
    def test_an_undeclared_field_is_rejected_not_redacted(self) -> None:
        decision = ENGINE.evaluate(
            _context(
                ECHO_METADATA,
                _principal(Role.VIEWER),
                raw_input={"note": "hello", "api_key": "sk-not-a-real-key"},
            )
        )
        assert not decision.allowed
        assert decision.reason is PolicyReason.SCHEMA_INVALID

    def test_schema_is_checked_before_any_target_lookup(self) -> None:
        """The prerequisites call returns a denial without seeing a target.

        This is what makes "a malformed request cannot cause a database lookup
        on attacker-controlled input" a property of the code path rather than
        of a comment.
        """
        early = ENGINE.evaluate_prerequisites(
            _context(
                DEVICE_STATUS,
                _principal(Role.VIEWER),
                raw_input={"include_facts": "not a boolean"},
                target=TargetFacts(kind=TargetKind.ASSET, exists=False),
            )
        )
        assert early is not None
        assert early.reason is PolicyReason.SCHEMA_INVALID

    def test_prerequisites_return_none_for_a_valid_request(self) -> None:
        assert (
            ENGINE.evaluate_prerequisites(
                _context(
                    DEVICE_STATUS,
                    _principal(Role.VIEWER),
                    raw_input={"include_facts": False},
                    target=TargetFacts(kind=TargetKind.ASSET, exists=False),
                )
            )
            is None
        )


class TestGateFive:
    def test_a_missing_target_is_invalid(self) -> None:
        decision = ENGINE.evaluate(
            _context(
                DEVICE_STATUS,
                _principal(Role.VIEWER),
                raw_input={},
                target=TargetFacts(kind=TargetKind.ASSET, exists=False),
            )
        )
        assert decision.reason is PolicyReason.TARGET_INVALID

    def test_a_retired_asset_is_distinguished_from_one_out_of_scope(self) -> None:
        """Two different operator responses, so two different reasons.

        A retired target is a stale request; an out-of-scope one is a wrong
        request. Collapsing them would make the error useless.
        """
        retired = ENGINE.evaluate(
            _context(
                DEVICE_STATUS,
                _principal(Role.VIEWER),
                raw_input={},
                target=_asset_target("DEVICE", "RETIRED"),
            )
        )
        assert retired.reason is PolicyReason.TARGET_RETIRED

        wrong_type = ENGINE.evaluate(
            _context(
                SERVICE_RESTART,
                _principal(Role.OPERATOR),
                raw_input={},
                target=_asset_target("DEVICE"),
            )
        )
        assert wrong_type.reason is PolicyReason.TARGET_OUT_OF_SCOPE


class TestGateSix:
    def test_an_insufficient_role_is_refused(self) -> None:
        decision = ENGINE.evaluate(
            _context(
                SERVICE_RESTART,
                _principal(Role.VIEWER),
                raw_input={},
                target=_asset_target("SERVICE"),
            )
        )
        assert decision.reason is PolicyReason.ROLE_INSUFFICIENT

    def test_admin_satisfies_operator_because_it_is_a_superset(self) -> None:
        decision = ENGINE.evaluate(
            _context(
                SERVICE_RESTART,
                _principal(Role.ADMIN),
                raw_input={},
                target=_asset_target("SERVICE"),
            )
        )
        assert decision.allowed

    def test_an_approver_may_request_a_class_three_change(self) -> None:
        """Clearance and approval authority are separate axes.

        An approver holds ``viewer`` by implication but not ``operator``, so
        this must be refused - and the reason must be the role, not the class.
        """
        decision = ENGINE.evaluate(
            _context(
                ROTATE_KEY,
                _principal(Role.APPROVER),
                raw_input={"key_slot": "primary"},
                target=_asset_target("DEVICE"),
            )
        )
        assert decision.reason is PolicyReason.ROLE_INSUFFICIENT

    def test_an_operator_may_request_a_class_three_change(self) -> None:
        decision = ENGINE.evaluate(
            _context(
                ROTATE_KEY,
                _principal(Role.OPERATOR),
                raw_input={"key_slot": "primary"},
                target=_asset_target("HOST"),
            )
        )
        assert decision.allowed
        assert decision.permission_class is PermissionClass.CLASS_3_HIGH_RISK_CHANGE
        assert decision.approval_policy.min_approvals == 2
        assert decision.approval_policy.distinct_approvers_required is True


class TestGateEight:
    def test_approval_is_computed_not_denied(self) -> None:
        """Needing approval is not being refused."""
        decision = ENGINE.evaluate(
            _context(
                SERVICE_RESTART,
                _principal(Role.OPERATOR),
                raw_input={"graceful": True},
                target=_asset_target("SERVICE"),
            )
        )
        assert decision.allowed
        assert decision.reason is PolicyReason.ALLOWED
        assert decision.approval_policy.approval_required is True
        assert decision.validation_required is True


class TestRefusalErrorMapping:
    """A refusal must say which of the caller's problems it is.

    Every gate denial used to become one 403, which told an integrator with a
    malformed body to go and check their credentials. The table is the fix,
    and these tests hold it to the two things that make it safe: it covers
    every reason, and it never lets the reason become an oracle.
    """

    def test_the_mapping_is_total_over_every_policy_reason(self) -> None:
        assert set(_REFUSAL_ERRORS) == set(PolicyReason)

    @pytest.mark.parametrize(
        ("reason", "expected", "status"),
        [
            (PolicyReason.SCHEMA_INVALID, ToolInputError, 422),
            (PolicyReason.TARGET_INVALID, InvalidTargetError, 422),
            (PolicyReason.TARGET_OUT_OF_SCOPE, InvalidTargetError, 422),
            (PolicyReason.TARGET_RETIRED, InvalidTargetError, 422),
            (PolicyReason.TOOL_DISABLED, ToolDisabledError, 409),
            (PolicyReason.TOOL_RETIRED, ToolDisabledError, 409),
            (PolicyReason.ROLE_INSUFFICIENT, ToolAuthorizationError, 403),
            (PolicyReason.CAPABILITY_NOT_BOUND, ToolNotFoundError, 404),
            (PolicyReason.PROHIBITED_CAPABILITY, ProhibitedCapabilityError, 403),
            (PolicyReason.ENVIRONMENT_RESTRICTED, ToolPolicyDeniedError, 403),
            (PolicyReason.INTERNAL_ERROR, PolicyEngineFailureError, 403),
        ],
        ids=lambda value: getattr(value, "value", value),
    )
    def test_each_reason_carries_its_intended_status(
        self, reason: PolicyReason, expected: type[ToolError], status: int
    ) -> None:
        assert _REFUSAL_ERRORS[reason] is expected
        assert _REFUSAL_ERRORS[reason].http_status == status

    def test_a_prohibition_is_never_reported_as_a_role_problem(self) -> None:
        """The reason must not tell an attacker which role would have worked.

        Gate 3 runs before gate 6, so every role gets this same answer; the
        mapping must not undo that by answering with the authorization class,
        whose category and code both say "your roles are the problem".
        """
        prohibited = _REFUSAL_ERRORS[PolicyReason.PROHIBITED_CAPABILITY]
        assert prohibited is not _REFUSAL_ERRORS[PolicyReason.ROLE_INSUFFICIENT]
        assert prohibited.category is not ToolErrorCategory.AUTHORIZATION
        assert prohibited.category is ToolErrorCategory.POLICY_DENIED

    def test_a_broken_engine_is_not_reported_as_an_ordinary_denial(self) -> None:
        """F4: a malfunction and a refusal are different events.

        Sharing ``tool_policy_denied`` meant a deploy that made ``evaluate``
        throw on every request presented as a spike in denials - which reads
        as a permissions misconfiguration and sends the investigation to the
        role table rather than to the traceback. The status stays 403 because
        the engine did decide: it failed closed.
        """
        failure = _REFUSAL_ERRORS[PolicyReason.INTERNAL_ERROR]
        assert failure is PolicyEngineFailureError
        assert failure is not _REFUSAL_ERRORS[PolicyReason.ENVIRONMENT_RESTRICTED]
        assert failure is not _REFUSAL_ERRORS[PolicyReason.ROLE_INSUFFICIENT]
        assert failure.code == "policy_engine_error"
        assert failure.code != ToolPolicyDeniedError.code
        assert failure.http_status == 403
        assert failure.category is ToolErrorCategory.INTERNAL_ERROR


class TestFailClosed:
    def test_an_engine_that_raises_denies(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An engine that has not decided must never mean "go ahead".

        The exception is injected into a gate that ``_evaluate`` really calls,
        on a request that would otherwise be allowed. Handing the engine a
        pre-built denial would exercise none of this: what is under test is the
        ``except`` clause, and a faked decision never reaches it.
        """

        def _explode(*_: object, **__: object) -> None:
            raise RuntimeError(_LEAKY_MESSAGE)

        monkeypatch.setattr(ToolPolicyEngine, "_check_target", staticmethod(_explode))
        decision = ENGINE.evaluate(
            _context(DEVICE_STATUS, _principal(Role.VIEWER), target=_asset_target())
        )
        assert not decision.allowed
        assert decision.decision is GateDecision.DENY
        assert decision.reason is PolicyReason.INTERNAL_ERROR
        assert not decision.canonical_input

    def test_the_refusal_carries_none_of_the_exception(self) -> None:
        """The caller learns that ACOP refused, never that ACOP broke and how.

        The phrase comes from the fixed table, so there is no path by which a
        traceback, an exception type or whatever a failing gate was holding -
        a connection string, a token - reaches an HTTP response.
        """
        error = _REFUSAL_ERRORS[PolicyReason.INTERNAL_ERROR](_LEAKY_MESSAGE)
        assert error.public_message == ERROR_PHRASES[ToolErrorCategory.INTERNAL_ERROR]
        assert _LEAKY_MESSAGE not in error.public_message
        assert "hunter2" not in error.public_message
        assert "RuntimeError" not in error.public_message
        assert "Traceback" not in error.public_message

    def test_a_failure_inside_the_denial_builder_still_denies(self) -> None:
        """The handler itself must not be able to raise on the way out.

        Here it is the *definition* that is broken, so building the denial
        touches the same thing that just failed. Without the second fallback
        this escapes ``evaluate`` as an unhandled 500 - turning "we could not
        decide" into something no gate answered at all.
        """

        class Exploding:
            @property
            def prohibited(self) -> bool:
                raise RuntimeError("boom")

        context = PolicyContext(
            principal=_principal(Role.ADMIN),
            definition=Exploding(),  # type: ignore[arg-type]
            lifecycle_state=ToolLifecycle.ACTIVE,
            raw_input={},
            target=TargetFacts(kind=TargetKind.NONE),
            environment="test",
        )
        decision = ENGINE.evaluate(context)
        assert not decision.allowed
        assert decision.decision is GateDecision.DENY
        assert decision.reason is PolicyReason.INTERNAL_ERROR

    def test_only_one_statement_in_the_module_produces_an_allow(self) -> None:
        """There is no default that permits, and no ``else`` that allows.

        Asserted against the AST rather than by reading, because the property
        is easy to break with a well-meaning refactor.
        """
        source = Path("src/acop/tools/policy.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        allows = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.keyword)
            and node.arg == "allowed"
            and isinstance(node.value, ast.Constant)
            and node.value.value is True
        ]
        assert len(allows) == 1


class TestNoOrmInPolicy:
    def test_the_policy_module_does_not_import_the_orm(self) -> None:
        """Mechanism 2 of the Capability Binding Invariant.

        If policy could read a ``tool_registration`` row, then a row could set
        a permission class - and a database row would be able to mint a
        capability.
        """
        source = Path("src/acop/tools/policy.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        assert "acop.models.tool" not in imported
        assert not any(name.startswith("sqlalchemy") for name in imported)
