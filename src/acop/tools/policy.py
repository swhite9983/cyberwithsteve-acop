"""The policy engine: eight gates, one allow, fail closed.

**This module does not import the ORM.** A unit test asserts that, because it
is mechanism 2 of the Capability Binding Invariant: policy reads the *code*
registry, and there is no path by which a database row could supply a
permission class, a required role, or an approval requirement. The one thing
policy takes from the database is lifecycle state - ACTIVE, DISABLED, RETIRED -
and it is passed in as a value, not looked up here.

**Gate order is load-bearing, not arbitrary:**

* **Prohibition (3) before authorization (6).** If a prohibited tool were
  refused for "insufficient role", the error message would tell an attacker
  which role would have worked. The denial reason must not vary by who asked.
* **Schema (4) before target (5).** A malformed request must not be able to
  cause a database lookup on attacker-controlled input.
* **Approval (8) last, and it never denies.** Computing whether approval is
  required is a different act from refusing; conflating them would mean a tool
  that needs approval and a tool that is forbidden produce the same shape of
  answer.

**Fail closed, structurally.** The only statement in this module producing
``allowed=True`` is the final line of :meth:`ToolPolicyEngine.evaluate`, after
all eight checks have run. There is no default, no ``else`` that allows, and no
early success. Any unhandled exception is caught and converted to a denial with
``PolicyReason.INTERNAL_ERROR`` - because an engine that raises has not decided
anything, and "has not decided" must never mean "go ahead".
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel
from pydantic import ValidationError as PydanticValidationError

from acop.auth.principal import Principal
from acop.core.logging import get_logger
from acop.models.provenance import PermissionClass
from acop.models.tool_vocabulary import (
    PROHIBITED_CAPABILITIES,
    GateDecision,
    PolicyReason,
    TargetKind,
    ToolLifecycle,
    effective_roles,
)
from acop.tools.contract import ApprovalPolicy, ToolDefinition

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class TargetFacts:
    """What ACOP knows about the requested target, looked up by the caller.

    Passed in rather than fetched here so this module stays free of the ORM.
    ``exists`` is explicit rather than implied by ``asset_id is None``, because
    "no target was named" and "the named target does not exist" are different
    answers and only one of them is an error.
    """

    kind: TargetKind
    exists: bool = True
    asset_id: uuid.UUID | None = None
    asset_type: str = ""
    lifecycle_state: str = ""
    display_name: str = ""
    external_ref: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PolicyContext:
    """Everything a gate may consider.

    The extension point named in the design: change-freeze windows, resource
    ownership and per-environment restrictions become new checks reading this
    object, with no signature change and no schema change.
    """

    principal: Principal
    #: ``None`` when a ``tool_registration`` row names a tool that no code
    #: declaration binds. That is gate 1, and it is a real reachable state -
    #: the adversarial test inserts exactly such a row by raw SQL.
    definition: ToolDefinition | None
    lifecycle_state: ToolLifecycle
    raw_input: dict[str, Any]
    target: TargetFacts
    environment: str
    request_time: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """The frozen outcome of an evaluation.

    Every policy field on it comes from the code registry. There is no
    constructor path that takes one from a request, which is what makes the
    invocation's security snapshot trustworthy: it is a copy of what code said,
    not an echo of what a caller sent.
    """

    allowed: bool
    reason: PolicyReason
    permission_class: PermissionClass
    approval_policy: ApprovalPolicy
    validation_required: bool
    required_roles: frozenset[str]
    execution_parameters: dict[str, Any]
    prohibited: bool
    registry_contract_hash: str
    evaluated_at: datetime
    #: The input after Pydantic validation, in canonical JSON form. Present
    #: only on an allow - a denied request has no validated input to speak of.
    canonical_input: dict[str, Any] = field(default_factory=dict)

    @property
    def decision(self) -> GateDecision:
        return GateDecision.ALLOW if self.allowed else GateDecision.DENY


class ToolPolicyEngine:
    """Evaluates the eight gates. Holds no state and touches no database."""

    def evaluate_prerequisites(self, context: PolicyContext) -> PolicyDecision | None:
        """Run gates 1-4 only: a denial, or ``None`` meaning "carry on".

        This exists so that "schema before target" is a property of the *code
        path* rather than of a comment. A caller resolves a target only after
        this returns ``None``, so a malformed request provably cannot cause a
        database lookup on attacker-controlled input - there is no ordering
        left to get wrong.

        Gates 1-4 are pure and cheap, so :meth:`evaluate` re-runs them rather
        than trusting that this was called first. Duplicated work is the price
        of not having a fail-open when someone skips a step.
        """
        try:
            return self._gates_one_to_four(context)[0]
        except Exception:
            return self._internal_error(context)

    def evaluate(self, context: PolicyContext) -> PolicyDecision:
        """Run every gate in order and return one frozen decision."""
        try:
            return self._evaluate(context)
        except Exception:
            return self._internal_error(context)

    # ------------------------------------------------------------------
    def _internal_error(self, context: PolicyContext) -> PolicyDecision:
        """Log and deny, without being able to raise on the way out.

        The handler itself must not throw. Building the log line touches the
        definition, and if *that* is what broke, an exception here would escape
        the very ``except`` that exists to guarantee a decision - turning "we
        could not decide" into an unhandled 500 rather than a denial.
        """
        try:
            logger.exception(
                "tools.policy.internal_error",
                tool=getattr(context.definition, "qualified_name", "<unknown>"),
                subject=context.principal.subject,
            )
        except Exception:  # noqa: S110 - a failed log must not decide policy
            # Deliberately swallowed and deliberately not re-logged: the
            # logger is what just failed. The denial below is the outcome that
            # matters, and it still happens.
            pass
        try:
            return self._deny(context, PolicyReason.INTERNAL_ERROR)
        except Exception:
            # Even the denial builder reads the definition. If that fails too,
            # the unbound shape is still a truthful, closed answer.
            return self._deny(
                PolicyContext(
                    principal=context.principal,
                    definition=None,
                    lifecycle_state=context.lifecycle_state,
                    raw_input={},
                    target=context.target,
                    environment=context.environment,
                    request_time=context.request_time,
                ),
                PolicyReason.INTERNAL_ERROR,
            )

    def _gates_one_to_four(
        self, context: PolicyContext
    ) -> tuple[PolicyDecision | None, dict[str, Any]]:
        """Binding, lifecycle, prohibition and schema. Touches no database."""
        definition = context.definition

        # Gate 1 - capability binding. The caller resolves the definition from
        # the *code* registry; ``None`` means a database row named a tool that
        # code does not declare, which is the Capability Binding Invariant
        # observed from the inside. Nothing below this line runs for it, so no
        # adapter is reached and no role is consulted.
        if definition is None:
            return self._deny(context, PolicyReason.CAPABILITY_NOT_BOUND), {}

        # Gate 2 - lifecycle. The one thing the database is allowed to say.
        if context.lifecycle_state is ToolLifecycle.RETIRED:
            return self._deny(context, PolicyReason.TOOL_RETIRED), {}
        if context.lifecycle_state is ToolLifecycle.DISABLED:
            return self._deny(context, PolicyReason.TOOL_DISABLED), {}

        # Gate 3 - prohibition. Before authorization, so the reason does not
        # vary by role and cannot be used as an oracle.
        if definition.prohibited or (
            definition.capability_tags & PROHIBITED_CAPABILITIES
        ):
            return self._deny(context, PolicyReason.PROHIBITED_CAPABILITY), {}

        # Gate 4 - schema. Before any target lookup.
        canonical = self._validate_input(definition.input_model, context.raw_input)
        if canonical is None:
            return self._deny(context, PolicyReason.SCHEMA_INVALID), {}
        return None, canonical

    def _evaluate(self, context: PolicyContext) -> PolicyDecision:
        denial, canonical = self._gates_one_to_four(context)
        if denial is not None:
            return denial
        definition = context.definition
        if definition is None:  # pragma: no cover - gate 1 guarantees this
            return self._deny(context, PolicyReason.CAPABILITY_NOT_BOUND)

        # Gate 5 - target.
        target_reason = self._check_target(definition, context.target)
        if target_reason is not None:
            return self._deny(context, target_reason)

        # Gate 6 - authorization.
        held = {role.value for role in effective_roles(context.principal.roles)}
        if not set(definition.required_roles).issubset(held):
            return self._deny(context, PolicyReason.ROLE_INSUFFICIENT)

        # Gate 7 - context. Today: environment restriction. Tomorrow: freeze
        # windows and ownership, added here without touching the other seven.
        allowed_envs = definition.approval_policy.allowed_environments
        if allowed_envs and context.environment not in allowed_envs:
            return self._deny(context, PolicyReason.ENVIRONMENT_RESTRICTED)

        # Gate 8 - approval. Computes a requirement; never denies. A tool that
        # needs approval is not a tool that was refused.
        return PolicyDecision(
            allowed=True,
            reason=PolicyReason.ALLOWED,
            permission_class=definition.permission_class,
            approval_policy=definition.approval_policy,
            validation_required=definition.validation_required,
            required_roles=frozenset(definition.required_roles),
            execution_parameters=definition.execution_parameters(),
            prohibited=False,
            registry_contract_hash=definition.contract_hash(),
            evaluated_at=context.request_time,
            canonical_input=canonical,
        )

    # ------------------------------------------------------------------
    @staticmethod
    def _validate_input(
        model: type[BaseModel], raw: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Validate and canonicalise, or ``None``.

        ``mode="json"`` rather than ``mode="python"`` so that a ``datetime`` or
        a ``UUID`` has one textual representation. The envelope digest is taken
        over this value, so an unstable rendering would make approvals fail at
        random.
        """
        try:
            instance = model.model_validate(raw)
        except PydanticValidationError:
            # The detail is genuinely useful to the caller and contains only
            # what they sent, but it is surfaced by the API layer's own
            # validation error - not smuggled into a policy reason.
            return None
        return dict(instance.model_dump(mode="json"))

    @staticmethod
    def _check_target(
        definition: ToolDefinition, target: TargetFacts
    ) -> PolicyReason | None:
        """Whether the named target is one this tool may act on."""
        if target.kind is not definition.target_type:
            return PolicyReason.TARGET_INVALID
        if definition.target_type is TargetKind.NONE:
            return None
        if definition.target_type is TargetKind.EXTERNAL_REF:
            return None if target.external_ref else PolicyReason.TARGET_INVALID
        if not target.exists or target.asset_id is None:
            return PolicyReason.TARGET_INVALID
        # A retired asset is a real row that must not be acted on. Distinct
        # from "out of scope" because the operator response differs: one is a
        # wrong target, the other is a stale one.
        if target.lifecycle_state and target.lifecycle_state != "ACTIVE":
            return PolicyReason.TARGET_RETIRED
        if target.asset_type not in definition.target_asset_types:
            return PolicyReason.TARGET_OUT_OF_SCOPE
        return None

    @staticmethod
    def _deny(context: PolicyContext, reason: PolicyReason) -> PolicyDecision:
        """Build a denial that still carries the tool's policy, for the record.

        The snapshot fields are populated even on a denial so the invocation
        row is a complete statement of what was refused and under what rules -
        an audit answer of "denied, but we no longer know what the tool
        required at the time" is not an answer.
        """
        definition = context.definition
        if definition is None:
            # Nothing is bound, so there is no declared policy to record.
            # PROHIBITED is the honest class for a capability ACOP cannot
            # execute, and ``reason`` carries the real explanation.
            return PolicyDecision(
                allowed=False,
                reason=reason,
                permission_class=PermissionClass.PROHIBITED,
                approval_policy=ApprovalPolicy(),
                validation_required=True,
                required_roles=frozenset(),
                execution_parameters={},
                prohibited=True,
                registry_contract_hash="",
                evaluated_at=context.request_time,
            )
        return PolicyDecision(
            allowed=False,
            reason=reason,
            permission_class=definition.permission_class,
            approval_policy=definition.approval_policy,
            validation_required=definition.validation_required,
            required_roles=frozenset(definition.required_roles),
            execution_parameters=definition.execution_parameters(),
            prohibited=definition.prohibited
            or bool(definition.capability_tags & PROHIBITED_CAPABILITIES),
            registry_contract_hash=definition.contract_hash(),
            evaluated_at=context.request_time,
        )


__all__ = [
    "PolicyContext",
    "PolicyDecision",
    "TargetFacts",
    "ToolPolicyEngine",
]
