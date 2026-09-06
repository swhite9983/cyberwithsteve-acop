"""The tool declaration contract and its fourteen import-time rules.

A tool is a frozen dataclass in reviewed Python. Not a row, not a config file,
not a YAML document loaded at startup. The reason is stated once here because
it governs the whole milestone:

*If a tool definition were data, then a SQL injection, a compromised admin
credential, a careless migration or a restored backup could mint a capability.*
As code, creating a capability requires a commit, a review and a deploy, and
``git log src/acop/tools/catalog/`` is the complete capability change history.

**The fourteen rules fail the build, not a request.** They run in
:func:`validate_declaration`, which the registry calls at import. A declaration
that puts a secret-bearing, network-locator or command field into a tool's
input schema does not produce a runtime denial - it produces a process that
will not start. That is the correct severity: rules 9, 10 and 11 are what make
the "no generic execution surface" claim true by construction rather than by
vigilance, and they are also what make the execution envelope's digest
recomputable, since the canonical input is then safe to persist verbatim.

**What is *not* here.** No default that weakens a class. Every class-derived
requirement is checked, never supplied: a Class 2 tool that forgets
``approval_required`` is rejected rather than quietly corrected, because a
silent correction trains people to omit the field and hides the one case where
the omission was a mistake in the other direction.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from acop.models.knowledge_vocabulary import Sensitivity
from acop.models.provenance import APPROVAL_REQUIRED_CLASSES, PermissionClass
from acop.models.tool_vocabulary import (
    APPROVAL_AUTHORITY_ROLES,
    CLASS_MINIMUM_ROLES,
    COMMAND_FIELDS,
    NETWORK_LOCATOR_FIELDS,
    PROHIBITED_CAPABILITIES,
    RETRYABLE_CATEGORIES,
    SECRET_FIELD_FRAGMENTS,
    TOOL_NAME_PATTERN,
    TOOL_VERSION_PATTERN,
    IdempotencyKind,
    TargetKind,
    ToolErrorCategory,
    ToolLifecycle,
)
from acop.tools.adapters.base import resolve_adapter
from acop.tools.errors import AdapterBindingError, ToolDeclarationError


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """When the framework may try again.

    Retries are the framework's decision, never the adapter's, and they are
    available only for categories where "it did not happen" is knowable -
    :data:`RETRYABLE_CATEGORIES`. A timeout is deliberately not retryable: a
    request that timed out may still be in flight on the far side.
    """

    max_attempts: int = 1
    backoff_seconds: float = 0.5
    retry_on: frozenset[ToolErrorCategory] = field(
        default_factory=lambda: frozenset(RETRYABLE_CATEGORIES)
    )


@dataclass(frozen=True, slots=True)
class ApprovalPolicy:
    """Who must agree before this tool runs, and for how long that holds.

    Class 3 strength is expressed here rather than by demanding a higher role.
    Two-person control is ``min_approvals=2`` with
    ``distinct_approvers_required``; urgency pressure is bounded by a shorter
    ``ttl_seconds``. Requiring an admin instead would conflate clearance with
    approval authority, and would mean the only people able to approve
    high-risk work are the people most able to bypass the control.
    """

    approval_required: bool = False
    min_approvals: int = 1
    approver_roles: frozenset[str] = field(
        default_factory=lambda: frozenset(role.value for role in APPROVAL_AUTHORITY_ROLES)
    )
    distinct_approvers_required: bool = False
    ttl_seconds: int = 3600
    #: Environments in which this tool may be invoked at all. Empty means any.
    allowed_environments: frozenset[str] = field(default_factory=frozenset)
    #: Declarative only. Whether a self-approval is *actually* permitted is
    #: derived server-side from configuration and policy together; a tool
    #: cannot grant itself the exemption.
    self_approval_permitted: bool = False

    def as_snapshot(self) -> dict[str, Any]:
        """The policy as applied, for the invocation's frozen record."""
        return {
            "approval_required": self.approval_required,
            "min_approvals": self.min_approvals,
            "approver_roles": sorted(self.approver_roles),
            "distinct_approvers_required": self.distinct_approvers_required,
            "ttl_seconds": self.ttl_seconds,
            "allowed_environments": sorted(self.allowed_environments),
            "self_approval_permitted": self.self_approval_permitted,
        }


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    """One executable capability, declared in code.

    Frozen because a definition that could be mutated after import would make
    the contract hash - and therefore every approval bound to it - a statement
    about a moment rather than about the deployed artifact.
    """

    tool_name: str
    tool_version: str
    permission_class: PermissionClass
    description: str
    input_model: type[BaseModel]
    output_model: type[BaseModel]
    adapter_id: str
    """Never model-visible and never in a descriptor. Knowing which adapter
    backs a tool tells an attacker where to aim."""

    required_roles: frozenset[str]
    target_type: TargetKind = TargetKind.NONE
    target_asset_types: frozenset[str] = field(default_factory=frozenset)
    capability_tags: frozenset[str] = field(default_factory=frozenset)
    prohibited: bool = False
    approval_policy: ApprovalPolicy = field(default_factory=ApprovalPolicy)
    validation_required: bool = False
    validation_delay_seconds: float = 0.0
    timeout_seconds: float = 30.0
    idempotency: IdempotencyKind = IdempotencyKind.NATURALLY_IDEMPOTENT
    adapter_idempotent: bool = True
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    sensitivity: Sensitivity = Sensitivity.INTERNAL
    #: Field names permitted in the sanitized output. Empty means "the output
    #: model's own fields", which is the normal case.
    output_allow_list: frozenset[str] = field(default_factory=frozenset)
    lifecycle_default: ToolLifecycle = ToolLifecycle.ACTIVE
    #: The single escape hatch for rule 6, so the prohibition mechanism itself
    #: can be tested. Exactly one catalog tool may set it, and a unit test
    #: asserts that.
    allow_registration_for_testing: bool = False

    @property
    def key(self) -> tuple[str, str]:
        """``(tool_name, tool_version)`` - the registry key."""
        return (self.tool_name, self.tool_version)

    @property
    def qualified_name(self) -> str:
        return f"{self.tool_name}@{self.tool_version}"

    def effective_output_fields(self) -> frozenset[str]:
        """The fields the sanitizer will keep."""
        if self.output_allow_list:
            return self.output_allow_list
        return frozenset(self.output_model.model_fields)

    def contract_hash(self) -> str:
        """SHA-256 over the security-significant declaration.

        Covers everything that changes what an approval means - identity,
        class, roles, schemas, approval and execution policy - and deliberately
        excludes ``description`` and ``lifecycle_default``, which are prose and
        an operational hint. Editing a Class 2 tool's schema in place therefore
        fails startup, because every prior approval was bound to an envelope
        computed under the old rules.
        """
        material = {
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "permission_class": self.permission_class.value,
            "adapter_id": self.adapter_id,
            "required_roles": sorted(self.required_roles),
            "target_type": self.target_type.value,
            "target_asset_types": sorted(self.target_asset_types),
            "capability_tags": sorted(self.capability_tags),
            "prohibited": self.prohibited,
            "approval_policy": self.approval_policy.as_snapshot(),
            "validation_required": self.validation_required,
            "timeout_seconds": self.timeout_seconds,
            "idempotency": self.idempotency.value,
            "adapter_idempotent": self.adapter_idempotent,
            "retry_max_attempts": self.retry_policy.max_attempts,
            "sensitivity": self.sensitivity.value,
            "input_schema": self.input_model.model_json_schema(),
            "output_schema": self.output_model.model_json_schema(),
        }
        canonical = json.dumps(
            material, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def execution_parameters(self) -> dict[str, Any]:
        """The execution policy as applied, for the invocation's snapshot."""
        return {
            "timeout_seconds": self.timeout_seconds,
            "idempotency": self.idempotency.value,
            "adapter_idempotent": self.adapter_idempotent,
            "max_attempts": self.retry_policy.max_attempts,
            "backoff_seconds": self.retry_policy.backoff_seconds,
            "retry_on": sorted(c.value for c in self.retry_policy.retry_on),
            "validation_required": self.validation_required,
            "validation_delay_seconds": self.validation_delay_seconds,
        }


# ---------------------------------------------------------------------------
# Import-time validation
# ---------------------------------------------------------------------------


def _schema_field_names(model: type[BaseModel]) -> list[str]:
    """Every field name in a model, including nested models.

    Nested because a forbidden name one level down is exactly as dangerous as
    one at the top: ``credentials.password`` is a password.
    """
    names: list[str] = []
    schema = model.model_json_schema()
    definitions: dict[str, Any] = schema.get("$defs", {})
    for block in (schema, *definitions.values()):
        names.extend(block.get("properties", {}))
    return names


def _forbids_additional_properties(model: type[BaseModel]) -> bool:
    """Whether every object in the schema refuses undeclared keys.

    ``additionalProperties: false`` is what turns an injected ``api_key`` field
    into a *rejection* rather than something merely redacted downstream, so it
    is checked for the whole schema tree, not only the top level.
    """
    schema = model.model_json_schema()
    blocks = [schema, *schema.get("$defs", {}).values()]
    for block in blocks:
        if block.get("type") != "object":
            continue
        if block.get("additionalProperties") is not False:
            return False
    return True


def _check_identity(definition: ToolDefinition) -> None:
    """Rule 14 (name and version shape)."""
    if not TOOL_NAME_PATTERN.match(definition.tool_name):
        raise ToolDeclarationError(
            f"Tool name {definition.tool_name!r} must be three to five "
            "lower-case dotted segments, e.g. 'domain.object.verb'."
        )
    if not TOOL_VERSION_PATTERN.match(definition.tool_version):
        raise ToolDeclarationError(
            f"Tool version {definition.tool_version!r} must be MAJOR.MINOR. "
            "An approval binds to a version, so 'latest' cannot exist."
        )


def _check_class_agreement(definition: ToolDefinition) -> None:
    """Rules 1, 2, 3 and 7 - the class must agree with its own policy."""
    requires_approval = definition.permission_class in APPROVAL_REQUIRED_CLASSES

    if requires_approval and not definition.approval_policy.approval_required:
        raise ToolDeclarationError(
            f"{definition.qualified_name} is {definition.permission_class.value} "
            "and must declare approval_required=True."
        )
    if requires_approval and not definition.validation_required:
        raise ToolDeclarationError(
            f"{definition.qualified_name} is {definition.permission_class.value} "
            "and must declare validation_required=True. A change nobody checks "
            "is a change nobody knows happened."
        )
    minimum = CLASS_MINIMUM_ROLES[definition.permission_class]
    missing = {role.value for role in minimum} - set(definition.required_roles)
    if missing:
        raise ToolDeclarationError(
            f"{definition.qualified_name} must require at least "
            f"{sorted(role.value for role in minimum)} for "
            f"{definition.permission_class.value}; missing {sorted(missing)}."
        )
    # Rule 7, both directions. A Class 0 tool with a target reaches outside
    # ACOP; a non-Class-0 tool without one has nothing to be scoped against.
    is_class_zero = definition.permission_class is PermissionClass.CLASS_0_INFORMATION
    has_no_target = definition.target_type is TargetKind.NONE
    if is_class_zero is not has_no_target:
        raise ToolDeclarationError(
            f"{definition.qualified_name}: target_type NONE and "
            "CLASS_0_INFORMATION must coincide. A Class 0 tool touches nothing "
            "outside ACOP, and any other class must name what it acts on."
        )
    if definition.target_type is TargetKind.ASSET and not definition.target_asset_types:
        raise ToolDeclarationError(
            f"{definition.qualified_name} targets assets but names no asset "
            "types, so no target could ever be refused as out of scope."
        )


def _check_approval_policy(definition: ToolDefinition) -> None:
    """Rules 4 and 5 - who may approve, and how many."""
    policy = definition.approval_policy
    if not policy.approval_required:
        return
    authority = {role.value for role in APPROVAL_AUTHORITY_ROLES}
    if not policy.approver_roles:
        raise ToolDeclarationError(
            f"{definition.qualified_name} requires approval but names no "
            "approver roles, so nobody could ever approve it."
        )
    outside = set(policy.approver_roles) - authority
    if outside:
        raise ToolDeclarationError(
            f"{definition.qualified_name} names {sorted(outside)} as approvers. "
            f"Approval authority is limited to {sorted(authority)}."
        )
    if policy.min_approvals < 1:
        raise ToolDeclarationError(
            f"{definition.qualified_name} declares min_approvals="
            f"{policy.min_approvals}; approval requires at least one approver."
        )
    if policy.min_approvals > 1 and not policy.distinct_approvers_required:
        raise ToolDeclarationError(
            f"{definition.qualified_name} declares min_approvals="
            f"{policy.min_approvals} without distinct_approvers_required. "
            "Asking two people and accepting the same person twice is one "
            "approval wearing a disguise."
        )
    if policy.ttl_seconds <= 0:
        raise ToolDeclarationError(
            f"{definition.qualified_name} declares a non-positive approval TTL. "
            "An approval that never expires is a standing grant."
        )


def _check_prohibition(definition: ToolDefinition) -> None:
    """Rule 6 - a prohibited capability category cannot be declared.

    The check is on the *tags*, not on the ``prohibited`` flag, and that is the
    point. A flag denies what someone remembered to flag; a category denies a
    shape of capability, so a future ``proxmox.vm.delete`` whose honest tag set
    includes ``vm.delete`` is refused at import rather than at review.
    """
    overlap = set(definition.capability_tags) & PROHIBITED_CAPABILITIES
    if not overlap:
        return
    if definition.allow_registration_for_testing:
        # The single escape hatch, and it does not make the tool executable:
        # gate 3 still denies every invocation, at both gates.
        return
    raise ToolDeclarationError(
        f"{definition.qualified_name} declares prohibited capability "
        f"{sorted(overlap)}. Prohibited categories are not reachable by role, "
        "approval or configuration. Removing one requires an ADR."
    )


def _check_idempotency(definition: ToolDefinition) -> None:
    """Rule 8 - a non-idempotent tool gets exactly one attempt."""
    if (
        definition.idempotency is IdempotencyKind.NON_IDEMPOTENT
        and definition.retry_policy.max_attempts != 1
    ):
        raise ToolDeclarationError(
            f"{definition.qualified_name} is NON_IDEMPOTENT and declares "
            f"max_attempts={definition.retry_policy.max_attempts}. Retrying it "
            "would act twice."
        )
    if definition.retry_policy.max_attempts < 1:
        raise ToolDeclarationError(
            f"{definition.qualified_name} declares max_attempts="
            f"{definition.retry_policy.max_attempts}; at least one is required."
        )
    unsupported = set(definition.retry_policy.retry_on) - set(RETRYABLE_CATEGORIES)
    if unsupported:
        raise ToolDeclarationError(
            f"{definition.qualified_name} would retry on "
            f"{sorted(c.value for c in unsupported)}. Only categories where "
            "'it did not happen' is knowable may be retried."
        )
    if definition.retry_policy.max_attempts > 1 and not definition.adapter_idempotent:
        raise ToolDeclarationError(
            f"{definition.qualified_name} permits retries but declares its "
            "adapter non-idempotent."
        )


def _check_input_schema(definition: ToolDefinition) -> None:
    """Rules 9, 10, 11 and 12 - the three static proofs, plus closure.

    These are the rules that make the "no generic execution surface" claim
    structural. A schema with no command field cannot express a command; a
    schema with no locator field cannot express a destination; a schema with no
    secret-bearing field makes the persisted canonical input safe to keep,
    which is what makes the envelope digest recomputable at the final gate.
    """
    for name in _schema_field_names(definition.input_model):
        lowered = name.lower()
        if any(fragment in lowered for fragment in SECRET_FIELD_FRAGMENTS):
            raise ToolDeclarationError(
                f"{definition.qualified_name} input field {name!r} names a "
                "secret. Credentials belong to the adapter; a tool that must "
                "change one accepts a reference, never a value."
            )
        if lowered in NETWORK_LOCATOR_FIELDS:
            raise ToolDeclarationError(
                f"{definition.qualified_name} input field {name!r} names a "
                "network locator. Resolving an address is the adapter's job, "
                "from registered identifiers - never from a caller's argument."
            )
        if lowered in COMMAND_FIELDS:
            raise ToolDeclarationError(
                f"{definition.qualified_name} input field {name!r} names a "
                "command. ACOP has no generic execution surface, and this is "
                "one of the three checks that prove it."
            )
    for label, model in (
        ("input_model", definition.input_model),
        ("output_model", definition.output_model),
    ):
        if not _forbids_additional_properties(model):
            raise ToolDeclarationError(
                f"{definition.qualified_name} {label} permits additional "
                "properties. An undeclared field such as 'api_key' must be "
                "rejected, not merely redacted downstream. Set "
                "model_config = ConfigDict(extra='forbid')."
            )


def _check_adapter_binding(definition: ToolDefinition) -> None:
    """Rule 13 - the adapter must resolve to real code.

    Checked at import so a tool that could be requested but never executed is
    a failed build rather than a confusing runtime denial. This is also where
    the code-only nature of adapter resolution is visible: the argument is a
    literal from a reviewed declaration.
    """
    if resolve_adapter(definition.adapter_id) is None:
        raise AdapterBindingError(
            f"{definition.qualified_name} names adapter "
            f"{definition.adapter_id!r}, which no module registers. Import the "
            "adapter module before the catalog."
        )


def validate_declaration(definition: ToolDefinition) -> None:
    """Apply all fourteen rules. Raises on the first violation.

    Rule 14's uniqueness half lives in the registry, which is the only thing
    that can see more than one declaration at a time.
    """
    _check_identity(definition)
    _check_class_agreement(definition)
    _check_approval_policy(definition)
    _check_prohibition(definition)
    _check_idempotency(definition)
    _check_input_schema(definition)
    _check_adapter_binding(definition)


#: Exposed for ``TestTheRuleCountIsHonest`` in ``tests/unit/test_tool_contract``,
#: which maps every ``_check_*`` function above to the rule numbers it carries
#: and asserts the union is exactly this many, and that each one is still
#: invoked. Without that mapping the constant would sit at 14 while a rule
#: quietly stopped running.
IMPORT_RULE_COUNT = 14

__all__ = [
    "IMPORT_RULE_COUNT",
    "ApprovalPolicy",
    "RetryPolicy",
    "ToolDefinition",
    "validate_declaration",
]
