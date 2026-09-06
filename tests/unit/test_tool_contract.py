"""The fourteen import-time rules, and the invariants that outlive them.

These tests are the reason rules 9, 10 and 11 can be described as making "no
generic execution surface" true by construction. A declaration that puts a
secret-bearing, network-locator or command field into a tool's input schema
does not produce a runtime denial - it fails the build, and this is where that
is proved.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from pydantic import BaseModel, ConfigDict

from acop.auth.principal import Role
from acop.models.provenance import PermissionClass
from acop.models.tool_vocabulary import (
    APPROVAL_AUTHORITY_ROLES,
    IdempotencyKind,
    InvocationState,
    TargetKind,
    ToolErrorCategory,
)
from acop.tools.catalog import CATALOG
from acop.tools.contract import (
    IMPORT_RULE_COUNT,
    ApprovalPolicy,
    RetryPolicy,
    ToolDefinition,
    validate_declaration,
)
from acop.tools.errors import AdapterBindingError, ToolDeclarationError


class Empty(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Loose(BaseModel):
    """Deliberately permits extra keys, which rule 12 forbids."""


def _definition(**overrides: object) -> ToolDefinition:
    base: dict[str, object] = {
        "tool_name": "test.thing.read",
        "tool_version": "1.0",
        "permission_class": PermissionClass.CLASS_1_READ_ONLY,
        "description": "A test tool.",
        "input_model": Empty,
        "output_model": Empty,
        "adapter_id": "test.simulated",
        "required_roles": frozenset({Role.VIEWER.value}),
        "target_type": TargetKind.ASSET,
        "target_asset_types": frozenset({"HOST"}),
    }
    base.update(overrides)
    return ToolDefinition(**base)  # type: ignore[arg-type]


class TestIdentity:
    def test_a_two_segment_name_is_refused(self) -> None:
        with pytest.raises(ToolDeclarationError, match="dotted segments"):
            validate_declaration(_definition(tool_name="thing.read"))

    def test_a_version_must_be_major_minor(self) -> None:
        """No "latest", and no patch component.

        An approval binds to a version. If a version could be resolved at
        request time, a deploy would silently change which code a queued
        approval refers to.
        """
        with pytest.raises(ToolDeclarationError, match=r"MAJOR\.MINOR"):
            validate_declaration(_definition(tool_version="latest"))


class TestClassAgreement:
    def test_a_change_class_must_require_approval(self) -> None:
        with pytest.raises(ToolDeclarationError, match="approval_required"):
            validate_declaration(
                _definition(
                    permission_class=PermissionClass.CLASS_2_LOW_RISK_CHANGE,
                    required_roles=frozenset({Role.OPERATOR.value}),
                    validation_required=True,
                )
            )

    def test_a_change_class_must_require_validation(self) -> None:
        with pytest.raises(ToolDeclarationError, match="validation_required"):
            validate_declaration(
                _definition(
                    permission_class=PermissionClass.CLASS_2_LOW_RISK_CHANGE,
                    required_roles=frozenset({Role.OPERATOR.value}),
                    approval_policy=ApprovalPolicy(approval_required=True),
                )
            )

    def test_a_tool_may_not_declare_below_its_class_minimum(self) -> None:
        with pytest.raises(ToolDeclarationError, match="must require at least"):
            validate_declaration(
                _definition(
                    permission_class=PermissionClass.CLASS_2_LOW_RISK_CHANGE,
                    required_roles=frozenset({Role.VIEWER.value}),
                    approval_policy=ApprovalPolicy(approval_required=True),
                    validation_required=True,
                )
            )

    def test_class_zero_and_no_target_must_coincide(self) -> None:
        """Both directions, because both are errors.

        A Class 0 tool with a target reaches outside ACOP; a non-Class-0 tool
        without one has nothing to be scoped against.
        """
        with pytest.raises(ToolDeclarationError, match="must coincide"):
            validate_declaration(
                _definition(permission_class=PermissionClass.CLASS_0_INFORMATION)
            )
        with pytest.raises(ToolDeclarationError, match="must coincide"):
            validate_declaration(
                _definition(target_type=TargetKind.NONE, target_asset_types=frozenset())
            )

    def test_an_asset_tool_must_name_the_types_it_accepts(self) -> None:
        with pytest.raises(ToolDeclarationError, match="names no asset"):
            validate_declaration(_definition(target_asset_types=frozenset()))


class TestApprovalPolicy:
    def test_only_approval_authority_roles_may_approve(self) -> None:
        with pytest.raises(ToolDeclarationError, match="Approval authority"):
            validate_declaration(
                _definition(
                    permission_class=PermissionClass.CLASS_2_LOW_RISK_CHANGE,
                    required_roles=frozenset({Role.OPERATOR.value}),
                    validation_required=True,
                    approval_policy=ApprovalPolicy(
                        approval_required=True,
                        approver_roles=frozenset({Role.OPERATOR.value}),
                    ),
                )
            )

    def test_two_approvals_require_distinct_approvers(self) -> None:
        """Asking two people and accepting one twice is one approval."""
        with pytest.raises(ToolDeclarationError, match="wearing a disguise"):
            validate_declaration(
                _definition(
                    permission_class=PermissionClass.CLASS_3_HIGH_RISK_CHANGE,
                    required_roles=frozenset({Role.OPERATOR.value}),
                    validation_required=True,
                    approval_policy=ApprovalPolicy(
                        approval_required=True,
                        min_approvals=2,
                        distinct_approvers_required=False,
                    ),
                )
            )

    def test_an_approval_must_expire(self) -> None:
        with pytest.raises(ToolDeclarationError, match="standing grant"):
            validate_declaration(
                _definition(
                    permission_class=PermissionClass.CLASS_2_LOW_RISK_CHANGE,
                    required_roles=frozenset({Role.OPERATOR.value}),
                    validation_required=True,
                    approval_policy=ApprovalPolicy(approval_required=True, ttl_seconds=0),
                )
            )


class TestProhibition:
    def test_a_prohibited_capability_tag_fails_the_build(self) -> None:
        """The check is on the tag, not on the flag.

        A future ``proxmox.vm.delete`` whose honest tag set includes
        ``vm.delete`` is refused at import rather than at review.
        """
        with pytest.raises(ToolDeclarationError, match="prohibited capability"):
            validate_declaration(_definition(capability_tags=frozenset({"vm.delete"})))

    def test_the_testing_marker_permits_registration_but_nothing_else(self) -> None:
        validate_declaration(
            _definition(
                capability_tags=frozenset({"arbitrary.shell"}),
                allow_registration_for_testing=True,
            )
        )

    def test_exactly_one_catalog_tool_carries_the_testing_marker(self) -> None:
        marked = [d for d in CATALOG if d.allow_registration_for_testing]
        assert len(marked) == 1
        assert marked[0].tool_name == "test.prohibited.shell_exec"


class TestIdempotency:
    def test_a_non_idempotent_tool_gets_one_attempt(self) -> None:
        with pytest.raises(ToolDeclarationError, match="act twice"):
            validate_declaration(
                _definition(
                    idempotency=IdempotencyKind.NON_IDEMPOTENT,
                    retry_policy=RetryPolicy(max_attempts=2),
                )
            )

    def test_only_knowably_safe_categories_may_be_retried(self) -> None:
        """A timeout is never retryable: the far side may still be acting."""
        with pytest.raises(ToolDeclarationError, match="knowable"):
            validate_declaration(
                _definition(
                    retry_policy=RetryPolicy(
                        max_attempts=2,
                        retry_on=frozenset({ToolErrorCategory.TIMEOUT}),
                    )
                )
            )

    def test_retries_require_an_idempotent_adapter(self) -> None:
        with pytest.raises(ToolDeclarationError, match="non-idempotent"):
            validate_declaration(
                _definition(
                    adapter_idempotent=False,
                    retry_policy=RetryPolicy(max_attempts=3),
                )
            )


class TestInputSchema:
    """Rules 9, 10, 11 and 12 - the three static proofs, plus closure."""

    @pytest.mark.parametrize(
        "field", ["password", "api_key", "ssh_key", "private_key", "auth_token"]
    )
    def test_a_secret_bearing_field_fails_the_build(self, field: str) -> None:
        model = type(
            "Secretive",
            (BaseModel,),
            {
                "__annotations__": {field: str},
                "model_config": ConfigDict(extra="forbid"),
            },
        )
        with pytest.raises(ToolDeclarationError, match="names a secret"):
            validate_declaration(_definition(input_model=model))

    @pytest.mark.parametrize("field", ["host", "ip_address", "url", "connection_string"])
    def test_a_network_locator_field_fails_the_build(self, field: str) -> None:
        model = type(
            "Addressed",
            (BaseModel,),
            {
                "__annotations__": {field: str},
                "model_config": ConfigDict(extra="forbid"),
            },
        )
        with pytest.raises(ToolDeclarationError, match="network locator"):
            validate_declaration(_definition(input_model=model))

    @pytest.mark.parametrize("field", ["command", "script", "shell", "sql", "raw"])
    def test_a_command_field_fails_the_build(self, field: str) -> None:
        model = type(
            "Commanding",
            (BaseModel,),
            {
                "__annotations__": {field: str},
                "model_config": ConfigDict(extra="forbid"),
            },
        )
        with pytest.raises(ToolDeclarationError, match="names a command"):
            validate_declaration(_definition(input_model=model))

    def test_a_forbidden_name_nested_one_level_down_is_still_caught(self) -> None:
        """``credentials.password`` is a password.

        A rule that only inspected top-level fields would be trivially evaded
        by wrapping the field in an object.
        """
        inner = type(
            "Inner",
            (BaseModel,),
            {
                "__annotations__": {"password": str},
                "model_config": ConfigDict(extra="forbid"),
            },
        )
        outer = type(
            "Outer",
            (BaseModel,),
            {
                "__annotations__": {"credentials": inner},
                "model_config": ConfigDict(extra="forbid"),
            },
        )
        with pytest.raises(ToolDeclarationError, match="names a secret"):
            validate_declaration(_definition(input_model=outer))

    def test_a_schema_must_forbid_additional_properties(self) -> None:
        """Rejection, not redaction.

        An undeclared ``api_key`` must be refused outright. A model that
        silently drops unknown keys would let an injected payload through and
        leave no trace that anything was attempted.
        """
        with pytest.raises(ToolDeclarationError, match="additional"):
            validate_declaration(_definition(input_model=Loose))


class TestAdapterBinding:
    def test_an_unbound_adapter_fails_the_build(self) -> None:
        with pytest.raises(AdapterBindingError, match="no module registers"):
            validate_declaration(_definition(adapter_id="does.not.exist"))


class TestCatalogInvariants:
    def test_every_declared_tool_passes_every_rule(self) -> None:
        for definition in CATALOG:
            validate_declaration(definition)

    def test_no_catalog_tool_names_admin_as_a_clearance_for_class_three(self) -> None:
        """Class 3 strength is policy, not role inflation.

        The R2 correction: an operator may *request* a high-risk change and an
        approver may approve it. Requiring an admin would mean the only people
        able to approve high-risk work are the people most able to bypass the
        control.
        """
        for definition in CATALOG:
            if definition.permission_class is PermissionClass.CLASS_3_HIGH_RISK_CHANGE:
                assert Role.ADMIN.value not in definition.required_roles

    def test_approval_authority_is_the_same_for_every_class(self) -> None:
        authority = {role.value for role in APPROVAL_AUTHORITY_ROLES}
        for definition in CATALOG:
            if definition.approval_policy.approval_required:
                assert set(definition.approval_policy.approver_roles) <= authority

    def test_the_contract_hash_is_stable_across_calls(self) -> None:
        for definition in CATALOG:
            assert definition.contract_hash() == definition.contract_hash()

    def test_every_contract_hash_is_distinct(self) -> None:
        digests = {d.contract_hash() for d in CATALOG}
        assert len(digests) == len(CATALOG)


#: Which check function carries which of the fourteen rules, read from the
#: functions' own docstrings. This is the mapping ``IMPORT_RULE_COUNT`` is a
#: summary of, and writing it out is what makes the count assertion mean
#: something: a bare ``assert IMPORT_RULE_COUNT == 14`` would pass while a rule
#: was silently dropped from ``validate_declaration``.
RULES_BY_CHECK: dict[str, frozenset[int]] = {
    "_check_identity": frozenset({14}),
    "_check_class_agreement": frozenset({1, 2, 3, 7}),
    "_check_approval_policy": frozenset({4, 5}),
    "_check_prohibition": frozenset({6}),
    "_check_idempotency": frozenset({8}),
    "_check_input_schema": frozenset({9, 10, 11, 12}),
    "_check_adapter_binding": frozenset({13}),
}


class TestTheRuleCountIsHonest:
    """``IMPORT_RULE_COUNT`` claims fourteen rules; these prove there are.

    The count is quoted in the module docstring and in the design, so it is
    exactly the kind of number that stays at 14 while the code drifts to
    thirteen. Both halves are checked: that every rule number one to fourteen
    is claimed by some check, and that every check claimed is actually invoked.
    """

    def test_the_checks_account_for_every_rule_exactly_once(self) -> None:
        covered = [rule for rules in RULES_BY_CHECK.values() for rule in sorted(rules)]
        assert sorted(covered) == list(range(1, IMPORT_RULE_COUNT + 1))
        assert len(covered) == len(set(covered)), "a rule is claimed by two checks"

    def test_validate_declaration_invokes_every_check(self) -> None:
        """Asserted against the AST, not by reading.

        A check function that still exists but is no longer called from
        ``validate_declaration`` is a rule that no longer runs, and it would
        look identical to a working one from the outside.
        """
        source = Path("src/acop/tools/contract.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        function = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "validate_declaration"
        )
        called = {
            node.func.id
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id.startswith("_check_")
        }
        assert called == set(RULES_BY_CHECK)

    def test_no_check_function_exists_that_no_rule_claims(self) -> None:
        """The other direction: a new check must be a documented rule.

        Adding ``_check_something`` without raising the count would leave the
        module docstring and the design describing a system with fewer rules
        than the build enforces.
        """
        source = Path("src/acop/tools/contract.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        defined = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name.startswith("_check_")
        }
        assert defined == set(RULES_BY_CHECK)


class TestNoSecondPermissionEnum:
    def test_the_vocabulary_module_declares_no_parallel_permission_enum(self) -> None:
        """M1's enum is the only one.

        ``audit_event.permission_class`` has carried these values since the
        first migration. A second enum would orphan every audit row written
        since M1.
        """
        import acop.models.tool_vocabulary as vocab

        members = {member.name for member in PermissionClass}
        for name in dir(vocab):
            value = getattr(vocab, name)
            if not isinstance(value, type) or not issubclass(
                value, InvocationState.__base__
            ):
                continue
            if value is PermissionClass:
                continue
            assert not members & {m.name for m in value}, name
