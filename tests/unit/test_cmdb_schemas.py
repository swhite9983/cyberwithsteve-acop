"""CMDB wire-schema validation.

The rules here mirror the database CHECKs so a malformed request fails at the
boundary with a readable message rather than as an IntegrityError.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError as PydanticValidationError

from acop.models.provenance import SourceType
from acop.models.vocabulary import AssetType, FactKind, LifecycleState, ValueType
from acop.schemas.asset import AssetCreate, AssetUpdate
from acop.schemas.fact import FactAssert


def _fact(**overrides: object) -> FactAssert:
    payload: dict[str, object] = {
        "predicate": "memory.total_bytes",
        "value_type": ValueType.NUMBER,
        "value_number": 12884901888,
        "source_type": SourceType.LIVE_DISCOVERY,
        "source_id": "proxmox:pve-doc-01",
    }
    payload.update(overrides)
    return FactAssert(**payload)  # type: ignore[arg-type]


class TestTypedValues:
    def test_exactly_one_value_column(self) -> None:
        assert _fact().value_number == 12884901888

    def test_two_values_rejected(self) -> None:
        with pytest.raises(PydanticValidationError, match="exactly one value column"):
            _fact(value_text="also set")

    def test_no_value_rejected(self) -> None:
        with pytest.raises(PydanticValidationError, match="exactly one value column"):
            FactAssert(
                predicate="memory.total_bytes",
                value_type=ValueType.NUMBER,
                source_type=SourceType.LIVE_DISCOVERY,
                source_id="s",
            )

    def test_value_type_must_match_populated_column(self) -> None:
        with pytest.raises(PydanticValidationError, match="populated column"):
            FactAssert(
                predicate="os.name",
                value_type=ValueType.NUMBER,
                value_text="ubuntu",
                source_type=SourceType.LIVE_DISCOVERY,
                source_id="s",
            )


class TestPredicateRules:
    def test_uppercase_predicate_is_lowercased(self) -> None:
        assert _fact(predicate="Memory.Total_Bytes").predicate == "memory.total_bytes"

    def test_malformed_predicate_rejected(self) -> None:
        with pytest.raises(PydanticValidationError, match="lowercase dotted"):
            _fact(predicate="Memory Total Bytes")

    def test_relationship_name_as_predicate_rejected(self) -> None:
        """Dual representation of an edge is silent corruption."""
        with pytest.raises(PydanticValidationError, match="relationship type"):
            _fact(
                predicate="runs_on",
                value_type=ValueType.TEXT,
                value_number=None,
                value_text="host-a",
            )

    def test_known_predicate_with_wrong_type_rejected(self) -> None:
        with pytest.raises(PydanticValidationError, match="registered as"):
            FactAssert(
                predicate="memory.total_bytes",
                value_type=ValueType.TEXT,
                value_text="lots",
                source_type=SourceType.LIVE_DISCOVERY,
                source_id="s",
            )

    def test_unknown_predicate_is_accepted(self) -> None:
        """Blocking discovery behind a code change for every new field would
        make Milestone 5 unworkable."""
        assert (
            _fact(
                predicate="proxmox.ballooning_enabled",
                value_type=ValueType.BOOL,
                value_number=None,
                value_bool=True,
            ).predicate
            == "proxmox.ballooning_enabled"
        )


class TestCallerCannotAssertTrust:
    def test_verification_status_is_not_an_input_field(self) -> None:
        assert "verification_status" not in FactAssert.model_fields

    def test_statement_class_is_not_an_input_field(self) -> None:
        assert "statement_class" not in FactAssert.model_fields

    def test_extra_fields_are_forbidden(self) -> None:
        with pytest.raises(PydanticValidationError):
            _fact(verification_status="VERIFIED")

    def test_desired_state_cannot_be_plainly_asserted(self) -> None:
        with pytest.raises(PydanticValidationError, match="desired state"):
            _fact(fact_kind=FactKind.DESIRED_STATE)


class TestAssetSchemas:
    def test_asset_type_is_not_updatable(self) -> None:
        """Type is identity, not metadata."""
        assert "asset_type" not in AssetUpdate.model_fields

    def test_cannot_create_already_retired(self) -> None:
        with pytest.raises(PydanticValidationError, match="already retired"):
            AssetCreate(
                asset_type=AssetType.VM,
                display_name="vm-doc-200",
                lifecycle_state=LifecycleState.RETIRED,
            )

    def test_retirement_is_not_a_plain_field_update(self) -> None:
        with pytest.raises(PydanticValidationError, match="retire"):
            AssetUpdate(lifecycle_state=LifecycleState.RETIRED)

    def test_inactive_is_a_normal_update(self) -> None:
        assert AssetUpdate(lifecycle_state=LifecycleState.INACTIVE) is not None
