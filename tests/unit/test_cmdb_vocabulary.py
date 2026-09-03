"""Vocabulary, registries and provenance rules."""

from __future__ import annotations

import pytest

from acop.core.exceptions import ConflictError, ValidationError
from acop.models.provenance import SourceType, StatementClass, VerificationStatus
from acop.models.vocabulary import (
    IDENTIFIER_NAMESPACES,
    RELATIONSHIP_SPECS,
    RESERVED_RELATIONSHIP_PREDICATES,
    STATEMENT_CLASS_FOR_SOURCE,
    VERIFICATION_STATUS_FOR_SOURCE,
    AssetType,
    AttestationAction,
    FactKind,
    RelationshipType,
)
from acop.schemas.asset import IdentifierInput
from acop.services.identity_resolver import normalise
from acop.services.provenance import (
    attribution_for,
    default_status_for,
    guard_authoritative_transition,
    is_authoritative,
    may_become_authoritative,
    statement_class_for,
)


class TestAssetTypes:
    def test_dependency_is_not_an_asset_type(self) -> None:
        """A dependency is an edge. Modelling it as an asset would create two
        representations of one relationship."""
        assert "DEPENDENCY" not in {item.value for item in AssetType}

    def test_mac_address_retained_for_import_fidelity(self) -> None:
        assert AssetType.MAC_ADDRESS in AssetType

    def test_mac_is_also_an_identifier_namespace(self) -> None:
        """The canonical representation, per the approved ruling."""
        assert IDENTIFIER_NAMESPACES["mac"].unique is True


class TestProvenanceDefaults:
    @pytest.mark.parametrize("source", list(SourceType))
    def test_every_source_maps_to_both_defaults(self, source: SourceType) -> None:
        assert source in STATEMENT_CLASS_FOR_SOURCE
        assert source in VERIFICATION_STATUS_FOR_SOURCE

    def test_ai_inference_is_always_an_inference(self) -> None:
        assert statement_class_for(SourceType.AI_INFERENCE) is StatementClass.INFERENCE

    def test_manual_entry_is_unverified_not_verified(self) -> None:
        """Typing a value into ACOP is not checking it against the device."""
        assert default_status_for(SourceType.MANUAL_ENTRY) is (
            VerificationStatus.UNVERIFIED
        )

    def test_live_discovery_is_discovered(self) -> None:
        assert default_status_for(SourceType.LIVE_DISCOVERY) is (
            VerificationStatus.DISCOVERED
        )

    def test_prometheus_is_observed(self) -> None:
        assert default_status_for(SourceType.PROMETHEUS) is VerificationStatus.OBSERVED

    def test_no_source_defaults_to_authoritative(self) -> None:
        """Authority is always an explicit act, never inherited from a source."""
        for status in VERIFICATION_STATUS_FOR_SOURCE.values():
            assert not is_authoritative(status)


class TestAuthorityGuards:
    def test_inference_may_never_become_authoritative(self) -> None:
        assert not may_become_authoritative(
            StatementClass.INFERENCE, SourceType.LIVE_DISCOVERY
        )

    def test_ai_source_may_never_become_authoritative(self) -> None:
        # Either field alone disqualifies, so editing one cannot escape it.
        assert not may_become_authoritative(
            StatementClass.OBSERVATION, SourceType.AI_INFERENCE
        )

    def test_observation_may_become_authoritative(self) -> None:
        assert may_become_authoritative(
            StatementClass.OBSERVATION, SourceType.LIVE_DISCOVERY
        )

    def test_guard_rejects_ai_promotion(self) -> None:
        with pytest.raises(ConflictError):
            guard_authoritative_transition(
                statement_class=StatementClass.INFERENCE,
                source_type=SourceType.AI_INFERENCE,
                target_status=VerificationStatus.VERIFIED,
            )

    def test_guard_rejects_non_authoritative_target(self) -> None:
        with pytest.raises(ValidationError):
            guard_authoritative_transition(
                statement_class=StatementClass.OBSERVATION,
                source_type=SourceType.LIVE_DISCOVERY,
                target_status=VerificationStatus.STALE,
            )


class TestAttribution:
    def test_verify_sets_verifier(self, approver_principal) -> None:
        fields = attribution_for(AttestationAction.VERIFY, approver_principal)
        assert fields["verified_by_subject"] == "acop:user:approver-a"
        assert fields["verification_status"] == VerificationStatus.VERIFIED.value

    def test_revoke_clears_current_attribution(self, approver_principal) -> None:
        """Safe only because fact_attestation keeps the immutable lineage.

        A row left claiming a verifier it no longer has would make the CHECK
        constraint meaningless and mislead anyone reading the row directly.
        """
        fields = attribution_for(AttestationAction.REVOKE, approver_principal)
        assert fields["verified_by_subject"] is None
        assert fields["approved_by_subject"] is None
        assert "verification_status" not in fields


class TestIdentifierNormalisation:
    @pytest.mark.parametrize(
        "raw",
        ["00:00:5E:00:53:01", "00-00-5e-00-53-01", "0000.5e00.5301", "00005E005301"],
    )
    def test_mac_variants_collapse_to_one_value(self, raw: str) -> None:
        assert (
            normalise(IdentifierInput(namespace="mac", value=raw)).value_normalized
            == "00005e005301"
        )

    def test_fqdn_trailing_dot_is_stripped(self) -> None:
        assert (
            normalise(
                IdentifierInput(namespace="fqdn", value="Host.Example.INVALID.")
            ).value_normalized
            == "host.example.invalid"
        )

    def test_serial_is_uppercased(self) -> None:
        assert (
            normalise(
                IdentifierInput(namespace="serial", value=" docserial0001 ")
            ).value_normalized
            == "DOCSERIAL0001"
        )

    def test_proxmox_vmid_is_never_unique(self) -> None:
        """VMIDs are reissued after deletion - the most dangerous correlator."""
        assert not normalise(
            IdentifierInput(namespace="proxmox:vmid", value="200")
        ).unique_in_namespace

    def test_hostname_is_never_unique(self) -> None:
        assert not normalise(
            IdentifierInput(namespace="hostname", value="web01")
        ).unique_in_namespace

    def test_unregistered_namespace_is_never_unique(self) -> None:
        """An unknown source must not be able to collapse two assets."""
        assert not normalise(
            IdentifierInput(namespace="unknown:thing", value="x")
        ).unique_in_namespace

    def test_namespace_format_is_validated(self) -> None:
        with pytest.raises(ValueError, match="lowercase segments"):
            IdentifierInput(namespace="Bad Namespace!", value="x")


class TestRelationshipRegistry:
    def test_every_type_has_a_spec(self) -> None:
        for item in RelationshipType:
            assert item in RELATIONSHIP_SPECS

    def test_connected_to_is_the_only_symmetric_type(self) -> None:
        symmetric = {t for t, s in RELATIONSHIP_SPECS.items() if s.symmetric}
        assert symmetric == {RelationshipType.CONNECTED_TO}

    def test_runs_on_reads_back_as_hosts(self) -> None:
        assert RELATIONSHIP_SPECS[RelationshipType.RUNS_ON].inverse_label == "HOSTS"

    def test_endpoint_types_are_enforced(self) -> None:
        spec = RELATIONSHIP_SPECS[RelationshipType.RUNS_ON]
        assert spec.permits(AssetType.VM, AssetType.HOST)
        assert not spec.permits(AssetType.VLAN, AssetType.GPU)

    def test_relationship_names_are_reserved_predicates(self) -> None:
        """Storing an edge as a fact too would be silent dual representation."""
        assert "runs_on" in RESERVED_RELATIONSHIP_PREDICATES
        assert "depends_on" in RESERVED_RELATIONSHIP_PREDICATES


class TestFactKind:
    def test_two_independent_axes(self) -> None:
        assert {item.value for item in FactKind} == {
            "OBSERVED_STATE",
            "DESIRED_STATE",
        }
