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

    def test_cluster_is_an_asset_type(self) -> None:
        """Milestone 5. A Proxmox cluster needs a type of its own.

        Without it the only ``MEMBER_OF`` targets are ``VLAN`` and ``DEVICE``,
        so a cluster would have to be stored as a device - a false type at the
        root of the graph, inherited by every node edge and every cluster-level
        fact hanging off it.
        """
        assert AssetType.CLUSTER in AssetType
        assert AssetType.CLUSTER.value == "CLUSTER"


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

    def test_the_stale_proxmox_namespaces_are_gone(self) -> None:
        """``proxmox:vmid`` and ``proxmox:cluster`` were removed in Milestone 5.

        Both were registered non-unique, which meant neither participated in
        identity resolution at all: a guest without a SMBIOS UUID matched
        nothing and was created fresh on every sweep. The instance-scoped
        replacements are unique, so they correlate.
        """
        assert "proxmox:vmid" not in IDENTIFIER_NAMESPACES
        assert "proxmox:cluster" not in IDENTIFIER_NAMESPACES

    def test_a_stale_namespace_still_normalises_but_correlates_nothing(self) -> None:
        """Removing a registration does not reject the value, and must not.

        An unregistered namespace is accepted and forced non-unique, so an
        identifier row written under the old name before this change keeps
        working and simply stops being a correlator - which is what it already
        was. Nothing needs migrating.
        """
        assert not normalise(
            IdentifierInput(namespace="proxmox:vmid", value="200")
        ).unique_in_namespace

    @pytest.mark.parametrize(
        "namespace",
        [
            "proxmox:instance",
            "proxmox:node",
            "proxmox:guest",
            "proxmox:storage",
            "proxmox:uuid",
        ],
    )
    def test_every_proxmox_namespace_is_unique(self, namespace: str) -> None:
        """All five correlate, because all five values are already scoped.

        Each value carries the ACOP-owned instance id (or, for
        ``proxmox:uuid``, is globally unique on its own), so it names one
        object in one installation and can belong to at most one **live**
        asset. Uniqueness here is what puts ``unique_in_namespace = true`` on
        the row, which is what brings the partial unique index into play -
        without it the namespace would not participate in identity resolution
        at all.
        """
        assert IDENTIFIER_NAMESPACES[namespace].unique is True
        assert normalise(
            IdentifierInput(namespace=namespace, value="homelab-pve/100")
        ).unique_in_namespace

    def test_uniqueness_is_scoped_to_live_rows(self) -> None:
        """Unique does not mean "used once, ever".

        The index is partial - ``WHERE retired_at IS NULL AND
        unique_in_namespace`` - so retiring an identifier frees its value. That
        is exactly what makes legitimate VMID reuse representable without a
        merge: the old asset keeps its history, its identifier is retired, and
        the reused value resolves to nothing and creates a new asset. The
        database half of this is proved in
        ``tests/integration/test_cmdb_constraints.py``.
        """
        spec = IDENTIFIER_NAMESPACES["proxmox:guest"]
        assert spec.unique is True
        assert "vmid" in spec.note or "VMID" in spec.note

    def test_an_instance_scoped_value_survives_normalisation_intact(self) -> None:
        """The separator must not be eaten.

        These values are composites - ``<instance>/<vmid>`` - and the default
        normaliser only trims and lowercases. A ``digits`` normaliser, which
        the old ``proxmox:vmid`` used, would strip the instance and the slash
        and collapse every instance into one namespace.
        """
        assert (
            normalise(
                IdentifierInput(namespace="proxmox:guest", value=" HomeLab-PVE/100 ")
            ).value_normalized
            == "homelab-pve/100"
        )

    def test_the_cluster_name_is_not_an_identity(self) -> None:
        """The reason ``proxmox:cluster`` is gone rather than merely unused.

        An administrator can rename a Proxmox cluster. Any identifier built on
        that name would change for every asset at once, orphaning all of them.
        The instance id is ACOP-owned precisely so nothing outside ACOP can
        change it.
        """
        assert not any(
            name.startswith("proxmox:") and "cluster" in name
            for name in IDENTIFIER_NAMESPACES
        )

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

    def test_a_host_may_be_a_member_of_a_cluster(self) -> None:
        """Milestone 5's one relationship change."""
        spec = RELATIONSHIP_SPECS[RelationshipType.MEMBER_OF]
        assert spec.permits(AssetType.HOST, AssetType.CLUSTER)

    def test_member_of_was_widened_only_on_the_target_side(self) -> None:
        """A host joins a cluster. A cluster joins nothing.

        Widening the source set as well would let one cluster be declared a
        member of another with nothing to say what that means, and the
        constraint is only worth having while it is narrow.
        """
        spec = RELATIONSHIP_SPECS[RelationshipType.MEMBER_OF]
        assert spec.sources == frozenset(
            {AssetType.SWITCH_PORT, AssetType.HOST, AssetType.VM}
        )
        assert spec.targets == frozenset(
            {AssetType.VLAN, AssetType.DEVICE, AssetType.CLUSTER}
        )
        assert not spec.permits(AssetType.CLUSTER, AssetType.CLUSTER)
        assert not spec.permits(AssetType.CLUSTER, AssetType.DEVICE)

    def test_no_other_relationship_learned_about_clusters(self) -> None:
        """The one change is ``MEMBER_OF`` targets. Nothing else moved.

        A cluster is not an interface holder, not a storage consumer, not a
        run-target and not a dependency endpoint, and none of those edge specs
        may quietly have gained it.
        """
        for kind, spec in RELATIONSHIP_SPECS.items():
            if kind is RelationshipType.MEMBER_OF:
                continue
            assert AssetType.CLUSTER not in spec.sources, kind
            assert AssetType.CLUSTER not in spec.targets, kind

    def test_previously_invalid_combinations_are_still_invalid(self) -> None:
        """The regression guard for a widening that went too far."""
        member_of = RELATIONSHIP_SPECS[RelationshipType.MEMBER_OF]
        assert not member_of.permits(AssetType.SERVICE, AssetType.VLAN)
        assert not member_of.permits(AssetType.HOST, AssetType.SERVICE)

        has_interface = RELATIONSHIP_SPECS[RelationshipType.HAS_INTERFACE]
        assert not has_interface.permits(AssetType.CONTAINER, AssetType.NETWORK_INTERFACE)
        assert not has_interface.permits(AssetType.HOST, AssetType.VM)

        uses_storage = RELATIONSHIP_SPECS[RelationshipType.USES_STORAGE]
        assert not uses_storage.permits(AssetType.CONTAINER, AssetType.STORAGE_DEVICE)

        ip_assigned = RELATIONSHIP_SPECS[RelationshipType.IP_ASSIGNED_TO]
        assert not ip_assigned.permits(AssetType.NETWORK_INTERFACE, AssetType.IP_ADDRESS)

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
