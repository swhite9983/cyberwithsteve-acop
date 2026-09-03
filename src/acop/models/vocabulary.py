"""CMDB vocabulary and registries.

Enumerated values plus the three code-level registries that let the CMDB accept
new asset types, identifier namespaces and relationship types without a
migration. Following ADR-0004, every enum is persisted as ``VARCHAR``; nothing
here creates a PostgreSQL ``ENUM`` type.

The registries are deliberately code rather than tables: a relationship type or
identifier namespace is part of ACOP's model of the world, not user-editable
data, and making them tables would turn adding one into a migration.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum

from acop.models.provenance import SourceType, StatementClass, VerificationStatus

# ---------------------------------------------------------------------------
# Asset vocabulary
# ---------------------------------------------------------------------------


class AssetType(StrEnum):
    """Kinds of thing the CMDB can hold.

    ``DEPENDENCY`` is deliberately absent: a dependency is an edge, modelled as
    the ``DEPENDS_ON`` relationship. Instantiating it as an asset would create
    two representations of one edge.

    ``MAC_ADDRESS`` is retained for import fidelity but is not the canonical
    representation - a MAC is the durable identity of a NIC, so it lives in the
    ``mac`` identifier namespace. See ``DISCOURAGED_ASSET_TYPES``.
    """

    DEVICE = "DEVICE"
    HOST = "HOST"
    VM = "VM"
    CONTAINER = "CONTAINER"
    NETWORK_INTERFACE = "NETWORK_INTERFACE"
    SWITCH_PORT = "SWITCH_PORT"
    VLAN = "VLAN"
    IP_ADDRESS = "IP_ADDRESS"
    MAC_ADDRESS = "MAC_ADDRESS"
    SERVICE = "SERVICE"
    STORAGE_DEVICE = "STORAGE_DEVICE"
    GPU = "GPU"
    APPLICATION = "APPLICATION"
    USER = "USER"
    LOCATION = "LOCATION"


#: Types that are accepted but are not the canonical representation. The
#: service warns rather than rejects, so an import using one still succeeds.
DISCOURAGED_ASSET_TYPES: dict[AssetType, str] = {
    AssetType.MAC_ADDRESS: (
        "A MAC address is the identity of a network interface. Prefer attaching "
        "it to a NETWORK_INTERFACE asset in the 'mac' identifier namespace."
    ),
}


class LifecycleState(StrEnum):
    """Where an asset is in its life.

    Deliberately absent: any "not seen recently" state. That is derived from
    ``last_seen_at`` against a staleness window, not a state a human sets - a
    collector outage must never rewrite the inventory.
    """

    PLANNED = "PLANNED"
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    RETIRED = "RETIRED"
    MERGED = "MERGED"


#: States in which an asset no longer represents something live. Facts and
#: relationships are closed when an asset enters one of these.
TERMINAL_LIFECYCLE_STATES: frozenset[LifecycleState] = frozenset(
    {LifecycleState.RETIRED, LifecycleState.MERGED}
)


# ---------------------------------------------------------------------------
# Fact vocabulary
# ---------------------------------------------------------------------------


class FactKind(StrEnum):
    """Which of the two independent axes a fact sits on.

    ``verification_status`` answers *how much do we trust this claim*.
    ``fact_kind`` answers *is this what is, or what should be*. Collapsing them
    makes configuration drift undetectable, because nothing distinguishes
    "Gi1/0/24 should be VLAN 400" from "Gi1/0/24 is VLAN 400".
    """

    OBSERVED_STATE = "OBSERVED_STATE"
    DESIRED_STATE = "DESIRED_STATE"


class ValueType(StrEnum):
    """Discriminator naming which typed value column carries the value."""

    TEXT = "TEXT"
    NUMBER = "NUMBER"
    BOOL = "BOOL"
    TIMESTAMP = "TIMESTAMP"
    JSON = "JSON"
    ASSET_REF = "ASSET_REF"


#: Maps the discriminator to the column that must be populated. The database
#: enforces the same rule; this is the application-side single definition.
VALUE_COLUMNS: dict[ValueType, str] = {
    ValueType.TEXT: "value_text",
    ValueType.NUMBER: "value_number",
    ValueType.BOOL: "value_bool",
    ValueType.TIMESTAMP: "value_timestamp",
    ValueType.JSON: "value_json",
    ValueType.ASSET_REF: "value_asset_id",
}


class AttestationAction(StrEnum):
    """A trust transition recorded in ``fact_attestation``."""

    VERIFY = "VERIFY"
    APPROVE = "APPROVE"
    REVOKE = "REVOKE"


#: Predicate names must be lowercase dotted segments. Enforced by a database
#: CHECK as well - retrofitting a naming convention after collectors have
#: written history means rewriting keys.
PREDICATE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_]*(\.[a-z0-9_]+)*$")

#: Namespace names allow ':' so a source can scope its own ids, e.g.
#: 'proxmox:vmid'.
NAMESPACE_PATTERN = re.compile(r"^[a-z0-9]+(:[a-z0-9_-]+)*$")


# ---------------------------------------------------------------------------
# Provenance defaults
# ---------------------------------------------------------------------------

#: Statement class implied by a source. A caller never chooses this: allowing
#: a client to declare its own epistemic class would let a collector label an
#: inference as an observation.
STATEMENT_CLASS_FOR_SOURCE: dict[SourceType, StatementClass] = {
    SourceType.LIVE_DISCOVERY: StatementClass.OBSERVATION,
    SourceType.CONFIG_FILE: StatementClass.OBSERVATION,
    SourceType.PROMETHEUS: StatementClass.OBSERVATION,
    SourceType.MANUAL_ENTRY: StatementClass.FACT,
    SourceType.DOCUMENTATION: StatementClass.FACT,
    SourceType.IMPORT: StatementClass.FACT,
    SourceType.AI_INFERENCE: StatementClass.INFERENCE,
}

#: Verification status implied by a source.
#:
#: MANUAL_ENTRY lands on UNVERIFIED, not VERIFIED, on purpose: typing a value
#: into ACOP is not checking it against the device. Verification is always an
#: explicit act on a specific row, never inherited from who wrote it.
VERIFICATION_STATUS_FOR_SOURCE: dict[SourceType, VerificationStatus] = {
    SourceType.LIVE_DISCOVERY: VerificationStatus.DISCOVERED,
    SourceType.CONFIG_FILE: VerificationStatus.DISCOVERED,
    SourceType.PROMETHEUS: VerificationStatus.OBSERVED,
    SourceType.MANUAL_ENTRY: VerificationStatus.UNVERIFIED,
    SourceType.DOCUMENTATION: VerificationStatus.UNVERIFIED,
    SourceType.IMPORT: VerificationStatus.UNVERIFIED,
    SourceType.AI_INFERENCE: VerificationStatus.UNVERIFIED,
}


# ---------------------------------------------------------------------------
# Identifier namespace registry
# ---------------------------------------------------------------------------


def _normalise_lower(value: str) -> str:
    return value.strip().lower()


def _normalise_upper(value: str) -> str:
    return value.strip().upper()


def _normalise_mac(value: str) -> str:
    return re.sub(r"[:.\-\s]", "", value).lower()


def _normalise_digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def _normalise_hostname(value: str) -> str:
    return value.strip().rstrip(".").lower()


@dataclass(frozen=True, slots=True)
class NamespaceSpec:
    """How one identifier namespace behaves."""

    name: str
    unique: bool
    """Whether a value in this namespace identifies at most one live asset.

    Written onto each row as ``unique_in_namespace`` so that a single partial
    unique index can enforce global uniqueness for the namespaces that have it
    while leaving the ones that genuinely do not - hostnames, IPs - free.
    """

    note: str = ""
    _normaliser: str = "lower"

    def normalise(self, value: str) -> str:
        return _NORMALISERS[self._normaliser](value)


_NORMALISERS = {
    "lower": _normalise_lower,
    "upper": _normalise_upper,
    "mac": _normalise_mac,
    "digits": _normalise_digits,
    "hostname": _normalise_hostname,
}


IDENTIFIER_NAMESPACES: dict[str, NamespaceSpec] = {
    spec.name: spec
    for spec in (
        NamespaceSpec("serial", True, "Chassis or drive serial", "upper"),
        NamespaceSpec("smbios:uuid", True, "Strongest host identity available"),
        NamespaceSpec(
            "mac",
            True,
            "Retire rather than move when a NIC is replaced",
            "mac",
        ),
        NamespaceSpec(
            "proxmox:vmid",
            False,
            "REUSED after deletion - never unique alone; pair with proxmox:cluster",
            "digits",
        ),
        NamespaceSpec("proxmox:uuid", True, "The safe Proxmox correlator"),
        NamespaceSpec("proxmox:cluster", False, "Scopes a vmid"),
        NamespaceSpec("docker:container-id", True, "New id on recreate, expected"),
        NamespaceSpec("hostname", False, "Correlation hint only", "hostname"),
        NamespaceSpec("fqdn", False, "Correlation hint only", "hostname"),
        NamespaceSpec("cisco:if-index", False, "Unique only within a device", "digits"),
        NamespaceSpec("acop:legacy-id", False, "Imported from a prior system"),
    )
}


# ---------------------------------------------------------------------------
# Relationship registry
# ---------------------------------------------------------------------------


class RelationshipType(StrEnum):
    """Typed edges between assets."""

    HAS_INTERFACE = "HAS_INTERFACE"
    CONNECTED_TO = "CONNECTED_TO"
    MEMBER_OF = "MEMBER_OF"
    RUNS_ON = "RUNS_ON"
    DEPENDS_ON = "DEPENDS_ON"
    IP_ASSIGNED_TO = "IP_ASSIGNED_TO"
    USES_STORAGE = "USES_STORAGE"


@dataclass(frozen=True, slots=True)
class EdgeSpec:
    """How one relationship type behaves."""

    symmetric: bool
    inverse_label: str
    """How the edge reads from the target's side, e.g. RUNS_ON -> HOSTS."""

    sources: frozenset[AssetType] = field(default_factory=frozenset)
    targets: frozenset[AssetType] = field(default_factory=frozenset)

    def permits(self, source: AssetType, target: AssetType) -> bool:
        """Whether this edge may join the given asset types.

        An empty endpoint set means "unconstrained", so a future type does not
        need every spec updated before it can participate.
        """
        source_ok = not self.sources or source in self.sources
        target_ok = not self.targets or target in self.targets
        return source_ok and target_ok


RELATIONSHIP_SPECS: dict[RelationshipType, EdgeSpec] = {
    RelationshipType.HAS_INTERFACE: EdgeSpec(
        symmetric=False,
        inverse_label="INTERFACE_OF",
        sources=frozenset({AssetType.DEVICE, AssetType.HOST, AssetType.VM}),
        targets=frozenset({AssetType.NETWORK_INTERFACE}),
    ),
    RelationshipType.CONNECTED_TO: EdgeSpec(
        symmetric=True,
        inverse_label="CONNECTED_TO",
        sources=frozenset(
            {AssetType.NETWORK_INTERFACE, AssetType.SWITCH_PORT, AssetType.DEVICE}
        ),
        targets=frozenset(
            {AssetType.NETWORK_INTERFACE, AssetType.SWITCH_PORT, AssetType.DEVICE}
        ),
    ),
    RelationshipType.MEMBER_OF: EdgeSpec(
        symmetric=False,
        inverse_label="HAS_MEMBER",
        sources=frozenset({AssetType.SWITCH_PORT, AssetType.HOST, AssetType.VM}),
        targets=frozenset({AssetType.VLAN, AssetType.DEVICE}),
    ),
    RelationshipType.RUNS_ON: EdgeSpec(
        symmetric=False,
        inverse_label="HOSTS",
        sources=frozenset({AssetType.VM, AssetType.CONTAINER, AssetType.SERVICE}),
        targets=frozenset({AssetType.HOST, AssetType.VM, AssetType.DEVICE}),
    ),
    RelationshipType.DEPENDS_ON: EdgeSpec(
        symmetric=False,
        inverse_label="REQUIRED_BY",
        sources=frozenset({AssetType.SERVICE, AssetType.APPLICATION}),
        targets=frozenset({AssetType.SERVICE, AssetType.APPLICATION}),
    ),
    RelationshipType.IP_ASSIGNED_TO: EdgeSpec(
        symmetric=False,
        inverse_label="HAS_IP",
        sources=frozenset({AssetType.IP_ADDRESS}),
        targets=frozenset({AssetType.NETWORK_INTERFACE}),
    ),
    RelationshipType.USES_STORAGE: EdgeSpec(
        symmetric=False,
        inverse_label="PROVIDES_STORAGE",
        sources=frozenset({AssetType.VM, AssetType.HOST, AssetType.SERVICE}),
        targets=frozenset({AssetType.STORAGE_DEVICE}),
    ),
}

#: Lowercased relationship type names. A fact predicate matching one of these
#: is rejected: an edge stored both as a fact and as a relationship is silent
#: dual representation.
RESERVED_RELATIONSHIP_PREDICATES: frozenset[str] = frozenset(
    item.value.lower() for item in RelationshipType
)


# ---------------------------------------------------------------------------
# Predicate registry
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PredicateSpec:
    """Expected shape of a known predicate."""

    value_type: ValueType
    unit: str | None = None
    description: str = ""


#: Known predicates are validated against this. Unknown predicates are still
#: accepted - blocking discovery behind a code change for every field it finds
#: would make Milestone 5 unworkable - but a known one used with the wrong
#: value type is a bug worth catching at the boundary.
KNOWN_PREDICATES: dict[str, PredicateSpec] = {
    "network.hostname": PredicateSpec(ValueType.TEXT, None, "Reported hostname"),
    "network.fqdn": PredicateSpec(ValueType.TEXT),
    "memory.total_bytes": PredicateSpec(ValueType.NUMBER, "bytes"),
    "cpu.cores": PredicateSpec(ValueType.NUMBER, "cores"),
    "storage.total_bytes": PredicateSpec(ValueType.NUMBER, "bytes"),
    "power.poe_enabled": PredicateSpec(ValueType.BOOL),
    "interface.admin_up": PredicateSpec(ValueType.BOOL),
    "interface.oper_up": PredicateSpec(ValueType.BOOL),
    "interface.speed_mbps": PredicateSpec(ValueType.NUMBER, "mbps"),
    "vlan.access_id": PredicateSpec(ValueType.NUMBER),
    "os.name": PredicateSpec(ValueType.TEXT),
    "os.version": PredicateSpec(ValueType.TEXT),
    "config.hash": PredicateSpec(ValueType.TEXT, None, "Drift evidence, not a secret"),
    "lifecycle.last_boot_at": PredicateSpec(ValueType.TIMESTAMP),
}


__all__ = [
    "DISCOURAGED_ASSET_TYPES",
    "IDENTIFIER_NAMESPACES",
    "KNOWN_PREDICATES",
    "NAMESPACE_PATTERN",
    "PREDICATE_PATTERN",
    "RELATIONSHIP_SPECS",
    "RESERVED_RELATIONSHIP_PREDICATES",
    "STATEMENT_CLASS_FOR_SOURCE",
    "TERMINAL_LIFECYCLE_STATES",
    "VALUE_COLUMNS",
    "VERIFICATION_STATUS_FOR_SOURCE",
    "AssetType",
    "AttestationAction",
    "EdgeSpec",
    "FactKind",
    "LifecycleState",
    "NamespaceSpec",
    "PredicateSpec",
    "RelationshipType",
    "ValueType",
]
