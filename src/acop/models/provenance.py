"""Fact provenance vocabulary.

Sections 2 and 10 of the design brief make the separation between discovered,
observed, verified, approved and inferred facts the central idea of the
platform. Milestone 2 builds the CMDB tables that use these values; this module
defines only the *vocabulary*, so that Milestone 1's audit log can already
record which class of statement an event concerns and Milestone 2 does not have
to renumber or rename anything.

Nothing here creates a database table. The enums are stored as ``VARCHAR`` at
the column level rather than as PostgreSQL ``ENUM`` types - see
``docs/decisions/ADR-0004-enums-as-varchar.md`` for why.
"""

from __future__ import annotations

from enum import StrEnum


class SourceType(StrEnum):
    """Where a stored fact came from."""

    LIVE_DISCOVERY = "LIVE_DISCOVERY"
    CONFIG_FILE = "CONFIG_FILE"
    PROMETHEUS = "PROMETHEUS"
    MANUAL_ENTRY = "MANUAL_ENTRY"
    DOCUMENTATION = "DOCUMENTATION"
    AI_INFERENCE = "AI_INFERENCE"
    IMPORT = "IMPORT"


class VerificationStatus(StrEnum):
    """How much confidence the platform places in a stored fact.

    The ordering below is the intended trust ordering, but it is deliberately
    not encoded as a comparison: ``CONFLICTING`` is not "worse than"
    ``STALE`` in a way that any code should reason about numerically. Conflict
    resolution is an explicit workflow, not an arithmetic comparison.
    """

    DISCOVERED = "DISCOVERED"
    OBSERVED = "OBSERVED"
    VERIFIED = "VERIFIED"
    APPROVED = "APPROVED"
    STALE = "STALE"
    CONFLICTING = "CONFLICTING"
    UNVERIFIED = "UNVERIFIED"


#: Statuses that represent a human- or policy-endorsed statement. AI inference
#: must never write these values; enforcement lives in the Milestone 2 service
#: layer, and this tuple is the single definition it will reference.
AUTHORITATIVE_STATUSES: tuple[VerificationStatus, ...] = (
    VerificationStatus.VERIFIED,
    VerificationStatus.APPROVED,
)


class StatementClass(StrEnum):
    """The epistemic class of a statement ACOP makes or stores.

    This is the distinction section 40 identifies as the definition of success:
    the system must know the difference between what it knows, what it
    observes, what it infers, and what it recommends.
    """

    FACT = "FACT"
    OBSERVATION = "OBSERVATION"
    INFERENCE = "INFERENCE"
    RECOMMENDATION = "RECOMMENDATION"


class PermissionClass(StrEnum):
    """Tool permission classes from section 7 of the design brief.

    Defined here in Milestone 1 so that the audit log can record the permission
    class of an action from the first record onward. The registry that assigns
    these to tools is Milestone 4.
    """

    CLASS_0_INFORMATION = "CLASS_0_INFORMATION"
    CLASS_1_READ_ONLY = "CLASS_1_READ_ONLY"
    CLASS_2_LOW_RISK_CHANGE = "CLASS_2_LOW_RISK_CHANGE"
    CLASS_3_HIGH_RISK_CHANGE = "CLASS_3_HIGH_RISK_CHANGE"
    PROHIBITED = "PROHIBITED"


#: Permission classes that require human approval before execution.
APPROVAL_REQUIRED_CLASSES: frozenset[PermissionClass] = frozenset(
    {
        PermissionClass.CLASS_2_LOW_RISK_CHANGE,
        PermissionClass.CLASS_3_HIGH_RISK_CHANGE,
    }
)
