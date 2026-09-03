"""Trust rules shared by facts and relationships.

Facts and relationships live in separate tables because edges need
directionality, symmetry and reverse indexes that facts do not. What they must
*not* have is separate trust logic - two implementations of "may this become
authoritative" would drift apart, and the one that drifted would be the one
that let an inference through.

So the rules live here as pure functions over the vocabulary, with no session
and no I/O, and both services call them. Milestone 2 wires only facts to the
API; relationship verification uses the same functions when it arrives.
"""

from __future__ import annotations

from datetime import UTC, datetime

from acop.auth.principal import Principal
from acop.core.exceptions import ConflictError, ValidationError
from acop.models.provenance import (
    AUTHORITATIVE_STATUSES,
    SourceType,
    StatementClass,
    VerificationStatus,
)
from acop.models.vocabulary import (
    STATEMENT_CLASS_FOR_SOURCE,
    VERIFICATION_STATUS_FOR_SOURCE,
    AttestationAction,
)


def statement_class_for(source_type: SourceType) -> StatementClass:
    """Epistemic class implied by a source.

    A caller never chooses this. Letting a client declare its own statement
    class would let a collector label an inference as an observation, which is
    the one thing the database CHECK exists to prevent.
    """
    return STATEMENT_CLASS_FOR_SOURCE[source_type]


def default_status_for(source_type: SourceType) -> VerificationStatus:
    """Verification status a new claim from this source starts at."""
    return VERIFICATION_STATUS_FOR_SOURCE[source_type]


def is_authoritative(status: VerificationStatus | str) -> bool:
    """Whether a status represents a human- or policy-endorsed statement."""
    value = (
        status if isinstance(status, VerificationStatus) else VerificationStatus(status)
    )
    return value in AUTHORITATIVE_STATUSES


def may_become_authoritative(
    statement_class: StatementClass | str, source_type: SourceType | str
) -> bool:
    """Whether a claim of this provenance is ever allowed to hold authority.

    Mirrors ``ck_*_inference_not_authoritative``. The database is the
    enforcement point; this exists so the service can return a clean 409
    instead of surfacing an IntegrityError.
    """
    cls = (
        statement_class
        if isinstance(statement_class, StatementClass)
        else StatementClass(statement_class)
    )
    src = source_type if isinstance(source_type, SourceType) else SourceType(source_type)
    return cls is not StatementClass.INFERENCE and src is not SourceType.AI_INFERENCE


def guard_authoritative_transition(
    *,
    statement_class: StatementClass | str,
    source_type: SourceType | str,
    target_status: VerificationStatus,
) -> None:
    """Raise if this claim may not be promoted to ``target_status``.

    Raises:
        ConflictError: The claim is an inference or AI-sourced.
        ValidationError: ``target_status`` is not an authoritative status.
    """
    if target_status not in AUTHORITATIVE_STATUSES:
        raise ValidationError(
            f"{target_status.value} is not an authoritative status.",
            context={"target_status": target_status.value},
        )
    if not may_become_authoritative(statement_class, source_type):
        raise ConflictError(
            "An AI inference can never be verified or approved. It may only "
            "stand as an UNVERIFIED parallel claim.",
            context={
                "statement_class": str(statement_class),
                "source_type": str(source_type),
            },
        )


def attribution_for(
    action: AttestationAction, principal: Principal, moment: datetime | None = None
) -> dict[str, object]:
    """Columns to set on the claim row for a trust transition.

    Revocation *clears* the current-attribution columns. That is safe only
    because ``fact_attestation`` keeps the immutable lineage - a row left
    claiming a verifier it no longer has would make the CHECK constraint
    meaningless and mislead anyone reading the row directly.
    """
    now = moment or datetime.now(UTC)
    if action is AttestationAction.VERIFY:
        return {
            "verification_status": VerificationStatus.VERIFIED.value,
            "verified_by_subject": principal.subject,
            "verified_at": now,
        }
    if action is AttestationAction.APPROVE:
        return {
            "verification_status": VerificationStatus.APPROVED.value,
            "approved_by_subject": principal.subject,
            "approved_at": now,
        }
    return {
        "verified_by_subject": None,
        "verified_at": None,
        "approved_by_subject": None,
        "approved_at": None,
    }


__all__ = [
    "attribution_for",
    "default_status_for",
    "guard_authoritative_transition",
    "is_authoritative",
    "may_become_authoritative",
    "statement_class_for",
]
