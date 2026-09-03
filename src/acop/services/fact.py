"""Fact assertion, history, conflict and trust transitions."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from acop.auth.principal import Principal
from acop.core.exceptions import ConflictError, NotFoundError, ValidationError
from acop.core.logging import get_logger
from acop.models.asset import Asset
from acop.models.fact import AssetFact, FactAttestation
from acop.models.provenance import SourceType, StatementClass, VerificationStatus
from acop.models.vocabulary import (
    VALUE_COLUMNS,
    AttestationAction,
    FactKind,
    ValueType,
)
from acop.schemas.fact import (
    ConflictingClaim,
    DesiredFactCreate,
    EffectiveValue,
    FactAssert,
    PredicateConflict,
)
from acop.services.provenance import (
    attribution_for,
    default_status_for,
    guard_authoritative_transition,
    is_authoritative,
    statement_class_for,
)
from acop.services.value_screen import FactValueScreen

logger = get_logger(__name__)

#: Outcomes of an assert.
CREATED = "CREATED"
SUPERSEDED = "SUPERSEDED"
TOUCHED = "TOUCHED"

#: Bases on which an effective value may be determined without a resolver.
AUTHORITATIVE_SINGLE = "AUTHORITATIVE_SINGLE"
UNANIMOUS = "UNANIMOUS"
UNRESOLVED = "UNRESOLVED"


def _value_of(fact: AssetFact) -> Any:
    """The populated value, whichever column holds it."""
    return getattr(fact, VALUE_COLUMNS[ValueType(fact.value_type)])


def _summarise(fact: AssetFact) -> str:
    """A short, safe rendering of a value for conflict reporting."""
    value = _value_of(fact)
    if value is None:  # pragma: no cover - CHECK makes this unreachable
        return ""
    text = str(value)
    return text if len(text) <= 120 else text[:117] + "..."


def _values_equal(existing: AssetFact, incoming: dict[str, Any]) -> bool:
    """Whether an incoming assert carries the same value as the live row.

    Numeric comparison goes through Decimal because PostgreSQL returns NUMERIC
    as Decimal; comparing a Decimal to a float would report a spurious change
    on every sweep and fill history with duplicates.
    """
    if existing.value_type != incoming["value_type"]:
        return False
    column = VALUE_COLUMNS[ValueType(existing.value_type)]
    current = getattr(existing, column)
    candidate = incoming.get(column)
    if column == "value_number":
        if current is None or candidate is None:
            return current is candidate
        return Decimal(str(current)) == Decimal(str(candidate))
    return bool(current == candidate)


class FactService:
    """The write and read path for claims about assets."""

    def __init__(
        self, session: AsyncSession, screen: FactValueScreen | None = None
    ) -> None:
        self._session = session
        self._screen = screen or FactValueScreen()

    # ------------------------------------------------------------------
    # Write path
    # ------------------------------------------------------------------
    async def assert_fact(
        self, asset_id: uuid.UUID, payload: FactAssert
    ) -> tuple[str, AssetFact, uuid.UUID | None, list[str]]:
        """Assert one claim.

        Returns ``(outcome, fact, superseded_id, redacted_json_keys)``.

        Three cases, and the middle one is what makes frequent rediscovery
        survivable:

        * no live row for this source        -> insert (CREATED)
        * live row, same value               -> advance last_seen_at (TOUCHED)
        * live row, different value          -> close it, insert (SUPERSEDED)
        """
        asset = await self._session.get(Asset, asset_id)
        if asset is None:
            raise NotFoundError(f"Asset {asset_id} does not exist.")

        screened = self._screen.screen(
            payload.predicate,
            value_text=payload.value_text,
            value_json=payload.value_json,
        )

        source_type = SourceType(str(payload.source_type))
        columns = self._value_columns(payload, screened.value_json)
        now = datetime.now(UTC)

        live = await self._live_claim(
            asset_id, payload.predicate, str(payload.fact_kind), payload.source_id
        )

        if live is not None and _values_equal(live, columns):
            live.last_seen_at = now
            live.confidence = payload.confidence
            await self._session.flush()
            return TOUCHED, live, None, list(screened.redacted_json_keys)

        superseded_id: uuid.UUID | None = None
        if live is not None:
            # Close first. Inserting while the old row is still live violates
            # uq_asset_fact_live_claim, and a partial unique index cannot be
            # deferred - so the order is mandatory, not stylistic.
            live.valid_to = now
            superseded_id = live.id
            await self._session.flush()

        fact = AssetFact(
            asset_id=asset_id,
            predicate=payload.predicate,
            fact_kind=str(payload.fact_kind),
            statement_class=statement_class_for(source_type).value,
            source_type=source_type.value,
            source_id=payload.source_id,
            confidence=payload.confidence,
            verification_status=default_status_for(source_type).value,
            unit=payload.unit,
            supersedes_fact_id=superseded_id,
            valid_from=now,
            first_seen_at=now,
            last_seen_at=now,
            **columns,
        )
        self._session.add(fact)
        await self._session.flush()
        asset.last_seen_at = now
        return (
            SUPERSEDED if superseded_id else CREATED,
            fact,
            superseded_id,
            list(screened.redacted_json_keys),
        )

    async def create_desired(
        self,
        asset_id: uuid.UUID,
        payload: DesiredFactCreate,
        principal: Principal,
        *,
        derived_from: uuid.UUID | None = None,
        request_id: str | None = None,
    ) -> AssetFact:
        """Declare an approved desired configuration.

        A desired state is a statement of intent, so it is its own row on the
        other axis rather than a status on an observation - which is what makes
        drift detectable once the observation moves.
        """
        asset = await self._session.get(Asset, asset_id)
        if asset is None:
            raise NotFoundError(f"Asset {asset_id} does not exist.")

        screened = self._screen.screen(
            payload.predicate,
            value_text=payload.value_text,
            value_json=payload.value_json,
        )
        columns = self._value_columns(payload, screened.value_json)
        now = datetime.now(UTC)

        live = await self._live_claim(
            asset_id,
            payload.predicate,
            FactKind.DESIRED_STATE.value,
            principal.subject,
        )
        if live is not None:
            live.valid_to = now
            await self._session.flush()

        fact = AssetFact(
            asset_id=asset_id,
            predicate=payload.predicate,
            fact_kind=FactKind.DESIRED_STATE.value,
            statement_class=StatementClass.FACT.value,
            source_type=SourceType.MANUAL_ENTRY.value,
            source_id=principal.subject,
            confidence=1.0,
            verification_status=VerificationStatus.APPROVED.value,
            approved_by_subject=principal.subject,
            approved_at=now,
            unit=payload.unit,
            supersedes_fact_id=live.id if live else None,
            derived_from_fact_id=derived_from,
            valid_from=now,
            first_seen_at=now,
            last_seen_at=now,
            **columns,
        )
        self._session.add(fact)
        await self._session.flush()
        self._record_attestation(
            fact,
            AttestationAction.APPROVE,
            VerificationStatus.UNVERIFIED.value,
            VerificationStatus.APPROVED.value,
            principal,
            payload.reason,
            request_id,
        )
        await self._session.flush()
        return fact

    # ------------------------------------------------------------------
    # Trust transitions
    # ------------------------------------------------------------------
    async def transition(
        self,
        fact_id: uuid.UUID,
        action: AttestationAction,
        principal: Principal,
        *,
        reason: str | None = None,
        request_id: str | None = None,
    ) -> AssetFact:
        """Verify, approve or revoke a fact.

        Approve on an observation is handled by the route, which promotes it
        into a DESIRED_STATE row; here APPROVE applies only to a fact already
        on the desired axis.
        """
        fact = await self._session.get(AssetFact, fact_id)
        if fact is None:
            raise NotFoundError(f"Fact {fact_id} does not exist.")
        if fact.valid_to is not None:
            raise ConflictError(
                "A closed historical claim cannot change trust state; it is "
                "already part of the record.",
                context={"fact_id": str(fact_id)},
            )

        from_status = fact.verification_status

        if action is AttestationAction.REVOKE:
            if not is_authoritative(from_status):
                raise ConflictError(
                    "Only a VERIFIED or APPROVED claim can be revoked.",
                    context={"current_status": from_status},
                )
            to_status = default_status_for(SourceType(fact.source_type)).value
        else:
            target = (
                VerificationStatus.VERIFIED
                if action is AttestationAction.VERIFY
                else VerificationStatus.APPROVED
            )
            guard_authoritative_transition(
                statement_class=fact.statement_class,
                source_type=fact.source_type,
                target_status=target,
            )
            await self._guard_single_authority(fact)
            to_status = target.value

        for column, value in attribution_for(action, principal).items():
            setattr(fact, column, value)
        fact.verification_status = to_status

        self._record_attestation(
            fact, action, from_status, to_status, principal, reason, request_id
        )
        await self._session.flush()
        return fact

    async def _guard_single_authority(self, fact: AssetFact) -> None:
        """Refuse a promotion that would create a second authoritative claim.

        The database enforces this too (``uq_asset_fact_live_authority``); this
        exists so the caller gets a 409 naming the incumbent instead of an
        opaque IntegrityError.
        """
        incumbent = (
            (
                await self._session.execute(
                    select(AssetFact).where(
                        AssetFact.asset_id == fact.asset_id,
                        AssetFact.predicate == fact.predicate,
                        AssetFact.fact_kind == fact.fact_kind,
                        AssetFact.valid_to.is_(None),
                        AssetFact.verification_status.in_(
                            [
                                VerificationStatus.VERIFIED.value,
                                VerificationStatus.APPROVED.value,
                            ]
                        ),
                        AssetFact.id != fact.id,
                    )
                )
            )
            .scalars()
            .first()
        )
        if incumbent is not None:
            raise ConflictError(
                "Another live claim for this predicate is already authoritative. "
                "Revoke it first - at most one claim may hold authority.",
                context={
                    "incumbent_fact_id": str(incumbent.id),
                    "incumbent_source_id": incumbent.source_id,
                },
            )

    def _record_attestation(
        self,
        fact: AssetFact,
        action: AttestationAction,
        from_status: str,
        to_status: str,
        principal: Principal,
        reason: str | None,
        request_id: str | None,
    ) -> None:
        """Append the immutable record of a trust transition.

        This is what makes clearing the fact's attribution columns on revoke
        safe: the lineage survives here regardless of audit-log retention.
        """
        fields = principal.to_audit_fields()
        self._session.add(
            FactAttestation(
                fact_id=fact.id,
                action=action.value,
                from_status=from_status,
                to_status=to_status,
                principal_subject=fields["principal_subject"],
                principal_type=fields["principal_type"],
                principal_issuer=fields["principal_issuer"],
                auth_method=fields["auth_method"],
                reason=reason,
                request_id=request_id,
                occurred_at=datetime.now(UTC),
            )
        )

    # ------------------------------------------------------------------
    # Read path
    # ------------------------------------------------------------------
    async def live_facts(
        self,
        asset_id: uuid.UUID,
        *,
        fact_kind: str | None = None,
        predicate: str | None = None,
    ) -> list[AssetFact]:
        query = select(AssetFact).where(
            AssetFact.asset_id == asset_id, AssetFact.valid_to.is_(None)
        )
        if fact_kind:
            query = query.where(AssetFact.fact_kind == fact_kind)
        if predicate:
            query = query.where(AssetFact.predicate == predicate)
        query = query.order_by(AssetFact.predicate, AssetFact.source_id)
        return list((await self._session.execute(query)).scalars())

    async def history(self, asset_id: uuid.UUID, predicate: str) -> list[AssetFact]:
        query = (
            select(AssetFact)
            .where(AssetFact.asset_id == asset_id, AssetFact.predicate == predicate)
            .order_by(AssetFact.valid_from.desc())
        )
        return list((await self._session.execute(query)).scalars())

    async def attestations(self, fact_ids: list[uuid.UUID]) -> list[FactAttestation]:
        if not fact_ids:
            return []
        query = (
            select(FactAttestation)
            .where(FactAttestation.fact_id.in_(fact_ids))
            .order_by(FactAttestation.occurred_at.desc())
        )
        return list((await self._session.execute(query)).scalars())

    async def conflicts(self, asset_id: uuid.UUID) -> list[PredicateConflict]:
        """Predicates where live sources disagree.

        ``CONFLICTING`` is derived here rather than stored on a row: marking a
        row conflicting would require deciding which row is wrong, which is
        exactly the judgement Milestone 2 declines to make.
        """
        grouped: dict[tuple[str, str], list[AssetFact]] = {}
        for fact in await self.live_facts(asset_id):
            grouped.setdefault((fact.predicate, fact.fact_kind), []).append(fact)

        conflicts: list[PredicateConflict] = []
        for (predicate, kind), facts in sorted(grouped.items()):
            distinct = {_summarise(item) for item in facts}
            if len(distinct) > 1:
                conflicts.append(
                    PredicateConflict(
                        predicate=predicate,
                        fact_kind=kind,
                        distinct_values=len(distinct),
                        claims=[self._claim(item) for item in facts],
                    )
                )
        return conflicts

    async def effective(
        self, asset_id: uuid.UUID, predicate: str, fact_kind: str
    ) -> EffectiveValue:
        """Determine the current value, or report that it is unresolved."""
        facts = await self.live_facts(asset_id, fact_kind=fact_kind, predicate=predicate)
        if not facts:
            raise NotFoundError(f"No live claim for {predicate!r} on asset {asset_id}.")

        authoritative = [f for f in facts if is_authoritative(f.verification_status)]
        distinct = {_summarise(f) for f in facts}
        conflict = len(distinct) > 1

        if len(authoritative) == 1:
            winner = authoritative[0]
            return EffectiveValue(
                predicate=predicate,
                fact_kind=fact_kind,
                basis=AUTHORITATIVE_SINGLE,
                fact=winner,
                conflict_present=conflict,
                resolution_required=False,
                dissenting_claims=[self._claim(f) for f in facts if f.id != winner.id],
            )

        # AI rows are excluded from the vote: the likeliest reason an inference
        # agrees with an observation is that it read the observation, so
        # counting it would treat echo as corroboration.
        non_inference = [
            f for f in facts if f.statement_class != StatementClass.INFERENCE.value
        ]
        if non_inference and len({_summarise(f) for f in non_inference}) == 1:
            return EffectiveValue(
                predicate=predicate,
                fact_kind=fact_kind,
                basis=UNANIMOUS,
                fact=non_inference[0],
                conflict_present=conflict,
                resolution_required=False,
                dissenting_claims=[
                    self._claim(f) for f in facts if f not in non_inference
                ],
            )

        return EffectiveValue(
            predicate=predicate,
            fact_kind=fact_kind,
            basis=UNRESOLVED,
            fact=None,
            conflict_present=conflict,
            resolution_required=True,
            inference_only=not non_inference,
            dissenting_claims=[self._claim(f) for f in facts],
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    async def _live_claim(
        self, asset_id: uuid.UUID, predicate: str, fact_kind: str, source_id: str
    ) -> AssetFact | None:
        return (
            (
                await self._session.execute(
                    select(AssetFact).where(
                        AssetFact.asset_id == asset_id,
                        AssetFact.predicate == predicate,
                        AssetFact.fact_kind == fact_kind,
                        AssetFact.source_id == source_id,
                        AssetFact.valid_to.is_(None),
                    )
                )
            )
            .scalars()
            .first()
        )

    @staticmethod
    def _claim(fact: AssetFact) -> ConflictingClaim:
        return ConflictingClaim(
            fact_id=fact.id,
            source_type=fact.source_type,
            source_id=fact.source_id,
            statement_class=fact.statement_class,
            verification_status=fact.verification_status,
            confidence=fact.confidence,
            value_summary=_summarise(fact),
        )

    @staticmethod
    def _value_columns(
        payload: FactAssert | DesiredFactCreate, screened_json: dict[str, Any] | None
    ) -> dict[str, Any]:
        value_type = ValueType(str(payload.value_type))
        columns: dict[str, Any] = {
            "value_type": value_type.value,
            "value_text": None,
            "value_number": None,
            "value_bool": None,
            "value_timestamp": None,
            "value_json": None,
            "value_asset_id": None,
        }
        column = VALUE_COLUMNS[value_type]
        if value_type is ValueType.JSON:
            columns[column] = screened_json
        elif value_type is ValueType.NUMBER:
            if payload.value_number is None:  # pragma: no cover - schema guards
                raise ValidationError("value_number is required for NUMBER.")
            # int() first for integral values so a byte count stores as
            # 17179869184 rather than 17179869184.0.
            raw = payload.value_number
            columns[column] = (
                Decimal(int(raw)) if float(raw).is_integer() else Decimal(str(raw))
            )
        else:
            columns[column] = getattr(payload, column)
        return columns


__all__ = [
    "AUTHORITATIVE_SINGLE",
    "CREATED",
    "SUPERSEDED",
    "TOUCHED",
    "UNANIMOUS",
    "UNRESOLVED",
    "FactService",
]
