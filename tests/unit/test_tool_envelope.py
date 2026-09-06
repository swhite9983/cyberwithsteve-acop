"""The execution envelope, the state machine, and the output sanitizer.

The envelope tests are about one property: the digest must be **stable** for
things that do not matter and **sensitive** to everything that does. A digest
that varied with key ordering would make approvals fail at random; one that did
not change when the target changed would let an approval be carried over to a
different request.
"""

from __future__ import annotations

import uuid

import pytest

from acop.models.tool_vocabulary import (
    IN_FLIGHT_STATES,
    LEGAL_TRANSITIONS,
    TERMINAL_STATES,
    InvocationState,
    TargetKind,
    is_legal_transition,
)
from acop.services.tools.sanitize import sanitize_output
from acop.tools.catalog import ROTATE_KEY, SERVICE_RESTART
from acop.tools.envelope import (
    build_envelope,
    build_target_block,
    canonical_json,
    envelope_digest,
)

ASSET = uuid.uuid4()


def _envelope(**overrides: object) -> dict:
    args: dict = {
        "definition": SERVICE_RESTART,
        "canonical_input": {"graceful": True, "drain_seconds": 0},
        "target": build_target_block(TargetKind.ASSET, asset_id=ASSET),
    }
    args.update(overrides)
    return build_envelope(
        args["definition"],
        canonical_input=args["canonical_input"],  # type: ignore[arg-type]
        target=args["target"],  # type: ignore[arg-type]
    )


class TestCanonicalisation:
    def test_key_order_does_not_change_the_digest(self) -> None:
        """A caller sending ``{"b":1,"a":2}`` asked for the same thing.

        JSON preserves insertion order, so without sorting the digest would
        depend on how a client's serialiser happened to emit the object.
        """
        first = envelope_digest(
            _envelope(canonical_input={"graceful": True, "drain_seconds": 5})
        )
        second = envelope_digest(
            _envelope(canonical_input={"drain_seconds": 5, "graceful": True})
        )
        assert first == second

    def test_a_uuid_has_one_representation(self) -> None:
        value = uuid.uuid4()
        assert canonical_json({"id": value}) == canonical_json({"id": str(value)})

    def test_a_frozenset_is_sorted_into_a_list(self) -> None:
        assert canonical_json(frozenset({"b", "a"})) == '["a","b"]'

    def test_an_unknown_type_raises_rather_than_being_stringified(self) -> None:
        """Silently calling ``str()`` would make the digest depend on a repr."""

        class Opaque:
            pass

        with pytest.raises(TypeError, match="canonical JSON"):
            canonical_json({"thing": Opaque()})


class TestDigestSensitivity:
    def test_changing_an_argument_changes_the_digest(self) -> None:
        assert envelope_digest(
            _envelope(canonical_input={"graceful": True, "drain_seconds": 0})
        ) != envelope_digest(
            _envelope(canonical_input={"graceful": False, "drain_seconds": 0})
        )

    def test_changing_the_target_changes_the_digest(self) -> None:
        other = build_target_block(TargetKind.ASSET, asset_id=uuid.uuid4())
        assert envelope_digest(_envelope()) != envelope_digest(_envelope(target=other))

    def test_changing_the_tool_changes_the_digest(self) -> None:
        assert envelope_digest(_envelope()) != envelope_digest(
            _envelope(definition=ROTATE_KEY, canonical_input={"key_slot": "primary"})
        )

    def test_the_envelope_carries_the_approval_policy(self) -> None:
        """So that loosening a tool's approval policy invalidates the approval.

        If the policy were outside the digest, a Class 3 tool could be quietly
        reduced to one approver while an approval given under two-person
        control was still pending, and the approval would still be honoured.
        """
        envelope = _envelope(
            definition=ROTATE_KEY, canonical_input={"key_slot": "primary"}
        )
        assert envelope["approval"]["min_approvals"] == 2
        assert envelope["approval"]["distinct_approvers_required"] is True

    def test_the_envelope_does_not_carry_a_display_name(self) -> None:
        """Renaming an asset must not invalidate a pending approval.

        A surprising failure with no security benefit: the identity that
        matters is the asset id, which cannot be renamed.
        """
        block = build_target_block(TargetKind.ASSET, asset_id=ASSET)
        assert set(block) == {"kind", "asset_id", "target_ref"}


class TestStateMachine:
    def test_execution_indeterminate_is_terminal_and_has_no_exit(self) -> None:
        """Closure is an appended reconciliation, never a state change.

        Rewriting the execution record later would replace what ACOP knew at
        execution time with something it did not know.
        """
        assert InvocationState.EXECUTION_INDETERMINATE in TERMINAL_STATES
        exits = {
            target
            for source, target in LEGAL_TRANSITIONS
            if source is InvocationState.EXECUTION_INDETERMINATE
        }
        assert exits == set()

    def test_executed_is_not_terminal(self) -> None:
        """The adapter said yes; that is not the same as it having happened."""
        assert InvocationState.EXECUTED not in TERMINAL_STATES
        assert is_legal_transition(InvocationState.EXECUTED, InvocationState.VALIDATING)
        assert is_legal_transition(InvocationState.EXECUTED, InvocationState.SUCCEEDED)

    def test_a_validating_lease_loss_is_not_indeterminate_execution(self) -> None:
        """The change happened; only the confirmation is missing."""
        assert is_legal_transition(
            InvocationState.VALIDATING, InvocationState.VALIDATION_FAILED
        )
        assert not is_legal_transition(
            InvocationState.VALIDATING, InvocationState.EXECUTION_INDETERMINATE
        )

    def test_no_terminal_state_has_an_outgoing_transition(self) -> None:
        for source, _ in LEGAL_TRANSITIONS:
            assert source not in TERMINAL_STATES, source

    def test_every_non_terminal_state_may_be_superseded(self) -> None:
        for state in InvocationState:
            if state in TERMINAL_STATES:
                continue
            assert is_legal_transition(state, InvocationState.SUPERSEDED)

    def test_both_in_flight_states_hold_a_lease(self) -> None:
        assert IN_FLIGHT_STATES == {
            InvocationState.EXECUTING,
            InvocationState.VALIDATING,
        }

    def test_a_ready_invocation_cannot_jump_straight_to_succeeded(self) -> None:
        assert not is_legal_transition(InvocationState.READY, InvocationState.SUCCEEDED)

    def test_an_awaiting_invocation_cannot_execute_without_approval(self) -> None:
        assert not is_legal_transition(
            InvocationState.AWAITING_APPROVAL, InvocationState.EXECUTING
        )
        assert not is_legal_transition(
            InvocationState.AWAITING_APPROVAL, InvocationState.READY
        )


class TestOutputSanitizer:
    def test_an_undeclared_field_is_dropped(self) -> None:
        """Constructed, not filtered.

        A deny-list would let through the first key nobody anticipated. The
        output is rebuilt from the permitted names instead.
        """
        clean, _ = sanitize_output(
            ROTATE_KEY,
            {
                "asset_id": str(ASSET),
                "key_slot": "primary",
                "key_identifier": "simkey-abc",
                "rotated_at": "2026-01-01T00:00:00Z",
                "private_key": "-----BEGIN RSA PRIVATE KEY-----",
                "debug_trace": "connected to 10.0.0.1",
            },
        )
        assert set(clean) == {
            "asset_id",
            "key_slot",
            "key_identifier",
            "rotated_at",
        }

    def test_the_digest_covers_what_was_stored(self) -> None:
        payload = {"asset_id": str(ASSET), "key_slot": "primary"}
        clean, digest = sanitize_output(ROTATE_KEY, payload)
        again, digest_again = sanitize_output(ROTATE_KEY, dict(reversed(payload.items())))  # type: ignore[call-overload]
        assert clean == again
        assert digest == digest_again

    def test_an_explicit_allow_list_narrows_the_output_model(self) -> None:
        assert ROTATE_KEY.effective_output_fields() == {
            "asset_id",
            "key_slot",
            "key_identifier",
            "rotated_at",
        }
