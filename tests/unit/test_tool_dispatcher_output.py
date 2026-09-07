"""The declared-output contract, and what a violation of it means.

``_declared_output`` is the only place an adapter's report is checked against
the tool's own ``output_model``. It used to answer a violation with ``{}``,
which the caller then published and the state machine carried to ``SUCCEEDED``
- a row claiming an outcome nobody observed, in an append-only table. It now
answers ``None``, and the caller fails the invocation.

Two of the tests here exist to pin down *why* it is ``None`` and not something
simpler:

* ``{}`` is a legitimate result. A tool whose output fields are all optional can
  validate an empty payload, and a sentinel that collides with a valid value
  cannot distinguish the broken case from the correct one.
* An exception would escape ``_record_adapter_result`` into ``_run_claimed`` and
  strand the invocation in ``EXECUTING`` with a live lease, which the reaper
  would eventually record as ``EXECUTION_INDETERMINATE`` - an unknown outcome
  needing a human, for a failure whose cause ACOP knows exactly.

See ADR-0023.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
import structlog.testing
from pydantic import BaseModel, ConfigDict

from acop.auth.principal import Role
from acop.models.knowledge_vocabulary import Sensitivity
from acop.models.provenance import PermissionClass
from acop.models.tool_vocabulary import (
    ERROR_PHRASES,
    RETRYABLE_CATEGORIES,
    IdempotencyKind,
    TargetKind,
    ToolErrorCategory,
)
from acop.models.vocabulary import AssetType
from acop.services.tools import dispatcher as dispatcher_module
from acop.services.tools.dispatcher import ExecutionDispatcher
from acop.tools.contract import ToolDefinition

_FORBID = ConfigDict(extra="forbid")

#: Shaped like the worst thing an adapter could hand back. If any of this
#: reaches a log line, a response or a row, the containment has failed.
_LEAKY_VALUE = "postgresql://acop:hunter2@db.internal/acop"


class _RequiredOut(BaseModel):
    """An ordinary output model: one required field, nothing optional."""

    model_config = _FORBID
    status: str
    observed_at: datetime


class _AllOptionalOut(BaseModel):
    """A tool that may legitimately observe nothing at all.

    This is not a contrived shape. A read whose every field is "present when
    the target reports it" looks exactly like this, and an empty answer from it
    is a true answer.
    """

    model_config = _FORBID
    note: str | None = None
    count: int | None = None


class _NoFieldsOut(BaseModel):
    """A tool that declares no output fields, like ``NeverOut`` in the catalog.

    This is the shape that makes ``{}`` a *legitimate* return value rather than
    a theoretical one, and therefore the shape that rules ``{}`` out as the
    violation sentinel. An all-optional model does not do it: pydantic dumps
    its unset fields as explicit nulls, so it yields ``{"note": None}``, not
    ``{}``. Only a model with nothing declared produces the empty dict.
    """

    model_config = _FORBID


def _definition(output_model: type[BaseModel], name: str) -> ToolDefinition:
    return ToolDefinition(
        tool_name=name,
        tool_version="1.0",
        permission_class=PermissionClass.CLASS_1_READ_ONLY,
        description="A read used to exercise the output contract.",
        input_model=_NoFieldsOut,
        output_model=output_model,
        adapter_id="test.simulated",
        required_roles=frozenset({Role.VIEWER.value}),
        target_type=TargetKind.ASSET,
        target_asset_types=frozenset({AssetType.SERVICE.value}),
        idempotency=IdempotencyKind.NATURALLY_IDEMPOTENT,
        sensitivity=Sensitivity.INTERNAL,
    )


class TestDeclaredOutput:
    """``_declared_output`` is a pure function; it is tested as one."""

    def test_a_valid_payload_is_returned_as_json_safe_primitives(self) -> None:
        """The unchanged happy path, including the datetime conversion."""
        definition = _definition(_RequiredOut, "test.contract.valid")
        moment = datetime(2026, 9, 6, 12, 0, tzinfo=UTC)

        result = ExecutionDispatcher._declared_output(
            definition, {"status": "ok", "observed_at": moment}
        )

        assert result is not None
        assert result["status"] == "ok"
        # mode="json": a raw datetime would abort the JSONB insert and would
        # give the result digest a value that depends on the driver.
        assert isinstance(result["observed_at"], str)
        assert result["observed_at"].startswith("2026-09-06T12:00")
        # Whatever comes back must survive the round trip into a JSONB column.
        json.dumps(result)

    def test_a_payload_missing_a_required_field_is_none(self) -> None:
        """Test A. The violation signal is ``None``, and specifically not ``{}``."""
        definition = _definition(_RequiredOut, "test.contract.missing")

        result = ExecutionDispatcher._declared_output(definition, {"status": "ok"})

        assert result is None
        # Stated separately because this is the distinction the whole change
        # turns on: the old behaviour returned a falsy dict, and every caller
        # that checked truthiness would still be wrong today.
        assert result != {}

    def test_an_undeclared_field_is_none(self) -> None:
        """Import rule 12 forces ``extra="forbid"``; this is that rule at runtime.

        An adapter that grew a field nobody declared is exactly the case the
        allow-list exists for, and it must not be published just because the
        declared fields happen to be present too.
        """
        definition = _definition(_RequiredOut, "test.contract.extra")

        result = ExecutionDispatcher._declared_output(
            definition,
            {
                "status": "ok",
                "observed_at": datetime(2026, 9, 6, tzinfo=UTC),
                "connection_string": _LEAKY_VALUE,
            },
        )

        assert result is None

    def test_a_wrongly_typed_field_is_none(self) -> None:
        definition = _definition(_RequiredOut, "test.contract.mistyped")

        result = ExecutionDispatcher._declared_output(
            definition, {"status": "ok", "observed_at": "not a timestamp at all"}
        )

        assert result is None

    def test_an_empty_payload_against_an_all_optional_model_is_valid(self) -> None:
        """Test B. An empty observation is a true answer, not a violation.

        Note what pydantic actually produces: unset optional fields dump as
        explicit nulls, so this is ``{"note": None, "count": None}`` rather than
        ``{}``. Asserted exactly, because a future switch to
        ``exclude_none=True`` would change what gets published and what the
        result digest covers, and that should break a test rather than pass
        quietly.
        """
        definition = _definition(_AllOptionalOut, "test.contract.optional")

        result = ExecutionDispatcher._declared_output(definition, {})

        assert result is not None
        assert result == {"note": None, "count": None}

    def test_a_model_with_no_declared_fields_returns_an_empty_dict(self) -> None:
        """Test B's sharp edge, and the whole reason the sentinel is ``None``.

        This tool's output validates to a genuinely empty dict. Had the
        violation signal stayed ``{}``, this correct, successful read would be
        indistinguishable from an adapter that broke its contract - and under
        the new caller it would be failed rather than published.
        """
        definition = _definition(_NoFieldsOut, "test.contract.nofields")

        result = ExecutionDispatcher._declared_output(definition, {})

        assert result == {}
        assert result is not None

    def test_a_violation_does_not_raise(self) -> None:
        """It returns; it never propagates.

        An exception here would leave the invocation in ``EXECUTING`` under a
        live lease until the reaper wrote ``EXECUTION_INDETERMINATE``, turning
        a precisely-known defect into an unknown outcome a human has to close
        by hand.
        """
        definition = _definition(_RequiredOut, "test.contract.noraise")

        # No pytest.raises: the assertion is that the call completes at all.
        assert ExecutionDispatcher._declared_output(definition, {"bogus": 1}) is None


class TestViolationDisclosure:
    """A violation is logged for an engineer, not for an attacker."""

    def test_the_log_names_the_fields_and_never_the_values(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Key names are what fixes the tool. Values are the adapter's, and unsafe.

        The logger is **substituted**, not reconfigured, and that is the third
        attempt at this test rather than a stylistic preference. ``capsys``
        failed first: the dispatcher's module logger binds its output stream on
        first use, so in a suite the line lands in some earlier test's captured
        stdout. ``structlog.testing.capture_logs`` failed second, and less
        obviously - it swaps the *global* processor chain, but
        ``configure_logging`` sets ``cache_logger_on_first_use=True``, so once
        any earlier test in the process has made this module log, the bound
        logger holds its own cached chain and never sees the swap. That failure
        was invisible when this file ran alone and appeared only in a full-suite
        run - unit and integration in one process.

        A recording double removes the dependence entirely. The property under
        test is *what this call passes to its logger*, which is a property of
        this function - not of how structlog happens to be configured in the
        process that happens to be running it.
        """
        definition = _definition(_RequiredOut, "test.contract.logging")
        recorder = structlog.testing.CapturingLogger()
        monkeypatch.setattr(dispatcher_module, "logger", recorder)

        ExecutionDispatcher._declared_output(
            definition, {"connection_string": _LEAKY_VALUE, "status": "ok"}
        )

        violations = [
            call
            for call in recorder.calls
            if call.args and call.args[0] == "tools.output.contract_violation"
        ]
        assert len(violations) == 1
        record = violations[0]

        assert record.method_name == "error"
        assert record.kwargs["tool"] == "test.contract.logging@1.0"
        # The names, so the declaration can be fixed...
        assert record.kwargs["fields"] == ["connection_string", "status"]
        # ...and nothing else. The whole call is serialised and searched,
        # because a leak that lands in an unexpected key is still a leak.
        rendered = json.dumps({"args": record.args, "kwargs": record.kwargs}, default=str)
        assert _LEAKY_VALUE not in rendered
        assert "hunter2" not in rendered


class TestRetryability:
    """Requirement 7: the new category must not be automatically retried."""

    def test_the_new_category_is_not_retryable(self) -> None:
        """Test D's unit half, proved from the existing machinery rather than added to it.

        ``RetryPolicy.retry_on`` defaults to ``RETRYABLE_CATEGORIES`` and import
        rule 8 refuses any declaration whose ``retry_on`` is not a subset of it,
        so a category absent from this set cannot be retried by any tool that
        imports successfully. No new machinery was needed; this is the proof.
        """
        assert ToolErrorCategory.OUTPUT_CONTRACT_VIOLATION not in RETRYABLE_CATEGORIES
        assert RETRYABLE_CATEGORIES == frozenset(
            {
                ToolErrorCategory.ADAPTER_UNAVAILABLE,
                ToolErrorCategory.TARGET_UNAVAILABLE,
            }
        )


class TestErrorPhrase:
    def test_every_category_has_a_phrase(self) -> None:
        """Totality, so a member added without a phrase fails here, not in a KeyError."""
        assert set(ERROR_PHRASES) == set(ToolErrorCategory)

    def test_the_phrase_is_fixed_and_says_nothing_about_the_payload(self) -> None:
        phrase = ERROR_PHRASES[ToolErrorCategory.OUTPUT_CONTRACT_VIOLATION]
        assert phrase == (
            "The tool returned a result that does not match its declared output."
        )
        # It is the public message, so it names no field, no value and no tool.
        assert "hunter2" not in phrase
        assert "{" not in phrase

    def test_it_is_distinct_from_internal_error(self) -> None:
        """The reason for a new member rather than reusing ``INTERNAL_ERROR``.

        ``INTERNAL_ERROR`` already covers a policy-engine malfunction and an
        unhandled adapter exception. Three causes with three different
        remediations must not share one category, or the category stops
        directing the investigation anywhere.
        """
        assert (
            ERROR_PHRASES[ToolErrorCategory.OUTPUT_CONTRACT_VIOLATION]
            != ERROR_PHRASES[ToolErrorCategory.INTERNAL_ERROR]
        )
