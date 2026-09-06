"""Tool-framework errors, and the one place a failure becomes a public phrase.

Every error here carries a :class:`~acop.models.tool_vocabulary.ToolErrorCategory`
and takes its public message from :data:`ERROR_PHRASES` - a fixed phrase per
category, never text from an adapter. That is the whole point of the class:
adapter output is the least trustworthy string in the system (it may quote a
device banner, an exception containing a connection string, or a response body
that echoed a credential), and a deny-list over it fails open the first time
something unanticipated comes back.

The internal message and context still carry the detail, and both go to the
structured log keyed by invocation id. Nothing from an adapter reaches an HTTP
response, an audit record, an invocation row, or a model.

Three design notes:

* ``ToolDeclarationError`` is deliberately *not* an
  :class:`~acop.core.exceptions.AcopError` subclass that maps to a status code.
  It is raised at import, so the correct outcome is a failed process, not a 500.
* ``ProhibitedCapabilityError`` maps to 403, not 404. Hiding the existence of a
  prohibited capability would be security theatre - the refusal is the feature,
  and it should be visible, loud and audited.
* ``InvocationStateConflictError`` is the one class here that carries no
  :class:`~acop.models.tool_vocabulary.ToolErrorCategory`, because it does not
  describe a tool failing. It describes a *request* arriving too late, and no
  category in that enum says that. It takes M1's ``ConflictError`` and its
  409 instead of inventing a category the invocation row would then have to be
  able to store.
"""

from __future__ import annotations

from typing import Any

from acop.core.exceptions import AcopError, ConflictError
from acop.models.tool_vocabulary import ERROR_PHRASES, ToolErrorCategory


class ToolDeclarationError(Exception):
    """A tool declaration violates an import-time rule.

    Raised while the catalog is being imported, so it fails the process rather
    than a request. This is the intended severity: a declaration that breaks
    rule 9, 10 or 11 would put a secret-bearing, network-locator or command
    field into a tool's input schema, and no amount of runtime checking makes
    that safe afterwards.
    """


class AdapterBindingError(Exception):
    """A declaration names an adapter that no code registers.

    Also an import-time failure. A tool whose adapter does not resolve is a
    tool that can be requested and never executed, which would surface as a
    confusing runtime denial instead of a build failure.
    """


class ToolError(AcopError):
    """Base for runtime tool failures.

    The public message is chosen by category. Callers may not supply one, which
    is what makes it impossible to leak adapter text by accident.
    """

    code = "tool_error"
    http_status = 500
    category: ToolErrorCategory = ToolErrorCategory.INTERNAL_ERROR

    def __init__(
        self,
        message: str | None = None,
        *,
        category: ToolErrorCategory | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        self.category = category or type(self).category
        # Per-instance, following the Milestone 3 pattern: the shared API
        # handler stays untouched and every category still gets its own phrase.
        self.public_message = ERROR_PHRASES[self.category]
        super().__init__(message, context=context)


class ToolNotFoundError(ToolError):
    """No tool with that name and version is bound to executable code.

    This is what a ``tool_registration`` row with no matching code declaration
    produces - the Capability Binding Invariant, observed from the outside.
    """

    code = "tool_not_found"
    http_status = 404
    category = ToolErrorCategory.CAPABILITY_NOT_BOUND


class ToolDisabledError(ToolError):
    """The tool exists in code but is DISABLED or RETIRED in the database."""

    code = "tool_disabled"
    http_status = 409
    category = ToolErrorCategory.POLICY_DENIED


class ProhibitedCapabilityError(ToolError):
    """The capability is prohibited. No role, approval or configuration lifts it."""

    code = "prohibited_capability"
    http_status = 403
    category = ToolErrorCategory.POLICY_DENIED


class ToolAuthorizationError(ToolError):
    """The principal does not hold the roles this tool requires."""

    code = "tool_not_authorized"
    http_status = 403
    category = ToolErrorCategory.AUTHORIZATION


class ToolPolicyDeniedError(ToolError):
    """A policy gate refused the invocation."""

    code = "tool_policy_denied"
    http_status = 403
    category = ToolErrorCategory.POLICY_DENIED


class PolicyEngineFailureError(ToolError):
    """The policy engine could not complete an evaluation, so it refused.

    Separate from ``ToolPolicyDeniedError`` even though both are a 403, and the
    reason is operational rather than contractual. A deploy that makes
    ``evaluate`` throw on every request would otherwise reach on-call as
    "denials are up", which reads as a permissions misconfiguration and sends
    the investigation to the role table instead of to the traceback.

    403 rather than 500 because the engine did decide: it failed closed, and a
    refusal is the truthful answer to give. A 500 would also make the malfunction
    legible to an unauthorised caller from the status line alone.
    """

    code = "policy_engine_error"
    http_status = 403
    category = ToolErrorCategory.INTERNAL_ERROR


class InvalidTargetError(ToolError):
    """The target is unknown, retired, or of a type this tool does not accept."""

    code = "invalid_target"
    http_status = 422
    category = ToolErrorCategory.INVALID_TARGET


class ToolInputError(ToolError):
    """The request does not satisfy the tool's input schema."""

    code = "tool_input_invalid"
    http_status = 422
    category = ToolErrorCategory.VALIDATION_ERROR


class IdempotencyConflictError(ToolError):
    """The idempotency key was used for a different execution envelope.

    Reusing a key for the *same* envelope returns the original invocation and
    is not an error. Reusing it for a different one is, because silently
    executing the new request under the old key would defeat the guarantee the
    key exists to provide.
    """

    code = "idempotency_conflict"
    http_status = 409
    category = ToolErrorCategory.IDEMPOTENCY_CONFLICT


class ApprovalRequiredError(ToolError):
    """The invocation cannot proceed until it is approved."""

    code = "approval_required"
    http_status = 409
    category = ToolErrorCategory.APPROVAL_REQUIRED


class DuplicateApprovalError(ToolError):
    """This approver has already approved this invocation.

    409 rather than the 500 an escaping ``IntegrityError`` produced. Two
    approvals from one person are one approval, and a second attempt is a
    foreseeable client action - a double-submitted form, a retried POST whose
    response was lost - so reporting it as a server error would send an
    operator hunting a fault that does not exist.

    The category is ``APPROVAL_REQUIRED`` because that remains the truth about
    the invocation: the duplicate bought nothing, and it is still waiting for
    an approval from somebody else.
    """

    code = "duplicate_approval"
    http_status = 409
    category = ToolErrorCategory.APPROVAL_REQUIRED


class ApprovalDeniedError(ToolError):
    """An eligible approver denied the invocation."""

    code = "approval_denied"
    http_status = 403
    category = ToolErrorCategory.APPROVAL_DENIED


class ApprovalExpiredError(ToolError):
    """The approval's TTL elapsed before execution began."""

    code = "approval_expired"
    http_status = 409
    category = ToolErrorCategory.APPROVAL_EXPIRED


class ApprovalEnvelopeMismatchError(ToolError):
    """The approval was given for a different execution envelope.

    The approver agreed to a specific request. If anything the digest covers
    has changed since, the approval does not transfer - it is invalidated, not
    carried forward.
    """

    code = "approval_envelope_mismatch"
    http_status = 409
    category = ToolErrorCategory.APPROVAL_INVALID_ENVELOPE


class SelfApprovalForbiddenError(ToolError):
    """The requester attempted to approve their own invocation."""

    code = "self_approval_forbidden"
    http_status = 403
    category = ToolErrorCategory.SELF_APPROVAL_FORBIDDEN


class ToolTimeoutError(ToolError):
    """The tool exceeded its declared deadline."""

    code = "tool_timeout"
    http_status = 504
    category = ToolErrorCategory.TIMEOUT


class AdapterUnavailableError(ToolError):
    """The adapter could not be reached. Retryable when the tool permits it."""

    code = "adapter_unavailable"
    http_status = 503
    category = ToolErrorCategory.ADAPTER_UNAVAILABLE


class TargetUnavailableError(ToolError):
    """The target could not be reached. Retryable when the tool permits it."""

    code = "target_unavailable"
    http_status = 503
    category = ToolErrorCategory.TARGET_UNAVAILABLE


class ToolExecutionError(ToolError):
    """The adapter reported a failure."""

    code = "tool_execution_failed"
    http_status = 502
    category = ToolErrorCategory.EXECUTION_FAILED


class InvalidStateTransitionError(ToolError):
    """A transition the state machine does not permit was attempted.

    Always a bug, never a user error, so it is a 500. It is a distinct class
    rather than a bare assertion so the dispatcher can catch it, record the
    attempted transition, and refuse rather than proceeding.
    """

    code = "invalid_state_transition"
    http_status = 500
    category = ToolErrorCategory.INTERNAL_ERROR


class StaleTransitionError(ToolError):
    """A transition was attempted from a state the row no longer holds.

    Distinct from ``InvalidStateTransitionError``: the move was legal, and it
    was legal *from what this worker last read*. Somebody else moved the row
    first. The write matched zero rows and nothing was changed, which is the
    point - the alternative is overwriting a newer, truer outcome with an older
    one, and that is how a completed execution gets relabelled as unknown.

    Loud by default, and a 500, because on the request path there is no benign
    reading of it: nothing else should have been touching that invocation. The
    background sweepers are the exception and they catch it explicitly, because
    losing a race to a worker that finished its job is the outcome they want.
    """

    code = "stale_transition"
    http_status = 500
    category = ToolErrorCategory.INTERNAL_ERROR


class InvocationStateConflictError(ConflictError):
    """A request lost a legitimate race for an invocation's next state.

    The 409 half of :class:`StaleTransitionError`, and the distinction is who
    was at fault. A stale transition on the request path is *usually* a defect:
    nothing else should have been touching that invocation, so 500 is the
    honest answer and the loud one. Cancellation is the exception. A person
    reading a queue decides to withdraw a request at the same moment a worker
    claims it, or an approver advances it, and both actions were correct when
    they were taken. Nothing is broken; the client simply asked for a state the
    row had already left.

    Reporting that as 500 sends an operator to look for a fault that does not
    exist and tells the client to retry something that will never succeed. 409
    says the true thing - the current state conflicts with the request - and a
    client can re-read the invocation and see why.

    The public message names no state, no identifier and no exception detail.
    Which state won is visible through ``GET /tool-invocations/{id}`` to a
    caller entitled to see it, and is in the structured log and the audit
    record for everybody else; putting it in the error body would leak the
    progress of an invocation to a caller who lost the right to read it the
    moment they were not its requester.
    """

    code = "invocation_state_conflict"
    public_message = (
        "The invocation changed state before this request was applied. "
        "Nothing was changed."
    )


__all__ = [
    "AdapterBindingError",
    "AdapterUnavailableError",
    "ApprovalDeniedError",
    "ApprovalEnvelopeMismatchError",
    "ApprovalExpiredError",
    "ApprovalRequiredError",
    "DuplicateApprovalError",
    "IdempotencyConflictError",
    "InvalidStateTransitionError",
    "InvalidTargetError",
    "InvocationStateConflictError",
    "PolicyEngineFailureError",
    "ProhibitedCapabilityError",
    "SelfApprovalForbiddenError",
    "StaleTransitionError",
    "TargetUnavailableError",
    "ToolAuthorizationError",
    "ToolDeclarationError",
    "ToolDisabledError",
    "ToolError",
    "ToolExecutionError",
    "ToolInputError",
    "ToolNotFoundError",
    "ToolPolicyDeniedError",
    "ToolTimeoutError",
]
