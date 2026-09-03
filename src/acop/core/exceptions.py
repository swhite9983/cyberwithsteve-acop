"""Application exception hierarchy.

A single base class gives the API layer one place to translate internal
failures into responses, and gives later milestones a defined contract for how
a failing tool reports itself to the orchestrator.

Design rule: an exception carries a *category*, never a raw upstream error
string destined for an unauthenticated response. Section 29 of the brief
requires ACOP to be explicit about what it does not know; leaking a raw
connection error to an anonymous caller is both an information disclosure and a
poor operational signal.
"""

from __future__ import annotations

from typing import Any


class AcopError(Exception):
    """Base class for all ACOP application errors."""

    #: Stable, machine-readable code. Safe to expose to callers.
    code: str = "acop_error"
    #: Default HTTP status used when this error surfaces through the API.
    http_status: int = 500
    #: Message shown to the caller. Must not contain secrets or internal detail.
    public_message: str = "An internal error occurred."

    def __init__(
        self,
        message: str | None = None,
        *,
        context: dict[str, Any] | None = None,
    ) -> None:
        self.internal_message = message or self.public_message
        self.context = context or {}
        super().__init__(self.internal_message)


class ConfigurationError(AcopError):
    """Configuration is missing or internally inconsistent."""

    code = "configuration_error"
    http_status = 500
    public_message = "The service is misconfigured."


class AuthenticationError(AcopError):
    """The caller could not be authenticated."""

    code = "authentication_failed"
    http_status = 401
    public_message = "Authentication failed."


class AuthorizationError(AcopError):
    """The caller was authenticated but is not permitted to act."""

    code = "not_authorized"
    http_status = 403
    public_message = "Not authorized."


class DependencyUnavailableError(AcopError):
    """A required downstream dependency could not be reached."""

    code = "dependency_unavailable"
    http_status = 503
    public_message = "A required dependency is unavailable."


class DatabaseUnavailableError(DependencyUnavailableError):
    """PostgreSQL could not be reached, or the connection was lost mid-query.

    Distinct from a general database error. A constraint violation is a bug in
    ACOP and should surface as 500; an unreachable database is an
    infrastructure condition and should surface as 503, matching what the
    health endpoint reports at the same moment.
    """

    code = "database_unavailable"
    http_status = 503
    public_message = "The ACOP datastore is unavailable."


class NotFoundError(AcopError):
    """The addressed resource does not exist."""

    code = "not_found"
    http_status = 404
    public_message = "The requested resource was not found."


class ValidationError(AcopError):
    """The request was well-formed but violates a domain rule."""

    code = "validation_failed"
    http_status = 422
    public_message = "The request violates a domain rule."


class ConflictError(AcopError):
    """The request contradicts existing state."""

    code = "conflict"
    http_status = 409
    public_message = "The request conflicts with existing state."


class IdentityConflictError(ConflictError):
    """Presented identifiers match more than one existing asset.

    ACOP refuses to guess. Picking one on a multi-match silently welds two real
    machines into one record, and there is no way back once facts have
    accumulated against the merged row - refusing is recoverable, guessing is
    not.
    """

    code = "identity_conflict"
    public_message = "Presented identifiers match more than one existing asset."


class SecretRejectedError(ValidationError):
    """A fact looked like it carried a credential.

    Raised at the CMDB service boundary. Key-based redaction cannot protect an
    entity-attribute-value table, because the attribute name lives in a column
    value rather than a mapping key - so the predicate is screened explicitly.
    """

    code = "secret_rejected"
    public_message = "The submitted fact appears to contain a secret and was rejected."


class VocabularyError(ValidationError):
    """A name violates the CMDB vocabulary or a registry rule."""

    code = "vocabulary_error"
    public_message = "The request uses an invalid name or an unsupported combination."


class OllamaError(AcopError):
    """Base class for inference-backend failures."""

    code = "ollama_error"
    http_status = 502
    public_message = "The inference backend returned an error."


class OllamaUnavailableError(OllamaError, DependencyUnavailableError):
    """Ollama could not be reached at all."""

    code = "ollama_unavailable"
    http_status = 503
    public_message = "The inference backend is unavailable."


class OllamaTimeoutError(OllamaError):
    """Ollama accepted the connection but did not respond in time."""

    code = "ollama_timeout"
    http_status = 504
    public_message = "The inference backend timed out."


class ModelNotAvailableError(OllamaError):
    """The configured model is not present on the inference host."""

    code = "model_not_available"
    http_status = 503
    public_message = "The configured model is not available."
