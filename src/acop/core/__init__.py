"""Cross-cutting application concerns: logging, correlation, errors, redaction."""

from acop.core.correlation import (
    REQUEST_ID_HEADER,
    get_request_id,
    new_request_id,
    normalise_request_id,
    reset_request_id,
    set_request_id,
)
from acop.core.exceptions import (
    AcopError,
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    DatabaseUnavailableError,
    DependencyUnavailableError,
    ModelNotAvailableError,
    OllamaError,
    OllamaTimeoutError,
    OllamaUnavailableError,
)
from acop.core.logging import configure_logging, get_logger
from acop.core.redaction import REDACTED, redact

__all__ = [
    "REDACTED",
    "REQUEST_ID_HEADER",
    "AcopError",
    "AuthenticationError",
    "AuthorizationError",
    "ConfigurationError",
    "DatabaseUnavailableError",
    "DependencyUnavailableError",
    "ModelNotAvailableError",
    "OllamaError",
    "OllamaTimeoutError",
    "OllamaUnavailableError",
    "configure_logging",
    "get_logger",
    "get_request_id",
    "new_request_id",
    "normalise_request_id",
    "redact",
    "reset_request_id",
    "set_request_id",
]
