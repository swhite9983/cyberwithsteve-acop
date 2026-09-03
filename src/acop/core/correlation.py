"""Request correlation.

Every inbound request is assigned a ``request_id``. That identifier is bound to
the logging context and, from Milestone 4 onward, is the join key between an
AI request, the tool calls it produced, the approval record, and the audit
trail. Establishing it in Milestone 1 means later milestones do not have to
retrofit traceability through existing call sites.
"""

from __future__ import annotations

import uuid
from contextvars import ContextVar, Token

_request_id: ContextVar[str | None] = ContextVar("acop_request_id", default=None)

REQUEST_ID_HEADER = "X-Request-ID"

#: Upper bound on an externally supplied correlation identifier. Prevents an
#: unbounded caller-controlled string from reaching logs or the database.
MAX_REQUEST_ID_LENGTH = 128


def new_request_id() -> str:
    """Generate a fresh correlation identifier."""
    return uuid.uuid4().hex


def normalise_request_id(candidate: str | None) -> str:
    """Accept a caller-supplied correlation ID, or mint a new one.

    Caller-supplied values are permitted so that an upstream proxy or a future
    alerting webhook can propagate its own trace ID, but the value is length
    limited and stripped of control characters before it is trusted.
    """
    if not candidate:
        return new_request_id()
    cleaned = "".join(ch for ch in candidate if ch.isprintable()).strip()
    if not cleaned:
        return new_request_id()
    return cleaned[:MAX_REQUEST_ID_LENGTH]


def set_request_id(request_id: str) -> Token[str | None]:
    """Bind ``request_id`` to the current context."""
    return _request_id.set(request_id)


def reset_request_id(token: Token[str | None]) -> None:
    """Restore the previous correlation context."""
    _request_id.reset(token)


def get_request_id() -> str | None:
    """Return the correlation ID bound to the current context, if any."""
    return _request_id.get()
