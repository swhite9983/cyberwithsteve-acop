"""One transaction per request, committed before the response is produced.

**The invariant.** When a mutating request returns a success status, its
transaction is already committed. A client that receives 201 and immediately
issues a dependent request must observe the committed state.

**Why this file exists.** ACOP originally committed in the teardown of the
``get_session`` dependency. FastAPI runs the exit code of a ``yield``
dependency from ``scope["fastapi_inner_astack"]``, and ``fastapi/routing.py``
unwinds that stack like this::

    async with AsyncExitStack() as request_stack:      # get_session teardown
        scope["fastapi_inner_astack"] = request_stack
        async with AsyncExitStack() as function_stack:
            response = await f(request)
        await response(scope, receive, send)           # <- response sent here
    # <- teardown runs here: session.commit()

The commit therefore happened *after* the bytes reached the client. Measured
against a real uvicorn server over TCP, an asset was still invisible on an
independent PostgreSQL connection in 116 of 150 requests that had already
returned 201, and the acceptance verifier failed with an
``ExclusionViolationError`` on ``ex_asset_fact_no_overlap`` when a re-assert
could not see the claim the previous request had created.

**The fix.** :class:`TransactionalRoute` wraps the endpoint callable itself, so
the commit happens inside ``f(request)`` - before a ``Response`` object exists,
and therefore before anything can be sent. The ordering guarantee comes from
ACOP's own call stack rather than from the framework's teardown ordering, which
has already changed once (FastAPI 0.106 moved it) and is not pinned by
``requirements.txt``.

**Rejected alternative.** FastAPI 0.141 accepts ``Depends(dep,
scope="function")``, which moves teardown to ``function_stack`` and would also
run the commit before the response. It is a two-word change, and it was
rejected because it makes a correctness guarantee depend on a framework
parameter that ``requirements.txt`` (``fastapi>=0.115,<1.0``) does not
guarantee is present - an older-but-permitted FastAPI would raise ``TypeError``
at import and take the service down. This bug exists precisely because
framework teardown ordering was trusted; the fix should not re-trust it.

**Read-only requests do not commit.** The session reports whether it actually
flushed any INSERT or UPDATE, so a pure ``GET`` ends with a rollback rather
than an empty ``COMMIT`` round trip. The flag - not the HTTP method - is the
trigger, because ``GET /whoami`` writes a Milestone 1 audit row and must still
commit it.
"""

from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable
from contextvars import ContextVar, Token
from typing import Any

from fastapi.routing import APIRoute
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession

from acop.core.logging import get_logger

logger = get_logger(__name__)


class RequestTransaction:
    """The session serving one request, plus whether it has written anything.

    ``wrote`` is a mutable attribute rather than a second context variable for
    a specific reason. It is set from a SQLAlchemy ``after_flush`` listener,
    which is synchronous ORM code executed inside the greenlet that
    ``AsyncSession`` uses to bridge to the sync ORM. A ``ContextVar.set()``
    performed in that greenlet does **not** propagate back to the awaiting
    coroutine's context, so the flag would always read ``False`` and nothing
    would ever commit. Mutating a shared object crosses that boundary because
    it is the same object, not the same context.
    """

    __slots__ = ("session", "wrote")

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.wrote = False


#: The transaction serving the request currently on this task. Set by
#: ``acop.api.deps.get_session``; read by the route wrapper, which cannot
#: receive it as an argument because not every endpoint declares a session.
#: Each request runs in its own task with its own context copy, so a value set
#: here is never visible to another request.
_REQUEST_TX: ContextVar[RequestTransaction | None] = ContextVar(
    "acop_request_transaction", default=None
)


def bind_request_session(session: AsyncSession) -> Token[RequestTransaction | None]:
    """Publish ``session`` as the current request's transaction.

    Returns the reset token so the dependency can restore the previous value on
    teardown. The ``after_flush`` listener is attached to the underlying sync
    session, which is where SQLAlchemy's ORM events live for an
    :class:`AsyncSession`. SQLAlchemy skips the flush entirely when nothing is
    pending, so the listener firing is a precise signal that an INSERT or
    UPDATE was actually emitted.
    """
    state = RequestTransaction(session)

    @event.listens_for(session.sync_session, "after_flush")
    def _mark_written(*_: object) -> None:
        state.wrote = True

    return _REQUEST_TX.set(state)


def unbind_request_session(token: Token[RequestTransaction | None]) -> None:
    """Restore the context value captured by :func:`bind_request_session`."""
    _REQUEST_TX.reset(token)


def current_request_transaction() -> RequestTransaction | None:
    """This request's transaction, or ``None`` if it needs no database."""
    return _REQUEST_TX.get()


def current_request_session() -> AsyncSession | None:
    """The session serving this request, or ``None`` if it needs no database."""
    state = _REQUEST_TX.get()
    return state.session if state is not None else None


def request_wrote() -> bool:
    """Whether this request has flushed at least one INSERT or UPDATE."""
    state = _REQUEST_TX.get()
    return state is not None and state.wrote


class TransactionalRoute(APIRoute):
    """An :class:`APIRoute` that commits the request transaction in-endpoint.

    The endpoint is wrapped **before** ``super().__init__()`` runs, and that
    ordering is not stylistic. ``APIRoute.__init__`` builds the dependency
    graph and the request handler from the callable it is given; replacing
    ``self.dependant.call`` afterwards is silently ignored, because the handler
    already holds the original. That was verified the hard way - the first
    version of this class wrapped after ``super().__init__()``, the wrapper
    never executed, and nothing committed.

    ``functools.wraps`` sets ``__wrapped__``, which ``inspect.signature``
    follows, so FastAPI introspects the real endpoint's signature: path and
    query parameters, response models and OpenAPI output are unchanged.

    Ordering, and why it is guaranteed:

    1. FastAPI solves dependencies; ``get_session`` publishes the session.
    2. FastAPI calls the endpoint - the wrapper below.
    3. The wrapper awaits the real endpoint, which performs the mutation and
       writes its audit record into the *same* session.
    4. The wrapper commits, once, covering both.
    5. Only then does the wrapper return, FastAPI build a ``Response``, and
       Starlette send it.

    Step 4 strictly precedes step 5 because step 4 is a statement inside the
    call whose return value step 5 consumes. No framework behaviour is relied
    on for that.
    """

    def __init__(self, path: str, endpoint: Callable[..., Any], **kwargs: Any) -> None:
        super().__init__(path, _commit_after(endpoint, path), **kwargs)


def _commit_after(
    endpoint: Callable[..., Any], path: str
) -> Callable[..., Awaitable[Any]]:
    """Wrap an endpoint so its transaction resolves before it returns."""

    @functools.wraps(endpoint)
    async def wrapper(**kwargs: Any) -> Any:
        try:
            result = await endpoint(**kwargs)
        except Exception:
            # Roll back before the exception becomes an error response, so a
            # refused request holds no locks while that response is written.
            # A denial recorded by AuditService.record_denial is untouched: it
            # committed on its own connection before this rollback.
            session = current_request_session()
            if session is not None:
                await _safe_rollback(session, path)
            raise

        state = current_request_transaction()
        if state is not None and state.wrote:
            # One commit for the whole request. The mutation and its SUCCESS
            # audit record were flushed into this same transaction, so they
            # become visible together or not at all.
            await state.session.commit()
        return result

    return wrapper


async def _safe_rollback(session: AsyncSession, path: str) -> None:
    """Roll back, never masking the exception that caused it."""
    try:
        await session.rollback()
    except Exception:
        logger.warning("request.rollback_failed", path=path)


__all__ = [
    "RequestTransaction",
    "TransactionalRoute",
    "bind_request_session",
    "current_request_session",
    "current_request_transaction",
    "request_wrote",
    "unbind_request_session",
]
