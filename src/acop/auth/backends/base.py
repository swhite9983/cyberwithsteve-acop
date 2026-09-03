"""Authentication backend contract.

A backend turns presented credentials into a :class:`~acop.auth.principal.Principal`
or declines. It knows about its own credential format and nothing else.

:class:`PresentedCredentials` deliberately does not expose a FastAPI ``Request``.
Backends therefore cannot reach into framework internals, are trivially
testable, and an OIDC backend added later needs no change to any call site -
only a new entry in the authenticator's backend list.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field

from acop.auth.principal import Principal


@dataclass(frozen=True, slots=True)
class PresentedCredentials:
    """Credential material extracted from an inbound request."""

    headers: Mapping[str, str] = field(default_factory=dict)
    """Header names are matched case-insensitively by :meth:`header`."""

    source_address: str | None = None
    user_agent: str | None = None

    def header(self, name: str) -> str | None:
        """Return a header value, matched case-insensitively."""
        target = name.lower()
        for key, value in self.headers.items():
            if key.lower() == target:
                return value
        return None


class AuthenticationBackend(ABC):
    """Base class for authentication backends."""

    #: Short machine name, used in logs and metrics.
    name: str = "base"

    #: The authority identifier recorded on principals this backend issues.
    #: Written into every downstream record's ``principal_issuer`` column.
    issuer: str = "acop:unknown"

    @abstractmethod
    async def authenticate(self, credentials: PresentedCredentials) -> Principal | None:
        """Return a principal, or ``None`` if this backend does not apply.

        Returning ``None`` means "no credentials of my type were presented" and
        allows the next backend to try. A backend that finds credentials of its
        own type but judges them invalid must also return ``None`` - the
        distinction between "absent" and "invalid" is deliberately not exposed
        to the caller, so that authentication failures cannot be used to probe
        which credential types the deployment accepts.
        """

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{type(self).__name__} name={self.name!r} issuer={self.issuer!r}>"
