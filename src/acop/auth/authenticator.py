"""Authentication orchestration.

Holds an ordered list of backends and returns the first principal produced.
Adding OIDC later is a one-line registration change here; no endpoint, service,
audit record or tool sees any difference.
"""

from __future__ import annotations

from collections.abc import Sequence

from acop.auth.backends.base import AuthenticationBackend, PresentedCredentials
from acop.auth.principal import Principal
from acop.core.exceptions import AuthenticationError
from acop.core.logging import get_logger

logger = get_logger(__name__)


class Authenticator:
    """Try each configured backend in order."""

    def __init__(
        self,
        backends: Sequence[AuthenticationBackend],
        *,
        enabled: bool = True,
        anonymous_principal: Principal | None = None,
    ) -> None:
        """
        Args:
            backends: Ordered authentication backends. Typed as a Sequence
                rather than a list so that a list of one concrete backend
                type is accepted (list is invariant).
            enabled: When ``False``, every request resolves to
                ``anonymous_principal``. Intended for local development and
                automated tests only; :class:`acop.config.Settings` refuses to
                start a staging or production deployment without credentials.
            anonymous_principal: Identity returned when authentication is
                disabled.
        """
        self._backends = list(backends)
        self._enabled = enabled
        self._anonymous = anonymous_principal

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def backend_names(self) -> list[str]:
        return [backend.name for backend in self._backends]

    async def authenticate(self, credentials: PresentedCredentials) -> Principal:
        """Resolve credentials to a principal.

        Raises:
            AuthenticationError: If no backend accepted the credentials.
        """
        if not self._enabled:
            if self._anonymous is None:  # pragma: no cover - guarded by wiring
                raise AuthenticationError(
                    "Authentication is disabled but no anonymous principal is configured."
                )
            return self._anonymous

        for backend in self._backends:
            principal = await backend.authenticate(credentials)
            if principal is not None:
                logger.debug(
                    "auth.succeeded",
                    backend=backend.name,
                    subject=principal.subject,
                    principal_type=principal.principal_type.value,
                )
                return principal

        raise AuthenticationError(
            "No configured authentication backend accepted the presented credentials.",
            context={"backends": self.backend_names},
        )
