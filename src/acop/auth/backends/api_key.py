"""Static API-key authentication backend.

This is the **Milestone 1 authentication mechanism only**. It exists so that
identity, authorisation and audit have something real to work with before an
identity provider is integrated, without any part of the platform above
:mod:`acop.auth` depending on how the identity was established.

Known limitations, recorded deliberately rather than discovered later:

* Secrets are held in configuration in plaintext. Replaced when a secrets
  manager is introduced; the comparison is already constant-time so that the
  change is a storage change, not a logic change.
* There is no credential rotation workflow, expiry, or revocation list.
* There is no rate limiting on authentication attempts. Acceptable because the
  API is not internet-exposed in this deployment; revisit before any external
  exposure.

None of these limitations are visible to callers of :meth:`authenticate`, which
is the point.
"""

from __future__ import annotations

import secrets

from acop.auth.backends.base import AuthenticationBackend, PresentedCredentials
from acop.auth.principal import AuthMethod, Principal, PrincipalType
from acop.config import ApiKeyPrincipalConfig
from acop.core.logging import get_logger

logger = get_logger(__name__)

#: Authority identifier recorded on principals issued by this backend.
API_KEY_ISSUER = "acop:api-key"


class ApiKeyBackend(AuthenticationBackend):
    """Authenticate a caller against a static list of configured keys."""

    name = "api_key"
    issuer = API_KEY_ISSUER

    def __init__(
        self,
        keys: list[ApiKeyPrincipalConfig],
        header_name: str = "X-ACOP-API-Key",
    ) -> None:
        self._keys = list(keys)
        self._header_name = header_name

    @property
    def header_name(self) -> str:
        return self._header_name

    @property
    def configured_key_count(self) -> int:
        return len(self._keys)

    async def authenticate(self, credentials: PresentedCredentials) -> Principal | None:
        """Return a principal for a valid key, otherwise ``None``."""
        presented = credentials.header(self._header_name)
        if presented is None:
            # Also accept "Authorization: Bearer <key>" so that a client
            # configured for a future OIDC deployment needs no header change.
            authorization = credentials.header("Authorization")
            if authorization and authorization.lower().startswith("bearer "):
                presented = authorization[7:].strip()

        if not presented:
            return None

        matched: ApiKeyPrincipalConfig | None = None
        for candidate in self._keys:
            # Compare every configured key rather than breaking on first match,
            # so that response time does not reveal the position of a key in the
            # configured list.
            if secrets.compare_digest(candidate.secret.get_secret_value(), presented):
                matched = candidate

        if matched is None:
            logger.warning("auth.api_key.rejected", backend=self.name)
            return None

        return Principal(
            subject=matched.subject,
            principal_type=PrincipalType(matched.principal_type),
            issuer=self.issuer,
            auth_method=AuthMethod.API_KEY,
            display_name=matched.display_name or matched.subject,
            roles=frozenset(matched.roles),
            # Nothing provider-specific to carry. Kept empty rather than
            # populated with configuration detail, to keep the quarantine rule
            # honest from the first backend onward.
            claims={},
        )
