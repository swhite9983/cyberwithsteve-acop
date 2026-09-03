"""Identity and authentication.

Everything outside this package deals in :class:`Principal` objects and never
in credentials, tokens, or provider concepts.
"""

from acop.auth.authenticator import Authenticator
from acop.auth.backends.api_key import API_KEY_ISSUER, ApiKeyBackend
from acop.auth.backends.base import AuthenticationBackend, PresentedCredentials
from acop.auth.principal import (
    ANONYMOUS_PRINCIPAL,
    SYSTEM_PRINCIPAL,
    AuthMethod,
    Principal,
    PrincipalType,
    Role,
)

__all__ = [
    "ANONYMOUS_PRINCIPAL",
    "API_KEY_ISSUER",
    "SYSTEM_PRINCIPAL",
    "ApiKeyBackend",
    "AuthMethod",
    "AuthenticationBackend",
    "Authenticator",
    "PresentedCredentials",
    "Principal",
    "PrincipalType",
    "Role",
]
