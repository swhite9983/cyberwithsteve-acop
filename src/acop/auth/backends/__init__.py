"""Authentication backends.

Register additional backends here. A backend must not be referenced by anything
outside :mod:`acop.auth`.
"""

from acop.auth.backends.api_key import API_KEY_ISSUER, ApiKeyBackend
from acop.auth.backends.base import AuthenticationBackend, PresentedCredentials

__all__ = [
    "API_KEY_ISSUER",
    "ApiKeyBackend",
    "AuthenticationBackend",
    "PresentedCredentials",
]
