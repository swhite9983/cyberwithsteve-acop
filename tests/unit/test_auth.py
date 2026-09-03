"""Identity and authentication.

The tests that matter most here are the neutrality tests: they assert that
nothing outside :mod:`acop.auth` can observe how a principal was authenticated,
beyond the four declared identity fields.
"""

from __future__ import annotations

import pytest

from acop.auth import (
    ApiKeyBackend,
    AuthenticationBackend,
    Authenticator,
    AuthMethod,
    PresentedCredentials,
    Principal,
    PrincipalType,
    Role,
)
from acop.config import ApiKeyPrincipalConfig
from acop.core.exceptions import AuthenticationError

SECRET = "correct-horse-battery-staple"
SUBJECT = "acop:user:steve"


def make_backend(**overrides: object) -> ApiKeyBackend:
    key = ApiKeyPrincipalConfig(
        subject=SUBJECT,
        secret=SECRET,
        display_name="Steve White",
        roles=["admin", "operator"],
        principal_type="human",
        **overrides,  # type: ignore[arg-type]
    )
    return ApiKeyBackend([key])


class TestApiKeyBackend:
    async def test_valid_key_produces_a_principal(self) -> None:
        backend = make_backend()
        principal = await backend.authenticate(
            PresentedCredentials(headers={"X-ACOP-API-Key": SECRET})
        )
        assert principal is not None
        assert principal.subject == SUBJECT
        assert principal.principal_type is PrincipalType.HUMAN
        assert principal.auth_method is AuthMethod.API_KEY
        assert principal.issuer == "acop:api-key"
        assert principal.roles == frozenset({"admin", "operator"})

    async def test_header_match_is_case_insensitive(self) -> None:
        backend = make_backend()
        principal = await backend.authenticate(
            PresentedCredentials(headers={"x-acop-api-key": SECRET})
        )
        assert principal is not None

    async def test_bearer_token_is_accepted(self) -> None:
        # Lets a client already configured for a bearer-token identity provider
        # work unchanged against the Milestone 1 backend.
        backend = make_backend()
        principal = await backend.authenticate(
            PresentedCredentials(headers={"Authorization": f"Bearer {SECRET}"})
        )
        assert principal is not None
        assert principal.subject == SUBJECT

    async def test_wrong_key_is_declined(self) -> None:
        backend = make_backend()
        assert (
            await backend.authenticate(
                PresentedCredentials(headers={"X-ACOP-API-Key": "wrong"})
            )
            is None
        )

    async def test_absent_credentials_are_declined(self) -> None:
        backend = make_backend()
        assert await backend.authenticate(PresentedCredentials(headers={})) is None

    async def test_empty_key_is_declined(self) -> None:
        backend = make_backend()
        assert (
            await backend.authenticate(
                PresentedCredentials(headers={"X-ACOP-API-Key": ""})
            )
            is None
        )

    async def test_no_provider_specific_claims_are_populated(self) -> None:
        # The quarantine rule: only a backend may write claims, and the API-key
        # backend has nothing provider-specific worth carrying.
        backend = make_backend()
        principal = await backend.authenticate(
            PresentedCredentials(headers={"X-ACOP-API-Key": SECRET})
        )
        assert principal is not None
        assert principal.claims == {}


class TestPrincipalNeutrality:
    def test_audit_fields_are_exactly_the_neutral_four(self) -> None:
        principal = Principal(
            subject=SUBJECT,
            principal_type=PrincipalType.HUMAN,
            issuer="acop:api-key",
            auth_method=AuthMethod.API_KEY,
            display_name="Steve White",
            roles=frozenset({"admin"}),
            claims={"groups": ["lab-admins"], "raw_token": "xyz"},
        )
        fields = principal.to_audit_fields()
        assert set(fields) == {
            "principal_subject",
            "principal_type",
            "principal_issuer",
            "auth_method",
        }
        # Provider-specific data must never reach a persisted record.
        assert "xyz" not in str(fields)
        assert "lab-admins" not in str(fields)

    def test_audit_fields_are_identical_across_auth_methods(self) -> None:
        """The neutrality acceptance test.

        The same actor, authenticated two different ways, produces the same
        subject and principal_type. Only issuer and auth_method differ - which
        is the point: an auditor can tell how the identity was proven without
        the record's shape changing.
        """
        via_api_key = Principal(
            subject=SUBJECT,
            principal_type=PrincipalType.HUMAN,
            issuer="acop:api-key",
            auth_method=AuthMethod.API_KEY,
        )
        via_oidc = Principal(
            subject=SUBJECT,
            principal_type=PrincipalType.HUMAN,
            issuer="https://idp.example.invalid/application/o/acop/",
            auth_method=AuthMethod.OIDC,
        )

        api_fields = via_api_key.to_audit_fields()
        oidc_fields = via_oidc.to_audit_fields()

        assert api_fields.keys() == oidc_fields.keys()
        assert api_fields["principal_subject"] == oidc_fields["principal_subject"]
        assert api_fields["principal_type"] == oidc_fields["principal_type"]
        assert api_fields["auth_method"] != oidc_fields["auth_method"]

    def test_principal_is_immutable(self) -> None:
        principal = Principal(
            subject=SUBJECT,
            principal_type=PrincipalType.HUMAN,
            issuer="acop:api-key",
            auth_method=AuthMethod.API_KEY,
            roles=frozenset({"viewer"}),
        )
        with pytest.raises((AttributeError, TypeError)):
            principal.roles = frozenset({"admin"})  # type: ignore[misc]

    def test_role_checks(self) -> None:
        principal = Principal(
            subject=SUBJECT,
            principal_type=PrincipalType.HUMAN,
            issuer="acop:api-key",
            auth_method=AuthMethod.API_KEY,
            roles=frozenset({"operator"}),
        )
        assert principal.has_role(Role.OPERATOR)
        assert principal.has_role("operator")
        assert not principal.has_role(Role.ADMIN)
        assert principal.has_any_role(Role.ADMIN, Role.OPERATOR)


class _AlwaysDeclines(AuthenticationBackend):
    name = "declines"
    issuer = "test:declines"

    async def authenticate(self, credentials: PresentedCredentials) -> Principal | None:
        return None


class _AlwaysAccepts(AuthenticationBackend):
    name = "accepts"
    issuer = "test:accepts"

    async def authenticate(self, credentials: PresentedCredentials) -> Principal:
        return Principal(
            subject="acop:test",
            principal_type=PrincipalType.SERVICE,
            issuer=self.issuer,
            auth_method=AuthMethod.OIDC,
        )


class TestAuthenticator:
    async def test_first_accepting_backend_wins(self) -> None:
        authenticator = Authenticator([_AlwaysDeclines(), _AlwaysAccepts()])
        principal = await authenticator.authenticate(PresentedCredentials())
        assert principal.issuer == "test:accepts"

    async def test_adding_a_backend_requires_no_downstream_change(self) -> None:
        """Registering a second backend is the entire OIDC integration change."""
        authenticator = Authenticator([make_backend(), _AlwaysAccepts()])
        by_key = await authenticator.authenticate(
            PresentedCredentials(headers={"X-ACOP-API-Key": SECRET})
        )
        by_other = await authenticator.authenticate(PresentedCredentials())
        assert by_key.to_audit_fields().keys() == by_other.to_audit_fields().keys()

    async def test_no_backend_accepts_raises(self) -> None:
        authenticator = Authenticator([_AlwaysDeclines()])
        with pytest.raises(AuthenticationError):
            await authenticator.authenticate(PresentedCredentials())

    async def test_disabled_authentication_returns_the_anonymous_principal(
        self,
    ) -> None:
        anonymous = Principal(
            subject="acop:anonymous",
            principal_type=PrincipalType.SYSTEM,
            issuer="acop:internal",
            auth_method=AuthMethod.SYSTEM,
        )
        authenticator = Authenticator(
            [make_backend()], enabled=False, anonymous_principal=anonymous
        )
        principal = await authenticator.authenticate(PresentedCredentials())
        assert principal.subject == "acop:anonymous"
        assert principal.roles == frozenset()
