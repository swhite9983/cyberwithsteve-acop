"""Provider-neutral identity model.

This is the contract every downstream subsystem depends on: audit records,
incidents, changes, approvals and tool executions all reference a
:class:`Principal`, and none of them know or care how that principal was
authenticated.

The neutrality rule, stated precisely:

* A ``Principal`` is described by four fields - ``subject``, ``principal_type``,
  ``issuer`` and ``auth_method``. Those four are what downstream records store.
* ``subject`` is an **opaque, stable** identifier. It is not an email address,
  not a username, not a distinguished name, not an OIDC ``sub`` claim by
  necessity - it is whatever string uniquely and permanently identifies the
  acting party in this deployment. When an identity provider is introduced
  later, its subject claim is *mapped onto* this value; historical records stay
  attributable because the value did not change.
* ``issuer`` records which authority vouched for the identity, so that an
  auditor can tell an API-key assertion from an OIDC assertion after the fact.
  It is a free-form string, not an enum, because the set of future issuers is
  not knowable now.
* Provider-specific data (OIDC claims, group memberships, token metadata) lives
  in ``claims`` and is **quarantined**: no code outside an authentication
  backend may read it. This is what stops provider assumptions from leaking
  into the platform.

Roles are the authorisation vocabulary. They are ACOP's own vocabulary, mapped
*into* by each backend, never adopted from a provider's group names verbatim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class PrincipalType(StrEnum):
    """What kind of actor this is.

    Distinguishing these matters for AI governance (section 18): an action
    taken by an autonomous agent must be distinguishable in the audit trail
    from the same action taken by a human, even when both run under the same
    integration credentials.
    """

    HUMAN = "human"
    SERVICE = "service"
    AGENT = "agent"
    SYSTEM = "system"


class AuthMethod(StrEnum):
    """How the identity was proven for this request."""

    API_KEY = "api_key"
    OIDC = "oidc"
    MTLS = "mtls"
    SYSTEM = "system"


class Role(StrEnum):
    """ACOP's own authorisation vocabulary.

    Deliberately small. Milestone 4 maps tool permission classes onto these;
    until then they exist so audit records and endpoint guards have something
    stable to reference.
    """

    ADMIN = "admin"
    """Full access, including approving Class 3 changes."""

    APPROVER = "approver"
    """May approve changes but not administer the platform."""

    OPERATOR = "operator"
    """May request actions and run read-only tools."""

    VIEWER = "viewer"
    """Read-only access to ACOP's own data."""


@dataclass(frozen=True, slots=True)
class Principal:
    """An authenticated actor.

    Frozen so that a principal cannot be mutated after authentication - an
    authorisation decision made early in a request cannot be invalidated by
    later code changing the roles.
    """

    subject: str
    principal_type: PrincipalType
    issuer: str
    auth_method: AuthMethod
    display_name: str = ""
    roles: frozenset[str] = field(default_factory=frozenset)
    authenticated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    claims: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)
    """Backend-specific data. Quarantined: only the issuing backend may read it."""

    def has_role(self, role: str | Role) -> bool:
        """Return ``True`` if this principal holds ``role``."""
        wanted = role.value if isinstance(role, Role) else role
        return wanted in self.roles

    def has_any_role(self, *roles: str | Role) -> bool:
        """Return ``True`` if this principal holds at least one of ``roles``."""
        return any(self.has_role(role) for role in roles)

    def to_audit_fields(self) -> dict[str, str]:
        """Return the provider-neutral identity fields for persistence.

        This method is the *only* sanctioned way to write identity into a
        durable record. It returns exactly the four neutral fields, so a new
        authentication backend can never widen what downstream tables store.
        """
        return {
            "principal_subject": self.subject,
            "principal_type": self.principal_type.value,
            "principal_issuer": self.issuer,
            "auth_method": self.auth_method.value,
        }


#: Identity used for actions ACOP takes on its own behalf - scheduled
#: collection, startup tasks, alert-driven investigation (Milestone 32). Given a
#: real principal rather than a null value so that no audit record is ever
#: written without a subject.
SYSTEM_PRINCIPAL = Principal(
    subject="acop:system",
    principal_type=PrincipalType.SYSTEM,
    issuer="acop:internal",
    auth_method=AuthMethod.SYSTEM,
    display_name="ACOP System",
    roles=frozenset({Role.OPERATOR.value}),
)

#: Identity used for unauthenticated requests to public endpoints (liveness and
#: readiness probes). Holds no roles.
ANONYMOUS_PRINCIPAL = Principal(
    subject="acop:anonymous",
    principal_type=PrincipalType.SYSTEM,
    issuer="acop:internal",
    auth_method=AuthMethod.SYSTEM,
    display_name="Anonymous",
    roles=frozenset(),
)
