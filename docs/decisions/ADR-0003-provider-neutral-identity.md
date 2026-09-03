# ADR-0003: Provider-neutral identity, with API keys as the first backend

**Status:** Accepted
**Date:** 2026-09-03
**Milestone:** 1

## Context

Every durable record ACOP will create answers the question "who did this":
audit events (Milestone 1), incidents (10), change requests (11), approvals
(11), and tool executions (12). The approval workflow in section 30 of the
design brief is meaningless without a reliable answer.

The design brief places no authentication in Milestone 1. Adding a subject to
those tables and their call sites once they hold real data is one of the more
disruptive refactors available.

Separately, an identity provider will eventually replace or supplement API keys.
The **explicit requirement** is that this must not change any downstream audit,
incident, change, approval, or tool-execution record.

## Decision

Introduce identity in Milestone 1 as a provider-neutral abstraction with
pluggable authentication backends. Static API keys are the first backend.

### The identity contract

A `Principal` is described by four fields, and those four are what durable
records store:

| Field | Meaning | Example (API key) | Example (OIDC) |
|---|---|---|---|
| `subject` | Opaque, **stable** identifier for the actor | `acop:user:steve` | `acop:user:steve` |
| `principal_type` | `human` / `service` / `agent` / `system` | `human` | `human` |
| `issuer` | Which authority vouched for the identity | `acop:api-key` | the IdP's issuer URL |
| `auth_method` | How it was proven this request | `api_key` | `oidc` |

`subject` is deliberately **not** an email address, a username, a distinguished
name, or any provider's subject claim by necessity. It is whatever string
uniquely and permanently identifies the actor in this deployment. When an
identity provider is introduced, its subject claim is *mapped onto* this
existing value.

`issuer` is a free-form string, not an enum, because the set of future issuers
is not knowable now. It is recorded so an auditor can distinguish an API-key
assertion from an IdP assertion after the fact.

### How neutrality is enforced

Three mechanisms, because a documented convention is not an enforcement:

1. **`Principal.to_audit_fields()` is the only sanctioned way to write identity
   into a durable record**, and it returns exactly the four fields above. A new
   backend cannot widen what downstream tables store.
2. **`claims` is quarantined.** Provider-specific data (OIDC claims, group
   memberships, token metadata) lives there, and no code outside an
   authentication backend may read it. This is what stops provider concepts
   leaking into services, agents and tools.
3. **Backends receive `PresentedCredentials`, not a framework request object.**
   They cannot reach into transport internals, and they are trivially testable.

Roles are ACOP's own vocabulary (`admin`, `approver`, `operator`, `viewer`).
Each backend maps *into* it; no provider's group names are adopted verbatim.

### Adding an identity provider later

The entire integration is: implement `AuthenticationBackend`, map the provider's
subject claim onto the existing `subject`, map its groups onto ACOP roles, and
append it to the list in `_build_authenticator()`.

A test asserts that the same actor authenticated two different ways produces
identical record shapes and an identical `subject`.

### Denormalised, not a foreign key

Audit records store the identity as strings rather than a foreign key to an
accounts table. Changing the authentication backend — or removing a person's
account entirely — must not invalidate history.

## Alternatives considered

**No authentication in Milestone 1**, as the brief specifies. Rejected: the
retrofit cost through the audit and approval layers is the highest-cost item
identified in the architecture review.

**Full identity-provider integration in Milestone 1.** Rejected: it couples the
verification of a deliberately trivial milestone to an external service being
up, and adds meaningful debugging surface to a milestone whose value is that it
is boring.

**Authorisation via an external policy engine (OPA, Cedar).** Deferred. The
authorisation decision that matters is per-tool, and the tool registry does not
exist until Milestone 4. Introducing a policy engine before there are policies
would be premature.

## Consequences

**Positive**

- Audit records carry a subject from the very first row.
- The API-key backend's limitations (plaintext secrets, no rotation, no rate
  limiting) are contained entirely within one module.
- Milestone 11's approval engine has a stable identity contract to build on.

**Negative**

- Roughly 150 lines of code with only one backend behind it, which is
  abstraction ahead of a second implementation — normally a smell. Accepted
  because the requirement for a second backend is explicit rather than
  speculative.
- `subject` stability is an operational discipline the abstraction cannot
  enforce. If a subject is changed at IdP-integration time, history silently
  stops being attributable. This is the one thing to get right at that point,
  and it is called out in the README and `.env.example`.
