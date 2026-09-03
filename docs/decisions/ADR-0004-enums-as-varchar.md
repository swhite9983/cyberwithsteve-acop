# ADR-0004: Store enumerated values as VARCHAR, not PostgreSQL ENUM

**Status:** Accepted
**Date:** 2026-09-03
**Milestone:** 1

## Context

ACOP has many enumerated vocabularies: audit outcomes and severities (Milestone
1), source types and verification statuses (Milestone 2), permission classes
(Milestone 4), incident severities (Milestone 10), change risk levels (11).

Several of these will gain members as the platform grows. Verification statuses
in particular are likely to: the design brief already lists seven, and conflict
handling may need more.

## Decision

Store enumerated values as `VARCHAR` columns, with the enumeration defined in
Python (`enum.StrEnum`) and validated at the Pydantic and service layers.

## Rationale

**[Fact]** Altering a PostgreSQL `ENUM` type is awkward. `ADD VALUE` cannot run
inside a transaction block in older versions, which conflicts with Alembic's
transactional DDL. Removing or renaming a value requires creating a new type,
rewriting every dependent column, and dropping the old type.

**[Fact]** SQLAlchemy's `Enum` type with `native_enum=True` generates these types
automatically, and Alembic's autogenerate handles changes to them poorly —
enum changes are frequently missed or generated incorrectly.

**[Opinion]** The integrity benefit of a native enum is largely redundant here.
Values are validated by Pydantic at the API boundary and by the service layer
before persistence, and nothing writes to these tables except ACOP.

## Alternatives considered

**PostgreSQL native ENUM.** Rejected for the migration friction above.

**VARCHAR with a CHECK constraint.** Gives database-level integrity with easier
migration than a native enum — a CHECK is dropped and recreated rather than
requiring a type rewrite. Rejected for Milestone 1 as adding migration work
without materially reducing risk, given the validation already in place.
**Reconsider this** if a future subsystem ever writes to these tables outside
the ACOP service layer — bulk import (Milestone 5 discovery) is the plausible
case.

**Lookup tables with foreign keys.** Rejected: correct for user-editable
taxonomies, over-engineered for vocabularies defined in code.

## Consequences

- Adding a vocabulary member is a code change with no migration.
- The database will accept an invalid string if something bypasses the service
  layer. Nothing does today; this is the accepted risk.
- Column widths are sized generously (`VARCHAR(32)` for most) so that a longer
  member name does not force a migration.
