# Audit log immutability

An audit log that the application can rewrite is not an audit log. Immutability
is enforced in layers, so that no single mistake defeats it.

## Layer 1 — Model (applied)

`AuditEvent` has `occurred_at` and `recorded_at` but **no** `updated_at`. There
is no ORM path that expresses an update.

## Layer 2 — Service (applied)

`AuditService` exposes exactly one public method: `record`. No update, no
delete, no bulk operation. A test asserts the public surface:

```python
public_methods = {n for n in dir(AuditService) if not n.startswith("_")}
assert public_methods == {"record"}
```

This is the layer a future contributor is most likely to erode, which is why it
is pinned by a test rather than a convention.

## Layer 3 — Database role (documented, not yet applied)

Milestone 1 runs as the database owner, which can drop the table. That is
acceptable while the log records only health checks and identity introspection.
It stops being acceptable once the log is evidence for change approvals.

Apply this in the same milestone that introduces the secrets manager, before
Milestone 12:

```sql
-- Migration role: owns the schema, used only by the `migrate` service.
CREATE ROLE acop_migrate LOGIN PASSWORD '<from secrets manager>';
ALTER DATABASE acop OWNER TO acop_migrate;

-- Application role: cannot rewrite history.
CREATE ROLE acop_app LOGIN PASSWORD '<from secrets manager>';
GRANT CONNECT ON DATABASE acop TO acop_app;
GRANT USAGE ON SCHEMA public TO acop_app;

-- Full DML on ordinary tables.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO acop_app;

-- Append-only on the audit log. This is the whole point.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_event FROM acop_app;
GRANT SELECT, INSERT ON audit_event TO acop_app;

-- Same rules for tables created later.
ALTER DEFAULT PRIVILEGES FOR ROLE acop_migrate IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO acop_app;
```

The application then uses `acop_app`; only the `migrate` service uses
`acop_migrate`. Verify with:

```sql
SELECT grantee, privilege_type
FROM information_schema.role_table_grants
WHERE table_name = 'audit_event' AND grantee = 'acop_app';
-- expect exactly SELECT and INSERT
```

Note the residual risk this leaves: `acop_migrate` can still alter the table.
That is unavoidable — something must be able to run migrations — and it is why
Layer 4 exists.

## Layer 4 — Off-host copy (future)

Database-level controls do not protect against an attacker who compromises the
host. For the audit log to be evidence rather than merely a record, a copy must
leave the machine:

- Ship audit events to a write-once destination (a syslog collector with
  append-only storage, or object storage with an immutability policy).
- Include a per-record hash chain so tampering with the local table is
  detectable by comparison.

**[Opinion]** This matters more for the portfolio and GRC value of the project
than for the home lab's actual risk profile, but it is the difference between an
audit log and an audit *trail*, and it is worth doing once incidents and changes
are real.

## What is deliberately not enforced

**Database triggers rejecting UPDATE/DELETE.** Rejected: a trigger can be
dropped by whatever role can create it, so it adds ceremony rather than
security. The role grant is the real control.

**Application-level hash chaining in Milestone 1.** Deferred to Layer 4, where
it belongs alongside off-host shipping. Chaining without an off-host copy
protects against nothing an attacker with database access cannot also rewrite.

## Retention

Not yet defined. Decide before Milestone 10, when incidents begin referencing
audit records as evidence. Considerations: incident investigations need the
window around the event; change validation needs the window around the change;
`occurred_at` is indexed, so time-based partitioning is straightforward to add
later if volume warrants it.

**Mapping.** NIST CSF PR.PT-1 (audit records determined, documented,
implemented, reviewed), DE.AE-3 (event data aggregated and correlated).
CIS Controls 8.2 (collect audit logs), 8.5 (collect detailed audit logs),
8.10 (retain audit logs).
