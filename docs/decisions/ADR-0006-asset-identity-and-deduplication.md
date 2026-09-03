# ADR-0006: Asset identity through external identifiers, resolved before write

**Status:** Accepted
**Date:** 2026-09-03
**Milestone:** 2

## Context

Every discovery source in Milestone 5 onward will re-report the same machines
on every sweep. Proxmox knows a VM by VMID and SMBIOS UUID; Cisco knows a
switch by serial and management IP; FleetDM knows a host by its own host id and
hardware serial. None of them share a key.

If ACOP has no answer to "is this the thing I already know about", one of two
failures is certain. Either every sweep creates duplicates, and the CMDB
becomes a list of sightings rather than a model of the estate; or matching is
guessed, and two machines are welded into one record.

The second is far worse. A duplicate is visible and mergeable. A wrongly merged
asset has facts from two machines interleaved in one history, and there is no
reliable way to pull them apart afterwards.

## Decision

1. Identity lives in `asset_identifier`, not on the asset row: an asset has
   many external names, in namespaces registered in code
   (`IDENTIFIER_NAMESPACES`).
2. Each namespace declares whether it is globally unique. A partial unique
   index enforces uniqueness only for those, and only while the identifier is
   live.
3. Every write path resolves identity **before** writing, through one
   `IdentityResolver`. A single match returns that asset; no match creates one;
   **more than one match raises `IdentityConflictError`, writes nothing, and
   returns 409.**
4. Automatic merging is not implemented. `LifecycleState.MERGED` and
   `merged_into_id` exist in the schema so a future human-approved merge does
   not need a migration.

## Rationale

**[Fact]** PostgreSQL partial unique indexes cannot be `DEFERRABLE`, so the
constraint fires at statement time. Read-then-write is therefore the correct
shape; catching `IntegrityError` after the fact would leave a partially written
transaction to unwind.

**[Best practice]** Refusing an ambiguous match is standard CMDB discipline.
ServiceNow's identification engine does the same thing for the same reason.

**[Opinion]** Refusing is recoverable and merging is not, so when the cost of
the two errors is this asymmetric, the tie does not go to convenience. A 409
naming both candidate assets is a five-minute fix for an operator. An
incorrectly merged pair of hosts may never be noticed.

**[Assumption]** Namespace registration in code, rather than in a table, will
remain workable through Milestone 5. If operators need to add namespaces
without a deploy, this becomes a lookup table. Recorded in `BACKLOG.md`.

## Alternatives considered

**Hostname as the identity key.** Rejected. Hostnames are reused, renamed,
duplicated across VLANs, and frequently wrong in exactly the environments a
CMDB is most needed. In ACOP the hostname is a *fact*, with provenance and
history, which is what it actually is.

**Fuzzy or scored matching.** Rejected for Milestone 2. It converts a
deterministic operation into a tunable one, and a threshold that is wrong once
produces the unrecoverable failure above. Reconsider only with human
confirmation in the loop.

**Merge on conflict.** Rejected — this is the failure mode the decision exists
to prevent.

**Let each collector own its own asset table.** Rejected: it makes correlation
across sources — the reason ACOP exists — a join nobody can write.

## Consequences

- A collector that supplies identifiers is idempotent by construction: the same
  call twice yields one asset.
- Multi-match returns 409 and produces a `DENIED` audit record written outside
  the rolled-back request transaction, so the refusal is on the record.
- Retiring an identifier frees its value for reuse, which is what actually
  happens when a serial number moves to a new chassis.
- Duplicates will exist and will need a merge workflow. That is accepted, and
  the schema is ready for it.
