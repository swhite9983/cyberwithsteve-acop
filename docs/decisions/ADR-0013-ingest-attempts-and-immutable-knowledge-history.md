# ADR-0013: Ingest attempts are separate from immutable document history

**Status:** Accepted
**Date:** 2026-09-04
**Milestone:** 3

## Context

Milestone 3 set two rules that turned out to conflict.

**Immutable history.** A document's versions and chunks are never rewritten. An
update creates a new version; old versions, chunks and the citations pointing at
them stay addressable, because an answer given last month cited something and
deleting it would make that answer unverifiable.

**Nothing rejected is stored.** Content that fails secret screening is not
persisted — not as a chunk, not as an embedding, not in an error body, not in
the audit log. Screening completes *before* the first content write, because
immutable history plus a stored secret leaves no remediation path.

The first design gave a quarantined submission a `knowledge_document_version`
with no content, so that the refusal had somewhere to live. That produced an
unresolvable state. A later false-positive override would have had to either
mutate that immutable row — violating the first rule — or insert a second
version with the same content hash, which `uq_document_raw_hash` forbids.

## Decision

The two rules get two tables, and the boundary between them is the security
gate.

`knowledge_ingest_attempt` is an **append-only process record**. Every
submission writes one, before anything else, on its own transaction. It may
retain: attempt id, principal, target metadata, submitted content hash, safe
request metadata, screening finding locators and fingerprints, status,
timestamps and disposition metadata. It must **not** retain rejected raw
content, any secret value, chunks, embeddings, or a canonical version
representing a failed ingestion.

`knowledge_document_version` is a **canonical immutable record**. It exists only
for submissions that passed the gate. The database enforces the boundary rather
than the service layer remembering it:

```sql
CHECK ((outcome IN ('CREATED','VERSIONED')) = (version_id IS NOT NULL))
```

`ScreeningOutcome` has exactly two members, `CLEAN` and `FLAGGED`.
`QUARANTINED` is deliberately absent: a quarantined submission never produces a
version, so the state is unrepresentable in the vocabulary.

**Which transaction writes what** is forced by two facts pulling in opposite
directions. A *failure* rolls the request back, so the attempt's final state
must be written where that rollback cannot reach it — an independent
transaction, the same mechanism as ADR-0009's `record_denial`. A *success* sets
`version_id`, which has a foreign key to a version created in the request
transaction that has not committed yet, so it must be part of that same
transaction — which is also what makes the attempt and the canonical version
atomic with each other.

## Dispositions

A finding is disposed of by an approver, and the disposition is scoped to
exactly what was reviewed: one source, one external reference, one raw content
hash, one finding fingerprint.

- `FALSE_POSITIVE` clears that fingerprint for those exact bytes and that exact
  target. Not the detector, not the document, not anything wider.
- `REMEDIATED_AT_SOURCE` records that a real secret was dealt with and **does
  not** unblock the original content. The submitter must edit their document,
  and edited content has a different hash.

No override can mean "store a known secret unchanged in normal searchable
knowledge."

Dispositions are append-only. A mistaken one is corrected by a later row and the
gate reads the most recent; the originating attempt is never mutated, because it
is a record of what happened at the time.

## Rationale

**Why the CHECK constraint rather than a service rule.** The rule has to hold
for code written by someone who has not read this ADR — including a future
importer, a bulk backfill, or a repair script run at 2am. A constraint holds for
all of them. **[Best practice]** Put invariants where they cannot be bypassed.

**Why an attempt is an event and a version is a resource.** Repeated identical
*successful* submissions write nothing new — idempotence is a property of
canonical state. Repeated *rejected* submissions append an attempt each time,
and that is correct: three attempts to submit a document containing a private
key is meaningfully different from one, and is exactly the signal a security
review wants.

**Why findings store a locator and a salted fingerprint.** The locator
("line 412, cols 18-64") points into the submitter's own copy, so a human can
find the material without ACOP holding it. The fingerprint is an HMAC with a
deployment salt, so repeated submissions are recognisable while the table cannot
become an offline-crackable dictionary of the estate's secrets. Both are
required outside development; an empty salt is refused at startup.

**Why prompt injection is flagged rather than blocked.** A security corpus will
contain material *about* prompt injection, which necessarily contains injection
strings. A blocking detector would make the platform unable to ingest the very
documentation that teaches it about the threat. The real controls are
structural: Milestone 3 executes no tools, the answer schema has no field that
can express a tool call, and retrieved text never occupies the system role.

**Where this maps.** NIST CSF `PR.DS` (data security) and `DE.CM` (continuous
monitoring); CIS Control 3 (data protection). The separation of a *process
record* from a *canonical record* is also ordinary records-management practice —
the log of an attempted filing is not the filing.

## Consequences

- A refusal returns a message naming the detector and a position, and the
  attempt id an approver can review. Milestone 1's error handler returns only a
  class-level generic message, so the knowledge errors build their public
  message per instance from non-sensitive material; the handler is unchanged.
- The attempt log is approver-scoped. What was blocked, by which detector and
  where, is a security review surface rather than general reading.
- An operator whose submission was refused cannot see the findings themselves
  and must ask an approver. That is the intended separation of duties, and the
  refusal message carries enough to start the conversation.
