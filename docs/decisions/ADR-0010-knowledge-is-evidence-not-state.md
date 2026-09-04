# ADR-0010: Knowledge is evidence, never authoritative state

**Status:** Accepted
**Date:** 2026-09-04
**Milestone:** 3

## Context

Milestone 2 established the CMDB as the platform's authoritative record: an
`asset_fact` is a claim with a source, a verification status and an attestation
trail, and moving a claim from `UNVERIFIED` to `VERIFIED` requires a human with
the approver role. That workflow is the whole reason the CMDB can be trusted.

Milestone 3 introduces a corpus of documents — runbooks, vendor manuals, policy
statements, configuration references — and the ability to retrieve passages from
it. Every RAG system faces the same pressure at this exact point: a document
says "the core switch is on VLAN 100", the CMDB has no such fact, and writing it
looks like an obvious improvement. It is available, it is probably right, and
the alternative is an answer that says "I found a document that claims this but
the CMDB does not record it."

Yielding to that pressure destroys the CMDB's meaning. A fact promoted from a
document has no discovery source, no attestation and no human behind it, but it
is stored in the same column as one that does — so `VERIFIED` stops meaning
"someone checked this" and starts meaning "something said this somewhere". There
is no way back once facts have accumulated: the two kinds are indistinguishable
after the fact.

## Decision

Milestone 3 contains **no code path that writes to** `asset`,
`asset_identifier`, `asset_fact`, `asset_relationship` or `fact_attestation`.

Knowledge may reference assets in exactly one direction. `knowledge_asset_mention`
carries a foreign key from a chunk to an asset; no Milestone 2 table has a column
pointing back. Document content can be *cited alongside* a CMDB fact and can be
*reported as conflicting with* one, and that is the entire extent of the
relationship.

The answer contract encodes the distinction rather than relying on wording.
`StatementKind` separates `SOURCED` (a document says this), `CMDB_FACT` (an
authoritative record holds this, and carries that record's real verification
status), `OBSERVATION`, `INFERENCE` (the model concluded this) and `UNRESOLVED`.
`build_answer` refuses — rather than repairs — a `SOURCED` statement that carries
a verification status, and refuses a `CMDB_FACT` statement that does not name the
fact it reports.

`KNOWLEDGE_FACT_SOURCE_PREFIX` (`"knowledge:chunk:"`) is reserved now and used by
nothing. When a later milestone promotes evidence into a fact, it will do so
through Milestone 2's existing assert-and-verify workflow, with a human, and the
resulting fact will name the chunk it came from.

## Rationale

**Why a structural prohibition rather than a rule.** A rule is a thing a future
contributor has to know. The knowledge subpackage imports no Milestone 2 write
model at all, and a test asserts that by reading the module source — so adding
such a write requires adding an import that a test rejects, rather than
remembering an ADR. **[Best practice]** Make the invariant checkable, not
memorable.

**Why the reference is one-way.** Retiring a knowledge source must never be able
to orphan or invalidate an authoritative row. With the foreign key pointing only
from knowledge into the CMDB, the entire knowledge corpus could be dropped and
every asset, fact and attestation would be unaffected. The reverse is not true,
and that asymmetry is exactly the intended relationship between evidence and
record. **[Best practice]** Dependencies point from the less trusted thing to
the more trusted thing.

**Why typed statements rather than a confidence score.** A score invites
threshold tuning, and a threshold silently converts an epistemic distinction into
an arithmetic one. "A document says this" and "we verified this" do not differ by
degree; a number cannot express the difference and will eventually be rounded
away. **[Opinion, held firmly]**

**Where this maps.** NIST CSF `ID.AM` (asset management) depends on the
inventory meaning something; CIS Control 1 likewise. The separation is also the
GRC-familiar distinction between *evidence* and *finding*: an auditor collects
the first and a human produces the second, and an audit that conflated them
would not be an audit.

## Consequences

- Milestone 3 answers will sometimes say "the runbook claims X; the CMDB has no
  such fact." That is the correct answer, not a gap to close.
- A `DOC_VS_CMDB` conflict is reported, never resolved. Picking one would turn a
  documentation error into an operational incident.
- Promotion of evidence to fact is deferred to a milestone that can put a human
  in the loop. The vocabulary for it exists; the code path does not.
- An operator who wants a documented value in the CMDB must assert it through
  the Milestone 2 API, where it will carry `MANUAL_ENTRY` as its source and be
  `UNVERIFIED` until someone verifies it. That is more friction, and the
  friction is the control.
