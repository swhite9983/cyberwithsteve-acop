# ADR-0012: ANN retrieval is an optimisation; the exact fallback is the floor

**Status:** Accepted
**Date:** 2026-09-04
**Milestone:** 3

## Context

An HNSW index returns the *k* nearest vectors it can find quickly. It knows
nothing about who is asking. Authorization, classification and lifecycle are
therefore applied to its output, and when the candidates it proposes are all
ineligible for this principal, the result is an empty answer that is
indistinguishable from "there is nothing relevant".

The first design answered this with over-fetch: ask the index for `k × N`
candidates, filter, return the top `k`. The R3 review rejected it with a concrete
case, and the case is decisive:

> Five thousand CONFIDENTIAL chunks clustered near the query. One PUBLIC chunk,
> further away. An operator asks.

Every one of the 5 000 is nearer than the PUBLIC chunk, so no fixed multiplier
reaches it. Over-fetch improves the *odds*; it is not a guarantee, and no value
of `N` makes it one. Worse, the failure is silent and load-dependent: the same
query returns the right answer on a small corpus and nothing on a large one.

## Decision

Retrieval has three stages and an explicit rule for moving between them.

1. **ANN.** The HNSW index proposes candidates, filtered only by space and
   lifecycle — exactly the columns in the partition's index predicate.
2. **Eligibility, in SQL.** Candidates are filtered against classification,
   trust, lifecycle and the caller's own filters *before* any content crosses
   back into Python.
3. **Exact fallback.** If stage 2 yielded fewer than `k`, that has exactly two
   causes, distinguished by a **bounded `COUNT` over the eligible population**:

   - **(A) more eligible rows exist than the ANN found** → rank the eligible set
     exhaustively;
   - **(B) fewer than `k` eligible rows exist at all** → the answer is already
     complete; an exhaustive scan would return the same rows.

Distinguishing them is not optional. Treating "fewer than k" as sufficient reason
to scan makes every selective query a full scan.

The exhaustive stage uses `WITH eligible AS MATERIALIZED (...)`, **not**
`SET LOCAL enable_indexscan = off`. It runs inside a `SAVEPOINT` carrying its own
`statement_timeout`, and is bounded by a configurable `exact_max_rows`.

Every call returns `RetrievalDiagnostics`: which strategy resolved it, ANN
candidate and eligible counts, the eligible population, whether that population
hit the cap, how many rows the exact stage ranked, per-stage latency, and —
critically — `degraded` and `degradation_reason`.

## Rationale

**Why `MATERIALIZED` and not `enable_indexscan`.** The obvious lever changes plan
selection for *every statement in the transaction*, and an ACOP retrieval call
shares its transaction with CMDB reads and audit writes. Silently de-optimising
those to fix one query is not an acceptable trade. `MATERIALIZED` is an
optimisation barrier scoped to a single CTE: the eligible set is computed first,
and the ranking that follows has no index to reach for.

**Why a SAVEPOINT.** A `statement_timeout` that fires aborts the transaction it
is in. Inside a savepoint it aborts only the fallback, leaving the caller's
transaction — and its audit writes — intact, so the call *degrades* instead of
failing. `SET LOCAL` inside a subtransaction also reverts when that
subtransaction aborts, so the timeout cannot leak.

**Why the population count is bounded.** An unbounded `COUNT` over a large corpus
costs about as much as the scan it exists to decide against, which would make the
cheap case pay the expensive case's price. The limit is one above the ceiling, so
"exactly at the cap" and "beyond it" remain distinguishable.

**Why degradation is in the payload rather than the logs.** Three results when
ten were asked for is either a complete answer or an incomplete one, and a
caller that cannot tell will read both as "there is nothing else". An approximate
answer presented as complete is the specific failure this milestone was corrected
to prevent. **[Best practice]** A system that cannot be complete should say so in
the same breath as the answer.

**Why the ANN stays blind to authorization.** Measured during implementation:
with the denormalised sensitivity predicate inside the ANN candidate CTE, the
index scan becomes authorization-aware, the ANN performs the eligibility
filtering itself, and the adversarial case stops being reachable — so the
correctness floor is never exercised. It would still be exercised *sometimes*,
depending on how far pgvector's candidate list happened to extend, which is a
non-deterministic authorization-shaped filter. The predicate is split:
lifecycle-only for the ANN, sensitivity added only where an exhaustive scan is
already happening.

**Where this maps.** Least privilege and defence in depth: the index is not a
security boundary and is not asked to be one; the SQL predicate is, and it is
applied identically in all three stages from a single shared constant so the
stages cannot drift apart.

## Consequences

- A retrieval call may issue up to three statements instead of one. The count
  query only runs when the ANN came up short.
- `exact_max_rows` (default 50 000) bounds the worst case. Beyond it the call
  returns a *structured degraded result* rather than an unbounded scan or a false
  claim of completeness.
- Disabling the fallback is possible and never silent: the strategy becomes
  `ANN_PARTIAL_FALLBACK_SKIPPED` and `degraded` is true. The test suite uses this
  as a negative control — the adversarial corpus is run twice, and the run with
  the fallback disabled must return nothing and say so.
- Hybrid retrieval inherits the dense leg's degradation. A lexical hit alongside
  an incomplete dense leg does not repair it.
