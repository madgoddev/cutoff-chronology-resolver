# Architecture

Registration binds a creator-scoped key, proposition, integer cutoff, explicit timestamp-selection rule, and bounded evidence text to one immutable fingerprint. Identical retries are idempotent.

Every validator independently extracts a closed finding, event time, publication time, and issue mask. The contract—not the LLM—derives the verdict with strict `< cutoff` semantics. Malformed, out-of-range, or different normalized output fails consensus; creator-only first resolution is immutable.

`matches_verdict` revalidates the record/audit relationship and exact expected fingerprint before returning true. Status views are informational only.
