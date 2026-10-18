# Proposed Frozen External Level-1 Protocol v1

## Scope

**Prospective source-separated external validation of the frozen reproducibly preserved Level-1 BGP incident-classification path.**

The protocol excludes any claim about the historical Level-2 temporal stacker.

## Fixed pipeline

1. Lock source-native incident metadata before retrieval; unresolved exact timestamps remain REVIEW.
2. Use `route-views2`, the frozen 60-minute context buffer, and the frozen incident-active segmentation rules.
3. Resolve modern 15-minute filenames normally. If and only if generated URLs are absent, use the official RouteViews directory index to select actual files overlapping the unchanged interval.
4. Parse with `bgpdump -q -m`; assign observations to windows by BGP timestamp, never filename timestamp.
5. Apply the frozen exact-prefix / affected-ASN / peer-origin-path / leak-segment relevance predicate.
6. Construct frozen five-minute PRE_CONTEXT, INCIDENT_ACTIVE, and POST_CONTEXT rows.
7. Generate the unchanged 44 Behavioral, 14 same-period CAIDA serial-2, and 16 same-date historical RPKI/ROV features.
8. Require exact 74 names, order, dtypes, missing-value behavior, and schema hash. Missing historical snapshots cause REVIEW; no temporal substitution is allowed.
9. Verify every preserved Level-1 artifact checksum, average probabilities across five models, then apply frozen mean incident aggregation.
10. Record all warnings/failures. Prediction correctness cannot alter reconstruction logic or eligibility.

## Gate before final external collection

The engineering pilot supports freezing the runner for dates where exact historical CAIDA and RPKI inputs exist. Candidate pre-screening must include enrichment-archive availability without inspecting model output. The final external cohort must remain unselected until this protocol is reviewed and frozen.
