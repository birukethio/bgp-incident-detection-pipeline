# TRAIN Equivalence Failure Analysis v1

Generated UTC: 2026-09-15T15:58:19.751152+00:00

## Finding

Stored TRAIN reference artifacts are available from frozen V4 features through Level-1 probabilities, mean aggregation, Level-2 meta-features, and final K1 incident predictions for the selected fixtures.

However, this recovery step did not find a frozen end-to-end implementation output regenerated from source incident metadata and RouteViews evidence for the same fixtures. Therefore, the artifacts can define a strong TRAIN-only fixture roster and reference targets, but they cannot by themselves establish implementation equivalence for a newly assembled IEC reconstruction/scoring implementation.

## Equivalence Stage Assessment

- E1 RouteViews/window count/timestamp/linkage: reference windows available, but no new implementation output compared.
- E2 V4 74-feature vectors: reference vectors available, but no new implementation output compared.
- E3 Level-1 scores: reference OOF scores available, but no new implementation output compared.
- E4 Mean aggregation: reference rows available, but no new implementation output compared.
- E5 Retrospective temporal meta-features: reference rows available, but no new implementation output compared.
- E6 Level-2 scores/ranking/predicted class: reference rows available, but no new implementation output compared.

## Cause Classification

Primary blocker: `missing historical artifact` / `new implementation output not generated`.

No evidence was found that the existing TRAIN reference artifacts are wrong. The limitation is that equivalence requires a side-by-side comparison between reference outputs and a newly assembled IEC execution implementation applied only to frozen TRAIN fixtures.
