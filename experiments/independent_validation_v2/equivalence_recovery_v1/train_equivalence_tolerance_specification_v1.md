# TRAIN Equivalence Tolerance Specification v1

Defined before any new implementation comparison.

- Window count, `window_id`, `incident_uid`, `window_start`, and `window_end`: exact string/count match required.
- Feature schema: exact 74/74 feature names and order required.
- Integer/count features: exact match required.
- Floating-point features: `EXACT_MATCH` if bitwise/string-equivalent after serialization; `NUMERICALLY_EQUIVALENT` if absolute difference <= 1e-9 and relative difference <= 1e-9.
- Level-1 probabilities: exact match preferred; numerically equivalent if maximum absolute probability difference <= 1e-9.
- Mean aggregation probabilities: numerically equivalent if maximum absolute probability difference <= 1e-9.
- Level-2 meta-features: exact for count/rank/vote features; <= 1e-9 absolute/relative tolerance for floating-point summaries.
- Level-2 class scores/ranking/predicted class: probability tolerance <= 1e-9 and identical predicted class/rank ordering.

Tolerances must not be loosened after observing discrepancies.
