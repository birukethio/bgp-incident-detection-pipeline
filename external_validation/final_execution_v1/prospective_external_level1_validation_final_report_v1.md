# Prospective External Level-1 Validation Final Report v1

## 1. Objective

This study evaluates **prospective source-separated external validation of the frozen reproducibly preserved Level-1 BGP incident-classification path**.

## 2. Separation from Original Praxis Experiment

The original 1,419-event Praxis, Validation partition, Final Holdout, and terminal Level-2 results remain unchanged. No protected partition was accessed or recomputed.

## 3. Prospective Protocol and Chronology

The engineering pilot preceded protocol freeze. The protocol was frozen at `2026-09-18T21:36:20Z`; the 18-event cohort was then screened and locked at `2026-09-19T03:08:38Z` before reconstruction or inference.

## 4. Engineering Pilot

Eight timestamp-qualified pilot incidents tested retrieval, parsing, windowing, historical enrichment, schema compatibility, and Level-1 execution. All nine pilot identifiers were permanently excluded from the final cohort.

## 5. Protocol Freeze

The collector, 60-minute context, segmentation, relevance predicate, five-minute features, CAIDA/RPKI temporal rules, missing-value handling, five model artifacts, class order, and mean aggregation were checksum-locked.

## 6. Independent Source Selection

Thirty-seven candidates were reviewed without model output. Eighteen passed source, label, timestamp, overlap, pilot-exclusion, and archival gates.

## 7. Final External Cohort

The locked cohort contains 18 incidents: 3 Hijacks, 5 Leaks, and 10 Outages.

## 8. Source and Temporal Concentration

IODA supplies 10/18 incidents (55.6%), all Outages. Events from 2021 account for 11/18 (61.1%). The sample is not representative of global BGP incident prevalence.

## 9. Reconstruction Yield

Exact V4 reconstruction and inference reached 18/18 incidents. One of 1,055 requested files for `V2-OUTAGE-010` was absent; this acquisition warning is retained.

## 10. Exact V4 Compatibility

All scored incidents used the exact 74-feature names, order, schema hash, historical CAIDA/RPKI rules, and frozen missing-value behavior. No later snapshot or feature substitution was used.

## 11. Frozen Level-1 Inference

Five checksum-verified Level-1 XGBoost models produced window probabilities. Scores were averaged across models and then across all eligible five-minute windows. No retraining, calibration, thresholding, or Level-2 model was used.

## 12. External Performance

- Macro F1: 0.412698
- Top-1: 0.555556 (10/18)
- Top-2: 0.722222 (13/18)
- MRR: 0.731481
- Mean true-class rank: 1.722222

## 13. Per-Class Performance

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| Hijack | 0.500000 | 0.666667 | 0.571429 | 3 |
| Leak | 0.000000 | 0.000000 | 0.000000 | 5 |
| Outage | 0.571429 | 0.800000 | 0.666667 | 10 |

## 14. Ranking Performance

True-class ranks were {1: 10, 2: 3, 3: 5}. Top-2 rescued 3 Top-1 errors.

## 15. Error Analysis

There were 8 Top-1 errors. They are retained verbatim in `final_external_error_analysis_v1.csv`; model disagreement was not used to challenge or change source labels.

## 16. Comparison with Internal Evidence

The closest internal comparator is the TRAIN-only mean-probability Level-1 reference, not the terminal Level-2 Holdout. Any comparison is across a different evaluation population. The original Level-2 Holdout metrics (Macro F1 0.920177, Top-1 0.920188, Top-2 0.990610, MRR 0.958529) are reported only as historical context and are not treated as an apples-to-apples baseline.

## 17. Threats to Validity

The external cohort is small and imbalanced; Hijack support is three. IODA and 2021 events dominate. Archive availability affected eligibility. Source-separated labels improve source independence but do not guarantee independence of underlying Internet-routing evidence. Public RouteViews visibility remains partial.

## 18. Conclusions

The experiment provides a bounded prospective test of the reproducibly preserved Level-1 path. Its evidence applies to this source- and time-concentrated cohort and does not externally validate the historical Level-2 temporal stacker.

## 19. Praxis Integration Recommendations

Add this as an explicitly additive external Level-1 validation extension. Preserve the original terminal Holdout as the primary full-architecture result and present this study with raw counts, confidence intervals, and its source/temporal limitations.
