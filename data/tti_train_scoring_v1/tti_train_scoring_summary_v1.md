# TRAIN TTI Scoring Summary v1

**TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS**

TTI definition: RouteViews-observable checkpoint TTI: the earliest tested observation checkpoint at which the frozen Level-1 classifier correctly identifies the incident class, measured relative to the first incident-relevant RouteViews observation following the independently documented incident start.

This is separate from the 25.58 ms downstream computational latency benchmark, live enterprise operational TTI, and the existing Final Holdout performance of the complete Level-1 + temporal-stacking architecture.

Preservation controls:

- Validation accessed/recomputed: NO
- Final Holdout accessed/recomputed: NO
- Model retrained/tuned/calibrated/optimized/modified: NO
- Primary Praxis architecture/results modified: NO
- Existing Final Holdout metrics remain authoritative: Macro F1 = 0.920177; Top-2 = 0.990610; MRR = 0.958529

Inputs:

- TTI-evaluable TRAIN incidents: 983
- Class counts: 327 Hijack / 329 Leak / 327 Outage
- Non-evaluable TRAIN incidents preserved outside denominators: 10
- Approved horizon rows scored: 3,932
- Horizons: 30 / 60 / 120 / 300 seconds
- Features: exact 74-feature V4 representation
- Onset rule: FIRST_POST_DOCUMENTED_EVENT_EVIDENCE
- Level-1 ensemble: five-model cross-fit XGBoost Level-1 ensemble with arithmetic mean of class probabilities across the five fold-specific Level-1 models

## Horizon Metrics

|   horizon_seconds |   n_incidents |   macro_f1 |   macro_f1_ci_lower |   macro_f1_ci_upper |   top1_accuracy |   top2_accuracy |      mrr | sample_unit   | scope                                                  |
|------------------:|--------------:|-----------:|--------------------:|--------------------:|----------------:|----------------:|---------:|:--------------|:-------------------------------------------------------|
|                30 |           983 |   0.790817 |            0.766662 |            0.816111 |        0.790437 |        0.932859 | 0.884028 | incident      | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
|                60 |           983 |   0.843014 |            0.81999  |            0.864024 |        0.842319 |        0.953204 | 0.91336  | incident      | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
|               120 |           983 |   0.873308 |            0.852695 |            0.893188 |        0.872838 |        0.97355  | 0.932011 | incident      | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
|               300 |           983 |   0.89844  |            0.878385 |            0.916555 |        0.898271 |        0.972533 | 0.944557 | incident      | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |

## Per-Class Metrics

|   horizon_seconds | class   |   precision |   recall |       f1 |   support | scope                                                  |
|------------------:|:--------|------------:|---------:|---------:|----------:|:-------------------------------------------------------|
|                30 | Hijack  |    0.697337 | 0.880734 | 0.778378 |       327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
|                30 | Leak    |    0.855019 | 0.699088 | 0.769231 |       329 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
|                30 | Outage  |    0.860465 | 0.792049 | 0.824841 |       327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
|                60 | Hijack  |    0.758355 | 0.902141 | 0.824022 |       327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
|                60 | Leak    |    0.888889 | 0.778116 | 0.829822 |       329 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
|                60 | Outage  |    0.905229 | 0.847095 | 0.875197 |       327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
|               120 | Hijack  |    0.811475 | 0.908257 | 0.857143 |       327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
|               120 | Leak    |    0.906149 | 0.851064 | 0.877743 |       329 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
|               120 | Outage  |    0.912338 | 0.859327 | 0.885039 |       327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
|               300 | Hijack  |    0.861671 | 0.914373 | 0.88724  |       327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
|               300 | Leak    |    0.912773 | 0.890578 | 0.901538 |       329 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
|               300 | Outage  |    0.92381  | 0.889908 | 0.906542 |       327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |

## Cumulative Identification

| identification_type   | checkpoint                 |   count |   percent |   denominator | scope                                                  |
|:----------------------|:---------------------------|--------:|----------:|--------------:|:-------------------------------------------------------|
| Top-1                 | <=30s                      |     777 | 0.790437  |           983 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-1                 | <=60s                      |     841 | 0.855544  |           983 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-1                 | <=120s                     |     883 | 0.898271  |           983 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-1                 | <=300s                     |     910 | 0.925738  |           983 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-1                 | NOT_IDENTIFIED_WITHIN_300S |      73 | 0.0742625 |           983 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-2                 | <=30s                      |     917 | 0.932859  |           983 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-2                 | <=60s                      |     943 | 0.959308  |           983 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-2                 | <=120s                     |     962 | 0.978637  |           983 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-2                 | <=300s                     |     965 | 0.981689  |           983 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-2                 | NOT_IDENTIFIED_WITHIN_300S |      18 | 0.0183113 |           983 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |

## Per-Class Cumulative Identification

| identification_type   | class   | checkpoint                 |   count |   percent |   denominator | scope                                                  |
|:----------------------|:--------|:---------------------------|--------:|----------:|--------------:|:-------------------------------------------------------|
| Top-1                 | Hijack  | <=30s                      |     288 | 0.880734  |           327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-1                 | Hijack  | <=60s                      |     297 | 0.908257  |           327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-1                 | Hijack  | <=120s                     |     303 | 0.926606  |           327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-1                 | Hijack  | <=300s                     |     310 | 0.948012  |           327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-1                 | Hijack  | NOT_IDENTIFIED_WITHIN_300S |      17 | 0.0519878 |           327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-1                 | Leak    | <=30s                      |     230 | 0.699088  |           329 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-1                 | Leak    | <=60s                      |     263 | 0.799392  |           329 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-1                 | Leak    | <=120s                     |     290 | 0.881459  |           329 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-1                 | Leak    | <=300s                     |     298 | 0.905775  |           329 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-1                 | Leak    | NOT_IDENTIFIED_WITHIN_300S |      31 | 0.0942249 |           329 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-1                 | Outage  | <=30s                      |     259 | 0.792049  |           327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-1                 | Outage  | <=60s                      |     281 | 0.859327  |           327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-1                 | Outage  | <=120s                     |     290 | 0.88685   |           327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-1                 | Outage  | <=300s                     |     302 | 0.923547  |           327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-1                 | Outage  | NOT_IDENTIFIED_WITHIN_300S |      25 | 0.0764526 |           327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-2                 | Hijack  | <=30s                      |     320 | 0.978593  |           327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-2                 | Hijack  | <=60s                      |     324 | 0.990826  |           327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-2                 | Hijack  | <=120s                     |     327 | 1         |           327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-2                 | Hijack  | <=300s                     |     327 | 1         |           327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-2                 | Hijack  | NOT_IDENTIFIED_WITHIN_300S |       0 | 0         |           327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-2                 | Leak    | <=30s                      |     288 | 0.87538   |           329 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-2                 | Leak    | <=60s                      |     303 | 0.920973  |           329 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-2                 | Leak    | <=120s                     |     313 | 0.951368  |           329 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-2                 | Leak    | <=300s                     |     316 | 0.960486  |           329 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-2                 | Leak    | NOT_IDENTIFIED_WITHIN_300S |      13 | 0.0395137 |           329 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-2                 | Outage  | <=30s                      |     309 | 0.944954  |           327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-2                 | Outage  | <=60s                      |     316 | 0.966361  |           327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-2                 | Outage  | <=120s                     |     322 | 0.984709  |           327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-2                 | Outage  | <=300s                     |     322 | 0.984709  |           327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| Top-2                 | Outage  | NOT_IDENTIFIED_WITHIN_300S |       5 | 0.0152905 |           327 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |

## Stability Notes

| stable_correct_checkpoint                 |   count |   percent |   denominator | scope                                                  |
|:------------------------------------------|--------:|----------:|--------------:|:-------------------------------------------------------|
| <=30s                                     |     748 | 0.760936  |           983 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| <=60s                                     |      56 | 0.0569685 |           983 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| <=120s                                    |      42 | 0.0427263 |           983 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| <=300s                                    |      37 | 0.0376399 |           983 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| NOT_IDENTIFIED_WITHIN_300S                |     100 | 0.101729  |           983 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| BECOMES_TOP1_CORRECT_THEN_LATER_INCORRECT |      39 | 0.0396745 |           983 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| TOP2_CORRECT_THEN_LATER_INCORRECT         |      12 | 0.0122075 |           983 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| TRUE_CLASS_PROBABILITY_DECREASES          |     590 | 0.600203  |           983 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |
| MAX_PROBABILITY_CONFIDENCE_DECREASES      |     628 | 0.638861  |           983 | TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS |

- Top-1 identified by <=300s: 910/983 (92.574%)
- Top-2 identified by <=300s: 965/983 (98.169%)
- Top-1 correct then later incorrect: 39
- Top-2 correct then later incorrect: 12
- True-class probability decreases across at least one step: 590
- Max-probability confidence decreases across at least one step: 628

These results are retrospective TRAIN-only early-classification diagnostics. They are not independent generalization estimates and do not replace the Final Holdout results.

Decision: TRAIN_TTI_RESULTS_READY_FOR_REVIEW
