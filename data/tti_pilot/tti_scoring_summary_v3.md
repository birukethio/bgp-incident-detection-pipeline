# TTI Scoring Summary v3

**TRAIN-ONLY TTI FEASIBILITY PILOT - n=9 - DESCRIPTIVE, NOT FINAL GENERALIZATION PERFORMANCE**

Scope: frozen reconstructed Level-1 XGBoost ensemble scoring of the approved 36 partial-horizon V4 rows.

- Validation accessed/recomputed: NO
- Final Holdout accessed/recomputed: NO
- Model retrained/tuned/calibrated: NO
- TTI rows scored: 36
- Pilot incidents: 9 TRAIN incidents, 3 Hijack / 3 Leak / 3 Outage
- Horizons: 30, 60, 120, 300 seconds
- Onset rule: FIRST_POST_DOCUMENTED_EVENT_EVIDENCE
- Ensemble rule: arithmetic mean class probability across five reconstructed Level-1 fold models

## Horizon Metrics

|   horizon_seconds |   evaluable_incidents |   macro_f1 |   hijack_f1 |   leak_f1 |   outage_f1 |   top1_accuracy |   top2_accuracy |      mrr | scope                                                                                      |
|------------------:|----------------------:|-----------:|------------:|----------:|------------:|----------------:|----------------:|---------:|:-------------------------------------------------------------------------------------------|
|                30 |                     9 |   0.885714 |           1 |       0.8 |    0.857143 |        0.888889 |        1        | 0.944444 | TRAIN-ONLY TTI FEASIBILITY PILOT - n=9 - DESCRIPTIVE, NOT FINAL GENERALIZATION PERFORMANCE |
|                60 |                     9 |   0.885714 |           1 |       0.8 |    0.857143 |        0.888889 |        0.888889 | 0.925926 | TRAIN-ONLY TTI FEASIBILITY PILOT - n=9 - DESCRIPTIVE, NOT FINAL GENERALIZATION PERFORMANCE |
|               120 |                     9 |   1        |           1 |       1   |    1        |        1        |        1        | 1        | TRAIN-ONLY TTI FEASIBILITY PILOT - n=9 - DESCRIPTIVE, NOT FINAL GENERALIZATION PERFORMANCE |
|               300 |                     9 |   1        |           1 |       1   |    1        |        1        |        1        | 1        | TRAIN-ONLY TTI FEASIBILITY PILOT - n=9 - DESCRIPTIVE, NOT FINAL GENERALIZATION PERFORMANCE |

## Checkpoint Summary

- Top-1 identified by <=300s checkpoint: 9/9
- Top-2 identified by <=300s checkpoint: 9/9
- Best descriptive horizon Macro F1: 1.000000

These values are feasibility-pilot diagnostics only and are not final generalization performance estimates.

Decision: PILOT_SUPPORTS_SCALE_UP
