# Full TRAIN TTI Horizon Feature Gate v2.1

- Scope: TRAIN-only TTI methodology/implementation correction.
- Validation accessed: NO
- Final Holdout accessed: NO
- Model scoring/retraining/tuning/calibration: NO
- Original TRAIN corpus incidents preserved: 993
- TTI-evaluable cohort: 983
- TTI-evaluable class counts: {'Leak': 329, 'Hijack': 327, 'Outage': 327}
- Non-evaluable status counts: {'TTI_NOT_EVALUABLE_INSUFFICIENT_ROUTEVIEWS_EVIDENCE': 9, 'TTI_NOT_EVALUABLE_ONSET_UNRESOLVED': 1}
- Horizon rows: 3932
- RPKI rows: 3932
- V4 rows: 3932
- Pilot RPKI equivalence: PASS
- Compatibility: {'PASS': 74}
- Leakage assertions: {'PASS': 3932}
- Onset rule: `FIRST_POST_DOCUMENTED_EVENT_EVIDENCE`
- Historical CAIDA alignment: PASS; copied from method-compatible v2 output.
- Historical RPKI alignment: PASS; used frozen TRAIN RPKI snapshot mapping/fallback behavior.

Recommendation: FULL_TRAIN_TTI_FEATURES_READY_FOR_SCORING
