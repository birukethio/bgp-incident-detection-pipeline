# Full TRAIN TTI Horizon Feature Gate v2

Scope: non-destructive TRAIN-only TTI horizon feature construction. No model scoring was performed.

- TRAIN corpus incidents: 993
- TTI-evaluable TRAIN cohort constructed: 983
- TTI-evaluable class counts: {'Leak': 329, 'Hijack': 327, 'Outage': 327}
- Not evaluable / excluded from TTI metric denominators: 10
- Not-evaluable status counts: {'TTI_NOT_EVALUABLE_INSUFFICIENT_ROUTEVIEWS_EVIDENCE': 9, 'TTI_NOT_EVALUABLE_NO_POST_DOCUMENTED_EVENT_EVIDENCE': 1}
- Horizon rows constructed: 3932
- Horizons: [30, 60, 120, 300]
- Onset rule: `FIRST_POST_DOCUMENTED_EVENT_EVIDENCE`
- Behavioral features: PRODUCED
- CAIDA features: PRODUCED
- RPKI/ROV features: NOT PRODUCED in this run; historical VRP index construction did not complete in practical runtime
- V4 merged 74-feature artifact: NOT PRODUCED because RPKI/ROV is incomplete
- Validation accessed: NO
- Final Holdout accessed: NO
- Model scoring/retraining/tuning: NO

## Review Findings

- The nine named reconstruction-insufficient incidents were confirmed as non-evaluable due to zero retained incident-relevant RouteViews observations.
- One additional TRAIN incident, `Outage:377`, has retained timestamped evidence only before the documented start. Under the approved onset rule, no first post-documented-event evidence exists, so it is not defensible for TTI horizons without methodology review.
- This produces 983 evaluable incidents rather than the expected 984 and 3,932 horizon rows rather than 3,936.
- Horizon leakage assertions over the constructed manifest passed.

## Required Remediation Before Scoring

1. Decide whether `Outage:377` should be excluded from TTI denominators, reclassified under a documented outage-specific onset policy, or marked TTI-not-evaluable.
2. Optimize or precompute the historical RPKI prefix-origin validation lookup for the 30/60/120/300-second TRAIN horizons, preserving the frozen RPKI definitions.
3. Rebuild `tti_train_horizon_rpki_v2.parquet` and then the merged 74-feature `tti_train_horizon_v4_v2.parquet` before any Level-1 scoring.

Recommendation: FULL_TRAIN_TTI_FEATURES_REQUIRE_REVIEW
