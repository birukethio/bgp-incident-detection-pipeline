# Independent Validation Protocol v1

## Status

This is a pre-execution protocol. No new confirmation set has been scored. The Final Holdout remains untouched.

## Frozen Inputs

### Model Artifacts

- Level-1 model/ensemble: `data/tti_pilot/reconstructed_level1_v1/` and `data/tti_pilot/level1_ensemble_manifest_v2.json`
- Level-1 schema: `data/tti_pilot/reconstructed_level1_v1/feature_schema_v4.json`
- Final candidate config: `config/k1_final_candidate_v1_1_deployable.yaml`
- K1 meta-feature schema: `config/k1_incident_meta_feature_schema_v1.yaml`
- K1 second-level config: `config/k1_second_level_xgb_final_v1.yaml`
- K1 implementation: `src/bgp_incident_detection/k1_incident_stacking.py`

### Feature Artifacts and Methodology

- Frozen V4 schema: 44 Behavioral + 14 CAIDA + 16 RPKI/ROV.
- Historical CAIDA snapshot selection must match the frozen TRAIN methodology.
- Historical RPKI/ROV snapshot selection must match the frozen TRAIN methodology.
- Feature order and missing-value policy must match the frozen V4 pipeline.
- Class order must remain Hijack, Leak, Outage.

## Confirmation Set Construction

1. Extract candidate events from preselected independent sources.
2. Normalize event class, source ID, source URL, affected ASN(s), affected prefix(es), start/end times, and description.
3. Remove events that overlap the frozen 1,419-event corpus.
4. Freeze the source-native and normalized candidate rosters.
5. Acquire RouteViews MRT data only for locked candidate events.
6. Generate frozen V4 features without modifying feature definitions.
7. Run compatibility/leakage gates.
8. Score only after all above artifacts are frozen.

## Incident Window Construction

The default confirmation design should use the same event-window logic as the final Praxis incident classification pipeline, not the TTI partial-horizon logic. For Hijack/Leak detector spans, event-active windows must follow the frozen incident-window policy. For Outage events, documented outage start/end intervals may be used when they are explicitly source-reported and ASN/network scoped.

## Scoring

- Level 1 produces class probabilities for each eligible five-minute window.
- Mean aggregation baseline uses mean class probability across eligible windows.
- K1 stacker constructs incident-level meta-features from the complete eligible incident window sequence and scores with the frozen Level-2 model.
- Ranking is descending probability over Hijack, Leak, Outage.

## Metrics

Primary:

- Incident Macro F1.

Secondary:

- Top-1 accuracy.
- Top-2 accuracy.
- MRR.
- Per-class precision/recall/F1.
- Confusion matrix.
- Mean true-class rank.
- Class/source-stratified descriptive summaries where sample size permits.

## Statistical Inference

- Unit: incident.
- Bootstrap: 10,000 incident-level resamples.
- Seed: 20260914.
- CI: percentile 95% confidence interval.
- Paired tests/comparisons use identical incident denominators.

## Failure and Exclusion Handling

Before scoring, classify each event as:

- `ELIGIBLE`
- `EXCLUDED_OVERLAPS_EXISTING_CORPUS`
- `EXCLUDED_MISSING_TIME`
- `EXCLUDED_MISSING_ASN_OR_PREFIX`
- `EXCLUDED_ROUTEVIEWS_RECONSTRUCTION_FAILURE`
- `EXCLUDED_V4_COMPATIBILITY_FAILURE`
- `EXCLUDED_LABEL_AMBIGUITY`
- `REVIEW_REQUIRED`

Do not create post-hoc exclusions after seeing predictions.

## Prohibited Actions

- No retraining.
- No tuning.
- No feature selection.
- No threshold selection.
- No recalibration.
- No architecture change.
- No Validation access for model decisions.
- No Final Holdout access.
- No peeking at confirmation predictions before the cohort and protocol are frozen.
- No post-hoc class-specific reinterpretation.

## Audit Logs Required for Execution

1. Source extraction log.
2. Deduplication/overlap log.
3. RouteViews acquisition log.
4. Feature-generation log.
5. V4 compatibility audit.
6. Scoring manifest.
7. Statistical output register.
8. Non-modification attestation.

## One-Time Rule

The locked confirmation set is evaluated once. After its results are observed, the model, features, event roster, exclusion rules, and metrics may not be changed and re-evaluated as if still confirmatory.
