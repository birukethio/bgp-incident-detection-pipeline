# Full TRAIN TTI Methodology v1

Experiment label: **TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS**

Approved target methodology: onset = `FIRST_POST_DOCUMENTED_EVENT_EVIDENCE`; cumulative horizons = 30, 60, 120, and 300 seconds; exact frozen V4 schema = 44 Behavioral + 14 CAIDA + 16 RPKI/ROV features; inference uses the verified `reconstructed_level1_v1` five-model XGBoost ensemble with no Level-2 temporal stacker.

## Gate Finding

The full 993-incident TRAIN scale-up cannot be scored from the currently preserved full-TRAIN artifacts without changing the validated pilot methodology. The reusable full TRAIN evidence store is aggregated at the frozen five-minute window grain and contains `window_start` / `window_end`, but no per-observation BGP timestamp column such as `observation_timestamp` or `bgp_timestamp_utc`.

Available compact evidence columns:

`window_id, incident_uid, window_start, window_end, prefix, origin_asn, normalized_as_path, observation_count, collector, source_mrt_count, processing_batch_id, parser, parser_command, source_commit, behavioral_feature_version, caida_feature_version`

The evidence manifest covers 993 TRAIN incidents and 68031 frozen five-minute windows, but that is not sufficient to construct 30/60/120/300-second cumulative horizons relative to observable onset.

## Preservation

No Validation or Final Holdout artifacts were accessed for scoring. No model was retrained, tuned, calibrated, or modified. Existing primary Praxis results remain untouched.
