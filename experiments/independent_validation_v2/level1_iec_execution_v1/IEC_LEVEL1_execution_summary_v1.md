# IEC Level-1 Execution Summary v1

Generated UTC: 2026-09-15T19:58:32.142919+00:00

## Locked Input

- Locked source-separated IEC roster: 63 incidents.
- Hijack / Leak / Outage: 16 / 17 / 30.
- Source-native non-Cloudflare labels were used from `experiments/independent_validation_v2/v2_IEC_final_source_separated_roster.csv`.
- Validation access: none.
- Final Holdout access: none.
- Level-2 fitting/reconstruction: none.
- Level-1 retraining/tuning/calibration: none.

## Required Pre-IEC Verification

E1-E4 frozen TRAIN fixture verification status: `PASS`.

The recovered implementation evidence verifies:

- E1 window reconstruction: exact on 9/9 frozen TRAIN fixtures.
- E2 V4 74-feature reconstruction: exact on 9/9 frozen TRAIN fixtures.
- E3 Level-1 probabilities: exact on 9/9 frozen TRAIN fixtures.
- E4 mean aggregation: exact on 9/9 frozen TRAIN fixtures.

## IEC Prospective Quality Gate

All 63 IEC candidates were prospectively assigned:

`RECONSTRUCTION_FAILED`

Reason:

`NO_VERIFIED_SOURCE_NATIVE_IEC_RECONSTRUCTION_IMPLEMENTATION`

This classification was made before inference and without using model predictions.

## Inference Status

No IEC event was scored. The evaluable roster is empty because no candidate reached the `EVALUABLE` state under the locked quality gate.

## H1 Status

`NOT_EXECUTED_NO_EVALUABLE_INCIDENTS_AFTER_PROSPECTIVE_GATE`

## H2 Status

`H2_EXTERNAL_CONFIRMATION_NOT_EXECUTED_COMPARATOR_NOT_REPRODUCIBLE`

## H3 Status

`H3_EXTERNAL_CONFIRMATION_NOT_EXECUTED_LEVEL2_ARTIFACT_NOT_PERSISTED`

## Interpretation

This result does not contradict the historical Final Holdout result or the TRAIN/Validation development record. It means the additional source-separated external validation could not be executed under the strict reproducibility boundary because the workspace lacks a verified arbitrary source-native IEC reconstruction implementation. The available verified implementation chain is strong through E1-E4 on frozen TRAIN fixtures, but that is not equivalent to safely processing new IEC source-native events.

## Final Disposition

`LEVEL1_SOURCE_SEPARATED_VALIDATION_INCONCLUSIVE`
