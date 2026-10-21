# IEC Level-1 Final Execution Lock v1

Generated UTC: 2026-09-15T19:58:20.613986+00:00

Status: `LOCKED_PENDING_EXECUTION`

## Scope

This lock governs the one-time source-separated external validation attempt for the reproducible Level-1 BGP incident classifier only.

Label for any reported result: `Source-Separated External Validation of the Level-1 BGP Incident Classifier`.

## Frozen IEC Roster

- Source-separated IEC roster path: `experiments/independent_validation_v2/v2_IEC_final_source_separated_roster.csv`
- Candidate incidents: 63
- Hijack: 16
- Leak: 17
- Outage: 30
- Labels: deterministic non-Cloudflare source-native labels from the frozen IEC roster.
- No incident replacement after prospective quality-gate processing.

## Frozen Methodology

- E1 RouteViews reconstruction/window linkage must follow the verified final RouteViews/windowing methodology.
- E2 feature pipeline: frozen V4, exactly 74 features.
- E3 classifier: verified reconstructed five-model Level-1 XGBoost ensemble.
- E4 incident aggregation: mean H/L/O probability across eligible windows.
- Evaluable status must be assigned before inference and without viewing model predictions.

## Metrics If Evaluable Incidents Exist

- N and class counts.
- Macro F1 with 95% incident-level bootstrap CI.
- Top-1, Top-2, MRR, mean true-class rank.
- Per-class precision, recall, and F1.
- Confusion matrix.
- Error analysis for every incorrect Top-1 prediction.
- Source-specific descriptive performance where sample size permits.

## Hypotheses

- H1: Level-1 source-separated external validation of the frozen V4 classifier.
- H2: External feature comparison only if a pre-IEC behavioral-only comparator is itself frozen and reproducible.
- H3: `H3_EXTERNAL_CONFIRMATION_NOT_EXECUTED_LEVEL2_ARTIFACT_NOT_PERSISTED`.

## Preconditions

- E1-E4 frozen TRAIN fixture verification status before IEC processing: `PASS`.
- Validation and Final Holdout access: prohibited.
- Level-2 fitting/reconstruction: prohibited.
- Level-1 retraining/tuning/calibration: prohibited.
