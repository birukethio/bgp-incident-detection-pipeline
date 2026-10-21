# Level-2 External Validation Closure v1

Final disposition: `LEVEL2_EXTERNAL_VALIDATION_CLOSED_WITH_DOCUMENTED_LIMITATION`

## Purpose

This closure record documents why source-separated external validation of the final Level-2 temporal stacker was not executed. It is a documentation-only artifact. No Level-2 model was retrained, reconstructed, refit, tuned, calibrated, or scored. No IEC incident was scored. Validation and Final Holdout were not accessed or recomputed.

## Evidence Basis

The implementation-recovery evidence established exact reproducibility through the executable pipeline stages that do not require the missing trained Level-2 object:

| Stage | Finding | Source artifact |
|---|---:|---|
| E1 window reconstruction | Exact / PASS, 9 of 9 TRAIN fixtures | `experiments/independent_validation_v2/implementation_recovery_v1/iec_E1_window_equivalence_v1.csv` |
| E2 V4 74-feature reconstruction | Exact / PASS, 9 of 9 TRAIN fixtures | `experiments/independent_validation_v2/implementation_recovery_v1/iec_E2_feature_equivalence_v1.csv` |
| E3 Level-1 XGBoost probabilities | Exact / PASS, 9 of 9 TRAIN fixtures | `experiments/independent_validation_v2/implementation_recovery_v1/iec_E3_level1_equivalence_v1.csv` |
| E4 mean aggregation | Exact / PASS, 9 of 9 TRAIN fixtures | `experiments/independent_validation_v2/implementation_recovery_v1/iec_E4_mean_equivalence_v1.csv` |
| E5 Level-2 meta-feature construction | Exact / PASS, 9 of 9 TRAIN fixtures | `experiments/independent_validation_v2/implementation_recovery_v1/iec_E5_meta_feature_equivalence_v1.csv` |
| E6 final Level-2 scores | Blocked | `experiments/independent_validation_v2/implementation_recovery_v1/iec_E6_level2_equivalence_v1.csv` |

The repository/Git/GitHub/artifact search concluded:

`FROZEN_LEVEL2_ARTIFACT_NOT_FOUND`

The strongest provenance evidence is that the final historical code path loaded the frozen YAML configuration, fit the Level-2 XGBoost model in memory from TRAIN meta-features, immediately generated predictions, and persisted prediction/result artifacts rather than the trained model object. The relevant code trace is recorded in:

`experiments/independent_validation_v2/implementation_recovery_v1/level2_artifact_search_v1/level2_code_trace_v1.csv`

## Procedural Reproducibility vs. Artifact Recoverability

The final Level-2 temporal stacker is **procedurally reproducible** in the sense that the repository records the architecture, Level-2 meta-feature construction, YAML hyperparameter/configuration path, TRAIN meta-feature inputs, and historical prediction/result artifacts.

The original trained Level-2 binary/object is **not recoverable**. No serialized XGBoost Booster, `XGBClassifier`, joblib, pickle, `.json`, `.ubj`, `.model`, or equivalent artifact was found in the current tree, Git history, GitHub refs, local Codex turn-diff refs, GitHub Actions metadata, releases, or model/checkpoint directories.

Therefore, Level 2 is procedurally specified, but the exact originally fitted binary is unavailable.

## Why External Level-2 Validation Was Not Executed

Refitting Level 2 after construction of the source-separated IEC roster was deliberately avoided because doing so would cross the evaluation boundary. The source-separated IEC set existed before the replacement/refit would have been produced. Even if the same YAML configuration and TRAIN meta-features were used, the resulting model would be a newly fitted model rather than the original historical frozen Level-2 artifact.

The project therefore did not refit Level 2 for IEC because this would:

- preserve the external-validation boundary;
- avoid introducing a newly fitted model after the external roster existed;
- avoid representing a reconstructed model as the original frozen model;
- preserve the integrity of the historical Final Holdout result;
- avoid making a source-separated external Level-2 confirmation claim that cannot be supported by a recoverable frozen trained artifact.

## H3 External Status

`H3_EXTERNAL_CONFIRMATION_NOT_EXECUTED_LEVEL2_ARTIFACT_NOT_PERSISTED`

This status does not alter any existing historical evidence:

- TRAIN nested/grouped-CV evidence for the Level-2 temporal stacker remains unchanged.
- Historical Final Holdout results remain unchanged.
- The Level-2 architecture remains a retrospective incident-level stacker.
- No claim of source-separated external Level-2 confirmation will be made.

## Boundary Statement

The source-separated IEC may still support documentation of source availability, external roster construction, and implementation recovery through E5. It does not provide an executed source-separated external validation of the final Level-2 temporal stacker, because E6 requires the original trained Level-2 object or an explicitly authorized post-hoc refit. This closure chooses methodological integrity over an unsupported executable substitution.

