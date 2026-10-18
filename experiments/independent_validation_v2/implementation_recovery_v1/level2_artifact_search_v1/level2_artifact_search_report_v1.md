# Frozen Level-2 XGBoost Artifact Search Report v1

## Scope

This was a read-only search for the original frozen trained Level-2 XGBoost artifact required to complete E6 of the IEC implementation-recovery gate.

No IEC incident was scored. No model was retrained, recreated, approximated, reconstructed, tuned, or calibrated. The broad repository-wide text search encountered Final Holdout artifact paths while looking for Level-2 model references; no Holdout inference, metric recomputation, or model evaluation was performed.

## Search Coverage

Searched locations:

- Current working tree.
- Local Git refs: `main`, `codex-chapter4-figures`, `origin/main`, `origin/codex-chapter4-figures`.
- Local Codex turn-diff refs, especially `dd406d2c6357204fc1e0338838696184a207ba77`, which contains the final K1 files that are not present on GitHub refs.
- Git object history for `.json`, `.ubj`, `.model`, `.bin`, `.pkl`, `.pickle`, `.joblib`, checkpoint, Booster, XGBoost, K1, stacker, and second-level names.
- GitHub remote refs after `git fetch --all --tags --prune`.
- GitHub Actions artifacts and run metadata through `gh`.
- GitHub releases through `gh`.
- Git LFS indicators. `git lfs` is not installed in this environment, and no `.gitattributes` LFS mapping file was present.
- Source code and notebooks for `save_model`, `load_model`, `Booster`, `XGBClassifier`, `joblib`, `pickle`, `K1_FINAL_SECOND_LEVEL_XGB_V1`, `K1-M2_XGB_K1-TEMPORAL`, and related model paths.

## Findings

No credible original frozen trained Level-2 model artifact was found.

The current tree contains model binaries for older baseline/domain-expert models and the verified reconstructed Level-1 fold models, but not a Level-2 K1 stacker model. The local Codex turn-diff ref contains final K1 configs, final prediction artifacts, final-prep verification outputs, and Level-1 models, but still no serialized Level-2 model file.

GitHub `main` and `codex-chapter4-figures` do not contain the final K1 artifact set. They also contain no Level-2 model binary. GitHub Actions artifact queries and release queries returned no available artifacts.

## Code Trace

The code that generated frozen Level-2 reference predictions does not load a trained model artifact:

- `src/bgp_incident_detection/k1_final_model_freeze.py::verify_fixed_config` constructs `model = xgb_meta_model(params)`, calls `model.fit(...)`, then calls `predict_meta(...)`. It writes verification CSVs and YAML config files, not model bytes.
- `src/bgp_incident_detection/final_holdout_evaluation.py::train_second_level_and_predict` loads `config/k1_second_level_xgb_final_v1.yaml`, constructs `model = xgb_meta_model(params)`, fits it on TRAIN meta-features, and predicts Holdout meta-features. It writes prediction CSVs, not a serialized model.
- `config/k1_final_candidate_v1_1_deployable.yaml` records the final fitting procedure and points to `config/k1_second_level_xgb_final_v1.yaml`; it records no model path, checksum, artifact ID, run ID, or object-store location.

Therefore, the strongest evidence is that the original frozen Level-2 model artifact was never persisted as a standalone binary. The frozen methodology persisted configuration, schema, verification metrics, and predictions.

## Relevant Non-Model Artifacts

- `config/k1_second_level_xgb_final_v1.yaml`
  - SHA-256: `4326f0eb845ceacfb28fee9a70e85a49c19445a3f41aa3b6a10945c74d3bd58d`
  - Defines `K1_FINAL_SECOND_LEVEL_XGB_V1`
  - Parameter hash: `40df040321ef`
  - XGBoost version recorded: `3.4.1`
  - Hyperparameters: `n_estimators=150`, `max_depth=3`, `learning_rate=0.03`, `subsample=1.0`, `colsample_bytree=0.8`, `reg_lambda=3.0`, `reg_alpha=0.05`

- `config/k1_incident_meta_feature_schema_v1.yaml`
  - SHA-256: `290bae06afb595a161ae864ccca8a64dd5d6594522128052657a43a1d143e1f3`
  - Freezes the 74 Level-2 meta-feature order.

- `data/modeling_k1/k1_incident_level_predictions_v1.parquet`
  - SHA-256: `a438ba365b0a1872b67f3e30bb05bb17af755edce7f5a5d4931a599476d45cb6`
  - Contains TRAIN-side K1 reference predictions including `K1-M2_XGB_K1-TEMPORAL`.

## Disposition

`FROZEN_LEVEL2_ARTIFACT_NOT_FOUND`

No artifact was copied into a recovery directory because no credible trained Level-2 model artifact was located. Creating one would require reconstruction/retraining, which was explicitly prohibited in this task.
