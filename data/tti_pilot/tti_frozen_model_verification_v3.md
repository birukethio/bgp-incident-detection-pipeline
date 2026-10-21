# TTI Frozen Model Verification v3

Status: `STOP_NOT_SCORED`

The approved v2 TTI feature input was verified, but the exact frozen Level-1 XGBoost model artifact could not be identified unambiguously as a loadable serialized model/ensemble.

## Verified Configuration Evidence

- `config/k1_final_candidate_v1_1_deployable.yaml`: `d7ef54c4e3d9491207cd137eaabe7630ffc7adab4df96b83a9b132bb022e5dc4`
- `config/final_model_candidate_v3_1_xgb_refined.yaml`: `a7fac0c315df80f23c73ab69cc28f74d9105873806d169d95d329fb8704a6aae`
- `config/final_holdout_protocol_v1.yaml`: `cdceb106f4c392f120764a0a5c0f573c71766785844ee6a0ed810694b50eef65`

## Expected Frozen Level-1 Model

- Candidate: `XGB_REFINED_TRAIN_CANDIDATE`
- XGBoost version: `3.4.1`
- Hyperparameters: `n_estimators=600`, `max_depth=6`, `learning_rate=0.125`, `subsample=0.9`, `colsample_bytree=0.9`, `min_child_weight=1`, `gamma=0`, `reg_alpha=0.01`, `reg_lambda=2.0`
- Feature schema: V4, exactly 74 features
- Class/probability order used by repository configs: `Hijack`, `Leak`, `Outage`
- Final architecture first-level inference strategy: `CROSSFIT_ENSEMBLE_FIRST_LEVEL`, arithmetic mean across five TRAIN fold models

## Artifact Search Result

- `data/final_holdout/final_holdout_level1_window_probabilities_v1.parquet` exists, but it is a prediction/probability artifact, not a reusable serialized Level-1 model.
- `data/validation/validation_xgb_window_predictions_v1.parquet` exists, but it is a prediction/probability artifact, not a reusable serialized Level-1 model.

Repository search found Random Forest `.joblib` files and historical XGBoost probability/result artifacts, but no unambiguous serialized XGBoost booster, `.ubj`, `.bst`, `.pkl`, `.joblib`, or equivalent five-model crossfit ensemble for the frozen Level-1 model.

## Gate Decision

No fitting, tuning, calibration, threshold selection, or model reconstruction was performed. Because applying the frozen Level-1 model requires a loadable frozen model artifact, TTI v3 scoring is stopped before prediction.
