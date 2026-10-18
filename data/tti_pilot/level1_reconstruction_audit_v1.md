# Level-1 Reconstruction Audit v1

This read-only audit preserves the primary Praxis experiment and Final Holdout as authoritative and immutable. No model was fit, serialized, tuned, scored, or reconstructed. Validation and Final Holdout were not accessed for computation.

## Recovered Training Specification

The final Level-1 model is identified as `XGB_REFINED_TRAIN_CANDIDATE`, used inside `K1_FINAL_DEPLOYABLE_V1_1`. The recovered input is `data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet`, with the TRAIN roster at `data/partitions_v2/train_incidents_v2.csv`. The training population is 993 TRAIN incidents with 331 Hijack, 331 Leak, and 331 Outage.

The V4 schema is recovered as exactly 74 features in this order: 44 Behavioral features, then 14 CAIDA features, then 16 RPKI/ROV features. The source order is `FEATURES_BY_VARIANT["V4"]` in `src/bgp_incident_detection/feature_ablation.py`.

I1 weighting is recovered as `sample_weight = 1 / group_size` within each `model_group_id`, computed only on the training side of each fold. The Level-1 model uses median imputation before XGBoost. No early stopping was found for the frozen Level-1 procedure; `n_estimators=600` is fixed.

## Deployable Level-1 Form

The final holdout protocol does not describe a single full-TRAIN Level-1 model as the deployable first-level object. It specifies `CROSSFIT_ENSEMBLE_FIRST_LEVEL` with arithmetic mean across five TRAIN fold models. Therefore a faithful reconstruction would need to rebuild all five fold-specific Level-1 XGBoost models using the exact grouped fold assignments.

## Missing Preserved Object

No unambiguous serialized Level-1 XGBoost model, booster, `.ubj`, `.bst`, `.pkl`, `.joblib`, or five-model crossfit ensemble was found. Existing XGBoost artifacts are configurations, metrics, probability outputs, or downstream K1/meta artifacts.

## Reference Fingerprints

The strongest TRAIN-only fingerprint is `data/modeling_k1/k1_window_oof_probabilities_v1.parquet`, which should contain the preserved leakage-safe first-level OOF probabilities. Additional fingerprints include K1 incident predictions, K1 meta-features, and K2/K2.5 fold caches. Validation and Final Holdout probability files exist, but they should remain sealed for TTI work unless explicitly authorized for a separate read-only historical comparison.

## Equivalence Checks For A Future Authorized Reconstruction

Recommended checks:

- exact row alignment by `window_id`, `incident_uid`, and fold;
- identical predicted Top-1 class for all TRAIN OOF windows;
- identical incident-level predicted class after aggregation/meta-feature reconstruction;
- maximum absolute class-probability difference <= `1e-6` for strict reproducibility, with `1e-5` as a practical XGBoost/platform tolerance;
- mean absolute probability difference <= `1e-7` strict, or <= `1e-6` practical;
- Pearson/Spearman correlation of each class probability >= `0.999999`;
- reproduced aggregate OOF metrics within `1e-6`;
- reproduced per-incident predictions exactly.

Similar Macro F1 alone is not sufficient.
