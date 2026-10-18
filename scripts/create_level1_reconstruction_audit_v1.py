from __future__ import annotations

import csv
import hashlib
from pathlib import Path


ROOT = Path("/Users/biruk/Documents/New project")
OUT = ROOT / "data/tti_pilot"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_csv(path: Path, rows: list[dict[str, object]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def exists(path: str) -> str:
    return "YES" if (ROOT / path).exists() else "NO"


def file_hash(path: str) -> str:
    p = ROOT / path
    return sha256(p) if p.exists() else ""


def main() -> None:
    spec_rows = [
        {"item": "final_level1_candidate", "value": "XGB_REFINED_TRAIN_CANDIDATE", "source_artifact": "config/final_model_candidate_v3_1_xgb_refined.yaml", "status": "RECOVERED"},
        {"item": "final_architecture_candidate", "value": "K1_FINAL_DEPLOYABLE_V1_1", "source_artifact": "config/k1_final_candidate_v1_1_deployable.yaml", "status": "RECOVERED"},
        {"item": "train_dataset", "value": "data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet", "source_artifact": "src/bgp_incident_detection/k1_incident_stacking.py; config/final_holdout_protocol_v1.yaml", "status": "RECOVERED"},
        {"item": "train_dataset_hash_sha256", "value": file_hash("data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet"), "source_artifact": "data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet", "status": "RECOVERED"},
        {"item": "train_roster", "value": "data/partitions_v2/train_incidents_v2.csv", "source_artifact": "data/partitions_v2/train_incidents_v2.csv", "status": "RECOVERED"},
        {"item": "train_roster_count", "value": "993 incidents; 331 Hijack / 331 Leak / 331 Outage", "source_artifact": "data/partitions_v2/train_incidents_v2.csv; data/modeling_k1/k1_oof_leakage_audit_v1.csv", "status": "RECOVERED"},
        {"item": "feature_schema", "value": "V4 = 44 Behavioral + 14 CAIDA + 16 RPKI/ROV = 74 features", "source_artifact": "config/feature_variants_v1.yaml; src/bgp_incident_detection/feature_ablation.py", "status": "RECOVERED"},
        {"item": "feature_order", "value": "BEHAVIORAL_FEATURE_NAMES + CAIDA_FEATURES + RPKI_FEATURES", "source_artifact": "src/bgp_incident_detection/feature_ablation.py:124-128", "status": "RECOVERED"},
        {"item": "sample_weighting", "value": "I1 incident-aware: sample_weight = 1 / count(window_id) within each model_group_id on the training side only", "source_artifact": "src/bgp_incident_detection/imbalance_model_experiment.py:206-208; data/modeling/xgboost_weight_semantics_audit_v1.csv", "status": "RECOVERED"},
        {"item": "hyperparameters", "value": "n_estimators=600; max_depth=6; learning_rate=0.125; subsample=0.9; colsample_bytree=0.9; min_child_weight=1; gamma=0; reg_alpha=0.01; reg_lambda=2.0; objective=multi:softprob; num_class=3; eval_metric=mlogloss", "source_artifact": "config/final_model_candidate_v3_1_xgb_refined.yaml; config/final_holdout_protocol_v1.yaml", "status": "RECOVERED"},
        {"item": "random_seed", "value": "20260828 for principal seed; K2 stability seeds 20260828-20260901; first_level_model sets random_state and seed when used in K1 code", "source_artifact": "config/final_model_candidate_v3_1_xgb_refined.yaml; src/bgp_incident_detection/k1_incident_stacking.py", "status": "RECOVERED_WITH_CAVEAT"},
        {"item": "xgboost_version", "value": "3.4.1 recorded", "source_artifact": "config/final_model_candidate_v3_1_xgb_refined.yaml; data/modeling/xgboost_environment_v1.csv", "status": "RECOVERED"},
        {"item": "runtime_library_versions", "value": "xgboost 3.4.1 recorded with conda-forge Python 3.12.2 on macOS-15.7.5-x86_64-i386-64bit; current audit runtime lacks xgboost/sklearn and cannot execute fitting", "source_artifact": "data/modeling/xgboost_environment_v1.csv; current read-only environment check", "status": "RECOVERED_WITH_CAVEAT"},
        {"item": "class_order", "value": "HIJACK, LEAK, OUTAGE encoded as 0, 1, 2; display order Hijack, Leak, Outage", "source_artifact": "src/bgp_incident_detection/model_baselines.py; src/bgp_incident_detection/k1_incident_stacking.py", "status": "RECOVERED"},
        {"item": "missing_value_handling", "value": "SimpleImputer(strategy='median') fit on the training data for each model; no scaler in Level-1 XGBoost pipeline", "source_artifact": "src/bgp_incident_detection/k1_incident_stacking.py:first_level_model; src/bgp_incident_detection/validation_confirmation.py", "status": "RECOVERED"},
        {"item": "preprocessing", "value": "V4 feature selection in frozen order, median imputation, label mapping; no calibration or thresholding for multiclass probability ranking", "source_artifact": "src/bgp_incident_detection/k1_incident_stacking.py; src/bgp_incident_detection/validation_confirmation.py", "status": "RECOVERED"},
        {"item": "deployable_level1_form", "value": "Final protocol says CROSSFIT_ENSEMBLE_FIRST_LEVEL with arithmetic mean across five TRAIN fold models, not a single full-TRAIN Level-1 model", "source_artifact": "config/final_holdout_protocol_v1.yaml; config/k1_final_candidate_v1_1_deployable.yaml; data/modeling_k2/k2_inference_probability_strategy_v1.csv", "status": "RECOVERED"},
        {"item": "fold_assignments", "value": "data/modeling/baseline_v1_grouped_cv_assignments_v1.csv; grouped by model_group_id, one fold per incident; cv_seed=20260828", "source_artifact": "data/modeling/baseline_v1_grouped_cv_assignments_v1.csv; data/modeling_k2/k2_first_level_leakage_audit_v1.csv", "status": "RECOVERED"},
        {"item": "five_model_training_procedure", "value": "For each fold, train Level-1 XGB on TRAIN rows whose fold != held-out fold, using I1 group-aware weights; predict held-out or unseen window probabilities; final unseen inference averages five fold models per final protocol", "source_artifact": "src/bgp_incident_detection/k1_incident_stacking.py; config/final_holdout_protocol_v1.yaml", "status": "RECOVERED"},
        {"item": "early_stopping", "value": "No early_stopping_rounds or eval_set found in Level-1 candidate fitting code; n_estimators fixed at 600", "source_artifact": "src/bgp_incident_detection/k1_incident_stacking.py; src/bgp_incident_detection/validation_confirmation.py", "status": "RECOVERED"},
        {"item": "nondeterminism", "value": "XGBoost candidate artifact records deterministic_status=STOCHASTIC_OR_SEED_SENSITIVE; tree_method differs between K1 helper (hist) and validation helper (default unspecified)", "source_artifact": "config/final_model_candidate_v3_1_xgb_refined.yaml; src/bgp_incident_detection/k1_incident_stacking.py; src/bgp_incident_detection/validation_confirmation.py", "status": "RISK"},
        {"item": "serialized_level1_model_artifact", "value": "No unambiguous serialized XGBoost booster/joblib/pickle/ubj/bst or five-model ensemble was found", "source_artifact": "repository model-artifact search", "status": "MISSING"},
    ]
    write_csv(OUT / "level1_training_specification_v1.csv", spec_rows, ["item", "value", "source_artifact", "status"])

    ref_paths = [
        ("K1 OOF window probabilities", "data/modeling_k1/k1_window_oof_probabilities_v1.parquet", "TRAIN OOF first-level probabilities; best fingerprint for fold-heldout reconstruction", "HIGH"),
        ("K1 incident-level predictions", "data/modeling_k1/k1_incident_level_predictions_v1.parquet", "TRAIN incident-level K1 predictions derived from first-level probabilities and meta-model", "MEDIUM"),
        ("K1 incident meta-features", "data/modeling_k1/k1_incident_meta_features_v1.parquet", "TRAIN meta-features derived from first-level probabilities; useful aggregate fingerprint", "MEDIUM"),
        ("K2 first-level leakage audit", "data/modeling_k2/k2_first_level_leakage_audit_v1.csv", "Confirms 993 incidents and held-out fold procedure", "SUPPORTING"),
        ("K2 probability shift audit", "data/modeling_k2/k2_oof_vs_fulltrain_probability_shift_v1.csv", "Shows full-TRAIN probability shift and why crossfit ensemble was recommended", "SUPPORTING"),
        ("K25 XGB meta cache seed 20260828 fold 1", "data/modeling_k25/meta_cache/xgb_seed_20260828_outer_1.parquet", "One preserved fold cache; other xgb_seed_* outer files also exist", "MEDIUM"),
        ("Validation XGB window predictions", "data/validation/validation_xgb_window_predictions_v1.parquet", "Do not access for TTI; historical fingerprint only, already created in Phase J", "SEALED_FOR_TTI"),
        ("Final Holdout Level-1 probabilities", "data/final_holdout/final_holdout_level1_window_probabilities_v1.parquet", "Do not access/recompute; historical terminal artifact only", "SEALED_FOR_TTI"),
        ("Frozen TRAIN V4 corpus", "data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet", "Exact Level-1 feature input", "HIGH"),
        ("Grouped CV assignments", "data/modeling/baseline_v1_grouped_cv_assignments_v1.csv", "Exact grouped folds for reconstructing five fold models", "HIGH"),
    ]
    ref_rows = []
    for name, path, purpose, value in ref_paths:
        ref_rows.append(
            {
                "artifact_name": name,
                "path": path,
                "exists": exists(path),
                "sha256": file_hash(path),
                "reference_use": purpose,
                "fingerprint_value": value,
                "tti_access_policy": "DO_NOT_USE_FOR_TTI_SCORING" if "validation" in path or "final_holdout" in path else "TRAIN_ONLY_OR_CONFIGURATION_REFERENCE",
            }
        )
    write_csv(OUT / "level1_reference_artifacts_v1.csv", ref_rows, ["artifact_name", "path", "exists", "sha256", "reference_use", "fingerprint_value", "tti_access_policy"])

    risk_rows = [
        {"risk": "serialized_model_missing", "severity": "HIGH", "evidence": "No loadable Level-1 XGBoost booster/ensemble found", "impact": "Cannot score TTI without reconstruction or methodological change", "mitigation": "Only reconstruct in a separately authorized phase and verify against preserved probability fingerprints"},
        {"risk": "xgboost_seed_sensitivity", "severity": "MEDIUM", "evidence": "final_model_candidate_v3_1_xgb_refined.yaml marks deterministic_status=STOCHASTIC_OR_SEED_SENSITIVE", "impact": "Exact probability reproduction may fail even with same seed/version", "mitigation": "Use strict but realistic probability tolerances and predicted-class equality against fingerprints"},
        {"risk": "environment_mismatch", "severity": "MEDIUM", "evidence": "Recorded environment has xgboost 3.4.1; current audit runtime lacks xgboost/sklearn", "impact": "Reconstruction requires restoring compatible modeling environment", "mitigation": "Use recorded xgboost/sklearn stack or containerize before reconstruction"},
        {"risk": "tree_method_ambiguity", "severity": "MEDIUM", "evidence": "K1 first_level_model uses tree_method='hist'; validation_confirmation model did not explicitly set tree_method", "impact": "Different code paths may not produce identical probabilities", "mitigation": "For final K1 Level-1 reconstruction use K1/final protocol path: crossfit ensemble with tree_method='hist'"},
        {"risk": "median_imputer_state_missing", "severity": "MEDIUM", "evidence": "No serialized imputer found; medians must be refit from exact fold TRAIN rows", "impact": "Any dataset/order/version mismatch changes inputs", "mitigation": "Recompute imputer medians only from exact fold training rows and compare transformed predictions"},
        {"risk": "parquet_engine_absent_in_current_runtime", "severity": "LOW", "evidence": "Current read-only runtime could not read Parquet due missing pyarrow/fastparquet", "impact": "Audit can hash artifacts but reconstruction needs Parquet support", "mitigation": "Use modeling environment with Parquet engine"},
        {"risk": "validation_holdout_fingerprints_sealed_for_tti", "severity": "LOW", "evidence": "Validation and Final Holdout prediction artifacts exist but must not be accessed for this TTI phase", "impact": "TTI reconstruction should verify on TRAIN fingerprints first", "mitigation": "Restrict equivalence checks to TRAIN OOF/meta artifacts unless user explicitly authorizes historical sealed-artifact read-only comparison"},
    ]
    write_csv(OUT / "level1_reconstruction_risks_v1.csv", risk_rows, ["risk", "severity", "evidence", "impact", "mitigation"])

    audit = """# Level-1 Reconstruction Audit v1

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
"""
    (OUT / "level1_reconstruction_audit_v1.md").write_text(audit, encoding="utf-8")

    gate = """# Level-1 Reconstruction Gate v1

## Gate Result

The original serialized frozen Level-1 model cannot be used because it was not preserved as a loadable artifact. However, the final training recipe is substantially recoverable:

- exact TRAIN corpus path recovered;
- exact TRAIN roster recovered;
- exact V4 feature schema and ordering recovered;
- exact I1 sample-weight function recovered;
- exact XGBoost hyperparameters recovered;
- class order recovered;
- missing-value handling recovered;
- grouped fold assignment artifact recovered;
- final protocol identifies the deployable Level-1 form as a five-model crossfit ensemble;
- TRAIN-derived probability fingerprints exist for verification.

The main caveats are seed sensitivity, missing serialized imputer/model state, environment mismatch, and the need to verify reproduced probabilities rather than accepting similar performance.

## Required Future Reconstruction Rule

A future reconstruction phase must rebuild the five fold-specific Level-1 XGBoost models only from TRAIN artifacts, serialize them as a new clearly versioned reconstructed artifact, and compare their probabilities against preserved TRAIN OOF fingerprints before any TTI scoring. Validation and Final Holdout must remain untouched unless a separate historical read-only verification is explicitly authorized.

Disposition: SAFE_TO_RECONSTRUCT_AND_VERIFY
"""
    (OUT / "level1_reconstruction_gate_v1.md").write_text(gate, encoding="utf-8")


if __name__ == "__main__":
    main()
