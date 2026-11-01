from __future__ import annotations

import hashlib
import json
import platform
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
import xgboost
import yaml

from src.bgp_incident_detection.k1_incident_stacking import (
    INCIDENT_LABELS,
    metrics,
    xgb_meta_model,
    y_codes,
)


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "experiments/level2_reconstruction_v1"
TRAIN_META = ROOT / "data/modeling_k1/k1_incident_meta_features_v1.parquet"
HOLDOUT_META = ROOT / "data/final_holdout/final_holdout_k1_meta_features_v1.parquet"
ARCHIVED = ROOT / "data/final_holdout/final_holdout_incident_rankings_v1.csv"
SCHEMA_CONFIG = ROOT / "config/k1_incident_meta_feature_schema_v1.yaml"
MODEL_CONFIG = ROOT / "config/k1_second_level_xgb_final_v1.yaml"

EXPECTED_SHA256 = {
    TRAIN_META: "97c11df4ffc48a10c23c6ede318124f07212c34434e45633580d61d08982b992",
    HOLDOUT_META: "9a0141fb9cde5812b3dc6fd4a2c39cc2d30c14f0f879f6e1ad1ef8cf8678d6f9",
    ARCHIVED: "11f7abeb30e2d3859417fba2009a8eddb0a0954fa97df6ef88d95352c950046e",
    SCHEMA_CONFIG: "290bae06afb595a161ae864ccca8a64dd5d6594522128052657a43a1d143e1f3",
    MODEL_CONFIG: "4326f0eb845ceacfb28fee9a70e85a49c19445a3f41aa3b6a10945c74d3bd58d",
}
EXPECTED_PARAMETER_HASH = "40df040321ef"
RECONSTRUCTION_LABEL = "Reconstructed Level-2 model - post-feedback reproducibility evaluation"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def gate_inputs() -> dict[str, str]:
    observed = {}
    for path, expected in EXPECTED_SHA256.items():
        actual = sha256(path)
        observed[str(path.relative_to(ROOT))] = actual
        if actual != expected:
            raise RuntimeError(f"Frozen input checksum mismatch: {path}: {actual} != {expected}")
    if sys.version_info[:3] != (3, 12, 2):
        raise RuntimeError(f"Python 3.12.2 required; found {platform.python_version()}")
    if xgboost.__version__ != "3.4.1":
        raise RuntimeError(f"XGBoost 3.4.1 required; found {xgboost.__version__}")
    return observed


def rank_predictions(frame: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, row in frame.iterrows():
        scores = {label: float(row[f"p_{label.lower()}"]) for label in INCIDENT_LABELS}
        order = sorted(scores.items(), key=lambda item: item[1], reverse=True)
        classes = [label for label, _ in order]
        rows.append(
            {
                **row.to_dict(),
                "rank_1_class": order[0][0],
                "rank_1_score": order[0][1],
                "rank_2_class": order[1][0],
                "rank_2_score": order[1][1],
                "rank_3_class": order[2][0],
                "rank_3_score": order[2][1],
                "predicted_class": order[0][0],
                "true_class_rank": classes.index(row["true_class"]) + 1,
            }
        )
    return pd.DataFrame(rows)


def metric_row(frame: pd.DataFrame) -> dict[str, float]:
    values = metrics(frame)
    return {key: float(values[key]) for key in ["incident_macro_f1", "top1", "top2", "mrr"]}


def main() -> None:
    input_hashes = gate_inputs()
    schema_doc = yaml.safe_load(SCHEMA_CONFIG.read_text(encoding="utf-8"))
    model_doc = yaml.safe_load(MODEL_CONFIG.read_text(encoding="utf-8"))
    schema = list(schema_doc["feature_order"])
    if len(schema) != 74 or schema_doc["feature_count"] != 74:
        raise RuntimeError("Frozen Level-2 schema is not exactly 74 features")
    if model_doc["candidate_parameter_hash"] != EXPECTED_PARAMETER_HASH:
        raise RuntimeError("Frozen Level-2 parameter hash mismatch")

    train = pd.read_parquet(TRAIN_META)
    holdout = pd.read_parquet(HOLDOUT_META)
    archived = pd.read_csv(ARCHIVED)
    if len(train) != 993 or train["incident_uid"].nunique() != 993:
        raise RuntimeError("Expected exactly 993 unique TRAIN incidents")
    if train["true_class"].value_counts().to_dict() != {"HIJACK": 331, "LEAK": 331, "OUTAGE": 331}:
        raise RuntimeError("TRAIN class balance mismatch")
    if len(holdout) != 213 or holdout["incident_uid"].nunique() != 213 or len(archived) != 213:
        raise RuntimeError("Expected exactly 213 Holdout incidents and archived predictions")
    if set(holdout["incident_uid"].astype(str)) != set(archived["incident_uid"].astype(str)):
        raise RuntimeError("Holdout and archived prediction incident identifiers differ")
    if list(train.columns[3:]) != schema or list(holdout.columns[3:]) != schema:
        raise RuntimeError("Frozen Level-2 feature order mismatch")
    if train[schema].isna().any().any() or holdout[schema].isna().any().any():
        raise RuntimeError("Unexpected missing values in preserved Level-2 matrices")

    params = {
        key: model_doc[key]
        for key in [
            "n_estimators",
            "max_depth",
            "learning_rate",
            "subsample",
            "colsample_bytree",
            "reg_alpha",
            "reg_lambda",
        ]
    }
    model = xgb_meta_model(params)
    model.fit(train[schema], y_codes(train["true_class"]))
    probabilities = model.predict_proba(holdout[schema])
    reconstructed = pd.DataFrame(
        {
            "reconstruction_label": RECONSTRUCTION_LABEL,
            "incident_uid": holdout["incident_uid"].to_numpy(),
            "true_class": holdout["true_class"].to_numpy(),
            "p_hijack": probabilities[:, 0],
            "p_leak": probabilities[:, 1],
            "p_outage": probabilities[:, 2],
        }
    )
    reconstructed = rank_predictions(reconstructed)

    if OUT.exists() and any(OUT.iterdir()):
        allowed = {Path(__file__).name}
        if {p.name for p in OUT.iterdir()} - allowed:
            raise RuntimeError(f"Output directory already contains reconstruction results: {OUT}")
    OUT.mkdir(parents=True, exist_ok=True)
    prediction_path = OUT / "reconstructed_level2_holdout_predictions_v1.csv"
    reconstructed.to_csv(prediction_path, index=False)

    archived_cols = [
        "incident_uid", "true_class", "p_hijack", "p_leak", "p_outage",
        "rank_1_class", "rank_2_class", "rank_3_class", "predicted_class", "true_class_rank",
    ]
    comparison = archived[archived_cols].merge(
        reconstructed[archived_cols], on="incident_uid", suffixes=("_original", "_reconstructed"), validate="one_to_one"
    )
    for label in ["hijack", "leak", "outage"]:
        comparison[f"abs_diff_p_{label}"] = (
            comparison[f"p_{label}_reconstructed"] - comparison[f"p_{label}_original"]
        ).abs()
    diff_cols = ["abs_diff_p_hijack", "abs_diff_p_leak", "abs_diff_p_outage"]
    comparison["max_abs_score_diff"] = comparison[diff_cols].max(axis=1)
    comparison["predicted_label_match"] = comparison["predicted_class_original"] == comparison["predicted_class_reconstructed"]
    for rank in [1, 2, 3]:
        comparison[f"rank_{rank}_match"] = comparison[f"rank_{rank}_class_original"] == comparison[f"rank_{rank}_class_reconstructed"]
    comparison["full_ranking_match"] = comparison[[f"rank_{rank}_match" for rank in [1, 2, 3]]].all(axis=1)
    comparison_path = OUT / "level2_incident_prediction_comparison_v1.csv"
    comparison.to_csv(comparison_path, index=False)

    original_metrics = metric_row(archived)
    reconstructed_metrics = metric_row(reconstructed)
    metric_rows = []
    for name in original_metrics:
        metric_rows.append(
            {
                "metric": name,
                "original_archived": original_metrics[name],
                "reconstructed": reconstructed_metrics[name],
                "reconstructed_minus_original": reconstructed_metrics[name] - original_metrics[name],
            }
        )
    pd.DataFrame(metric_rows).to_csv(OUT / "level2_reproducibility_metrics_v1.csv", index=False)

    score_diffs = comparison[diff_cols].to_numpy().ravel()
    label_matches = int(comparison["predicted_label_match"].sum())
    ranking_matches = int(comparison["full_ranking_match"].sum())
    max_diff = float(score_diffs.max())
    mean_diff = float(score_diffs.mean())
    incidents_gt_1e12 = int((comparison["max_abs_score_diff"] > 1e-12).sum())
    incidents_gt_1e6 = int((comparison["max_abs_score_diff"] > 1e-6).sum())
    discrepancies = comparison[(~comparison["predicted_label_match"]) | (~comparison["full_ranking_match"])]
    discrepancies.to_csv(OUT / "level2_prediction_discrepancies_v1.csv", index=False)
    if label_matches != 213 or ranking_matches != 213:
        disposition = "FAILED_REPRODUCTION"
    elif max_diff <= 1e-12:
        disposition = "EXACT_REPRODUCTION"
    elif max_diff <= 1e-6:
        disposition = "NUMERICAL_REPRODUCTION"
    else:
        disposition = "BEHAVIORAL_REPRODUCTION"

    pipeline_path = OUT / "reconstructed_level2_pipeline_v1.joblib"
    imputer_path = OUT / "reconstructed_level2_median_imputer_v1.joblib"
    xgb_path = OUT / "reconstructed_level2_xgboost_v1.json"
    joblib.dump(model, pipeline_path)
    joblib.dump(model.named_steps["imputer"], imputer_path)
    model.named_steps["model"].save_model(xgb_path)
    shutil.copy2(SCHEMA_CONFIG, OUT / "frozen_level2_feature_schema_v1.yaml")
    shutil.copy2(MODEL_CONFIG, OUT / "frozen_level2_configuration_v1.yaml")

    manifest = {
        "artifact_label": RECONSTRUCTION_LABEL,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "one_controlled_fit": True,
        "training_population": {"rows": 993, "classes": {"HIJACK": 331, "LEAK": 331, "OUTAGE": 331}},
        "holdout_comparison_population": 213,
        "class_order": list(INCIDENT_LABELS),
        "feature_count": 74,
        "feature_order": schema,
        "preprocessing": "SimpleImputer(strategy=median), fitted on TRAIN only; no scaling",
        "parameter_hash": EXPECTED_PARAMETER_HASH,
        "parameters": params,
        "fixed_model_options": {
            "objective": "multi:softprob", "num_class": 3, "eval_metric": "mlogloss",
            "random_state": 20260828, "seed": 20260828, "tree_method": "hist", "n_jobs": -1,
        },
        "input_sha256": input_hashes,
        "disposition": disposition,
    }
    (OUT / "level2_reconstruction_manifest_v1.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    environment = {
        "python": platform.python_version(), "platform": platform.platform(),
        "xgboost": xgboost.__version__, "scikit_learn": sklearn.__version__,
        "numpy": np.__version__, "pandas": pd.__version__, "joblib": joblib.__version__,
    }
    (OUT / "level2_reconstruction_environment_v1.json").write_text(json.dumps(environment, indent=2) + "\n", encoding="utf-8")
    (OUT / "reproduce_level2_reconstruction_v1.txt").write_text(
        "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python experiments/level2_reconstruction_v1/run_level2_reconstruction_v1.py\n",
        encoding="utf-8",
    )

    summary = pd.DataFrame([{
        "disposition": disposition,
        "incidents": 213,
        "predicted_label_matches": label_matches,
        "top1_ranking_matches": int(comparison["rank_1_match"].sum()),
        "top2_position_matches": int(comparison["rank_2_match"].sum()),
        "top3_position_matches": int(comparison["rank_3_match"].sum()),
        "full_ranking_matches": ranking_matches,
        "mean_absolute_class_score_difference": mean_diff,
        "maximum_absolute_class_score_difference": max_diff,
        "incidents_any_score_difference_gt_1e_12": incidents_gt_1e12,
        "incidents_any_score_difference_gt_1e_6": incidents_gt_1e6,
        "predicted_label_or_ranking_discrepancies": len(discrepancies),
    }])
    summary.to_csv(OUT / "level2_reconstruction_summary_v1.csv", index=False)

    report = "# Final Level-2 Reconstruction and Prediction Equivalence Test\n\n"
    report += f"**Artifact status:** {RECONSTRUCTION_LABEL}\n\n"
    report += f"**Disposition:** `{disposition}`\n\n"
    report += "The original trained Level-2 object was not preserved. This artifact is one controlled post-feedback reconstruction using the frozen implementation, configuration, TRAIN meta-features, seed, and environment. No Level-1 model was retrained, and Final Holdout labels were not used for fitting, tuning, calibration, or model selection.\n\n"
    report += "## Equivalence results\n\n"
    report += f"- Predicted-label agreement: {label_matches}/213\n"
    report += f"- Full ranking agreement: {ranking_matches}/213\n"
    report += f"- Mean absolute class-score difference: {mean_diff:.17g}\n"
    report += f"- Maximum absolute class-score difference: {max_diff:.17g}\n"
    report += f"- Incidents with any score difference > 1e-12: {incidents_gt_1e12}\n"
    report += f"- Incidents with any score difference > 1e-6: {incidents_gt_1e6}\n"
    report += f"- Label or ranking discrepancies: {len(discrepancies)}\n\n"
    report += "## Aggregate metrics\n\n| Metric | Original archived | Reconstructed | Delta |\n|---|---:|---:|---:|\n"
    for name in original_metrics:
        report += f"| {name} | {original_metrics[name]:.15f} | {reconstructed_metrics[name]:.15f} | {reconstructed_metrics[name]-original_metrics[name]:.15g} |\n"
    report += "\nThe archived predictions remain the authoritative historical Final Holdout result. The reconstructed model is retained separately as reproducibility evidence and is not a replacement for the unavailable original serialized object.\n"
    (OUT / "level2_reconstruction_final_report_v1.md").write_text(report, encoding="utf-8")

    checksum_rows = []
    for path in sorted(p for p in OUT.iterdir() if p.is_file() and p.name != "level2_reconstruction_output_checksums_v1.csv"):
        checksum_rows.append({"file": path.name, "sha256": sha256(path), "bytes": path.stat().st_size})
    pd.DataFrame(checksum_rows).to_csv(OUT / "level2_reconstruction_output_checksums_v1.csv", index=False)
    print(json.dumps(summary.iloc[0].to_dict(), indent=2))


if __name__ == "__main__":
    main()
