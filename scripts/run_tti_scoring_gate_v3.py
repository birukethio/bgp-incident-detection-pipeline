from __future__ import annotations

import csv
import hashlib
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path("/Users/biruk/Documents/New project")
OUT = ROOT / "data/tti_pilot"
V2_FEATURES = OUT / "tti_horizon_v4_features_v2.csv"
V2_ONSET = OUT / "tti_onset_analysis_v2.csv"
V2_COMPAT = OUT / "tti_v4_compatibility_v2.csv"
V2_LEAKAGE = OUT / "tti_leakage_assertions_v2.csv"

CONFIGS = [
    ROOT / "config/k1_final_candidate_v1_1_deployable.yaml",
    ROOT / "config/final_model_candidate_v3_1_xgb_refined.yaml",
    ROOT / "config/final_holdout_protocol_v1.yaml",
]

MODEL_CANDIDATES = [
    ROOT / "data/final_holdout/final_holdout_level1_window_probabilities_v1.parquet",
    ROOT / "data/validation/validation_xgb_window_predictions_v1.parquet",
]

CLASS_ORDER = ["Hijack", "Leak", "Outage"]


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, object]], fieldnames: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def model_verification() -> tuple[str, dict[str, str]]:
    config_lines = []
    for path in CONFIGS:
        config_lines.append(f"- `{path.relative_to(ROOT)}`: `{sha256(path)}`")
    candidates = []
    for path in MODEL_CANDIDATES:
        if path.exists():
            candidates.append(f"- `{path.relative_to(ROOT)}` exists, but it is a prediction/probability artifact, not a reusable serialized Level-1 model.")
    candidate_text = "\n".join(candidates) if candidates else "- No Level-1 XGBoost model-like artifact found."
    text = f"""# TTI Frozen Model Verification v3

Status: `STOP_NOT_SCORED`

The approved v2 TTI feature input was verified, but the exact frozen Level-1 XGBoost model artifact could not be identified unambiguously as a loadable serialized model/ensemble.

## Verified Configuration Evidence

{chr(10).join(config_lines)}

## Expected Frozen Level-1 Model

- Candidate: `XGB_REFINED_TRAIN_CANDIDATE`
- XGBoost version: `3.4.1`
- Hyperparameters: `n_estimators=600`, `max_depth=6`, `learning_rate=0.125`, `subsample=0.9`, `colsample_bytree=0.9`, `min_child_weight=1`, `gamma=0`, `reg_alpha=0.01`, `reg_lambda=2.0`
- Feature schema: V4, exactly 74 features
- Class/probability order used by repository configs: `Hijack`, `Leak`, `Outage`
- Final architecture first-level inference strategy: `CROSSFIT_ENSEMBLE_FIRST_LEVEL`, arithmetic mean across five TRAIN fold models

## Artifact Search Result

{candidate_text}

Repository search found Random Forest `.joblib` files and historical XGBoost probability/result artifacts, but no unambiguous serialized XGBoost booster, `.ubj`, `.bst`, `.pkl`, `.joblib`, or equivalent five-model crossfit ensemble for the frozen Level-1 model.

## Gate Decision

No fitting, tuning, calibration, threshold selection, or model reconstruction was performed. Because applying the frozen Level-1 model requires a loadable frozen model artifact, TTI v3 scoring is stopped before prediction.
"""
    (OUT / "tti_frozen_model_verification_v3.md").write_text(text, encoding="utf-8")
    return "STOP_NOT_SCORED", {"class_order": ",".join(CLASS_ORDER)}


def main() -> None:
    features = read_csv(V2_FEATURES)
    onset = {row["incident_uid"]: row for row in read_csv(V2_ONSET)}
    compat = read_csv(V2_COMPAT)
    leakage = read_csv(V2_LEAKAGE)
    status, _ = model_verification()
    if len(features) != 36:
        raise RuntimeError("expected 36 v2 horizon rows")
    if Counter(row["status"] for row in compat) != Counter({"PASS": 74}):
        raise RuntimeError("v2 V4 compatibility gate is not all PASS")
    if Counter(row["status"] for row in leakage) != Counter({"PASS": 36}):
        raise RuntimeError("v2 leakage assertions are not all PASS")

    pred_rows = []
    for row in features:
        flag = onset[row["incident_uid"]]["ambiguity_review_flag"]
        pred_rows.append(
            {
                "incident_id": row["incident_id"],
                "incident_uid": row["incident_uid"],
                "true_class": row["category"],
                "horizon_seconds": row["horizon_seconds"],
                "selected_onset": row["selected_onset_utc"],
                "hijack_probability": "",
                "leak_probability": "",
                "outage_probability": "",
                "predicted_top1_class": "NOT_SCORED",
                "true_class_rank": "",
                "top1_correct": "",
                "top2_correct": "",
                "onset_review_flag": flag,
                "status": status,
                "notes": "Exact loadable frozen Level-1 XGBoost artifact was not identified; no fitting or model reconstruction allowed.",
            }
        )
    write_csv(
        OUT / "tti_incident_predictions_v3.csv",
        pred_rows,
        ["incident_id", "incident_uid", "true_class", "horizon_seconds", "selected_onset", "hijack_probability", "leak_probability", "outage_probability", "predicted_top1_class", "true_class_rank", "top1_correct", "top2_correct", "onset_review_flag", "status", "notes"],
    )

    metric_rows = []
    for horizon in ["30", "60", "120", "300"]:
        metric_rows.append(
            {
                "horizon_seconds": horizon,
                "evaluable_incidents": 0,
                "macro_f1": "NA",
                "hijack_f1": "NA",
                "leak_f1": "NA",
                "outage_f1": "NA",
                "top1_accuracy": "NA",
                "top2_accuracy": "NA",
                "mrr": "NA",
                "confusion_matrix": "NA",
                "status": status,
                "notes": "Pilot/descriptive scoring not executed because frozen model artifact gate failed.",
            }
        )
    write_csv(
        OUT / "tti_horizon_metrics_v3.csv",
        metric_rows,
        ["horizon_seconds", "evaluable_incidents", "macro_f1", "hijack_f1", "leak_f1", "outage_f1", "top1_accuracy", "top2_accuracy", "mrr", "confusion_matrix", "status", "notes"],
    )

    cm_rows = []
    for horizon in ["30", "60", "120", "300"]:
        for true in CLASS_ORDER:
            for pred in CLASS_ORDER:
                cm_rows.append({"horizon_seconds": horizon, "true_class": true, "predicted_class": pred, "count": "NA", "status": status})
    write_csv(OUT / "tti_confusion_matrices_v3.csv", cm_rows, ["horizon_seconds", "true_class", "predicted_class", "count", "status"])

    checkpoint_rows = []
    by_incident = defaultdict(list)
    for row in pred_rows:
        by_incident[row["incident_uid"]].append(row)
    for uid, rows in sorted(by_incident.items()):
        rows = sorted(rows, key=lambda r: int(r["horizon_seconds"]))
        checkpoint_rows.append(
            {
                "incident_uid": uid,
                "incident_id": rows[0]["incident_id"],
                "true_class": rows[0]["true_class"],
                "top1_tti_checkpoint": ">300s / NOT_IDENTIFIED_WITHIN_TESTED_HORIZON / NOT_SCORED",
                "top2_tti_checkpoint": ">300s / NOT_IDENTIFIED_WITHIN_TESTED_HORIZON / NOT_SCORED",
                "stable_correct_checkpoint": "NOT_SCORED",
                "status": status,
                "notes": "TTI checkpoints require model probabilities; no scoring was run.",
            }
        )
    write_csv(OUT / "tti_checkpoint_results_v3.csv", checkpoint_rows, ["incident_uid", "incident_id", "true_class", "top1_tti_checkpoint", "top2_tti_checkpoint", "stable_correct_checkpoint", "status", "notes"])

    trajectory_rows = []
    for uid, rows in sorted(by_incident.items()):
        trajectory_rows.append(
            {
                "incident_uid": uid,
                "incident_id": rows[0]["incident_id"],
                "true_class": rows[0]["true_class"],
                "trajectory_30_60_120_300": "NOT_SCORED -> NOT_SCORED -> NOT_SCORED -> NOT_SCORED",
                "top1_correct_trajectory": "NA -> NA -> NA -> NA",
                "top2_correct_trajectory": "NA -> NA -> NA -> NA",
                "stable_correct_checkpoint": "NOT_SCORED",
                "onset_review_flag": rows[0]["onset_review_flag"],
                "status": status,
            }
        )
    write_csv(OUT / "tti_prediction_trajectories_v3.csv", trajectory_rows, ["incident_uid", "incident_id", "true_class", "trajectory_30_60_120_300", "top1_correct_trajectory", "top2_correct_trajectory", "stable_correct_checkpoint", "onset_review_flag", "status"])

    sens_rows = []
    for row in onset.values():
        if row["ambiguity_review_flag"] == "REVIEW_CHANGE_ONSET_DIFFERS":
            selected = row["selected_onset"]
            change = row["candidate_change_based_onset"]
            sens_rows.append(
                {
                    "incident_uid": row["incident_uid"],
                    "category": row["category"],
                    "selected_first_post_documented_evidence_onset": selected,
                    "diagnostic_change_based_onset": change,
                    "difference_seconds": "",
                    "could_change_checkpoint_membership_or_interpretation": "YES",
                    "notes": "Difference is small in the v2 onset table, but sensitivity is retained and not optimized against performance.",
                }
            )
    write_csv(OUT / "tti_onset_sensitivity_v3.csv", sens_rows, ["incident_uid", "category", "selected_first_post_documented_evidence_onset", "diagnostic_change_based_onset", "difference_seconds", "could_change_checkpoint_membership_or_interpretation", "notes"])

    summary = f"""# TTI Scoring Summary v3

Scope: non-destructive TRAIN-only frozen Level-1 scoring gate for the 9-incident TTI pilot.

The approved input, `tti_horizon_v4_features_v2.csv`, was present and contained 36 rows with exactly 74 V4 feature columns. The v2 compatibility and leakage gates were still PASS: 74/74 feature checks PASS and 36/36 leakage assertions PASS.

Scoring was not executed. The exact frozen Level-1 XGBoost model artifact used by the final Praxis architecture could not be identified unambiguously as a loadable serialized model or five-model crossfit ensemble. Repository configs define the candidate, class order, hyperparameters, and inference strategy, but available XGBoost artifacts are result/probability files rather than reusable model binaries. Reconstructing the model by fitting from TRAIN would violate this phase.

Created `NOT_SCORED` v3 prediction, metric, confusion, checkpoint, trajectory, and onset-sensitivity outputs so the gate is documented without changing any prior artifact.

Decision: PILOT_REQUIRES_METHODOLOGY_REVIEW
"""
    (OUT / "tti_scoring_summary_v3.md").write_text(summary, encoding="utf-8")
    print({"status": status, "predictions": len(pred_rows), "metrics": len(metric_rows), "decision": "PILOT_REQUIRES_METHODOLOGY_REVIEW"})


if __name__ == "__main__":
    main()
