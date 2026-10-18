from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, precision_recall_fscore_support


TTI_DIR = Path("data/tti_pilot")
MODEL_DIR = TTI_DIR / "reconstructed_level1_v1"
FEATURES = TTI_DIR / "tti_horizon_v4_features_v2.csv"
ONSET = TTI_DIR / "tti_onset_analysis_v2.csv"
SCHEMA = MODEL_DIR / "feature_schema_v4.json"
ENSEMBLE_MANIFEST = TTI_DIR / "level1_ensemble_manifest_v2.json"

LABELS = ["HIJACK", "LEAK", "OUTAGE"]
DISPLAY = {"HIJACK": "Hijack", "LEAK": "Leak", "OUTAGE": "Outage"}
PROB_COLS = ["hijack_probability", "leak_probability", "outage_probability"]
HORIZONS = [30, 60, 120, 300]


def normalize_class(value: Any) -> str:
    text = str(value).strip().upper()
    if text not in LABELS:
        raise ValueError(f"Unexpected class label: {value!r}")
    return text


def checkpoint_label(value: int | None) -> str:
    return f"<={value}s checkpoint" if value is not None else ">300s / NOT_IDENTIFIED_WITHIN_TESTED_HORIZON"


def reciprocal_rank(true_class: str, probabilities: np.ndarray) -> int:
    order = np.argsort(probabilities)[::-1]
    true_index = LABELS.index(true_class)
    return int(np.where(order == true_index)[0][0] + 1)


def load_inputs() -> tuple[pd.DataFrame, list[str], dict[str, Any]]:
    with SCHEMA.open(encoding="utf-8") as handle:
        feature_schema = json.load(handle)
    if len(feature_schema) != 74:
        raise ValueError("Reconstructed Level-1 schema is not exactly 74 features.")
    with ENSEMBLE_MANIFEST.open(encoding="utf-8") as handle:
        manifest = json.load(handle)
    if manifest.get("status") != "RECONSTRUCTED_LEVEL1_EQUIVALENCE_PASS":
        raise ValueError("Reconstructed Level-1 ensemble has not passed equivalence.")
    if manifest.get("class_order") != LABELS:
        raise ValueError(f"Unexpected class order in ensemble manifest: {manifest.get('class_order')}")
    df = pd.read_csv(FEATURES)
    if len(df) != 36:
        raise ValueError(f"Expected 36 TTI horizon rows; found {len(df)}.")
    if sorted(df["horizon_seconds"].unique().tolist()) != HORIZONS:
        raise ValueError("Expected exactly 30/60/120/300 second horizons.")
    if set(df["partition"].astype(str).str.lower()) != {"train"}:
        raise ValueError("TTI scoring pilot must use TRAIN rows only.")
    counts = df.drop_duplicates("incident_uid")["category"].map(lambda x: DISPLAY[normalize_class(x)]).value_counts().to_dict()
    if counts != {"Hijack": 3, "Leak": 3, "Outage": 3}:
        raise ValueError(f"Expected 3/3/3 pilot incidents; found {counts}.")
    missing = [feature for feature in feature_schema if feature not in df.columns]
    if missing:
        raise ValueError(f"TTI V4 input missing required features: {missing}")
    return df, feature_schema, manifest


def load_models() -> list[Any]:
    models = []
    for fold in [1, 2, 3, 4, 5]:
        path = MODEL_DIR / f"level1_xgb_fold_{fold}_hist_njobs_minus1.joblib"
        if not path.exists():
            raise FileNotFoundError(path)
        models.append(joblib.load(path))
    return models


def score_rows(df: pd.DataFrame, features: list[str]) -> pd.DataFrame:
    models = load_models()
    probs = np.stack([model.predict_proba(df[features]) for model in models], axis=0).mean(axis=0)
    out = df[
        [
            "incident_id",
            "incident_uid",
            "category",
            "partition",
            "horizon_seconds",
            "selected_onset_utc",
            "horizon_cutoff_utc",
        ]
    ].copy()
    out["true_class"] = out["category"].map(lambda x: DISPLAY[normalize_class(x)])
    out["hijack_probability"] = probs[:, 0]
    out["leak_probability"] = probs[:, 1]
    out["outage_probability"] = probs[:, 2]
    pred_indices = probs.argmax(axis=1)
    out["predicted_top1_class"] = [DISPLAY[LABELS[i]] for i in pred_indices]
    out["true_class_rank"] = [reciprocal_rank(cls.upper(), row) for cls, row in zip(out["true_class"], probs)]
    out["top1_correct"] = out["predicted_top1_class"] == out["true_class"]
    out["top2_correct"] = out["true_class_rank"] <= 2
    onset = pd.read_csv(ONSET)[["incident_uid", "ambiguity_review_flag"]]
    out = out.merge(onset, on="incident_uid", how="left", validate="many_to_one")
    out = out.rename(columns={"selected_onset_utc": "selected_onset", "ambiguity_review_flag": "onset_review_flag"})
    return out


def metric_rows(predictions: pd.DataFrame) -> list[dict[str, Any]]:
    rows = []
    for horizon, group in predictions.groupby("horizon_seconds"):
        y_true = group["true_class"]
        y_pred = group["predicted_top1_class"]
        per_class = precision_recall_fscore_support(y_true, y_pred, labels=[DISPLAY[label] for label in LABELS], zero_division=0)
        rows.append(
            {
                "horizon_seconds": int(horizon),
                "evaluable_incidents": int(len(group)),
                "macro_f1": float(f1_score(y_true, y_pred, labels=[DISPLAY[label] for label in LABELS], average="macro", zero_division=0)),
                "hijack_f1": float(per_class[2][0]),
                "leak_f1": float(per_class[2][1]),
                "outage_f1": float(per_class[2][2]),
                "top1_accuracy": float(group["top1_correct"].mean()),
                "top2_accuracy": float(group["top2_correct"].mean()),
                "mrr": float((1.0 / group["true_class_rank"]).mean()),
                "scope": "TRAIN-ONLY TTI FEASIBILITY PILOT - n=9 - DESCRIPTIVE, NOT FINAL GENERALIZATION PERFORMANCE",
            }
        )
    return rows


def confusion_rows(predictions: pd.DataFrame) -> list[dict[str, Any]]:
    rows = []
    display_labels = [DISPLAY[label] for label in LABELS]
    for horizon, group in predictions.groupby("horizon_seconds"):
        matrix = confusion_matrix(group["true_class"], group["predicted_top1_class"], labels=display_labels)
        for i, true_class in enumerate(display_labels):
            for j, predicted_class in enumerate(display_labels):
                rows.append(
                    {
                        "horizon_seconds": int(horizon),
                        "true_class": true_class,
                        "predicted_class": predicted_class,
                        "count": int(matrix[i, j]),
                    }
                )
    return rows


def checkpoint_rows(predictions: pd.DataFrame) -> list[dict[str, Any]]:
    rows = []
    for uid, group in predictions.sort_values("horizon_seconds").groupby("incident_uid"):
        horizons = group["horizon_seconds"].tolist()
        top1 = group["top1_correct"].tolist()
        top2 = group["top2_correct"].tolist()
        top1_checkpoint = next((h for h, ok in zip(horizons, top1) if ok), None)
        top2_checkpoint = next((h for h, ok in zip(horizons, top2) if ok), None)
        stable = None
        for idx, horizon in enumerate(horizons):
            if all(top1[idx:]):
                stable = horizon
                break
        rows.append(
            {
                "incident_id": group["incident_id"].iloc[0],
                "incident_uid": uid,
                "true_class": group["true_class"].iloc[0],
                "top1_tti_checkpoint": checkpoint_label(top1_checkpoint),
                "top2_tti_checkpoint": checkpoint_label(top2_checkpoint),
                "stable_correct_checkpoint": checkpoint_label(stable),
                "identified_top1_by_300s": bool(top1_checkpoint is not None),
                "identified_top2_by_300s": bool(top2_checkpoint is not None),
                "onset_review_flag": group["onset_review_flag"].iloc[0],
            }
        )
    return rows


def trajectory_rows(predictions: pd.DataFrame) -> list[dict[str, Any]]:
    rows = []
    for uid, group in predictions.sort_values("horizon_seconds").groupby("incident_uid"):
        row: dict[str, Any] = {
            "incident_id": group["incident_id"].iloc[0],
            "incident_uid": uid,
            "true_class": group["true_class"].iloc[0],
            "trajectory": " -> ".join(f"{int(r.horizon_seconds)}s:{r.predicted_top1_class}" for r in group.itertuples()),
            "onset_review_flag": group["onset_review_flag"].iloc[0],
        }
        for r in group.itertuples():
            prefix = f"h{int(r.horizon_seconds)}"
            row[f"{prefix}_top1"] = r.predicted_top1_class
            row[f"{prefix}_true_rank"] = int(r.true_class_rank)
            row[f"{prefix}_top1_correct"] = bool(r.top1_correct)
            row[f"{prefix}_top2_correct"] = bool(r.top2_correct)
            row[f"{prefix}_p_hijack"] = float(r.hijack_probability)
            row[f"{prefix}_p_leak"] = float(r.leak_probability)
            row[f"{prefix}_p_outage"] = float(r.outage_probability)
        rows.append(row)
    return rows


def onset_sensitivity_rows() -> list[dict[str, Any]]:
    onset = pd.read_csv(ONSET)
    rows = []
    for row in onset[onset["ambiguity_review_flag"].eq("REVIEW_CHANGE_ONSET_DIFFERS")].itertuples():
        selected = pd.to_datetime(row.selected_onset, utc=True)
        change = pd.to_datetime(row.candidate_change_based_onset, utc=True)
        diff = (change - selected).total_seconds()
        rows.append(
            {
                "incident_uid": row.incident_uid,
                "category": row.category,
                "selected_first_post_documented_evidence_onset": row.selected_onset,
                "diagnostic_change_based_onset": row.candidate_change_based_onset,
                "difference_seconds": diff,
                "could_change_checkpoint_membership_or_interpretation": abs(diff) > 0,
                "notes": "Primary onset was not changed; sensitivity is descriptive and not performance-selected.",
            }
        )
    return rows


def write_summary(predictions: pd.DataFrame, metrics: pd.DataFrame, disposition: str) -> None:
    top1_by_300 = int(pd.DataFrame(checkpoint_rows(predictions))["identified_top1_by_300s"].sum())
    top2_by_300 = int(pd.DataFrame(checkpoint_rows(predictions))["identified_top2_by_300s"].sum())
    best_macro = metrics["macro_f1"].max()
    lines = [
        "# TTI Scoring Summary v3",
        "",
        "**TRAIN-ONLY TTI FEASIBILITY PILOT - n=9 - DESCRIPTIVE, NOT FINAL GENERALIZATION PERFORMANCE**",
        "",
        "Scope: frozen reconstructed Level-1 XGBoost ensemble scoring of the approved 36 partial-horizon V4 rows.",
        "",
        "- Validation accessed/recomputed: NO",
        "- Final Holdout accessed/recomputed: NO",
        "- Model retrained/tuned/calibrated: NO",
        "- TTI rows scored: 36",
        "- Pilot incidents: 9 TRAIN incidents, 3 Hijack / 3 Leak / 3 Outage",
        "- Horizons: 30, 60, 120, 300 seconds",
        "- Onset rule: FIRST_POST_DOCUMENTED_EVENT_EVIDENCE",
        "- Ensemble rule: arithmetic mean class probability across five reconstructed Level-1 fold models",
        "",
        "## Horizon Metrics",
        "",
        metrics.to_markdown(index=False),
        "",
        "## Checkpoint Summary",
        "",
        f"- Top-1 identified by <=300s checkpoint: {top1_by_300}/9",
        f"- Top-2 identified by <=300s checkpoint: {top2_by_300}/9",
        f"- Best descriptive horizon Macro F1: {best_macro:.6f}",
        "",
        "These values are feasibility-pilot diagnostics only and are not final generalization performance estimates.",
        "",
        f"Decision: {disposition}",
    ]
    (TTI_DIR / "tti_scoring_summary_v3.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run() -> str:
    df, features, _manifest = load_inputs()
    predictions = score_rows(df, features)
    metrics = pd.DataFrame(metric_rows(predictions))
    confusion = pd.DataFrame(confusion_rows(predictions))
    checkpoints = pd.DataFrame(checkpoint_rows(predictions))
    trajectories = pd.DataFrame(trajectory_rows(predictions))
    onset_sensitivity = pd.DataFrame(onset_sensitivity_rows())

    status_ok = (
        len(predictions) == 36
        and predictions[PROB_COLS].notna().all().all()
        and np.allclose(predictions[PROB_COLS].sum(axis=1).to_numpy(), 1.0, atol=1e-6)
        and set(predictions["partition"].astype(str).str.lower()) == {"train"}
    )
    disposition = "PILOT_SUPPORTS_SCALE_UP" if status_ok else "PILOT_REQUIRES_METHODOLOGY_REVIEW"

    predictions.to_csv(TTI_DIR / "tti_incident_predictions_v3.csv", index=False)
    metrics.to_csv(TTI_DIR / "tti_horizon_metrics_v3.csv", index=False)
    confusion.to_csv(TTI_DIR / "tti_confusion_matrices_v3.csv", index=False)
    checkpoints.to_csv(TTI_DIR / "tti_checkpoint_results_v3.csv", index=False)
    trajectories.to_csv(TTI_DIR / "tti_prediction_trajectories_v3.csv", index=False)
    onset_sensitivity.to_csv(TTI_DIR / "tti_onset_sensitivity_v3.csv", index=False)
    write_summary(predictions, metrics, disposition)
    return disposition


def main() -> None:
    parser = argparse.ArgumentParser(description="Score the 9-incident TRAIN-only TTI pilot with the verified reconstructed Level-1 ensemble.")
    parser.parse_args()
    print(run())


if __name__ == "__main__":
    main()
