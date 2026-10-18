from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, precision_recall_fscore_support


INPUT_DIR = Path("data/tti_train_full_v2_1")
OUTPUT_DIR = Path("data/tti_train_scoring_v1")
FIGURE_DIR = OUTPUT_DIR / "figures"
MODEL_DIR = Path("data/tti_pilot/reconstructed_level1_v1")
SCHEMA = MODEL_DIR / "feature_schema_v4.json"
ENSEMBLE_MANIFEST = Path("data/tti_pilot/level1_ensemble_manifest_v2.json")
FEATURES = INPUT_DIR / "tti_train_horizon_v4_v2_1.parquet"
COHORT = INPUT_DIR / "tti_train_evaluable_cohort_v2_1.csv"
INSUFFICIENT = INPUT_DIR / "tti_insufficient_evidence_review_v2_1.csv"
COMPATIBILITY = INPUT_DIR / "tti_train_horizon_compatibility_v2_1.csv"
LEAKAGE = INPUT_DIR / "tti_train_horizon_leakage_v2_1.csv"
GATE = INPUT_DIR / "tti_train_horizon_gate_v2_1.md"

PREDICTIONS = OUTPUT_DIR / "tti_train_predictions_v1.csv"
HORIZON_METRICS = OUTPUT_DIR / "tti_train_horizon_metrics_v1.csv"
PER_CLASS_METRICS = OUTPUT_DIR / "tti_train_per_class_metrics_v1.csv"
CONFUSION_MATRICES = OUTPUT_DIR / "tti_train_confusion_matrices_v1.csv"
CHECKPOINT_TTI = OUTPUT_DIR / "tti_train_checkpoint_tti_v1.csv"
CUMULATIVE_IDENTIFICATION = OUTPUT_DIR / "tti_train_cumulative_identification_v1.csv"
PER_CLASS_TTI = OUTPUT_DIR / "tti_train_per_class_tti_v1.csv"
PREDICTION_TRAJECTORIES = OUTPUT_DIR / "tti_train_prediction_trajectories_v1.csv"
STABILITY = OUTPUT_DIR / "tti_train_stability_v1.csv"
BOOTSTRAP_CI = OUTPUT_DIR / "tti_train_bootstrap_ci_v1.csv"
SUMMARY = OUTPUT_DIR / "tti_train_scoring_summary_v1.md"

LABELS = ["HIJACK", "LEAK", "OUTAGE"]
DISPLAY = {"HIJACK": "Hijack", "LEAK": "Leak", "OUTAGE": "Outage"}
DISPLAY_LABELS = [DISPLAY[label] for label in LABELS]
PROB_COLS = ["hijack_probability", "leak_probability", "outage_probability"]
HORIZONS = [30, 60, 120, 300]
BOOTSTRAP_SEED = 20260828
BOOTSTRAP_ITERATIONS = 2000
EXPERIMENT_LABEL = "TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS"
TTI_DEFINITION = (
    "RouteViews-observable checkpoint TTI: the earliest tested observation checkpoint at which "
    "the frozen Level-1 classifier correctly identifies the incident class, measured relative to "
    "the first incident-relevant RouteViews observation following the independently documented "
    "incident start."
)


def normalize_class(value: Any) -> str:
    text = str(value).strip().upper()
    if text not in LABELS:
        raise ValueError(f"Unexpected class label: {value!r}")
    return text


def checkpoint_label(value: int | None) -> str:
    return f"<={value}s" if value is not None else "NOT_IDENTIFIED_WITHIN_300S"


def horizon_sort_key(label: str) -> int:
    order = {"<=30s": 0, "<=60s": 1, "<=120s": 2, "<=300s": 3, "NOT_IDENTIFIED_WITHIN_300S": 4}
    return order[label]


def rank_for_true_class(true_class: str, probabilities: np.ndarray) -> int:
    order = np.argsort(probabilities)[::-1]
    true_index = LABELS.index(normalize_class(true_class))
    return int(np.where(order == true_index)[0][0] + 1)


def top_order(probabilities: np.ndarray) -> str:
    order = np.argsort(probabilities)[::-1]
    return " > ".join(DISPLAY[LABELS[index]] for index in order)


def load_inputs() -> tuple[pd.DataFrame, list[str], dict[str, Any]]:
    gate_text = GATE.read_text(encoding="utf-8")
    required_gate_phrases = [
        "Recommendation: FULL_TRAIN_TTI_FEATURES_READY_FOR_SCORING",
        "Validation accessed: NO",
        "Final Holdout accessed: NO",
        "Model scoring/retraining/tuning/calibration: NO",
        "TTI-evaluable cohort: 983",
        "Horizon rows: 3932",
        "V4 rows: 3932",
        "Compatibility: {'PASS': 74}",
        "Leakage assertions: {'PASS': 3932}",
    ]
    missing_gate = [phrase for phrase in required_gate_phrases if phrase not in gate_text]
    if missing_gate:
        raise RuntimeError(f"TTI v2.1 gate is not ready for scoring: {missing_gate}")

    compatibility = pd.read_csv(COMPATIBILITY)
    leakage = pd.read_csv(LEAKAGE)
    if compatibility["status"].value_counts().to_dict() != {"PASS": 74}:
        raise RuntimeError("Expected 74/74 V4 compatibility PASS before scoring.")
    if leakage["status"].value_counts().to_dict() != {"PASS": 3932}:
        raise RuntimeError("Expected 3932/3932 leakage assertions PASS before scoring.")

    with SCHEMA.open(encoding="utf-8") as handle:
        feature_schema = json.load(handle)
    if len(feature_schema) != 74:
        raise ValueError(f"Expected exactly 74 V4 features; found {len(feature_schema)}")

    with ENSEMBLE_MANIFEST.open(encoding="utf-8") as handle:
        manifest = json.load(handle)
    if manifest.get("status") != "RECONSTRUCTED_LEVEL1_EQUIVALENCE_PASS":
        raise RuntimeError("Reconstructed Level-1 ensemble has not passed equivalence.")
    if manifest.get("class_order") != LABELS:
        raise RuntimeError(f"Unexpected class order: {manifest.get('class_order')}")
    if manifest.get("validation_accessed") is not False or manifest.get("final_holdout_accessed") is not False:
        raise RuntimeError("Reconstructed ensemble manifest indicates Validation or Holdout access.")

    cohort = pd.read_csv(COHORT)
    if len(cohort) != 983:
        raise RuntimeError(f"Expected 983 TTI-evaluable TRAIN incidents; found {len(cohort)}")
    counts = cohort["category"].map(lambda x: DISPLAY[normalize_class(x)]).value_counts().to_dict()
    if counts != {"Leak": 329, "Hijack": 327, "Outage": 327}:
        raise RuntimeError(f"Unexpected TTI cohort class counts: {counts}")
    if set(cohort["partition"].astype(str).str.lower()) != {"train"}:
        raise RuntimeError("TTI cohort contains non-TRAIN rows.")

    insufficient = pd.read_csv(INSUFFICIENT)
    status_counts = insufficient["final_tti_status"].value_counts().to_dict()
    expected_non_eval = {
        "TTI_NOT_EVALUABLE_INSUFFICIENT_ROUTEVIEWS_EVIDENCE": 9,
        "TTI_NOT_EVALUABLE_ONSET_UNRESOLVED": 1,
    }
    if status_counts != expected_non_eval:
        raise RuntimeError(f"Unexpected non-evaluable status counts: {status_counts}")

    df = pd.read_parquet(FEATURES)
    if len(df) != 3932:
        raise RuntimeError(f"Expected 3,932 horizon rows; found {len(df)}")
    if sorted(df["horizon_seconds"].unique().tolist()) != HORIZONS:
        raise RuntimeError("Expected exactly 30/60/120/300 second horizons.")
    if df["incident_uid"].nunique() != 983:
        raise RuntimeError(f"Expected 983 unique incidents; found {df['incident_uid'].nunique()}")
    if set(df["partition"].astype(str).str.lower()) != {"train"}:
        raise RuntimeError("TTI features contain non-TRAIN rows.")
    missing = [feature for feature in feature_schema if feature not in df.columns]
    if missing:
        raise RuntimeError(f"Missing V4 features: {missing}")
    if list(df.columns[-74:]) != feature_schema:
        raise RuntimeError("V4 feature order does not match reconstructed Level-1 schema.")
    merged_counts = df.drop_duplicates("incident_uid")["category"].map(lambda x: DISPLAY[normalize_class(x)]).value_counts().to_dict()
    if merged_counts != {"Leak": 329, "Hijack": 327, "Outage": 327}:
        raise RuntimeError(f"Unexpected V4 class counts: {merged_counts}")
    return df.sort_values(["incident_uid", "horizon_seconds"]).reset_index(drop=True), feature_schema, manifest


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
    x = df[features]
    probabilities = np.stack([model.predict_proba(x) for model in models], axis=0).mean(axis=0)
    if not np.allclose(probabilities.sum(axis=1), 1.0, atol=1e-6):
        raise RuntimeError("Predicted class probabilities do not sum to 1.0 within tolerance.")
    output = df[
        [
            "incident_id",
            "incident_uid",
            "category",
            "partition",
            "horizon_seconds",
            "selected_onset_utc",
            "horizon_cutoff_utc",
            "observation_count_in_horizon",
        ]
    ].copy()
    output["true_class"] = output["category"].map(lambda x: DISPLAY[normalize_class(x)])
    output["hijack_probability"] = probabilities[:, 0]
    output["leak_probability"] = probabilities[:, 1]
    output["outage_probability"] = probabilities[:, 2]
    output["predicted_top1_class"] = [DISPLAY[LABELS[index]] for index in probabilities.argmax(axis=1)]
    output["top2_ordering"] = [top_order(row) for row in probabilities]
    output["true_class_rank"] = [rank_for_true_class(true_class, row) for true_class, row in zip(output["true_class"], probabilities)]
    output["top1_correct"] = output["predicted_top1_class"].eq(output["true_class"])
    output["top2_correct"] = output["true_class_rank"].le(2)
    output["experiment_scope"] = EXPERIMENT_LABEL
    return output


def bootstrap_macro_f1(group: pd.DataFrame, iterations: int = BOOTSTRAP_ITERATIONS) -> dict[str, float]:
    rng = np.random.default_rng(BOOTSTRAP_SEED + int(group["horizon_seconds"].iloc[0]))
    incident_ids = group["incident_uid"].to_numpy()
    true_by_id = group.set_index("incident_uid")["true_class"]
    pred_by_id = group.set_index("incident_uid")["predicted_top1_class"]
    values = np.empty(iterations, dtype=float)
    for index in range(iterations):
        sample_ids = rng.choice(incident_ids, size=len(incident_ids), replace=True)
        values[index] = f1_score(
            true_by_id.loc[sample_ids],
            pred_by_id.loc[sample_ids],
            labels=DISPLAY_LABELS,
            average="macro",
            zero_division=0,
        )
    return {
        "macro_f1_ci_lower": float(np.quantile(values, 0.025)),
        "macro_f1_ci_upper": float(np.quantile(values, 0.975)),
        "macro_f1_bootstrap_mean": float(values.mean()),
        "macro_f1_bootstrap_std": float(values.std(ddof=1)),
    }


def metric_tables(predictions: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    horizon_rows = []
    per_class_rows = []
    bootstrap_rows = []
    for horizon, group in predictions.groupby("horizon_seconds", sort=True):
        y_true = group["true_class"]
        y_pred = group["predicted_top1_class"]
        precision, recall, f1, support = precision_recall_fscore_support(
            y_true, y_pred, labels=DISPLAY_LABELS, zero_division=0
        )
        boot = bootstrap_macro_f1(group)
        bootstrap_rows.append(
            {
                "horizon_seconds": int(horizon),
                "n_incidents": int(len(group)),
                "bootstrap_iterations": BOOTSTRAP_ITERATIONS,
                **boot,
                "sample_unit": "incident",
                "scope": EXPERIMENT_LABEL,
            }
        )
        horizon_rows.append(
            {
                "horizon_seconds": int(horizon),
                "n_incidents": int(len(group)),
                "macro_f1": float(f1_score(y_true, y_pred, labels=DISPLAY_LABELS, average="macro", zero_division=0)),
                "macro_f1_ci_lower": boot["macro_f1_ci_lower"],
                "macro_f1_ci_upper": boot["macro_f1_ci_upper"],
                "top1_accuracy": float(group["top1_correct"].mean()),
                "top2_accuracy": float(group["top2_correct"].mean()),
                "mrr": float((1.0 / group["true_class_rank"]).mean()),
                "sample_unit": "incident",
                "scope": EXPERIMENT_LABEL,
            }
        )
        for idx, class_name in enumerate(DISPLAY_LABELS):
            per_class_rows.append(
                {
                    "horizon_seconds": int(horizon),
                    "class": class_name,
                    "precision": float(precision[idx]),
                    "recall": float(recall[idx]),
                    "f1": float(f1[idx]),
                    "support": int(support[idx]),
                    "scope": EXPERIMENT_LABEL,
                }
            )
    return pd.DataFrame(horizon_rows), pd.DataFrame(per_class_rows), pd.DataFrame(bootstrap_rows)


def confusion_rows(predictions: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for horizon, group in predictions.groupby("horizon_seconds", sort=True):
        matrix = confusion_matrix(group["true_class"], group["predicted_top1_class"], labels=DISPLAY_LABELS)
        for true_idx, true_class in enumerate(DISPLAY_LABELS):
            for pred_idx, predicted_class in enumerate(DISPLAY_LABELS):
                rows.append(
                    {
                        "horizon_seconds": int(horizon),
                        "true_class": true_class,
                        "predicted_class": predicted_class,
                        "count": int(matrix[true_idx, pred_idx]),
                    }
                )
    return pd.DataFrame(rows)


def checkpoint_rows(predictions: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for uid, group in predictions.sort_values("horizon_seconds").groupby("incident_uid", sort=True):
        horizons = group["horizon_seconds"].astype(int).tolist()
        top1 = group["top1_correct"].astype(bool).tolist()
        top2 = group["top2_correct"].astype(bool).tolist()
        top1_checkpoint = next((h for h, ok in zip(horizons, top1) if ok), None)
        top2_checkpoint = next((h for h, ok in zip(horizons, top2) if ok), None)
        stable_checkpoint = None
        for idx, horizon in enumerate(horizons):
            if all(top1[idx:]):
                stable_checkpoint = horizon
                break
        correct_then_later_incorrect = any(top1[idx] and not all(top1[idx:]) for idx in range(len(top1)))
        top2_then_later_incorrect = any(top2[idx] and not all(top2[idx:]) for idx in range(len(top2)))
        true_probs = []
        max_probs = []
        for row in group.itertuples(index=False):
            probabilities = {
                "Hijack": row.hijack_probability,
                "Leak": row.leak_probability,
                "Outage": row.outage_probability,
            }
            true_probs.append(float(probabilities[row.true_class]))
            max_probs.append(float(max(probabilities.values())))
        rows.append(
            {
                "incident_id": group["incident_id"].iloc[0],
                "incident_uid": uid,
                "true_class": group["true_class"].iloc[0],
                "top1_tti_checkpoint": checkpoint_label(top1_checkpoint),
                "top2_tti_checkpoint": checkpoint_label(top2_checkpoint),
                "stable_correct_checkpoint": checkpoint_label(stable_checkpoint),
                "top1_identified_within_300s": top1_checkpoint is not None,
                "top2_identified_within_300s": top2_checkpoint is not None,
                "top1_correct_then_later_incorrect": correct_then_later_incorrect,
                "top2_correct_then_later_incorrect": top2_then_later_incorrect,
                "true_class_probability_decreases": any(b < a for a, b in zip(true_probs, true_probs[1:])),
                "max_probability_confidence_decreases": any(b < a for a, b in zip(max_probs, max_probs[1:])),
                "scope": EXPERIMENT_LABEL,
            }
        )
    return pd.DataFrame(rows)


def cumulative_identification(checkpoints: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    rows = []
    per_class_rows = []
    total = len(checkpoints)
    for mode, col in [("Top-1", "top1_tti_checkpoint"), ("Top-2", "top2_tti_checkpoint")]:
        for label in ["<=30s", "<=60s", "<=120s", "<=300s", "NOT_IDENTIFIED_WITHIN_300S"]:
            count = int(checkpoints[col].eq(label).sum()) if label == "NOT_IDENTIFIED_WITHIN_300S" else int(checkpoints[col].map(horizon_sort_key).le(horizon_sort_key(label)).sum())
            rows.append(
                {
                    "identification_type": mode,
                    "checkpoint": label,
                    "count": count,
                    "percent": count / total,
                    "denominator": total,
                    "scope": EXPERIMENT_LABEL,
                }
            )
        for class_name, class_group in checkpoints.groupby("true_class", sort=True):
            class_total = len(class_group)
            for label in ["<=30s", "<=60s", "<=120s", "<=300s", "NOT_IDENTIFIED_WITHIN_300S"]:
                count = int(class_group[col].eq(label).sum()) if label == "NOT_IDENTIFIED_WITHIN_300S" else int(class_group[col].map(horizon_sort_key).le(horizon_sort_key(label)).sum())
                per_class_rows.append(
                    {
                        "identification_type": mode,
                        "class": class_name,
                        "checkpoint": label,
                        "count": count,
                        "percent": count / class_total,
                        "denominator": class_total,
                        "scope": EXPERIMENT_LABEL,
                    }
                )
    stability_counts = checkpoints["stable_correct_checkpoint"].value_counts().to_dict()
    stability_rows = []
    for label in ["<=30s", "<=60s", "<=120s", "<=300s", "NOT_IDENTIFIED_WITHIN_300S"]:
        count = int(stability_counts.get(label, 0))
        stability_rows.append(
            {
                "stable_correct_checkpoint": label,
                "count": count,
                "percent": count / total,
                "denominator": total,
                "scope": EXPERIMENT_LABEL,
            }
        )
    stability_rows.extend(
        [
            {
                "stable_correct_checkpoint": "BECOMES_TOP1_CORRECT_THEN_LATER_INCORRECT",
                "count": int(checkpoints["top1_correct_then_later_incorrect"].sum()),
                "percent": float(checkpoints["top1_correct_then_later_incorrect"].mean()),
                "denominator": total,
                "scope": EXPERIMENT_LABEL,
            },
            {
                "stable_correct_checkpoint": "TOP2_CORRECT_THEN_LATER_INCORRECT",
                "count": int(checkpoints["top2_correct_then_later_incorrect"].sum()),
                "percent": float(checkpoints["top2_correct_then_later_incorrect"].mean()),
                "denominator": total,
                "scope": EXPERIMENT_LABEL,
            },
            {
                "stable_correct_checkpoint": "TRUE_CLASS_PROBABILITY_DECREASES",
                "count": int(checkpoints["true_class_probability_decreases"].sum()),
                "percent": float(checkpoints["true_class_probability_decreases"].mean()),
                "denominator": total,
                "scope": EXPERIMENT_LABEL,
            },
            {
                "stable_correct_checkpoint": "MAX_PROBABILITY_CONFIDENCE_DECREASES",
                "count": int(checkpoints["max_probability_confidence_decreases"].sum()),
                "percent": float(checkpoints["max_probability_confidence_decreases"].mean()),
                "denominator": total,
                "scope": EXPERIMENT_LABEL,
            },
        ]
    )
    return pd.DataFrame(rows), pd.DataFrame(per_class_rows), pd.DataFrame(stability_rows)


def trajectory_rows(predictions: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for uid, group in predictions.sort_values("horizon_seconds").groupby("incident_uid", sort=True):
        row: dict[str, Any] = {
            "incident_id": group["incident_id"].iloc[0],
            "incident_uid": uid,
            "true_class": group["true_class"].iloc[0],
            "top1_trajectory": " -> ".join(f"{int(r.horizon_seconds)}s:{r.predicted_top1_class}" for r in group.itertuples(index=False)),
            "top2_rank_trajectory": " -> ".join(f"{int(r.horizon_seconds)}s:rank{int(r.true_class_rank)}" for r in group.itertuples(index=False)),
            "scope": EXPERIMENT_LABEL,
        }
        true_probs = []
        max_probs = []
        for r in group.itertuples(index=False):
            prefix = f"h{int(r.horizon_seconds)}"
            probs = {"Hijack": r.hijack_probability, "Leak": r.leak_probability, "Outage": r.outage_probability}
            row[f"{prefix}_top1"] = r.predicted_top1_class
            row[f"{prefix}_top2_ordering"] = r.top2_ordering
            row[f"{prefix}_true_rank"] = int(r.true_class_rank)
            row[f"{prefix}_top1_correct"] = bool(r.top1_correct)
            row[f"{prefix}_top2_correct"] = bool(r.top2_correct)
            row[f"{prefix}_p_hijack"] = float(r.hijack_probability)
            row[f"{prefix}_p_leak"] = float(r.leak_probability)
            row[f"{prefix}_p_outage"] = float(r.outage_probability)
            row[f"{prefix}_true_class_probability"] = float(probs[r.true_class])
            row[f"{prefix}_max_probability"] = float(max(probs.values()))
            true_probs.append(float(probs[r.true_class]))
            max_probs.append(float(max(probs.values())))
        row["top1_changes_correct_to_incorrect"] = any(
            row[f"h{a}_top1_correct"] and not row[f"h{b}_top1_correct"] for a, b in zip(HORIZONS, HORIZONS[1:])
        )
        row["top2_changes_correct_to_incorrect"] = any(
            row[f"h{a}_top2_correct"] and not row[f"h{b}_top2_correct"] for a, b in zip(HORIZONS, HORIZONS[1:])
        )
        row["true_class_probability_decreases"] = any(b < a for a, b in zip(true_probs, true_probs[1:]))
        row["max_probability_confidence_decreases"] = any(b < a for a, b in zip(max_probs, max_probs[1:]))
        rows.append(row)
    return pd.DataFrame(rows)


def save_figure(fig: plt.Figure, stem: str) -> None:
    FIGURE_DIR.mkdir(parents=True, exist_ok=True)
    for suffix in ["png", "pdf"]:
        fig.savefig(FIGURE_DIR / f"{stem}.{suffix}", dpi=300, bbox_inches="tight")
    fig.savefig(FIGURE_DIR / f"{stem}_highres_chart_only.jpg", dpi=600, bbox_inches="tight", pil_kwargs={"quality": 95})
    plt.close(fig)


def make_figures(metrics: pd.DataFrame, cumulative: pd.DataFrame, per_class_tti: pd.DataFrame, stability: pd.DataFrame) -> None:
    x = np.arange(len(HORIZONS))
    fig, ax = plt.subplots(figsize=(8.2, 4.6))
    for metric, label in [("macro_f1", "Macro F1"), ("top2_accuracy", "Top-2"), ("mrr", "MRR")]:
        y = metrics.sort_values("horizon_seconds")[metric].to_numpy()
        ax.plot(x, y, marker="o", linewidth=2.2, label=label)
        for xi, yi in zip(x, y):
            ax.text(xi, yi + 0.012, f"{yi:.3f}", ha="center", va="bottom", fontsize=8)
    ax.set_xticks(x)
    ax.set_xticklabels([f"{h}s" for h in HORIZONS])
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Incident-level score")
    ax.set_xlabel("Cumulative observation horizon")
    ax.grid(axis="y", alpha=0.25)
    ax.legend(loc="lower right", frameon=False)
    save_figure(fig, "figure_tti_a_early_classification_performance_v1")

    top1 = cumulative[cumulative["identification_type"].eq("Top-1") & ~cumulative["checkpoint"].eq("NOT_IDENTIFIED_WITHIN_300S")].copy()
    fig, ax = plt.subplots(figsize=(7.2, 4.4))
    bars = ax.bar(top1["checkpoint"], top1["percent"], color="#3b6ea8")
    for bar, count, pct in zip(bars, top1["count"], top1["percent"]):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.015, f"{count}\n{pct:.1%}", ha="center", va="bottom", fontsize=8)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Cumulative Top-1 identified")
    ax.set_xlabel("Checkpoint")
    ax.grid(axis="y", alpha=0.25)
    save_figure(fig, "figure_tti_b_cumulative_top1_identification_v1")

    class_top1 = per_class_tti[per_class_tti["identification_type"].eq("Top-1") & ~per_class_tti["checkpoint"].eq("NOT_IDENTIFIED_WITHIN_300S")].copy()
    fig, ax = plt.subplots(figsize=(8.8, 4.8))
    width = 0.24
    checkpoints = ["<=30s", "<=60s", "<=120s", "<=300s"]
    for idx, class_name in enumerate(DISPLAY_LABELS):
        subset = class_top1[class_top1["class"].eq(class_name)].set_index("checkpoint").loc[checkpoints]
        positions = np.arange(len(checkpoints)) + (idx - 1) * width
        ax.bar(positions, subset["percent"], width=width, label=class_name)
    ax.set_xticks(np.arange(len(checkpoints)))
    ax.set_xticklabels(checkpoints)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Cumulative Top-1 identified")
    ax.set_xlabel("Checkpoint")
    ax.grid(axis="y", alpha=0.25)
    ax.legend(frameon=False)
    save_figure(fig, "figure_tti_c_per_class_cumulative_top1_identification_v1")

    stable = stability[stability["stable_correct_checkpoint"].isin(["<=30s", "<=60s", "<=120s", "<=300s", "NOT_IDENTIFIED_WITHIN_300S"])].copy()
    fig, ax = plt.subplots(figsize=(8.0, 4.4))
    bars = ax.bar(stable["stable_correct_checkpoint"], stable["count"], color="#607d3b")
    for bar, count, pct in zip(bars, stable["count"], stable["percent"]):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 5, f"{int(count)}\n{pct:.1%}", ha="center", va="bottom", fontsize=8)
    ax.set_ylabel("Incident count")
    ax.set_xlabel("Stable-correct checkpoint")
    ax.grid(axis="y", alpha=0.25)
    save_figure(fig, "figure_tti_d_stable_correct_checkpoint_distribution_v1")


def write_summary(
    metrics: pd.DataFrame,
    per_class: pd.DataFrame,
    cumulative: pd.DataFrame,
    per_class_tti: pd.DataFrame,
    stability: pd.DataFrame,
    checkpoints: pd.DataFrame,
    manifest: dict[str, Any],
    disposition: str,
) -> None:
    final_top1 = cumulative[(cumulative["identification_type"].eq("Top-1")) & (cumulative["checkpoint"].eq("<=300s"))].iloc[0]
    final_top2 = cumulative[(cumulative["identification_type"].eq("Top-2")) & (cumulative["checkpoint"].eq("<=300s"))].iloc[0]
    lines = [
        "# TRAIN TTI Scoring Summary v1",
        "",
        f"**{EXPERIMENT_LABEL}**",
        "",
        f"TTI definition: {TTI_DEFINITION}",
        "",
        "This is separate from the 25.58 ms downstream computational latency benchmark, live enterprise operational TTI, and the existing Final Holdout performance of the complete Level-1 + temporal-stacking architecture.",
        "",
        "Preservation controls:",
        "",
        "- Validation accessed/recomputed: NO",
        "- Final Holdout accessed/recomputed: NO",
        "- Model retrained/tuned/calibrated/optimized/modified: NO",
        "- Primary Praxis architecture/results modified: NO",
        "- Existing Final Holdout metrics remain authoritative: Macro F1 = 0.920177; Top-2 = 0.990610; MRR = 0.958529",
        "",
        "Inputs:",
        "",
        "- TTI-evaluable TRAIN incidents: 983",
        "- Class counts: 327 Hijack / 329 Leak / 327 Outage",
        "- Non-evaluable TRAIN incidents preserved outside denominators: 10",
        "- Approved horizon rows scored: 3,932",
        "- Horizons: 30 / 60 / 120 / 300 seconds",
        "- Features: exact 74-feature V4 representation",
        "- Onset rule: FIRST_POST_DOCUMENTED_EVENT_EVIDENCE",
        f"- Level-1 ensemble: {manifest.get('model_family')} with {manifest.get('inference_combination_rule')}",
        "",
        "## Horizon Metrics",
        "",
        metrics.to_markdown(index=False),
        "",
        "## Per-Class Metrics",
        "",
        per_class.to_markdown(index=False),
        "",
        "## Cumulative Identification",
        "",
        cumulative.to_markdown(index=False),
        "",
        "## Per-Class Cumulative Identification",
        "",
        per_class_tti.to_markdown(index=False),
        "",
        "## Stability Notes",
        "",
        stability.to_markdown(index=False),
        "",
        f"- Top-1 identified by <=300s: {int(final_top1['count'])}/983 ({final_top1['percent']:.3%})",
        f"- Top-2 identified by <=300s: {int(final_top2['count'])}/983 ({final_top2['percent']:.3%})",
        f"- Top-1 correct then later incorrect: {int(checkpoints['top1_correct_then_later_incorrect'].sum())}",
        f"- Top-2 correct then later incorrect: {int(checkpoints['top2_correct_then_later_incorrect'].sum())}",
        f"- True-class probability decreases across at least one step: {int(checkpoints['true_class_probability_decreases'].sum())}",
        f"- Max-probability confidence decreases across at least one step: {int(checkpoints['max_probability_confidence_decreases'].sum())}",
        "",
        "These results are retrospective TRAIN-only early-classification diagnostics. They are not independent generalization estimates and do not replace the Final Holdout results.",
        "",
        f"Decision: {disposition}",
    ]
    SUMMARY.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run() -> str:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    FIGURE_DIR.mkdir(parents=True, exist_ok=True)
    df, features, manifest = load_inputs()
    predictions = score_rows(df, features)
    metrics, per_class, bootstrap = metric_tables(predictions)
    confusion = confusion_rows(predictions)
    checkpoints = checkpoint_rows(predictions)
    cumulative, per_class_tti, stability = cumulative_identification(checkpoints)
    trajectories = trajectory_rows(predictions)

    status_ok = (
        len(predictions) == 3932
        and predictions["incident_uid"].nunique() == 983
        and predictions[PROB_COLS].notna().all().all()
        and np.allclose(predictions[PROB_COLS].sum(axis=1).to_numpy(), 1.0, atol=1e-6)
        and set(predictions["partition"].astype(str).str.lower()) == {"train"}
        and sorted(predictions["horizon_seconds"].unique().tolist()) == HORIZONS
        and len(metrics) == 4
        and (metrics["n_incidents"] == 983).all()
    )
    disposition = "TRAIN_TTI_RESULTS_READY_FOR_REVIEW" if status_ok else "TRAIN_TTI_RESULTS_REQUIRE_METHODOLOGY_REVIEW"

    predictions.to_csv(PREDICTIONS, index=False)
    metrics.to_csv(HORIZON_METRICS, index=False)
    per_class.to_csv(PER_CLASS_METRICS, index=False)
    confusion.to_csv(CONFUSION_MATRICES, index=False)
    checkpoints.to_csv(CHECKPOINT_TTI, index=False)
    cumulative.to_csv(CUMULATIVE_IDENTIFICATION, index=False)
    per_class_tti.to_csv(PER_CLASS_TTI, index=False)
    trajectories.to_csv(PREDICTION_TRAJECTORIES, index=False)
    stability.to_csv(STABILITY, index=False)
    bootstrap.to_csv(BOOTSTRAP_CI, index=False)
    make_figures(metrics, cumulative, per_class_tti, stability)
    write_summary(metrics, per_class, cumulative, per_class_tti, stability, checkpoints, manifest, disposition)
    return disposition


def main() -> None:
    parser = argparse.ArgumentParser(description="Run TRAIN-only retrospective TTI scoring over the approved v2.1 horizon V4 corpus.")
    parser.parse_args()
    print(run())


if __name__ == "__main__":
    main()
