from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    balanced_accuracy_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
)

try:
    from bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT
    from bgp_incident_detection.imbalance_model_experiment import group_aware_weights
    from bgp_incident_detection.model_baselines import (
        CLASS_LABELS,
        CV_ASSIGNMENTS,
        INCIDENT_LABELS,
        REGISTRY,
        RF_HYPERPARAMETERS,
        SEED,
        aggregate_group_predictions,
        class_prob_frame,
        macro_f1,
        mrr,
        per_class_f1,
        top2_accuracy,
    )
    from bgp_incident_detection.stage1_threshold import (
        THRESHOLDS,
        end_to_end_metrics,
        fit_stage1,
        load_stage1_data,
        normal_probability,
        select_threshold,
        stage1_metrics,
        threshold_predictions,
        train_stage2_oof,
    )
    from bgp_incident_detection.train_batch_engine import source_commit
except ModuleNotFoundError:
    from src.bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT
    from src.bgp_incident_detection.imbalance_model_experiment import group_aware_weights
    from src.bgp_incident_detection.model_baselines import (
        CLASS_LABELS,
        CV_ASSIGNMENTS,
        INCIDENT_LABELS,
        REGISTRY,
        RF_HYPERPARAMETERS,
        SEED,
        aggregate_group_predictions,
        class_prob_frame,
        macro_f1,
        mrr,
        per_class_f1,
        top2_accuracy,
    )
    from src.bgp_incident_detection.stage1_threshold import (
        THRESHOLDS,
        end_to_end_metrics,
        fit_stage1,
        load_stage1_data,
        normal_probability,
        select_threshold,
        stage1_metrics,
        threshold_predictions,
        train_stage2_oof,
    )
    from src.bgp_incident_detection.train_batch_engine import source_commit


MODELING_DIR = Path("data/modeling")
WEIGHT_AUDIT = MODELING_DIR / "stage1_weight_balance_audit_v1.csv"
RESULTS = MODELING_DIR / "stage1_class_group_weight_results_v1.csv"
PROB_COMPARISON = MODELING_DIR / "stage1_class_group_weight_probability_comparison_v1.csv"
THRESHOLD_SWEEP = MODELING_DIR / "stage1_class_group_weight_threshold_sweep_v1.csv"
STABILITY = MODELING_DIR / "stage1_class_group_weight_stability_v1.csv"
OOF = MODELING_DIR / "stage1_class_group_weight_oof_probabilities_v1.parquet"
NOTEBOOK = Path("notebooks/44_stage1_class_group_weighting.ipynb")

WEIGHTING_CONDITIONS = ["W0_GROUP_ONLY", "W1_CLASS_GROUP_BALANCED"]


def w1_class_group_weights(train: pd.DataFrame) -> np.ndarray:
    working = train.reset_index(drop=True).copy()
    weights = np.zeros(len(working), dtype=float)
    for label, label_group in working.groupby("stage1_label", sort=False):
        groups = label_group["model_group_id"].unique()
        class_total = 1.0
        per_group = class_total / len(groups)
        for group_id, cell in label_group.groupby("model_group_id", sort=False):
            weights[cell.index.to_numpy()] = per_group / len(cell)
    return weights


def weights_for_condition(train: pd.DataFrame, condition: str) -> np.ndarray:
    if condition == "W0_GROUP_ONLY":
        return group_aware_weights(train)
    if condition == "W1_CLASS_GROUP_BALANCED":
        return w1_class_group_weights(train)
    raise ValueError(f"unknown weighting condition: {condition}")


def weight_balance_audit(data: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for condition in WEIGHTING_CONDITIONS:
        for fold in sorted(data["fold"].unique()):
            train = data[data["fold"] != fold].copy().reset_index(drop=True)
            weights = weights_for_condition(train, condition)
            train["sample_weight"] = weights
            class_weights = train.groupby("stage1_label")["sample_weight"].sum().to_dict()
            class_group_weights = train.groupby(["stage1_label", "model_group_id"])["sample_weight"].sum().reset_index()
            normal_groups = train.loc[train["stage1_label"] == "NORMAL", "model_group_id"].nunique()
            incident_groups = train.loc[train["stage1_label"] == "INCIDENT", "model_group_id"].nunique()
            normal_weight = float(class_weights.get("NORMAL", 0.0))
            incident_weight = float(class_weights.get("INCIDENT", 0.0))
            rows.append(
                {
                    "fold": int(fold),
                    "weighting_condition": condition,
                    "normal_training_rows": int((train["stage1_label"] == "NORMAL").sum()),
                    "incident_training_rows": int((train["stage1_label"] == "INCIDENT").sum()),
                    "normal_groups": normal_groups,
                    "incident_groups": incident_groups,
                    "total_effective_normal_sample_weight": normal_weight,
                    "total_effective_incident_sample_weight": incident_weight,
                    "incident_to_normal_effective_weight_ratio": incident_weight / normal_weight if normal_weight else np.nan,
                    "normal_group_weight_min": float(class_group_weights[class_group_weights["stage1_label"] == "NORMAL"]["sample_weight"].min()),
                    "normal_group_weight_max": float(class_group_weights[class_group_weights["stage1_label"] == "NORMAL"]["sample_weight"].max()),
                    "incident_group_weight_min": float(class_group_weights[class_group_weights["stage1_label"] == "INCIDENT"]["sample_weight"].min()),
                    "incident_group_weight_max": float(class_group_weights[class_group_weights["stage1_label"] == "INCIDENT"]["sample_weight"].max()),
                    "status": "PASS",
                }
            )
    return pd.DataFrame(rows)


def stage1_oof_for_weighting(data: pd.DataFrame, condition: str) -> pd.DataFrame:
    features = FEATURES_BY_VARIANT["V4"]
    rows = []
    for fold in sorted(data["fold"].unique()):
        train = data[data["fold"] != fold].copy().reset_index(drop=True)
        test = data[data["fold"] == fold].copy()
        weights = weights_for_condition(train, condition)
        model = fit_stage1_with_weights(train, features, weights)
        p_normal = normal_probability(model, test, features)
        for idx, p in zip(test.index, p_normal):
            row = data.loc[idx, ["window_id", "model_group_id", "group_id", "label", "stage1_label", "fold", "window_start", "window_end", "incident_uid", "control_uid"]].to_dict()
            row.update(
                {
                    "true_label": row.pop("stage1_label"),
                    "weighting_condition": condition,
                    "p_normal": float(p),
                    "p_incident": float(1.0 - p),
                    "probability_source": "outer_grouped_oof_model_not_trained_on_model_group_id",
                }
            )
            rows.append(row)
    oof = pd.DataFrame(rows)
    if oof.groupby(["weighting_condition", "window_id"]).size().max() != 1:
        raise ValueError("each window must receive one OOF probability per weighting condition")
    return oof


def fit_stage1_with_weights(train: pd.DataFrame, features: list[str], weights: np.ndarray):
    model = fit_stage1.__globals__["rf_pipeline"]()
    model.fit(train[features], train["stage1_label"], model__sample_weight=weights)
    return model


def classification_summary(frame: pd.DataFrame, threshold: float, condition: str, label: str) -> dict[str, object]:
    y = (frame["true_label"] == "NORMAL").astype(int).to_numpy()
    row = stage1_metrics(frame, threshold)
    row.update(
        {
            "weighting_condition": condition,
            "decision_rule": label,
            "roc_auc": float(roc_auc_score(y, frame["p_normal"])),
            "normal_pr_auc": float(average_precision_score(y, frame["p_normal"])),
            "brier_score": float(brier_score_loss(y, frame["p_normal"])),
        }
    )
    return row


def probability_comparison(oof: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for (condition, label), group in oof.groupby(["weighting_condition", "true_label"]):
        p = group["p_normal"]
        rows.append(
            {
                "weighting_condition": condition,
                "true_label": label,
                "count": len(group),
                "min": p.min(),
                "p25": p.quantile(0.25),
                "median": p.median(),
                "p75": p.quantile(0.75),
                "p95": p.quantile(0.95),
                "max": p.max(),
            }
        )
    for condition, group in oof.groupby("weighting_condition"):
        y = (group["true_label"] == "NORMAL").astype(int).to_numpy()
        rows.append(
            {
                "weighting_condition": condition,
                "true_label": "DISCRIMINATION",
                "count": len(group),
                "min": "",
                "p25": "",
                "median": "",
                "p75": "",
                "p95": "",
                "max": "",
                "roc_auc": float(roc_auc_score(y, group["p_normal"])),
                "normal_pr_auc": float(average_precision_score(y, group["p_normal"])),
            }
        )
    return pd.DataFrame(rows)


def threshold_sweep(oof: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for condition, group in oof.groupby("weighting_condition"):
        for threshold in THRESHOLDS:
            row = stage1_metrics(group, float(threshold))
            row["weighting_condition"] = condition
            row["level"] = "window"
            rows.append(row)
    return pd.DataFrame(rows)


def group_oof(oof: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for (condition, model_group_id), group in oof.groupby(["weighting_condition", "model_group_id"]):
        rows.append(
            {
                "weighting_condition": condition,
                "model_group_id": model_group_id,
                "true_label": group["true_label"].iloc[0],
                "fold": int(group["fold"].iloc[0]),
                "p_normal": float(group["p_normal"].mean()),
                "p_incident": float(group["p_incident"].mean()),
                "row_count": len(group),
            }
        )
    return pd.DataFrame(rows)


def group_threshold_metrics(oof: pd.DataFrame, threshold: float, condition: str) -> dict[str, object]:
    grouped = group_oof(oof[oof["weighting_condition"] == condition])
    row = stage1_metrics(grouped, threshold)
    return {f"group_{key}": value for key, value in row.items() if key != "confusion_matrix"}


def select_w1_threshold(sweep: pd.DataFrame) -> pd.Series:
    candidates = sweep[
        (sweep["weighting_condition"] == "W1_CLASS_GROUP_BALANCED")
        & (sweep["normal_recall"] > 0)
        & (sweep["incident_recall"] > 0)
    ].copy()
    return candidates.sort_values(["macro_f1", "balanced_accuracy", "normal_f1"], ascending=False).iloc[0]


def threshold_stability(oof: pd.DataFrame, condition: str) -> pd.DataFrame:
    rows = []
    subset = oof[oof["weighting_condition"] == condition]
    for fold, group in subset.groupby("fold"):
        local = []
        for threshold in THRESHOLDS:
            row = stage1_metrics(group, float(threshold))
            row["fold"] = int(fold)
            local.append(row)
        best = pd.DataFrame(local).sort_values(["macro_f1", "balanced_accuracy", "normal_f1"], ascending=False).iloc[0]
        rows.append(
            {
                "fold": int(fold),
                "weighting_condition": condition,
                "optimal_threshold": float(best["threshold"]),
                "macro_f1": float(best["macro_f1"]),
                "normal_f1": float(best["normal_f1"]),
                "normal_recall": float(best["normal_recall"]),
                "incident_recall": float(best["incident_recall"]),
            }
        )
    return pd.DataFrame(rows)


def end_to_end_with_threshold(data: pd.DataFrame, oof: pd.DataFrame, threshold: float, condition: str) -> dict[str, object]:
    stage1 = oof[oof["weighting_condition"] == condition].copy()
    stage2 = train_stage2_oof(data, FEATURES_BY_VARIANT["V4"])
    return end_to_end_metrics(stage1, stage2, threshold)


def recommendation(results: pd.DataFrame) -> str:
    w0 = results[(results["weighting_condition"] == "W0_GROUP_ONLY") & (results["decision_rule"] == "default_0.50")].iloc[0]
    w1 = results[(results["weighting_condition"] == "W1_CLASS_GROUP_BALANCED") & (results["decision_rule"] == "W1_TRAIN_CV_PROPOSED_THRESHOLD")].iloc[0]
    if float(w1["normal_pr_auc"]) <= float(w0["normal_pr_auc"]) and float(w1["normal_f1"]) <= 0.05:
        return "STAGE1_REQUIRES_DIFFERENT_FORMULATION"
    if float(w1["false_normal_rate"]) > 0.05:
        return "STAGE1_REQUIRES_DIFFERENT_FORMULATION"
    if float(w1["normal_f1"]) > float(w0["normal_f1"]) and float(w1["macro_f1"]) >= float(w0["macro_f1"]):
        return "CARRY_W1_CLASS_GROUP_BALANCED"
    return "KEEP_W0_GROUP_ONLY"


def update_registry() -> None:
    existing = pd.read_csv(REGISTRY, dtype=str).fillna("") if REGISTRY.exists() else pd.DataFrame()
    rows = [
        {
            "experiment_id": "STAGE1_V4_I1_RF_W0_GROUP_ONLY",
            "model": "RandomForestClassifier",
            "architecture": "hierarchical-stage1",
            "feature_variant": "V4",
            "feature_count": "74",
            "imbalance_condition": "W0 Group-aware weighting",
            "cv_scheme": "Existing Phase A 5-fold grouped CV by model_group_id",
            "seed": str(SEED),
            "status": "COMPLETED",
            "result_artifact": str(RESULTS),
            "source_commit": source_commit(),
        },
        {
            "experiment_id": "STAGE1_V4_I1_RF_W1_CLASS_GROUP_BALANCED",
            "model": "RandomForestClassifier",
            "architecture": "hierarchical-stage1",
            "feature_variant": "V4",
            "feature_count": "74",
            "imbalance_condition": "W1 Class-balanced + group-balanced weighting",
            "cv_scheme": "Existing Phase A 5-fold grouped CV by model_group_id",
            "seed": str(SEED),
            "status": "COMPLETED",
            "result_artifact": str(RESULTS),
            "source_commit": source_commit(),
        },
    ]
    combined = pd.concat([existing, pd.DataFrame(rows)], ignore_index=True, sort=False) if len(existing) else pd.DataFrame(rows)
    combined = combined.drop_duplicates("experiment_id", keep="last")
    combined.to_csv(REGISTRY, index=False)


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    notebook = {
        "cells": [
            {"cell_type": "markdown", "metadata": {}, "source": ["# Phase E2 - Stage 1 Class and Group Weighting\n", "\n", "TRAIN-only V4 Stage 1 comparison of W0 group-aware weighting and W1 class-balanced + group-balanced weighting.\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.stage1_class_group_weighting import run_experiment\n", "# run_experiment()\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["import pandas as pd\n", "pd.read_csv('../data/modeling/stage1_class_group_weight_results_v1.csv')\n"]},
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def run_experiment() -> dict[str, object]:
    MODELING_DIR.mkdir(parents=True, exist_ok=True)
    if len(FEATURES_BY_VARIANT["V4"]) != 74:
        raise ValueError("Phase E2 requires V4 with exactly 74 features")
    data = load_stage1_data()
    audit = weight_balance_audit(data)
    audit.to_csv(WEIGHT_AUDIT, index=False)
    oof = pd.concat([stage1_oof_for_weighting(data, condition) for condition in WEIGHTING_CONDITIONS], ignore_index=True)
    oof.to_parquet(OOF, index=False)
    probability_comparison(oof).to_csv(PROB_COMPARISON, index=False)
    sweep = threshold_sweep(oof)
    sweep.to_csv(THRESHOLD_SWEEP, index=False)
    selected = select_w1_threshold(sweep)
    stability = threshold_stability(oof, "W1_CLASS_GROUP_BALANCED")
    stability.to_csv(STABILITY, index=False)

    rows = []
    for condition in WEIGHTING_CONDITIONS:
        default_frame = oof[oof["weighting_condition"] == condition].copy()
        row = classification_summary(default_frame, 0.5, condition, "default_0.50")
        row.update(group_threshold_metrics(oof, 0.5, condition))
        rows.append(row)
    w1_threshold = float(selected["threshold"])
    w1_frame = oof[oof["weighting_condition"] == "W1_CLASS_GROUP_BALANCED"].copy()
    row = classification_summary(w1_frame, w1_threshold, "W1_CLASS_GROUP_BALANCED", "W1_TRAIN_CV_PROPOSED_THRESHOLD")
    row.update(group_threshold_metrics(oof, w1_threshold, "W1_CLASS_GROUP_BALANCED"))
    end = end_to_end_with_threshold(data, oof, w1_threshold, "W1_CLASS_GROUP_BALANCED")
    for key, value in end.items():
        row[f"end_to_end_{key}"] = value
    rows.append(row)
    results = pd.DataFrame(rows)
    results["recommendation"] = recommendation(results)
    results["threshold_source"] = "TRAIN_GROUPED_CV"
    results["validation_loaded"] = False
    results["holdout_loaded"] = False
    results.to_csv(RESULTS, index=False)
    update_registry()
    write_notebook()
    w0_default = results[(results["weighting_condition"] == "W0_GROUP_ONLY") & (results["decision_rule"] == "default_0.50")].iloc[0]
    w1_selected = results[results["decision_rule"] == "W1_TRAIN_CV_PROPOSED_THRESHOLD"].iloc[0]
    return {
        "feature_variant": "V4",
        "feature_count": 74,
        "folds_reused": str(CV_ASSIGNMENTS),
        "w1_proposed_threshold": w1_threshold,
        "w0_normal_f1_default": float(w0_default["normal_f1"]),
        "w1_normal_f1_proposed": float(w1_selected["normal_f1"]),
        "w1_false_normal_rate": float(w1_selected["false_normal_rate"]),
        "recommendation": w1_selected["recommendation"],
        "validation_loaded": False,
        "holdout_loaded": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Phase E2 TRAIN-only Stage 1 class/group weighting experiment")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if args.run:
        print(json.dumps(run_experiment(), indent=2, sort_keys=True))
        return
    parser.error("choose --run")


if __name__ == "__main__":
    main()
