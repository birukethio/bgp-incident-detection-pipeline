from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.calibration import calibration_curve
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    balanced_accuracy_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    log_loss,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline

try:
    from bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT, load_assignments, load_variant
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
    from bgp_incident_detection.train_batch_engine import source_commit
except ModuleNotFoundError:
    from src.bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT, load_assignments, load_variant
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
    from src.bgp_incident_detection.train_batch_engine import source_commit


MODELING_DIR = Path("data/modeling")
OOF = MODELING_DIR / "stage1_oof_probabilities_v1.parquet"
PROB_DIST = MODELING_DIR / "stage1_probability_distribution_v1.csv"
CAL_BEFORE = MODELING_DIR / "stage1_calibration_before_v1.csv"
CAL_COMPARISON = MODELING_DIR / "stage1_calibration_comparison_v1.csv"
THRESHOLD_SWEEP = MODELING_DIR / "stage1_threshold_sweep_v1.csv"
GROUP_SWEEP = MODELING_DIR / "stage1_group_threshold_sweep_v1.csv"
STABILITY = MODELING_DIR / "stage1_threshold_stability_v1.csv"
SUMMARY = MODELING_DIR / "stage1_threshold_selection_summary_v1.csv"
ERROR_ANALYSIS = MODELING_DIR / "stage1_threshold_error_analysis_v1.csv"
NOTEBOOK = Path("notebooks/43_stage1_calibration_and_threshold.ipynb")

CALIBRATION_METHODS = ["C0_NONE", "C1_SIGMOID", "C2_ISOTONIC"]
THRESHOLDS = np.round(np.arange(0.01, 1.00, 0.01), 2)
INNER_SPLITS = 3


def rf_pipeline() -> Pipeline:
    return Pipeline(
        [
            ("imputer", SimpleImputer(strategy="median")),
            ("model", RandomForestClassifier(**RF_HYPERPARAMETERS)),
        ]
    )


def load_stage1_data() -> pd.DataFrame:
    features = FEATURES_BY_VARIANT["V4"]
    if len(features) != 74:
        raise ValueError("Phase E requires exactly 74 V4 features")
    df = load_variant("V4")
    assignments = load_assignments(df)
    data = df.merge(assignments, on="window_id", how="left", validate="one_to_one")
    data["stage1_label"] = np.where(data["label"] == "NORMAL", "NORMAL", "INCIDENT")
    if set(data["partition"].astype(str)) != {"train"}:
        raise ValueError("Phase E must use TRAIN only")
    if data.groupby("model_group_id")["fold"].nunique().max() != 1:
        raise ValueError("model_group_id crosses folds")
    return data


def fit_stage1(train: pd.DataFrame, features: list[str]) -> Pipeline:
    model = rf_pipeline()
    weights = group_aware_weights(train)
    model.fit(train[features], train["stage1_label"], model__sample_weight=weights)
    return model


def normal_probability(model: Pipeline, frame: pd.DataFrame, features: list[str]) -> np.ndarray:
    probs = class_prob_frame(list(model.classes_), model.predict_proba(frame[features]), ["NORMAL", "INCIDENT"])
    return probs["NORMAL"].to_numpy()


def inner_oof_probabilities(train: pd.DataFrame, features: list[str]) -> tuple[np.ndarray, np.ndarray]:
    groups = train[["model_group_id", "stage1_label"]].drop_duplicates("model_group_id").sort_values("model_group_id")
    splitter = StratifiedGroupKFold(n_splits=INNER_SPLITS, shuffle=True, random_state=SEED)
    group_fold = {}
    X = np.zeros(len(groups))
    for fold, (_, test_idx) in enumerate(splitter.split(X, groups["stage1_label"], groups["model_group_id"])):
        for idx in test_idx:
            group_fold[groups.iloc[idx]["model_group_id"]] = fold
    working = train.copy()
    working["inner_fold"] = working["model_group_id"].map(group_fold)
    if working["inner_fold"].isna().any():
        raise ValueError("inner grouped split failed")
    probabilities = np.zeros(len(working), dtype=float)
    for inner_fold in sorted(working["inner_fold"].unique()):
        inner_train = working[working["inner_fold"] != inner_fold]
        inner_test = working[working["inner_fold"] == inner_fold]
        model = fit_stage1(inner_train, features)
        probabilities[inner_test.index.to_numpy() - working.index.min()] = normal_probability(model, inner_test, features)
    labels = (working["stage1_label"] == "NORMAL").astype(int).to_numpy()
    return probabilities, labels


def fit_calibrator(method: str, train: pd.DataFrame, features: list[str]):
    if method == "C0_NONE":
        return None
    probs, labels = inner_oof_probabilities(train.reset_index(drop=True), features)
    if method == "C1_SIGMOID":
        calibrator = LogisticRegression(random_state=SEED, solver="lbfgs")
        calibrator.fit(probs.reshape(-1, 1), labels)
        return calibrator
    if method == "C2_ISOTONIC":
        calibrator = IsotonicRegression(out_of_bounds="clip")
        calibrator.fit(probs, labels)
        return calibrator
    raise ValueError(f"unknown calibration method: {method}")


def apply_calibrator(method: str, calibrator, raw_p_normal: np.ndarray) -> np.ndarray:
    if method == "C0_NONE":
        return raw_p_normal
    if method == "C1_SIGMOID":
        return calibrator.predict_proba(raw_p_normal.reshape(-1, 1))[:, 1]
    if method == "C2_ISOTONIC":
        return calibrator.predict(raw_p_normal)
    raise ValueError(f"unknown calibration method: {method}")


def oof_probabilities(data: pd.DataFrame, features: list[str]) -> pd.DataFrame:
    rows = []
    for fold in sorted(data["fold"].unique()):
        train = data[data["fold"] != fold].copy()
        test = data[data["fold"] == fold].copy()
        base = fit_stage1(train, features)
        raw_p = normal_probability(base, test, features)
        calibrators = {method: fit_calibrator(method, train, features) for method in CALIBRATION_METHODS}
        for method in CALIBRATION_METHODS:
            p_normal = apply_calibrator(method, calibrators[method], raw_p)
            for idx, p in zip(test.index, p_normal):
                row = data.loc[idx, ["window_id", "model_group_id", "group_id", "label", "stage1_label", "fold", "window_start", "window_end", "incident_uid", "control_uid"]].to_dict()
                row.update(
                    {
                        "true_label": row.pop("stage1_label"),
                        "calibration_method": method,
                        "p_normal": float(p),
                        "p_incident": float(1.0 - p),
                        "probability_source": "outer_grouped_oof_model_not_trained_on_model_group_id",
                    }
                )
                rows.append(row)
    oof = pd.DataFrame(rows)
    if oof.groupby(["calibration_method", "window_id"]).size().max() != 1:
        raise ValueError("each window must have one OOF probability per calibration method")
    return oof


def threshold_predictions(frame: pd.DataFrame, threshold: float) -> list[str]:
    return np.where(frame["p_normal"].to_numpy() >= threshold, "NORMAL", "INCIDENT").tolist()


def stage1_metrics(frame: pd.DataFrame, threshold: float) -> dict[str, object]:
    y_true = frame["true_label"].tolist()
    y_pred = threshold_predictions(frame, threshold)
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, labels=["NORMAL", "INCIDENT"], zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=["NORMAL", "INCIDENT"])
    false_normal = int(cm[1, 0])
    false_incident = int(cm[0, 1])
    return {
        "threshold": threshold,
        "normal_precision": float(precision[0]),
        "normal_recall": float(recall[0]),
        "normal_f1": float(f1[0]),
        "incident_precision": float(precision[1]),
        "incident_recall": float(recall[1]),
        "incident_f1": float(f1[1]),
        "macro_f1": float(f1_score(y_true, y_pred, labels=["NORMAL", "INCIDENT"], average="macro", zero_division=0)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "false_normal_rate": false_normal / max(1, int((frame["true_label"] == "INCIDENT").sum())),
        "false_incident_rate": false_incident / max(1, int((frame["true_label"] == "NORMAL").sum())),
        "confusion_matrix": json.dumps(cm.tolist()),
    }


def probability_distribution(oof: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for (method, label), group in oof.groupby(["calibration_method", "true_label"]):
        probs = group["p_normal"]
        rows.append(
            {
                "calibration_method": method,
                "true_label": label,
                "count": len(group),
                "min": probs.min(),
                "p01": probs.quantile(0.01),
                "p05": probs.quantile(0.05),
                "p25": probs.quantile(0.25),
                "median": probs.median(),
                "p75": probs.quantile(0.75),
                "p95": probs.quantile(0.95),
                "p99": probs.quantile(0.99),
                "max": probs.max(),
            }
        )
    return pd.DataFrame(rows)


def ece_score(y_true_binary: np.ndarray, p_normal: np.ndarray, bins: int = 10) -> float:
    edges = np.linspace(0, 1, bins + 1)
    total = len(p_normal)
    score = 0.0
    for low, high in zip(edges[:-1], edges[1:]):
        mask = (p_normal >= low) & (p_normal < high if high < 1 else p_normal <= high)
        if not mask.any():
            continue
        score += mask.mean() * abs(float(y_true_binary[mask].mean()) - float(p_normal[mask].mean()))
    return float(score)


def calibration_summary(oof: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    comparison = []
    reliability = []
    for method, group in oof.groupby("calibration_method"):
        y = (group["true_label"] == "NORMAL").astype(int).to_numpy()
        p = group["p_normal"].to_numpy()
        comparison.append(
            {
                "calibration_method": method,
                "roc_auc": float(roc_auc_score(y, p)),
                "pr_auc_normal": float(average_precision_score(y, p)),
                "average_precision": float(average_precision_score(y, p)),
                "brier_score": float(brier_score_loss(y, p)),
                "log_loss": float(log_loss(y, np.column_stack([1 - p, p]), labels=[0, 1])),
                "ece_10_bin": ece_score(y, p),
                "notes": "OOF probabilities; calibration fit from training-side inner grouped OOF predictions only",
            }
        )
        bins = pd.cut(group["p_normal"], np.linspace(0, 1, 11), include_lowest=True)
        for interval, binned in group.groupby(bins, observed=False):
            if len(binned) == 0:
                continue
            yy = (binned["true_label"] == "NORMAL").astype(int)
            reliability.append(
                {
                    "calibration_method": method,
                    "probability_bin": str(interval),
                    "count": len(binned),
                    "mean_predicted_p_normal": float(binned["p_normal"].mean()),
                    "observed_normal_rate": float(yy.mean()),
                    "absolute_error": abs(float(binned["p_normal"].mean()) - float(yy.mean())),
                }
            )
    return pd.DataFrame(comparison), pd.DataFrame(reliability)


def threshold_sweep(oof: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for method, group in oof.groupby("calibration_method"):
        for threshold in THRESHOLDS:
            row = stage1_metrics(group, float(threshold))
            row["calibration_method"] = method
            row["level"] = "window"
            rows.append(row)
    return pd.DataFrame(rows)


def group_oof(oof: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for (method, model_group_id), group in oof.groupby(["calibration_method", "model_group_id"]):
        rows.append(
            {
                "calibration_method": method,
                "model_group_id": model_group_id,
                "true_label": group["true_label"].iloc[0],
                "fold": int(group["fold"].iloc[0]),
                "p_normal": float(group["p_normal"].mean()),
                "p_incident": float(group["p_incident"].mean()),
                "row_count": len(group),
            }
        )
    return pd.DataFrame(rows)


def group_threshold_sweep(oof: pd.DataFrame) -> pd.DataFrame:
    grouped = group_oof(oof)
    rows = []
    for method, group in grouped.groupby("calibration_method"):
        for threshold in THRESHOLDS:
            row = stage1_metrics(group, float(threshold))
            row["calibration_method"] = method
            row["level"] = "group"
            rows.append(row)
    return pd.DataFrame(rows)


def select_threshold(sweep: pd.DataFrame, method: str) -> pd.Series:
    candidates = sweep[
        (sweep["calibration_method"] == method)
        & (sweep["normal_recall"] > 0)
        & (sweep["incident_recall"] > 0)
    ].copy()
    if candidates.empty:
        candidates = sweep[sweep["calibration_method"] == method].copy()
    candidates = candidates.sort_values(["macro_f1", "balanced_accuracy", "normal_f1"], ascending=False)
    return candidates.iloc[0]


def select_calibration_method(calibration: pd.DataFrame, sweep: pd.DataFrame) -> tuple[str, str]:
    c0 = calibration[calibration["calibration_method"] == "C0_NONE"].iloc[0]
    c0_best = select_threshold(sweep, "C0_NONE")
    candidates = []
    for _, row in calibration.iterrows():
        method = row["calibration_method"]
        best = select_threshold(sweep, method)
        brier_gain = float(c0["brier_score"]) - float(row["brier_score"])
        log_loss_gain = float(c0["log_loss"]) - float(row["log_loss"])
        roc_drop = float(c0["roc_auc"]) - float(row["roc_auc"])
        pr_drop = float(c0["pr_auc_normal"]) - float(row["pr_auc_normal"])
        candidates.append(
            {
                "method": method,
                "brier_gain": brier_gain,
                "log_loss_gain": log_loss_gain,
                "roc_drop": roc_drop,
                "pr_drop": pr_drop,
                "threshold_macro_f1": float(best["macro_f1"]),
                "material_brier_gain": brier_gain >= 0.0001,
                "preserves_discrimination": roc_drop <= 0.005 and pr_drop <= 0.0005,
            }
        )
    viable = [
        item
        for item in candidates
        if item["method"] != "C0_NONE"
        and item["material_brier_gain"]
        and item["preserves_discrimination"]
        and item["threshold_macro_f1"] >= float(c0_best["macro_f1"]) - 0.001
    ]
    if not viable:
        return (
            "C0_NONE",
            "Selected C0_NONE: calibrated alternatives did not provide material Brier improvement while preserving ROC/PR discrimination and threshold Macro F1; isotonic is not preferred with the small Normal sample.",
        )
    best = sorted(viable, key=lambda item: (item["brier_gain"], item["log_loss_gain"], item["threshold_macro_f1"]), reverse=True)[0]
    return best["method"], "Selected calibrated method after material calibration gain with preserved discrimination."


def threshold_stability(oof: pd.DataFrame, selected_method: str) -> pd.DataFrame:
    rows = []
    subset = oof[oof["calibration_method"] == selected_method]
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
                "calibration_method": selected_method,
                "optimal_threshold": float(best["threshold"]),
                "macro_f1": float(best["macro_f1"]),
                "normal_f1": float(best["normal_f1"]),
                "normal_recall": float(best["normal_recall"]),
                "incident_f1": float(best["incident_f1"]),
            }
        )
    return pd.DataFrame(rows)


def train_stage2_oof(data: pd.DataFrame, features: list[str]) -> pd.DataFrame:
    rows = []
    for fold in sorted(data["fold"].unique()):
        train = data[(data["fold"] != fold) & (data["label"].isin(INCIDENT_LABELS))].copy()
        test = data[data["fold"] == fold].copy()
        model = rf_pipeline()
        model.fit(train[features], train["label"], model__sample_weight=group_aware_weights(train))
        probs = class_prob_frame(list(model.classes_), model.predict_proba(test[features]), INCIDENT_LABELS)
        probs.index = test.index
        for idx in test.index:
            row = data.loc[idx, ["window_id", "group_id", "model_group_id", "label", "fold"]].to_dict()
            for label in INCIDENT_LABELS:
                row[f"stage2_p_{label.lower()}"] = float(probs.loc[idx, label])
            rows.append(row)
    return pd.DataFrame(rows)


def end_to_end_metrics(stage1: pd.DataFrame, stage2: pd.DataFrame, threshold: float) -> dict[str, object]:
    merged = stage1.merge(stage2, on=["window_id", "group_id", "model_group_id", "label", "fold"], how="left", validate="one_to_one")
    end_probs = pd.DataFrame({"NORMAL": merged["p_normal"]})
    for label in INCIDENT_LABELS:
        end_probs[label] = np.where(
            merged["p_normal"] >= threshold,
            0.0,
            merged["p_incident"] * merged[f"stage2_p_{label.lower()}"],
        )
    y_pred = end_probs.idxmax(axis=1).tolist()
    y_true = merged["label"].tolist()
    row = {
        "four_class_macro_f1": macro_f1(y_true, y_pred, CLASS_LABELS),
        "top2_accuracy": top2_accuracy(y_true, end_probs),
        "mrr": mrr(y_true, end_probs),
        "confusion_matrix": json.dumps(confusion_matrix(y_true, y_pred, labels=CLASS_LABELS).tolist()),
    }
    row.update(per_class_f1(y_true, y_pred, CLASS_LABELS))
    predictions = merged[["window_id", "group_id"]].copy()
    predictions["true_label"] = y_true
    for label in CLASS_LABELS:
        predictions[f"prob_{label}"] = end_probs[label].to_numpy()
    gy_true, gy_pred, gprobs = aggregate_group_predictions(predictions, CLASS_LABELS)
    row["group_macro_f1"] = macro_f1(gy_true, gy_pred, CLASS_LABELS)
    return row


def error_analysis(stage1: pd.DataFrame, threshold: float, limit: int = 5000) -> pd.DataFrame:
    frame = stage1.copy()
    frame["predicted_stage1_label"] = threshold_predictions(frame, threshold)
    errors = frame[frame["predicted_stage1_label"] != frame["true_label"]].copy()
    return errors[
        [
            "window_id",
            "model_group_id",
            "group_id",
            "true_label",
            "predicted_stage1_label",
            "fold",
            "p_normal",
            "p_incident",
            "label",
            "incident_uid",
            "control_uid",
            "window_start",
            "window_end",
        ]
    ].sort_values(["true_label", "p_normal"]).head(limit)


def update_registry() -> None:
    existing = pd.read_csv(REGISTRY, dtype=str).fillna("") if REGISTRY.exists() else pd.DataFrame()
    rows = []
    for experiment_id, method in [
        ("STAGE1_V4_I1_RF_CAL_NONE", "C0_NONE"),
        ("STAGE1_V4_I1_RF_CAL_SIGMOID", "C1_SIGMOID"),
        ("STAGE1_V4_I1_RF_CAL_ISOTONIC", "C2_ISOTONIC"),
        ("STAGE1_V4_I1_RF_THRESHOLD_CV", "TRAIN_CV_PROPOSED_THRESHOLD"),
    ]:
        rows.append(
            {
                "experiment_id": experiment_id,
                "model": "RandomForestClassifier",
                "architecture": "hierarchical-stage1",
                "feature_variant": "V4",
                "feature_count": "74",
                "imbalance_condition": "I1 Group-aware weighting",
                "cv_scheme": "Existing Phase A 5-fold grouped CV by model_group_id",
                "seed": str(SEED),
                "status": "COMPLETED",
                "result_artifact": str(SUMMARY),
                "source_commit": source_commit(),
                "calibration_or_threshold": method,
            }
        )
    new = pd.DataFrame(rows)
    combined = pd.concat([existing, new], ignore_index=True, sort=False) if len(existing) else new
    combined = combined.drop_duplicates("experiment_id", keep="last")
    combined.to_csv(REGISTRY, index=False)


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    notebook = {
        "cells": [
            {"cell_type": "markdown", "metadata": {}, "source": ["# Phase E - Stage 1 Calibration and Threshold\n", "\n", "TRAIN-only V4/I1 Stage 1 OOF probability analysis, calibration, and TRAIN-CV proposed threshold selection.\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.stage1_threshold import run_experiment\n", "# run_experiment()\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["import pandas as pd\n", "pd.read_csv('../data/modeling/stage1_threshold_selection_summary_v1.csv')\n"]},
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def run_experiment() -> dict[str, object]:
    MODELING_DIR.mkdir(parents=True, exist_ok=True)
    features = FEATURES_BY_VARIANT["V4"]
    data = load_stage1_data()
    oof = oof_probabilities(data, features)
    c0 = oof[oof["calibration_method"] == "C0_NONE"].copy()
    c0[["window_id", "model_group_id", "true_label", "fold", "p_normal", "p_incident"]].to_parquet(OOF, index=False)
    probability_distribution(oof).to_csv(PROB_DIST, index=False)
    cal_compare, reliability = calibration_summary(oof)
    cal_compare[cal_compare["calibration_method"] == "C0_NONE"].to_csv(CAL_BEFORE, index=False)
    cal_compare.to_csv(CAL_COMPARISON, index=False)
    reliability.to_csv(MODELING_DIR / "stage1_calibration_reliability_bins_v1.csv", index=False)
    sweep = threshold_sweep(oof)
    sweep.to_csv(THRESHOLD_SWEEP, index=False)
    group_sweep = group_threshold_sweep(oof)
    group_sweep.to_csv(GROUP_SWEEP, index=False)

    selected_method, calibration_selection_reason = select_calibration_method(cal_compare, sweep)
    best = select_threshold(sweep, selected_method)
    stability = threshold_stability(oof, selected_method)
    stability.to_csv(STABILITY, index=False)
    selected_stage1 = oof[oof["calibration_method"] == selected_method].copy()
    default_stage1 = oof[oof["calibration_method"] == "C0_NONE"].copy()
    selected_metrics = stage1_metrics(selected_stage1, float(best["threshold"]))
    default_metrics = stage1_metrics(default_stage1, 0.5)
    stage2 = train_stage2_oof(data, features)
    selected_end = end_to_end_metrics(selected_stage1, stage2, float(best["threshold"]))
    default_end = end_to_end_metrics(default_stage1, stage2, 0.5)
    error_analysis(selected_stage1, float(best["threshold"])).to_csv(ERROR_ANALYSIS, index=False)
    summary = pd.DataFrame(
        [
            {
                "selection_label": "TRAIN_CV_PROPOSED_THRESHOLD",
                "threshold_source": "TRAIN_GROUPED_CV",
                "feature_variant": "V4",
                "feature_count": 74,
                "imbalance_condition": "I1",
                "calibration_method": selected_method,
                "calibration_selection_reason": calibration_selection_reason,
                "default_threshold": 0.5,
                "proposed_stage1_threshold": float(best["threshold"]),
                "optimized_threshold_minus_default_threshold": float(best["threshold"]) - 0.5,
                "stage1_macro_f1_default": default_metrics["macro_f1"],
                "stage1_macro_f1_proposed": selected_metrics["macro_f1"],
                "stage1_macro_f1_improvement": selected_metrics["macro_f1"] - default_metrics["macro_f1"],
                "normal_f1_default": default_metrics["normal_f1"],
                "normal_f1_proposed": selected_metrics["normal_f1"],
                "normal_f1_improvement": selected_metrics["normal_f1"] - default_metrics["normal_f1"],
                "normal_precision_proposed": selected_metrics["normal_precision"],
                "normal_recall_proposed": selected_metrics["normal_recall"],
                "incident_f1_proposed": selected_metrics["incident_f1"],
                "balanced_accuracy_proposed": selected_metrics["balanced_accuracy"],
                "false_normal_rate_proposed": selected_metrics["false_normal_rate"],
                "false_incident_rate_proposed": selected_metrics["false_incident_rate"],
                "end_to_end_macro_f1_default": default_end["four_class_macro_f1"],
                "end_to_end_macro_f1_proposed": selected_end["four_class_macro_f1"],
                "end_to_end_macro_f1_improvement": selected_end["four_class_macro_f1"] - default_end["four_class_macro_f1"],
                "group_macro_f1_default": default_end["group_macro_f1"],
                "group_macro_f1_proposed": selected_end["group_macro_f1"],
                "group_macro_f1_improvement": selected_end["group_macro_f1"] - default_end["group_macro_f1"],
                "top2_accuracy_proposed": selected_end["top2_accuracy"],
                "mrr_proposed": selected_end["mrr"],
                "hijack_f1_proposed": selected_end["hijack_f1"],
                "leak_f1_proposed": selected_end["leak_f1"],
                "outage_f1_proposed": selected_end["outage_f1"],
                "validation_loaded": False,
                "holdout_loaded": False,
                "notes": "Proposed threshold only; not final until Validation confirmation. Objective=max Stage 1 Macro F1 with nonzero recall for both classes.",
            }
        ]
    )
    summary.to_csv(SUMMARY, index=False)
    update_registry()
    write_notebook()
    return {
        "rows": len(c0),
        "feature_variant": "V4",
        "feature_count": len(features),
        "calibration_method": selected_method,
        "proposed_stage1_threshold": float(best["threshold"]),
        "threshold_source": "TRAIN_GROUPED_CV",
        "stage1_macro_f1_default": default_metrics["macro_f1"],
        "stage1_macro_f1_proposed": selected_metrics["macro_f1"],
        "normal_f1_default": default_metrics["normal_f1"],
        "normal_f1_proposed": selected_metrics["normal_f1"],
        "end_to_end_macro_f1_proposed": selected_end["four_class_macro_f1"],
        "group_macro_f1_proposed": selected_end["group_macro_f1"],
        "validation_loaded": False,
        "holdout_loaded": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Phase E TRAIN-only Stage 1 calibration and threshold selection")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if args.run:
        print(json.dumps(run_experiment(), indent=2, sort_keys=True))
        return
    parser.error("choose --run")


if __name__ == "__main__":
    main()
