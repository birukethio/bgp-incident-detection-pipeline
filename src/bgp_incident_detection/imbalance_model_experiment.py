from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import confusion_matrix, f1_score, precision_recall_fscore_support
from sklearn.pipeline import Pipeline

try:
    from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
    from bgp_incident_detection.model_baselines import (
        CLASS_LABELS,
        CV_ASSIGNMENTS,
        INCIDENT_LABELS,
        INCIDENT_V1,
        NORMAL_V1,
        REGISTRY,
        RF_HYPERPARAMETERS,
        SEED,
        aggregate_group_predictions,
        class_prob_frame,
        common_result,
        macro_f1,
        mrr,
        normalize_category,
        per_class_f1,
        top2_accuracy,
    )
    from bgp_incident_detection.train_batch_engine import source_commit
except ModuleNotFoundError:
    from src.bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
    from src.bgp_incident_detection.model_baselines import (
        CLASS_LABELS,
        CV_ASSIGNMENTS,
        INCIDENT_LABELS,
        INCIDENT_V1,
        NORMAL_V1,
        REGISTRY,
        RF_HYPERPARAMETERS,
        SEED,
        aggregate_group_predictions,
        class_prob_frame,
        common_result,
        macro_f1,
        mrr,
        normalize_category,
        per_class_f1,
        top2_accuracy,
    )
    from src.bgp_incident_detection.train_batch_engine import source_commit


MODELING_DIR = Path("data/modeling")
FOLD_RESULTS = MODELING_DIR / "imbalance_fold_results_v1.csv"
WEIGHT_AUDIT = MODELING_DIR / "imbalance_effective_weight_audit_v1.csv"
P95_AUDIT = MODELING_DIR / "p95_temporal_sampling_audit_v1.csv"
PAIRED_COMPARISON = MODELING_DIR / "imbalance_paired_fold_comparison_v1.csv"
MODEL_COMPARISON = MODELING_DIR / "imbalance_strategy_model_comparison_v1.csv"
NOTEBOOK = Path("notebooks/40_v1_imbalance_treatment_experiment.ipynb")
P95_WINDOW_CAP = 164

TREATMENTS = ["I0", "I1", "I2"]
MODEL_TASKS = ["RF_SINGLE", "RF_HIER"]


def load_v1_dataset_with_time() -> pd.DataFrame:
    normal = pd.read_parquet(NORMAL_V1)
    incident = pd.read_parquet(INCIDENT_V1)

    normal_rows = normal[
        [
            "window_id",
            "window_start",
            "window_end",
            "candidate_period_id",
            "associated_incident_uid",
            "category",
            "partition",
        ]
        + BEHAVIORAL_FEATURE_NAMES
    ].copy()
    normal_rows["incident_uid"] = ""
    normal_rows["control_uid"] = normal_rows["candidate_period_id"].astype(str)
    normal_rows["label"] = "NORMAL"
    normal_rows["group_id"] = normal_rows["candidate_period_id"].astype(str)
    normal_rows["model_group_id"] = normal_rows["associated_incident_uid"].astype(str)

    incident_rows = incident[
        [
            "window_id",
            "window_start",
            "window_end",
            "incident_uid",
            "category",
            "partition",
        ]
        + BEHAVIORAL_FEATURE_NAMES
    ].copy()
    incident_rows["control_uid"] = ""
    incident_rows["label"] = incident_rows["category"].map(normalize_category)
    incident_rows["group_id"] = incident_rows["incident_uid"].astype(str)
    incident_rows["model_group_id"] = incident_rows["incident_uid"].astype(str)
    incident_rows["candidate_period_id"] = ""
    incident_rows["associated_incident_uid"] = ""

    df = pd.concat([normal_rows, incident_rows], ignore_index=True, sort=False)
    df["window_id"] = df["window_id"].astype(str)
    df["model_group_id"] = df["model_group_id"].astype(str)
    df["group_id"] = df["group_id"].astype(str)
    df["window_start_ts"] = pd.to_datetime(df["window_start"], utc=True, errors="coerce")

    if len(normal_rows) != 516:
        raise ValueError(f"expected 516 Normal rows, found {len(normal_rows)}")
    if len(incident_rows) != 68031:
        raise ValueError(f"expected 68,031 incident rows, found {len(incident_rows)}")
    if set(df["partition"].astype(str)) != {"train"}:
        raise ValueError("Phase B must use TRAIN rows only")
    if len(BEHAVIORAL_FEATURE_NAMES) != 44:
        raise ValueError("Phase B must use exactly the 44 V1 behavioral features")
    forbidden = [c for c in df.columns if c.startswith("caida_") or c.startswith("rpki_")]
    if forbidden:
        raise ValueError(f"Phase B must not include CAIDA/RPKI features: {forbidden}")
    if df["window_start_ts"].isna().any():
        raise ValueError("window_start timestamps must parse before temporal capping")
    return df


def load_phase_a_assignments(df: pd.DataFrame) -> pd.DataFrame:
    if not CV_ASSIGNMENTS.exists():
        raise FileNotFoundError(f"missing Phase A CV assignments: {CV_ASSIGNMENTS}")
    assignments = pd.read_csv(CV_ASSIGNMENTS, dtype=str, low_memory=False).fillna("")
    assignments["fold"] = assignments["fold"].astype(int)
    assignments["window_id"] = assignments["window_id"].astype(str)
    assignments["model_group_id"] = assignments["model_group_id"].astype(str)

    if set(assignments["window_id"]) != set(df["window_id"]):
        raise ValueError("Phase B dataset does not match Phase A CV assignment window IDs")
    if assignments["window_id"].duplicated().any():
        raise ValueError("Phase A CV assignments contain duplicate window_id values")
    if assignments.groupby("model_group_id")["fold"].nunique().max() != 1:
        raise ValueError("Phase A CV assignments split a model_group_id across folds")
    if set(assignments["feature_variant"]) != {"V1"}:
        raise ValueError("Phase B requires V1 CV assignments")
    return assignments[["window_id", "fold"]]


def rf_pipeline() -> Pipeline:
    return Pipeline(
        [
            ("imputer", SimpleImputer(strategy="median")),
            ("model", RandomForestClassifier(**RF_HYPERPARAMETERS)),
        ]
    )


def temporal_cap_group(group: pd.DataFrame, cap: int = P95_WINDOW_CAP) -> pd.DataFrame:
    ordered = group.sort_values(["window_start_ts", "window_id"]).reset_index(drop=True)
    if len(ordered) <= cap:
        return ordered
    indices = np.linspace(0, len(ordered) - 1, cap)
    selected = sorted(set(int(round(idx)) for idx in indices))
    cursor = 0
    while len(selected) < cap and cursor < len(ordered):
        if cursor not in selected:
            selected.append(cursor)
        cursor += 1
    selected = sorted(selected[:cap])
    return ordered.iloc[selected].copy()


def apply_p95_cap(train: pd.DataFrame, model_task: str, fold: int) -> tuple[pd.DataFrame, list[dict[str, object]]]:
    rows = []
    kept_groups = []
    for model_group_id, group in train.groupby("model_group_id", sort=False):
        capped = temporal_cap_group(group, P95_WINDOW_CAP)
        kept_groups.append(capped)
        if len(group) > P95_WINDOW_CAP:
            rows.append(
                {
                    "fold": fold,
                    "model_task": model_task,
                    "imbalance_condition": "I2",
                    "model_group_id": model_group_id,
                    "original_rows": len(group),
                    "retained_rows": len(capped),
                    "discarded_rows": len(group) - len(capped),
                    "original_start": group["window_start_ts"].min().isoformat(),
                    "original_end": group["window_start_ts"].max().isoformat(),
                    "retained_start": capped["window_start_ts"].min().isoformat(),
                    "retained_end": capped["window_start_ts"].max().isoformat(),
                    "selection_method": "deterministic_linspace_first_last_even_temporal_coverage",
                    "status": "PASS" if len(capped) <= P95_WINDOW_CAP else "FAIL",
                }
            )
    capped_train = pd.concat(kept_groups, ignore_index=True, sort=False)
    return capped_train, rows


def group_aware_weights(train: pd.DataFrame) -> np.ndarray:
    group_sizes = train.groupby("model_group_id")["window_id"].transform("count").astype(float)
    return (1.0 / group_sizes).to_numpy()


def effective_weight_audit(
    train_before: pd.DataFrame,
    train_after: pd.DataFrame,
    sample_weight: np.ndarray | None,
    model_task: str,
    fold: int,
    treatment: str,
    stage_label_column: str = "label",
) -> dict[str, object]:
    weights = np.ones(len(train_after), dtype=float) if sample_weight is None else sample_weight
    working = train_after[["model_group_id", stage_label_column]].copy()
    working["sample_weight"] = weights
    group_weight = working.groupby("model_group_id")["sample_weight"].sum()
    class_weight = working.groupby(stage_label_column)["sample_weight"].sum().to_dict()
    return {
        "fold": fold,
        "model_task": model_task,
        "imbalance_condition": treatment,
        "training_rows_before_treatment": len(train_before),
        "training_rows_after_treatment": len(train_after),
        "independent_training_groups": train_after["model_group_id"].nunique(),
        "min_aggregate_group_weight": float(group_weight.min()),
        "median_aggregate_group_weight": float(group_weight.median()),
        "max_aggregate_group_weight": float(group_weight.max()),
        "effective_class_weights": json.dumps(class_weight, sort_keys=True),
        "status": "PASS" if treatment == "I0" or np.isclose(group_weight.min(), group_weight.max()) else "REVIEW",
        "notes": "I0 preserves natural row imbalance; I1/I2 compute 1/N group weights inside the training fold only",
    }


def training_subset(train: pd.DataFrame, treatment: str, model_task: str, fold: int) -> tuple[pd.DataFrame, np.ndarray | None, list[dict[str, object]]]:
    if treatment == "I0":
        return train.copy(), None, []
    if treatment == "I1":
        weighted = train.copy()
        return weighted, group_aware_weights(weighted), []
    if treatment == "I2":
        capped, p95_rows = apply_p95_cap(train, model_task, fold)
        return capped, group_aware_weights(capped), p95_rows
    raise ValueError(f"unknown treatment: {treatment}")


def fit_pipeline(model: Pipeline, train: pd.DataFrame, label_column: str, sample_weight: np.ndarray | None) -> None:
    kwargs = {}
    if sample_weight is not None:
        kwargs["model__sample_weight"] = sample_weight
    model.fit(train[BEHAVIORAL_FEATURE_NAMES], train[label_column], **kwargs)


def prefixed_result(result: dict[str, object], treatment: str, model_task: str, phase: str = "end_to_end") -> dict[str, object]:
    result["imbalance_condition"] = treatment
    result["model_task"] = model_task
    result["phase"] = phase
    return result


def fit_single_rf(data: pd.DataFrame, treatment: str) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    results = []
    weight_rows = []
    p95_rows = []
    for fold in sorted(data["fold"].unique()):
        train_before = data[data["fold"] != fold].copy()
        test = data[data["fold"] == fold].copy()
        train, weights, cap_rows = training_subset(train_before, treatment, "RF_SINGLE", int(fold))
        p95_rows.extend(cap_rows)
        weight_rows.append(effective_weight_audit(train_before, train, weights, "RF_SINGLE", int(fold), treatment))

        model = rf_pipeline()
        started = time.perf_counter()
        fit_pipeline(model, train, "label", weights)
        train_seconds = time.perf_counter() - started

        started = time.perf_counter()
        probs = class_prob_frame(list(model.classes_), model.predict_proba(test[BEHAVIORAL_FEATURE_NAMES]), CLASS_LABELS)
        infer_seconds = time.perf_counter() - started
        y_pred = probs.idxmax(axis=1).tolist()
        y_true = test["label"].tolist()
        experiment_id = f"V1_{treatment}_RF_SINGLE"
        results.append(prefixed_result(common_result(experiment_id, int(fold), train, test, train_seconds, infer_seconds, "window", y_true, y_pred, probs, CLASS_LABELS), treatment, "RF_SINGLE"))

        predictions = test[["window_id", "group_id"]].copy()
        predictions["true_label"] = y_true
        for label in CLASS_LABELS:
            predictions[f"prob_{label}"] = probs[label].to_numpy()
        gy_true, gy_pred, gprobs = aggregate_group_predictions(predictions, CLASS_LABELS)
        results.append(prefixed_result(common_result(experiment_id, int(fold), train, test, train_seconds, infer_seconds, "group", gy_true, gy_pred, gprobs, CLASS_LABELS), treatment, "RF_SINGLE"))
    return results, weight_rows, p95_rows


def stage1_result(
    experiment_id: str,
    fold: int,
    train: pd.DataFrame,
    test: pd.DataFrame,
    train_seconds: float,
    infer_seconds: float,
    y_true: list[str],
    y_pred: list[str],
    probs: pd.DataFrame,
) -> dict[str, object]:
    row = {
        "experiment_id": experiment_id,
        "fold": fold,
        "evaluation_scope": "window",
        "train_groups": train["model_group_id"].nunique(),
        "test_groups": test["model_group_id"].nunique(),
        "train_rows": len(train),
        "test_rows": len(test),
        "macro_f1": macro_f1(y_true, y_pred, ["NORMAL", "INCIDENT"]),
        "top2_accuracy": "",
        "mrr": mrr(y_true, probs),
        "train_seconds": round(train_seconds, 3),
        "inference_seconds": round(infer_seconds, 3),
        "confusion_matrix": json.dumps(confusion_matrix(y_true, y_pred, labels=["NORMAL", "INCIDENT"]).tolist()),
        "hyperparameters": json.dumps(RF_HYPERPARAMETERS, sort_keys=True),
        "notes": "",
    }
    row.update(per_class_f1(y_true, y_pred, ["NORMAL", "INCIDENT"]))
    return row


def fit_hierarchical_rf(data: pd.DataFrame, treatment: str) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    results = []
    weight_rows = []
    p95_rows = []
    for fold in sorted(data["fold"].unique()):
        base_train = data[data["fold"] != fold].copy()
        test = data[data["fold"] == fold].copy()
        base_train["stage1_label"] = np.where(base_train["label"] == "NORMAL", "NORMAL", "INCIDENT")
        test["stage1_label"] = np.where(test["label"] == "NORMAL", "NORMAL", "INCIDENT")

        stage1_train, stage1_weights, stage1_cap_rows = training_subset(base_train, treatment, "RF_HIER_STAGE1", int(fold))
        p95_rows.extend(stage1_cap_rows)
        weight_rows.append(effective_weight_audit(base_train, stage1_train, stage1_weights, "RF_HIER_STAGE1", int(fold), treatment, "stage1_label"))

        incident_base_train = base_train[base_train["label"].isin(INCIDENT_LABELS)].copy()
        stage2_train, stage2_weights, stage2_cap_rows = training_subset(incident_base_train, treatment, "RF_HIER_STAGE2", int(fold))
        p95_rows.extend(stage2_cap_rows)
        weight_rows.append(effective_weight_audit(incident_base_train, stage2_train, stage2_weights, "RF_HIER_STAGE2", int(fold), treatment))

        stage1 = rf_pipeline()
        stage2 = rf_pipeline()
        started = time.perf_counter()
        fit_pipeline(stage1, stage1_train, "stage1_label", stage1_weights)
        fit_pipeline(stage2, stage2_train, "label", stage2_weights)
        train_seconds = time.perf_counter() - started

        started = time.perf_counter()
        stage1_probs = class_prob_frame(list(stage1.classes_), stage1.predict_proba(test[BEHAVIORAL_FEATURE_NAMES]), ["NORMAL", "INCIDENT"])
        stage1_probs.index = test.index
        stage2_probs = class_prob_frame(list(stage2.classes_), stage2.predict_proba(test[BEHAVIORAL_FEATURE_NAMES]), INCIDENT_LABELS)
        stage2_probs.index = test.index
        infer_seconds = time.perf_counter() - started

        experiment_id = f"V1_{treatment}_RF_HIER"
        stage1_pred = stage1_probs.idxmax(axis=1).tolist()
        results.append(prefixed_result(stage1_result(f"{experiment_id}_STAGE1", int(fold), stage1_train, test, train_seconds, infer_seconds, test["stage1_label"].tolist(), stage1_pred, stage1_probs), treatment, "RF_HIER", "stage1"))

        incident_test = test[test["label"].isin(INCIDENT_LABELS)].copy()
        incident_stage2_probs = stage2_probs.loc[incident_test.index].reset_index(drop=True)
        stage2_pred = incident_stage2_probs.idxmax(axis=1).tolist()
        results.append(prefixed_result(common_result(f"{experiment_id}_STAGE2", int(fold), stage2_train, incident_test, train_seconds, infer_seconds, "window", incident_test["label"].tolist(), stage2_pred, incident_stage2_probs, INCIDENT_LABELS), treatment, "RF_HIER", "stage2"))

        end_probs = pd.DataFrame({"NORMAL": stage1_probs["NORMAL"]})
        for label in INCIDENT_LABELS:
            end_probs[label] = stage1_probs["INCIDENT"] * stage2_probs[label]
        end_pred = end_probs.idxmax(axis=1).tolist()
        results.append(prefixed_result(common_result(experiment_id, int(fold), stage1_train, test, train_seconds, infer_seconds, "window", test["label"].tolist(), end_pred, end_probs, CLASS_LABELS), treatment, "RF_HIER"))

        predictions = test[["window_id", "group_id"]].copy()
        predictions["true_label"] = test["label"].tolist()
        for label in CLASS_LABELS:
            predictions[f"prob_{label}"] = end_probs[label].to_numpy()
        gy_true, gy_pred, gprobs = aggregate_group_predictions(predictions, CLASS_LABELS)
        results.append(prefixed_result(common_result(experiment_id, int(fold), stage1_train, test, train_seconds, infer_seconds, "group", gy_true, gy_pred, gprobs, CLASS_LABELS), treatment, "RF_HIER"))
    return results, weight_rows, p95_rows


def summarize_strategy(fold_results: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for (experiment_id, treatment, model_task), group in fold_results.groupby(["experiment_id", "imbalance_condition", "model_task"]):
        if experiment_id.endswith("_STAGE1") or experiment_id.endswith("_STAGE2"):
            continue
        window = group[group["evaluation_scope"] == "window"]
        grouped = group[group["evaluation_scope"] == "group"]
        stage1 = fold_results[(fold_results["experiment_id"] == f"{experiment_id}_STAGE1") & (fold_results["evaluation_scope"] == "window")]
        stage2 = fold_results[(fold_results["experiment_id"] == f"{experiment_id}_STAGE2") & (fold_results["evaluation_scope"] == "window")]
        source = window if len(window) else group
        row = {
            "model": model_task,
            "imbalance_condition": treatment,
            "train_rows_used": float(pd.to_numeric(source["train_rows"], errors="coerce").mean()),
            "window_macro_f1_mean": float(pd.to_numeric(window["macro_f1"], errors="coerce").mean()) if len(window) else "",
            "window_macro_f1_std": float(pd.to_numeric(window["macro_f1"], errors="coerce").std(ddof=1)) if len(window) > 1 else "",
            "group_macro_f1_mean": float(pd.to_numeric(grouped["macro_f1"], errors="coerce").mean()) if len(grouped) else "",
            "group_macro_f1_std": float(pd.to_numeric(grouped["macro_f1"], errors="coerce").std(ddof=1)) if len(grouped) > 1 else "",
            "normal_f1": float(pd.to_numeric(window["normal_f1"], errors="coerce").mean()) if "normal_f1" in window and len(window) else "",
            "hijack_f1": float(pd.to_numeric(window["hijack_f1"], errors="coerce").mean()) if "hijack_f1" in window and len(window) else "",
            "leak_f1": float(pd.to_numeric(window["leak_f1"], errors="coerce").mean()) if "leak_f1" in window and len(window) else "",
            "outage_f1": float(pd.to_numeric(window["outage_f1"], errors="coerce").mean()) if "outage_f1" in window and len(window) else "",
            "top2": float(pd.to_numeric(window["top2_accuracy"], errors="coerce").mean()) if len(window) else "",
            "mrr": float(pd.to_numeric(window["mrr"], errors="coerce").mean()) if len(window) else "",
            "stage1_macro_f1": float(pd.to_numeric(stage1["macro_f1"], errors="coerce").mean()) if len(stage1) else "",
            "stage2_macro_f1": float(pd.to_numeric(stage2["macro_f1"], errors="coerce").mean()) if len(stage2) else "",
            "notes": "TRAIN-only grouped CV; Phase B imbalance treatment comparison only",
        }
        rows.append(row)
    return pd.DataFrame(rows).sort_values(["model", "imbalance_condition"])


def metric_lookup(fold_results: pd.DataFrame, model_task: str, treatment: str, fold: int) -> dict[str, float]:
    experiment_id = f"V1_{treatment}_{model_task}"
    end_window = fold_results[
        (fold_results["experiment_id"] == experiment_id)
        & (fold_results["fold"] == fold)
        & (fold_results["evaluation_scope"] == "window")
    ].iloc[0]
    end_group = fold_results[
        (fold_results["experiment_id"] == experiment_id)
        & (fold_results["fold"] == fold)
        & (fold_results["evaluation_scope"] == "group")
    ].iloc[0]
    metrics = {
        "window_macro_f1": float(end_window["macro_f1"]),
        "group_macro_f1": float(end_group["macro_f1"]),
        "normal_f1": float(end_window.get("normal_f1", np.nan)),
        "top2": float(end_window["top2_accuracy"]),
        "mrr": float(end_window["mrr"]),
    }
    stage2 = fold_results[
        (fold_results["experiment_id"] == f"{experiment_id}_STAGE2")
        & (fold_results["fold"] == fold)
        & (fold_results["evaluation_scope"] == "window")
    ]
    metrics["stage2_macro_f1"] = float(stage2.iloc[0]["macro_f1"]) if len(stage2) else np.nan
    return metrics


def paired_fold_comparison(fold_results: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for model_task in MODEL_TASKS:
        for fold in sorted(fold_results["fold"].unique()):
            base = {treatment: metric_lookup(fold_results, model_task, treatment, int(fold)) for treatment in TREATMENTS}
            for left, right in [("I1", "I0"), ("I2", "I0"), ("I2", "I1")]:
                row = {"model": model_task, "fold": int(fold), "comparison": f"{left}-{right}"}
                for metric in ["window_macro_f1", "group_macro_f1", "normal_f1", "stage2_macro_f1", "top2", "mrr"]:
                    row[f"{metric}_delta"] = base[left][metric] - base[right][metric]
                rows.append(row)
    return pd.DataFrame(rows)


def update_registry() -> None:
    existing = pd.read_csv(REGISTRY, dtype=str).fillna("") if REGISTRY.exists() else pd.DataFrame()
    new_rows = []
    for treatment in TREATMENTS:
        for architecture, model_task in [("single-stage", "RF_SINGLE"), ("hierarchical", "RF_HIER")]:
            new_rows.append(
                {
                    "experiment_id": f"V1_{treatment}_{model_task}",
                    "model": "RandomForestClassifier",
                    "architecture": architecture,
                    "feature_variant": "V1",
                    "feature_count": "44",
                    "imbalance_condition": {
                        "I0": "I0 Natural",
                        "I1": "I1 Group-aware weighting",
                        "I2": "I2 p95 cap + group-aware weighting",
                    }[treatment],
                    "cv_scheme": "Existing Phase A 5-fold grouped CV by model_group_id",
                    "seed": str(SEED),
                    "status": "COMPLETED",
                    "result_artifact": str(MODEL_COMPARISON),
                    "source_commit": source_commit(),
                }
            )
    new = pd.DataFrame(new_rows)
    if len(existing):
        combined = pd.concat([existing, new], ignore_index=True, sort=False)
        combined = combined.drop_duplicates("experiment_id", keep="last")
    else:
        combined = new
    combined.to_csv(REGISTRY, index=False)


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    notebook = {
        "cells": [
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": [
                    "# Phase B - V1 Imbalance Treatment Experiment\n",
                    "\n",
                    "TRAIN-only comparison of I0 natural rows, I1 group-aware weighting, and I2 p95 cap plus group-aware weighting. Uses V1 behavioral features only and the frozen Phase A grouped folds.\n",
                ],
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": [
                    "from bgp_incident_detection.imbalance_model_experiment import run_experiment\n",
                    "# run_experiment()\n",
                ],
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": [
                    "import pandas as pd\n",
                    "pd.read_csv('../data/modeling/imbalance_strategy_model_comparison_v1.csv')\n",
                ],
            },
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def run_experiment() -> dict[str, object]:
    df = load_v1_dataset_with_time()
    assignments = load_phase_a_assignments(df)
    data = df.merge(assignments, on="window_id", how="left", validate="one_to_one")
    if data["fold"].isna().any():
        raise ValueError("all V1 windows must have Phase A fold assignments")

    results: list[dict[str, object]] = []
    weight_rows: list[dict[str, object]] = []
    p95_rows: list[dict[str, object]] = []
    for treatment in TREATMENTS:
        single_results, single_weight, single_p95 = fit_single_rf(data, treatment)
        hier_results, hier_weight, hier_p95 = fit_hierarchical_rf(data, treatment)
        results.extend(single_results)
        results.extend(hier_results)
        weight_rows.extend(single_weight)
        weight_rows.extend(hier_weight)
        p95_rows.extend(single_p95)
        p95_rows.extend(hier_p95)

    MODELING_DIR.mkdir(parents=True, exist_ok=True)
    fold_results = pd.DataFrame(results)
    fold_results.to_csv(FOLD_RESULTS, index=False)
    pd.DataFrame(weight_rows).to_csv(WEIGHT_AUDIT, index=False)
    pd.DataFrame(p95_rows).to_csv(P95_AUDIT, index=False)
    comparison = summarize_strategy(fold_results)
    comparison.to_csv(MODEL_COMPARISON, index=False)
    paired = paired_fold_comparison(fold_results)
    paired.to_csv(PAIRED_COMPARISON, index=False)
    update_registry()
    write_notebook()

    i2_train = []
    for fold in sorted(data["fold"].unique()):
        capped, _ = apply_p95_cap(data[data["fold"] != fold].copy(), "SUMMARY", int(fold))
        i2_train.append(len(capped))
    return {
        "feature_variant": "V1",
        "feature_count": len(BEHAVIORAL_FEATURE_NAMES),
        "total_rows": len(data),
        "label_counts": dict(Counter(data["label"])),
        "folds_reused": str(CV_ASSIGNMENTS),
        "treatments": TREATMENTS,
        "i0_train_rows_per_fold_mean": float((len(data) - data.groupby("fold").size()).mean()),
        "i1_train_rows_per_fold_mean": float((len(data) - data.groupby("fold").size()).mean()),
        "i2_train_rows_per_fold_mean": float(np.mean(i2_train)),
        "p95_window_cap": P95_WINDOW_CAP,
        "fold_results": str(FOLD_RESULTS),
        "model_comparison": str(MODEL_COMPARISON),
        "paired_comparison": str(PAIRED_COMPARISON),
        "weight_audit": str(WEIGHT_AUDIT),
        "p95_audit": str(P95_AUDIT),
        "holdout_loaded": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Phase B V1 imbalance treatment experiment")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if args.run:
        print(json.dumps(run_experiment(), indent=2, sort_keys=True))
        return
    parser.error("choose --run")


if __name__ == "__main__":
    main()
