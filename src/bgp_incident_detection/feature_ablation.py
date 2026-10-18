from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline

try:
    from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
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
        normalize_category,
        per_class_f1,
        top2_accuracy,
    )
    from bgp_incident_detection.train_batch_engine import source_commit
except ModuleNotFoundError:
    from src.bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
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
        normalize_category,
        per_class_f1,
        top2_accuracy,
    )
    from src.bgp_incident_detection.train_batch_engine import source_commit


MODELING_DIR = Path("data/modeling")
RESULTS = MODELING_DIR / "feature_variant_ablation_results_v1.csv"
FOLD_RESULTS = MODELING_DIR / "feature_variant_ablation_fold_results_v1.csv"
PAIRED = MODELING_DIR / "feature_ablation_paired_fold_comparison_v1.csv"
CONTRIBUTION = MODELING_DIR / "enrichment_contribution_summary_v1.csv"
SCHEMA_AUDIT = MODELING_DIR / "feature_variant_schema_audit_v1.csv"
NOTEBOOK = Path("notebooks/41_feature_variant_ablation.ipynb")

VARIANT_PATHS = {
    "V1": {
        "incident": Path("data/train_frozen/frozen_train_behavioral_corpus_v1.parquet"),
        "normal": Path("data/model_ready/frozen_normal_v1_v1.parquet"),
    },
    "V2": {
        "incident": Path("data/train_frozen/frozen_train_v2_behavioral_caida_v1.parquet"),
        "normal": Path("data/model_ready/frozen_normal_v2_v1.parquet"),
    },
    "V3": {
        "incident": Path("data/train_frozen/frozen_train_v3_behavioral_rpki_v1.parquet"),
        "normal": Path("data/model_ready/frozen_normal_v3_v1.parquet"),
    },
    "V4": {
        "incident": Path("data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet"),
        "normal": Path("data/model_ready/frozen_normal_v4_v1.parquet"),
    },
}

CAIDA_FEATURES = [
    "caida_path_observation_count",
    "caida_paths_with_no_as_path_count",
    "caida_paths_with_unknown_relationship_count",
    "caida_unknown_relationship_transition_count",
    "caida_customer_to_provider_transition_count",
    "caida_provider_to_customer_transition_count",
    "caida_peer_to_peer_transition_count",
    "caida_valley_free_valid_path_count",
    "caida_valley_free_violation_path_count",
    "caida_valley_free_violation_ratio",
    "caida_max_violation_count_per_path",
    "caida_mean_violation_count_per_path",
    "caida_customer_provider_transition_ratio",
    "caida_peer_transition_ratio",
]

RPKI_FEATURES = [
    "rpki_evidence_observation_count",
    "rpki_evaluable_observation_count",
    "rpki_valid_observation_count",
    "rpki_invalid_observation_count",
    "rpki_not_found_observation_count",
    "rpki_unevaluable_observation_count",
    "rpki_invalid_origin_observation_count",
    "rpki_invalid_maxlength_observation_count",
    "rpki_valid_observation_ratio",
    "rpki_invalid_observation_ratio",
    "rpki_not_found_observation_ratio",
    "rpki_unique_valid_prefix_count",
    "rpki_unique_invalid_prefix_count",
    "rpki_unique_not_found_prefix_count",
    "rpki_state_diversity_count",
    "rpki_dominant_state_code",
]

FEATURES_BY_VARIANT = {
    "V1": BEHAVIORAL_FEATURE_NAMES,
    "V2": BEHAVIORAL_FEATURE_NAMES + CAIDA_FEATURES,
    "V3": BEHAVIORAL_FEATURE_NAMES + RPKI_FEATURES,
    "V4": BEHAVIORAL_FEATURE_NAMES + CAIDA_FEATURES + RPKI_FEATURES,
}

EXPECTED_COUNTS = {"V1": 44, "V2": 58, "V3": 60, "V4": 74}
PAIR_DELTAS = [("V2", "V1"), ("V3", "V1"), ("V4", "V1"), ("V4", "V2"), ("V4", "V3")]


def rf_pipeline() -> Pipeline:
    return Pipeline(
        [
            ("imputer", SimpleImputer(strategy="median")),
            ("model", RandomForestClassifier(**RF_HYPERPARAMETERS)),
        ]
    )


def load_variant(variant: str) -> pd.DataFrame:
    paths = VARIANT_PATHS[variant]
    features = FEATURES_BY_VARIANT[variant]
    normal = pd.read_parquet(paths["normal"])
    incident = pd.read_parquet(paths["incident"])

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
        + features
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
        + features
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
    if len(df) != 68547:
        raise ValueError(f"{variant} expected 68,547 rows, found {len(df)}")
    if set(df["partition"].astype(str)) != {"train"}:
        raise ValueError(f"{variant} must be TRAIN only")
    if len(features) != EXPECTED_COUNTS[variant]:
        raise ValueError(f"{variant} expected {EXPECTED_COUNTS[variant]} features, found {len(features)}")
    missing = [feature for feature in features if feature not in df.columns]
    if missing:
        raise ValueError(f"{variant} missing feature columns: {missing}")
    return df


def validate_feature_schemas() -> pd.DataFrame:
    rows = []
    base_behavioral = list(BEHAVIORAL_FEATURE_NAMES)
    for variant, features in FEATURES_BY_VARIANT.items():
        df = load_variant(variant)
        behavioral_ok = [feature for feature in base_behavioral if feature in df.columns] == base_behavioral
        caida_expected = variant in {"V2", "V4"}
        rpki_expected = variant in {"V3", "V4"}
        caida_ok = all(feature in df.columns for feature in CAIDA_FEATURES) == caida_expected
        rpki_ok = all(feature in df.columns for feature in RPKI_FEATURES) == rpki_expected
        forbidden = []
        if not caida_expected:
            forbidden.extend([feature for feature in CAIDA_FEATURES if feature in df.columns])
        if not rpki_expected:
            forbidden.extend([feature for feature in RPKI_FEATURES if feature in df.columns])
        status = "PASS" if len(features) == EXPECTED_COUNTS[variant] and behavioral_ok and caida_ok and rpki_ok and not forbidden else "FAIL"
        rows.append(
            {
                "feature_variant": variant,
                "expected_feature_count": EXPECTED_COUNTS[variant],
                "observed_feature_count": len(features),
                "behavioral_columns_identical": behavioral_ok,
                "caida_schema_ok": caida_ok,
                "rpki_schema_ok": rpki_ok,
                "forbidden_feature_columns": json.dumps(forbidden),
                "row_count": len(df),
                "status": status,
            }
        )
    audit = pd.DataFrame(rows)
    if set(audit["status"]) != {"PASS"}:
        raise ValueError("feature schema validation failed")
    return audit


def load_assignments(df: pd.DataFrame) -> pd.DataFrame:
    assignments = pd.read_csv(CV_ASSIGNMENTS, dtype=str, low_memory=False).fillna("")
    assignments["fold"] = assignments["fold"].astype(int)
    assignments["window_id"] = assignments["window_id"].astype(str)
    assignments["model_group_id"] = assignments["model_group_id"].astype(str)
    if set(assignments["window_id"]) != set(df["window_id"]):
        raise ValueError("variant rows do not match the frozen Phase A CV assignments")
    if assignments.groupby("model_group_id")["fold"].nunique().max() != 1:
        raise ValueError("model_group_id crosses folds")
    return assignments[["window_id", "fold"]]


def fit_pipeline(model: Pipeline, train: pd.DataFrame, features: list[str], label_column: str, weights: np.ndarray) -> None:
    model.fit(train[features], train[label_column], model__sample_weight=weights)


def result_row(
    experiment_id: str,
    variant: str,
    model: str,
    fold: int,
    scope: str,
    phase: str,
    train: pd.DataFrame,
    test: pd.DataFrame,
    y_true: list[str],
    y_pred: list[str],
    probs: pd.DataFrame,
    labels: list[str],
    fit_time: float,
    inference_time: float,
) -> dict[str, object]:
    row = {
        "experiment_id": experiment_id,
        "model": model,
        "feature_variant": variant,
        "feature_count": EXPECTED_COUNTS[variant],
        "imbalance_condition": "I1",
        "fold": fold,
        "evaluation_scope": scope,
        "phase": phase,
        "train_rows": len(train),
        "test_rows": len(test),
        "train_groups": train["model_group_id"].nunique(),
        "test_groups": test["model_group_id"].nunique(),
        "macro_f1": macro_f1(y_true, y_pred, labels),
        "top2_accuracy": top2_accuracy(y_true, probs) if len(labels) > 2 else "",
        "mrr": mrr(y_true, probs),
        "fit_time": round(fit_time, 3),
        "inference_time": round(inference_time, 3),
        "confusion_matrix": json.dumps(confusion_matrix(y_true, y_pred, labels=labels).tolist()),
        "hyperparameters": json.dumps(RF_HYPERPARAMETERS, sort_keys=True),
        "stage1_decision_rule": "default_argmax_probability",
        "notes": "TRAIN-only paired feature-variant ablation; I1 group-aware weighting only",
    }
    row.update(per_class_f1(y_true, y_pred, labels))
    return row


def add_stage1_auc(row: dict[str, object], y_true: list[str], probs: pd.DataFrame) -> None:
    y_binary = [1 if value == "INCIDENT" else 0 for value in y_true]
    try:
        row["roc_auc"] = float(roc_auc_score(y_binary, probs["INCIDENT"]))
        row["pr_auc"] = float(average_precision_score(y_binary, probs["INCIDENT"]))
    except ValueError:
        row["roc_auc"] = ""
        row["pr_auc"] = ""


def fit_single(data: pd.DataFrame, variant: str, features: list[str]) -> list[dict[str, object]]:
    rows = []
    experiment_id = f"{variant}_I1_RF_SINGLE"
    for fold in sorted(data["fold"].unique()):
        train = data[data["fold"] != fold].copy()
        test = data[data["fold"] == fold].copy()
        weights = group_aware_weights(train)
        model = rf_pipeline()
        started = time.perf_counter()
        fit_pipeline(model, train, features, "label", weights)
        fit_time = time.perf_counter() - started
        started = time.perf_counter()
        probs = class_prob_frame(list(model.classes_), model.predict_proba(test[features]), CLASS_LABELS)
        inference_time = time.perf_counter() - started
        y_true = test["label"].tolist()
        y_pred = probs.idxmax(axis=1).tolist()
        rows.append(result_row(experiment_id, variant, "RF_SINGLE", int(fold), "window", "end_to_end", train, test, y_true, y_pred, probs, CLASS_LABELS, fit_time, inference_time))

        predictions = test[["window_id", "group_id"]].copy()
        predictions["true_label"] = y_true
        for label in CLASS_LABELS:
            predictions[f"prob_{label}"] = probs[label].to_numpy()
        gy_true, gy_pred, gprobs = aggregate_group_predictions(predictions, CLASS_LABELS)
        rows.append(result_row(experiment_id, variant, "RF_SINGLE", int(fold), "group", "end_to_end", train, test, gy_true, gy_pred, gprobs, CLASS_LABELS, fit_time, inference_time))
    return rows


def fit_hier(data: pd.DataFrame, variant: str, features: list[str]) -> list[dict[str, object]]:
    rows = []
    experiment_id = f"{variant}_I1_RF_HIER"
    for fold in sorted(data["fold"].unique()):
        base_train = data[data["fold"] != fold].copy()
        test = data[data["fold"] == fold].copy()
        base_train["stage1_label"] = np.where(base_train["label"] == "NORMAL", "NORMAL", "INCIDENT")
        test["stage1_label"] = np.where(test["label"] == "NORMAL", "NORMAL", "INCIDENT")
        stage1_weights = group_aware_weights(base_train)
        incident_train = base_train[base_train["label"].isin(INCIDENT_LABELS)].copy()
        stage2_weights = group_aware_weights(incident_train)

        stage1 = rf_pipeline()
        stage2 = rf_pipeline()
        started = time.perf_counter()
        fit_pipeline(stage1, base_train, features, "stage1_label", stage1_weights)
        fit_pipeline(stage2, incident_train, features, "label", stage2_weights)
        fit_time = time.perf_counter() - started

        started = time.perf_counter()
        stage1_probs = class_prob_frame(list(stage1.classes_), stage1.predict_proba(test[features]), ["NORMAL", "INCIDENT"])
        stage1_probs.index = test.index
        stage2_probs = class_prob_frame(list(stage2.classes_), stage2.predict_proba(test[features]), INCIDENT_LABELS)
        stage2_probs.index = test.index
        inference_time = time.perf_counter() - started

        stage1_pred = stage1_probs.idxmax(axis=1).tolist()
        stage1_row = result_row(f"{experiment_id}_STAGE1", variant, "RF_HIER", int(fold), "window", "stage1", base_train, test, test["stage1_label"].tolist(), stage1_pred, stage1_probs, ["NORMAL", "INCIDENT"], fit_time, inference_time)
        add_stage1_auc(stage1_row, test["stage1_label"].tolist(), stage1_probs)
        rows.append(stage1_row)

        incident_test = test[test["label"].isin(INCIDENT_LABELS)].copy()
        incident_stage2_probs = stage2_probs.loc[incident_test.index].reset_index(drop=True)
        stage2_pred = incident_stage2_probs.idxmax(axis=1).tolist()
        rows.append(result_row(f"{experiment_id}_STAGE2", variant, "RF_HIER", int(fold), "window", "stage2", incident_train, incident_test, incident_test["label"].tolist(), stage2_pred, incident_stage2_probs, INCIDENT_LABELS, fit_time, inference_time))

        end_probs = pd.DataFrame({"NORMAL": stage1_probs["NORMAL"]})
        for label in INCIDENT_LABELS:
            end_probs[label] = stage1_probs["INCIDENT"] * stage2_probs[label]
        end_pred = end_probs.idxmax(axis=1).tolist()
        rows.append(result_row(experiment_id, variant, "RF_HIER", int(fold), "window", "end_to_end", base_train, test, test["label"].tolist(), end_pred, end_probs, CLASS_LABELS, fit_time, inference_time))

        predictions = test[["window_id", "group_id"]].copy()
        predictions["true_label"] = test["label"].tolist()
        for label in CLASS_LABELS:
            predictions[f"prob_{label}"] = end_probs[label].to_numpy()
        gy_true, gy_pred, gprobs = aggregate_group_predictions(predictions, CLASS_LABELS)
        rows.append(result_row(experiment_id, variant, "RF_HIER", int(fold), "group", "end_to_end", base_train, test, gy_true, gy_pred, gprobs, CLASS_LABELS, fit_time, inference_time))
    return rows


def mean_std(series: pd.Series) -> tuple[float | str, float | str]:
    values = pd.to_numeric(series, errors="coerce").dropna()
    if not len(values):
        return "", ""
    return float(values.mean()), float(values.std(ddof=1)) if len(values) > 1 else ""


def summarize_results(fold_results: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for (model, variant), group in fold_results.groupby(["model", "feature_variant"]):
        end_window = group[(group["phase"] == "end_to_end") & (group["evaluation_scope"] == "window")]
        end_group = group[(group["phase"] == "end_to_end") & (group["evaluation_scope"] == "group")]
        stage1 = group[group["phase"] == "stage1"]
        stage2 = group[group["phase"] == "stage2"]
        wm, ws = mean_std(end_window["macro_f1"])
        gm, gs = mean_std(end_group["macro_f1"])
        s1m, _ = mean_std(stage1["macro_f1"])
        s2m, _ = mean_std(stage2["macro_f1"])
        top2, _ = mean_std(end_window["top2_accuracy"])
        rank, _ = mean_std(end_window["mrr"])
        fit, _ = mean_std(end_window["fit_time"])
        infer, _ = mean_std(end_window["inference_time"])
        row = {
            "model": model,
            "feature_variant": variant,
            "feature_count": EXPECTED_COUNTS[variant],
            "imbalance_condition": "I1",
            "window_macro_f1": wm,
            "window_macro_f1_std": ws,
            "group_macro_f1": gm,
            "group_macro_f1_std": gs,
            "normal_f1": pd.to_numeric(end_window.get("normal_f1", pd.Series(dtype=float)), errors="coerce").mean() if len(end_window) else "",
            "hijack_f1": pd.to_numeric(end_window.get("hijack_f1", pd.Series(dtype=float)), errors="coerce").mean() if len(end_window) else "",
            "leak_f1": pd.to_numeric(end_window.get("leak_f1", pd.Series(dtype=float)), errors="coerce").mean() if len(end_window) else "",
            "outage_f1": pd.to_numeric(end_window.get("outage_f1", pd.Series(dtype=float)), errors="coerce").mean() if len(end_window) else "",
            "stage1_macro_f1": s1m,
            "stage2_macro_f1": s2m,
            "top2_accuracy": top2,
            "mrr": rank,
            "fit_time": fit,
            "inference_time": infer,
            "stage1_normal_precision": pd.to_numeric(stage1.get("normal_precision", pd.Series(dtype=float)), errors="coerce").mean() if len(stage1) else "",
            "stage1_normal_recall": pd.to_numeric(stage1.get("normal_recall", pd.Series(dtype=float)), errors="coerce").mean() if len(stage1) else "",
            "stage1_normal_f1": pd.to_numeric(stage1.get("normal_f1", pd.Series(dtype=float)), errors="coerce").mean() if len(stage1) else "",
            "stage1_incident_precision": pd.to_numeric(stage1.get("incident_precision", pd.Series(dtype=float)), errors="coerce").mean() if len(stage1) else "",
            "stage1_incident_recall": pd.to_numeric(stage1.get("incident_recall", pd.Series(dtype=float)), errors="coerce").mean() if len(stage1) else "",
            "stage1_incident_f1": pd.to_numeric(stage1.get("incident_f1", pd.Series(dtype=float)), errors="coerce").mean() if len(stage1) else "",
            "stage1_roc_auc": pd.to_numeric(stage1.get("roc_auc", pd.Series(dtype=float)), errors="coerce").mean() if len(stage1) else "",
            "stage1_pr_auc": pd.to_numeric(stage1.get("pr_auc", pd.Series(dtype=float)), errors="coerce").mean() if len(stage1) else "",
        }
        rows.append(row)
    return pd.DataFrame(rows).sort_values(["model", "feature_variant"])


def metric_lookup(fold_results: pd.DataFrame, model: str, variant: str, fold: int) -> dict[str, float]:
    end_window = fold_results[(fold_results["model"] == model) & (fold_results["feature_variant"] == variant) & (fold_results["fold"] == fold) & (fold_results["phase"] == "end_to_end") & (fold_results["evaluation_scope"] == "window")].iloc[0]
    end_group = fold_results[(fold_results["model"] == model) & (fold_results["feature_variant"] == variant) & (fold_results["fold"] == fold) & (fold_results["phase"] == "end_to_end") & (fold_results["evaluation_scope"] == "group")].iloc[0]
    stage1 = fold_results[(fold_results["model"] == model) & (fold_results["feature_variant"] == variant) & (fold_results["fold"] == fold) & (fold_results["phase"] == "stage1")]
    stage2 = fold_results[(fold_results["model"] == model) & (fold_results["feature_variant"] == variant) & (fold_results["fold"] == fold) & (fold_results["phase"] == "stage2")]
    return {
        "window_macro_f1": float(end_window["macro_f1"]),
        "group_macro_f1": float(end_group["macro_f1"]),
        "normal_f1": float(end_window.get("normal_f1", np.nan)),
        "stage1_macro_f1": float(stage1.iloc[0]["macro_f1"]) if len(stage1) else np.nan,
        "stage1_normal_f1": float(stage1.iloc[0]["normal_f1"]) if len(stage1) else np.nan,
        "hijack_f1": float(end_window.get("hijack_f1", np.nan)),
        "leak_f1": float(end_window.get("leak_f1", np.nan)),
        "outage_f1": float(end_window.get("outage_f1", np.nan)),
        "stage2_macro_f1": float(stage2.iloc[0]["macro_f1"]) if len(stage2) else np.nan,
        "top2": float(end_window["top2_accuracy"]),
        "mrr": float(end_window["mrr"]),
    }


def paired_comparison(fold_results: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for model in ["RF_SINGLE", "RF_HIER"]:
        for fold in sorted(fold_results["fold"].unique()):
            values = {variant: metric_lookup(fold_results, model, variant, int(fold)) for variant in VARIANT_PATHS}
            for left, right in PAIR_DELTAS:
                row = {"model": model, "fold": int(fold), "comparison": f"{left}-{right}", "left_variant": left, "right_variant": right}
                for metric in ["window_macro_f1", "group_macro_f1", "normal_f1", "stage1_macro_f1", "stage1_normal_f1", "stage2_macro_f1", "hijack_f1", "leak_f1", "outage_f1", "top2", "mrr"]:
                    row[f"{metric}_delta"] = values[left][metric] - values[right][metric]
                rows.append(row)
    return pd.DataFrame(rows)


def ci95(values: pd.Series) -> tuple[float | str, float | str]:
    cleaned = pd.to_numeric(values, errors="coerce").dropna()
    if len(cleaned) < 2:
        return "", ""
    half_width = 1.96 * float(cleaned.std(ddof=1)) / np.sqrt(len(cleaned))
    return float(cleaned.mean() - half_width), float(cleaned.mean() + half_width)


def contribution_summary(paired: pd.DataFrame) -> pd.DataFrame:
    rows = []
    definitions = [
        ("Behavioral baseline", "V1", ""),
        ("CAIDA incremental contribution", "V2-V1", "V4-V3"),
        ("RPKI incremental contribution", "V3-V1", "V4-V2"),
        ("Combined CAIDA+RPKI contribution", "V4-V1", ""),
    ]
    metrics = {
        "Stage 1": "stage1_normal_f1_delta",
        "Stage 2": "stage2_macro_f1_delta",
        "end-to-end H1": "window_macro_f1_delta",
        "B0": "window_macro_f1_delta",
    }
    for label, primary, secondary in definitions:
        for scope, metric in metrics.items():
            if primary == "V1":
                rows.append({"contribution": label, "scope": scope, "comparison": "V1 baseline", "mean_delta": 0.0, "std_delta": 0.0, "ci95_low": 0.0, "ci95_high": 0.0, "positive_folds": "", "notes": "Reference behavioral-only baseline"})
                continue
            model_filter = "RF_HIER" if scope != "B0" else "RF_SINGLE"
            subset = paired[(paired["model"] == model_filter) & (paired["comparison"] == primary)]
            if secondary:
                subset = pd.concat([subset, paired[(paired["model"] == model_filter) & (paired["comparison"] == secondary)]], ignore_index=True)
            values = pd.to_numeric(subset[metric], errors="coerce").dropna()
            low, high = ci95(values)
            rows.append(
                {
                    "contribution": label,
                    "scope": scope,
                    "comparison": primary + (f" and {secondary}" if secondary else ""),
                    "mean_delta": float(values.mean()) if len(values) else "",
                    "std_delta": float(values.std(ddof=1)) if len(values) > 1 else "",
                    "ci95_low": low,
                    "ci95_high": high,
                    "positive_folds": int((values > 0).sum()) if len(values) else "",
                    "notes": "Paired grouped-fold deltas; do not overinterpret tiny means",
                }
            )
    return pd.DataFrame(rows)


def update_registry() -> None:
    existing = pd.read_csv(REGISTRY, dtype=str).fillna("") if REGISTRY.exists() else pd.DataFrame()
    rows = []
    for variant in VARIANT_PATHS:
        for model, architecture in [("RF_SINGLE", "single-stage"), ("RF_HIER", "hierarchical")]:
            rows.append(
                {
                    "experiment_id": f"{variant}_I1_{model}",
                    "model": "RandomForestClassifier",
                    "architecture": architecture,
                    "feature_variant": variant,
                    "feature_count": str(EXPECTED_COUNTS[variant]),
                    "imbalance_condition": "I1 Group-aware weighting",
                    "cv_scheme": "Existing Phase A 5-fold grouped CV by model_group_id",
                    "seed": str(SEED),
                    "status": "COMPLETED",
                    "result_artifact": str(RESULTS),
                    "source_commit": source_commit(),
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
            {"cell_type": "markdown", "metadata": {}, "source": ["# Phase C - Feature Variant Ablation\n", "\n", "TRAIN-only paired grouped-CV ablation for V1/V2/V3/V4 using I1 group-aware weighting and fixed Random Forest hyperparameters.\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.feature_ablation import run_experiment\n", "# run_experiment()\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["import pandas as pd\n", "pd.read_csv('../data/modeling/feature_variant_ablation_results_v1.csv')\n"]},
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def run_experiment() -> dict[str, object]:
    MODELING_DIR.mkdir(parents=True, exist_ok=True)
    schema = validate_feature_schemas()
    schema.to_csv(SCHEMA_AUDIT, index=False)
    rows = []
    fold_signature = None
    for variant, features in FEATURES_BY_VARIANT.items():
        df = load_variant(variant)
        assignments = load_assignments(df)
        data = df.merge(assignments, on="window_id", how="left", validate="one_to_one")
        signature = assignments.sort_values("window_id")[["window_id", "fold"]].to_dict(orient="records")
        if fold_signature is None:
            fold_signature = signature
        elif signature != fold_signature:
            raise ValueError("feature variants do not use identical fold assignments")
        rows.extend(fit_single(data, variant, features))
        rows.extend(fit_hier(data, variant, features))

    fold_results = pd.DataFrame(rows)
    fold_results.to_csv(FOLD_RESULTS, index=False)
    summary = summarize_results(fold_results)
    summary.to_csv(RESULTS, index=False)
    paired = paired_comparison(fold_results)
    paired.to_csv(PAIRED, index=False)
    contribution = contribution_summary(paired)
    contribution.to_csv(CONTRIBUTION, index=False)
    update_registry()
    write_notebook()
    return {
        "feature_counts": EXPECTED_COUNTS,
        "folds_reused": str(CV_ASSIGNMENTS),
        "imbalance_condition": "I1",
        "models": ["RF_SINGLE", "RF_HIER"],
        "fold_results": str(FOLD_RESULTS),
        "results": str(RESULTS),
        "paired_comparison": str(PAIRED),
        "contribution_summary": str(CONTRIBUTION),
        "schema_audit": str(SCHEMA_AUDIT),
        "holdout_loaded": False,
        "validation_loaded": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Phase C TRAIN-only feature-variant ablation")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if args.run:
        print(json.dumps(run_experiment(), indent=2, sort_keys=True))
        return
    parser.error("choose --run")


if __name__ == "__main__":
    main()
