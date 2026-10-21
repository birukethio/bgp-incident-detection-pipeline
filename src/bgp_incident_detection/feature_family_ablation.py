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
from sklearn.metrics import average_precision_score, confusion_matrix, precision_recall_fscore_support, roc_auc_score
from sklearn.pipeline import Pipeline

try:
    from bgp_incident_detection.feature_ablation import (
        CAIDA_FEATURES,
        RPKI_FEATURES,
        load_assignments,
        load_variant,
    )
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
    from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
    from bgp_incident_detection.train_batch_engine import source_commit
except ModuleNotFoundError:
    from src.bgp_incident_detection.feature_ablation import (
        CAIDA_FEATURES,
        RPKI_FEATURES,
        load_assignments,
        load_variant,
    )
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
    from src.bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
    from src.bgp_incident_detection.train_batch_engine import source_commit


MODELING_DIR = Path("data/modeling")
BEHAVIORAL_INVENTORY = Path("data/pilot/behavioral_feature_inventory_v1.csv")
CAIDA_INVENTORY = Path("data/enrichment/caida/caida_feature_inventory_v1.csv")
RPKI_INVENTORY = Path("data/enrichment/rpki/rpki_feature_inventory_v1.csv")

INVENTORY_OUT = MODELING_DIR / "feature_family_inventory_v1.csv"
RESULTS = MODELING_DIR / "feature_family_ablation_results_v1.csv"
FOLD_RESULTS = MODELING_DIR / "feature_family_ablation_fold_results_v1.csv"
PAIRED = MODELING_DIR / "feature_family_ablation_paired_fold_v1.csv"
RANKING = MODELING_DIR / "feature_family_contribution_ranking_v1.csv"
NOTEBOOK = Path("notebooks/42_feature_family_ablation.ipynb")

FULL_VARIANT = "FAM_V4_FULL"
I1_CONDITION = "I1"

BEHAVIORAL_FAMILY_MAP = {
    "update_count": "announcement_update_activity",
    "announcement_count": "announcement_update_activity",
    "update_rate_per_minute": "announcement_update_activity",
    "announcement_rate_per_minute": "announcement_update_activity",
    "announcement_ratio": "announcement_update_activity",
    "announcement_to_withdrawal_ratio": "announcement_update_activity",
    "withdrawal_count": "withdrawal_activity",
    "withdrawal_rate_per_minute": "withdrawal_activity",
    "withdrawal_ratio": "withdrawal_activity",
    "unique_prefix_count": "prefix_dynamics",
    "unique_announced_prefix_count": "prefix_dynamics",
    "unique_withdrawn_prefix_count": "prefix_dynamics",
    "prefix_churn_count": "prefix_dynamics",
    "prefix_with_both_announce_withdraw_count": "prefix_dynamics",
    "unique_peer_asn_count": "peer_visibility_behavior",
    "peer_prefix_pair_count": "peer_visibility_behavior",
    "peer_origin_pair_count": "peer_visibility_behavior",
    "peer_as_path_pair_count": "peer_visibility_behavior",
    "unique_next_hop_count": "peer_visibility_behavior",
    "community_observation_count": "peer_visibility_behavior",
    "community_observation_ratio": "peer_visibility_behavior",
    "unique_community_count": "peer_visibility_behavior",
    "med_observation_count": "peer_visibility_behavior",
    "unique_med_count": "peer_visibility_behavior",
    "local_pref_observation_count": "peer_visibility_behavior",
    "atomic_aggregate_count": "peer_visibility_behavior",
    "unique_origin_asn_count": "origin_change_moas_behavior",
    "origin_diversity_ratio": "origin_change_moas_behavior",
    "moas_prefix_count": "origin_change_moas_behavior",
    "moas_prefix_ratio": "origin_change_moas_behavior",
    "origin_change_event_count": "origin_change_moas_behavior",
    "unique_as_path_count": "as_path_length_structure",
    "as_path_length_min": "as_path_length_structure",
    "as_path_length_max": "as_path_length_structure",
    "as_path_length_mean": "as_path_length_structure",
    "as_path_length_median": "as_path_length_structure",
    "as_path_length_std": "as_path_length_structure",
    "as_path_length_p95": "as_path_length_structure",
    "as_path_length_range": "as_path_length_structure",
    "path_prepending_observation_count": "prepending_behavior",
    "path_prepending_ratio": "prepending_behavior",
    "prepended_asn_repetition_count": "prepending_behavior",
    "multi_path_prefix_count": "as_path_instability_path_change",
    "path_diversity_mean_per_prefix": "as_path_instability_path_change",
}


def rf_pipeline() -> Pipeline:
    return Pipeline(
        [
            ("imputer", SimpleImputer(strategy="median")),
            ("model", RandomForestClassifier(**RF_HYPERPARAMETERS)),
        ]
    )


def feature_family_inventory() -> pd.DataFrame:
    behavioral = pd.read_csv(BEHAVIORAL_INVENTORY).fillna("")
    caida = pd.read_csv(CAIDA_INVENTORY).fillna("")
    rpki = pd.read_csv(RPKI_INVENTORY).fillna("")
    rows = []
    for feature in BEHAVIORAL_FEATURE_NAMES:
        source = behavioral[behavioral["feature_name"] == feature]
        if source.empty:
            raise ValueError(f"behavioral inventory missing {feature}")
        family = BEHAVIORAL_FAMILY_MAP.get(feature)
        if not family:
            raise ValueError(f"no Phase D family mapping for {feature}")
        rows.append(
            {
                "feature_name": feature,
                "source_variant": "V1_behavioral_inventory",
                "feature_family": family,
                "definition": source.iloc[0]["definition"],
            }
        )
    for feature in CAIDA_FEATURES:
        source = caida[caida["feature_name"] == feature]
        if source.empty:
            raise ValueError(f"CAIDA inventory missing {feature}")
        rows.append(
            {
                "feature_name": feature,
                "source_variant": "V2_V4_CAIDA_inventory",
                "feature_family": "caida_as_relationship",
                "definition": source.iloc[0]["definition"],
            }
        )
    for feature in RPKI_FEATURES:
        source = rpki[rpki["feature_name"] == feature]
        if source.empty:
            raise ValueError(f"RPKI inventory missing {feature}")
        rows.append(
            {
                "feature_name": feature,
                "source_variant": "V3_V4_RPKI_inventory",
                "feature_family": "rpki_rov",
                "definition": source.iloc[0]["definition"],
            }
        )
    inventory = pd.DataFrame(rows)
    counts = inventory.groupby("feature_family")["feature_name"].transform("count")
    inventory["feature_count_in_family"] = counts
    if len(inventory) != 74:
        raise ValueError(f"expected 74 V4 features in family inventory, found {len(inventory)}")
    if inventory["feature_name"].duplicated().any():
        raise ValueError("each feature must be assigned exactly once")
    if set(inventory["feature_name"]) != set(BEHAVIORAL_FEATURE_NAMES + CAIDA_FEATURES + RPKI_FEATURES):
        raise ValueError("family inventory does not exactly match full V4 feature set")
    return inventory


def ablation_variants(inventory: pd.DataFrame) -> dict[str, list[str]]:
    full = BEHAVIORAL_FEATURE_NAMES + CAIDA_FEATURES + RPKI_FEATURES
    variants = {FULL_VARIANT: full}
    for family in sorted(inventory["feature_family"].unique()):
        remove = set(inventory.loc[inventory["feature_family"] == family, "feature_name"])
        variants[f"FAM_V4_MINUS_{family.upper()}"] = [feature for feature in full if feature not in remove]
    return variants


def fit_pipeline(model: Pipeline, train: pd.DataFrame, features: list[str], label_column: str, weights: np.ndarray) -> None:
    model.fit(train[features], train[label_column], model__sample_weight=weights)


def metric_row(
    experiment_id: str,
    model_name: str,
    removal_family: str,
    feature_count: int,
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
        "model": model_name,
        "feature_variant": "V4",
        "ablation_variant": experiment_id.rsplit("_RF_", 1)[0],
        "removed_family": removal_family,
        "feature_count": feature_count,
        "imbalance_condition": I1_CONDITION,
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
        "notes": "TRAIN-only V4 feature-family ablation; I1 group-aware weighting only",
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


def fit_single(data: pd.DataFrame, variant_id: str, features: list[str], removal_family: str) -> list[dict[str, object]]:
    rows = []
    experiment_id = f"{variant_id}_RF_SINGLE"
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
        rows.append(metric_row(experiment_id, "RF_SINGLE", removal_family, len(features), int(fold), "window", "end_to_end", train, test, y_true, y_pred, probs, CLASS_LABELS, fit_time, inference_time))

        predictions = test[["window_id", "group_id"]].copy()
        predictions["true_label"] = y_true
        for label in CLASS_LABELS:
            predictions[f"prob_{label}"] = probs[label].to_numpy()
        gy_true, gy_pred, gprobs = aggregate_group_predictions(predictions, CLASS_LABELS)
        rows.append(metric_row(experiment_id, "RF_SINGLE", removal_family, len(features), int(fold), "group", "end_to_end", train, test, gy_true, gy_pred, gprobs, CLASS_LABELS, fit_time, inference_time))
    return rows


def fit_hier(data: pd.DataFrame, variant_id: str, features: list[str], removal_family: str) -> list[dict[str, object]]:
    rows = []
    experiment_id = f"{variant_id}_RF_HIER"
    for fold in sorted(data["fold"].unique()):
        base_train = data[data["fold"] != fold].copy()
        test = data[data["fold"] == fold].copy()
        base_train["stage1_label"] = np.where(base_train["label"] == "NORMAL", "NORMAL", "INCIDENT")
        test["stage1_label"] = np.where(test["label"] == "NORMAL", "NORMAL", "INCIDENT")
        incident_train = base_train[base_train["label"].isin(INCIDENT_LABELS)].copy()
        stage1_weights = group_aware_weights(base_train)
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
        stage1_row = metric_row(f"{experiment_id}_STAGE1", "RF_HIER", removal_family, len(features), int(fold), "window", "stage1", base_train, test, test["stage1_label"].tolist(), stage1_pred, stage1_probs, ["NORMAL", "INCIDENT"], fit_time, inference_time)
        add_stage1_auc(stage1_row, test["stage1_label"].tolist(), stage1_probs)
        rows.append(stage1_row)

        incident_test = test[test["label"].isin(INCIDENT_LABELS)].copy()
        incident_stage2_probs = stage2_probs.loc[incident_test.index].reset_index(drop=True)
        stage2_pred = incident_stage2_probs.idxmax(axis=1).tolist()
        rows.append(metric_row(f"{experiment_id}_STAGE2", "RF_HIER", removal_family, len(features), int(fold), "window", "stage2", incident_train, incident_test, incident_test["label"].tolist(), stage2_pred, incident_stage2_probs, INCIDENT_LABELS, fit_time, inference_time))

        end_probs = pd.DataFrame({"NORMAL": stage1_probs["NORMAL"]})
        for label in INCIDENT_LABELS:
            end_probs[label] = stage1_probs["INCIDENT"] * stage2_probs[label]
        end_pred = end_probs.idxmax(axis=1).tolist()
        rows.append(metric_row(experiment_id, "RF_HIER", removal_family, len(features), int(fold), "window", "end_to_end", base_train, test, test["label"].tolist(), end_pred, end_probs, CLASS_LABELS, fit_time, inference_time))

        predictions = test[["window_id", "group_id"]].copy()
        predictions["true_label"] = test["label"].tolist()
        for label in CLASS_LABELS:
            predictions[f"prob_{label}"] = end_probs[label].to_numpy()
        gy_true, gy_pred, gprobs = aggregate_group_predictions(predictions, CLASS_LABELS)
        rows.append(metric_row(experiment_id, "RF_HIER", removal_family, len(features), int(fold), "group", "end_to_end", base_train, test, gy_true, gy_pred, gprobs, CLASS_LABELS, fit_time, inference_time))
    return rows


def mean_std(series: pd.Series) -> tuple[float | str, float | str]:
    values = pd.to_numeric(series, errors="coerce").dropna()
    if not len(values):
        return "", ""
    return float(values.mean()), float(values.std(ddof=1)) if len(values) > 1 else ""


def summarize_results(fold_results: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for (experiment_id, model_name, removal), group in fold_results.groupby(["experiment_id", "model", "removed_family"]):
        if experiment_id.endswith("_STAGE1") or experiment_id.endswith("_STAGE2"):
            continue
        end_window = group[(group["phase"] == "end_to_end") & (group["evaluation_scope"] == "window")]
        end_group = group[(group["phase"] == "end_to_end") & (group["evaluation_scope"] == "group")]
        stage1 = fold_results[(fold_results["experiment_id"] == f"{experiment_id}_STAGE1") & (fold_results["phase"] == "stage1")]
        stage2 = fold_results[(fold_results["experiment_id"] == f"{experiment_id}_STAGE2") & (fold_results["phase"] == "stage2")]
        row = {
            "experiment_id": experiment_id,
            "model": model_name,
            "ablation_variant": experiment_id.rsplit("_RF_", 1)[0],
            "removed_family": removal,
            "feature_count": int(end_window["feature_count"].iloc[0]) if len(end_window) else "",
            "imbalance_condition": I1_CONDITION,
        }
        for output, source, column in [
            ("window_macro_f1", end_window, "macro_f1"),
            ("group_macro_f1", end_group, "macro_f1"),
            ("normal_f1", end_window, "normal_f1"),
            ("hijack_f1", end_window, "hijack_f1"),
            ("leak_f1", end_window, "leak_f1"),
            ("outage_f1", end_window, "outage_f1"),
            ("top2_accuracy", end_window, "top2_accuracy"),
            ("mrr", end_window, "mrr"),
            ("stage1_macro_f1", stage1, "macro_f1"),
            ("stage1_normal_precision", stage1, "normal_precision"),
            ("stage1_normal_recall", stage1, "normal_recall"),
            ("stage1_normal_f1", stage1, "normal_f1"),
            ("stage1_incident_f1", stage1, "incident_f1"),
            ("stage1_roc_auc", stage1, "roc_auc"),
            ("stage1_pr_auc", stage1, "pr_auc"),
            ("stage2_macro_f1", stage2, "macro_f1"),
            ("stage2_hijack_f1", stage2, "hijack_f1"),
            ("stage2_leak_f1", stage2, "leak_f1"),
            ("stage2_outage_f1", stage2, "outage_f1"),
            ("stage2_top2_accuracy", stage2, "top2_accuracy"),
            ("stage2_mrr", stage2, "mrr"),
            ("fit_time", end_window, "fit_time"),
            ("inference_time", end_window, "inference_time"),
        ]:
            mean, std = mean_std(source[column]) if len(source) and column in source else ("", "")
            row[output] = mean
            row[f"{output}_std"] = std
        rows.append(row)
    return pd.DataFrame(rows).sort_values(["model", "ablation_variant"])


def metric_lookup(fold_results: pd.DataFrame, model_name: str, variant_id: str, fold: int) -> dict[str, float]:
    exp = f"{variant_id}_{model_name}"
    end_window = fold_results[(fold_results["experiment_id"] == exp) & (fold_results["fold"] == fold) & (fold_results["phase"] == "end_to_end") & (fold_results["evaluation_scope"] == "window")].iloc[0]
    end_group = fold_results[(fold_results["experiment_id"] == exp) & (fold_results["fold"] == fold) & (fold_results["phase"] == "end_to_end") & (fold_results["evaluation_scope"] == "group")].iloc[0]
    stage1 = fold_results[(fold_results["experiment_id"] == f"{exp}_STAGE1") & (fold_results["fold"] == fold) & (fold_results["phase"] == "stage1")]
    stage2 = fold_results[(fold_results["experiment_id"] == f"{exp}_STAGE2") & (fold_results["fold"] == fold) & (fold_results["phase"] == "stage2")]
    return {
        "window_macro_f1": float(end_window["macro_f1"]),
        "group_macro_f1": float(end_group["macro_f1"]),
        "stage1_macro_f1": float(stage1.iloc[0]["macro_f1"]) if len(stage1) else np.nan,
        "normal_f1": float(end_window.get("normal_f1", np.nan)),
        "stage1_normal_f1": float(stage1.iloc[0]["normal_f1"]) if len(stage1) else np.nan,
        "stage2_macro_f1": float(stage2.iloc[0]["macro_f1"]) if len(stage2) else np.nan,
        "hijack_f1": float(end_window.get("hijack_f1", np.nan)),
        "leak_f1": float(end_window.get("leak_f1", np.nan)),
        "outage_f1": float(end_window.get("outage_f1", np.nan)),
        "top2": float(end_window["top2_accuracy"]),
        "mrr": float(end_window["mrr"]),
    }


def paired_family_deltas(fold_results: pd.DataFrame, variants: dict[str, list[str]]) -> pd.DataFrame:
    rows = []
    for model_name in ["RF_SINGLE", "RF_HIER"]:
        for fold in sorted(fold_results["fold"].unique()):
            full = metric_lookup(fold_results, model_name, FULL_VARIANT, int(fold))
            for variant_id in variants:
                if variant_id == FULL_VARIANT:
                    continue
                removal = variant_id.replace("FAM_V4_MINUS_", "").lower()
                minus = metric_lookup(fold_results, model_name, variant_id, int(fold))
                row = {"model": model_name, "fold": int(fold), "removed_family": removal, "comparison": f"{FULL_VARIANT}-{variant_id}"}
                for metric in ["window_macro_f1", "group_macro_f1", "stage1_macro_f1", "normal_f1", "stage1_normal_f1", "stage2_macro_f1", "hijack_f1", "leak_f1", "outage_f1", "top2", "mrr"]:
                    row[f"{metric}_delta"] = full[metric] - minus[metric]
                rows.append(row)
    return pd.DataFrame(rows)


def contribution_ranking(paired: pd.DataFrame) -> pd.DataFrame:
    scopes = {
        "overall_end_to_end_window": ("RF_HIER", "window_macro_f1_delta"),
        "overall_end_to_end_group": ("RF_HIER", "group_macro_f1_delta"),
        "stage1": ("RF_HIER", "stage1_macro_f1_delta"),
        "stage1_normal": ("RF_HIER", "stage1_normal_f1_delta"),
        "stage2": ("RF_HIER", "stage2_macro_f1_delta"),
        "hijack": ("RF_HIER", "hijack_f1_delta"),
        "leak": ("RF_HIER", "leak_f1_delta"),
        "outage": ("RF_HIER", "outage_f1_delta"),
        "b0_single_stage_window": ("RF_SINGLE", "window_macro_f1_delta"),
        "b0_single_stage_group": ("RF_SINGLE", "group_macro_f1_delta"),
    }
    rows = []
    for scope, (model_name, metric) in scopes.items():
        subset = paired[paired["model"] == model_name]
        grouped = subset.groupby("removed_family")[metric]
        scored = []
        for family, values in grouped:
            clean = pd.to_numeric(values, errors="coerce").dropna()
            scored.append(
                {
                    "ranking_scope": scope,
                    "model": model_name,
                    "removed_family": family,
                    "metric": metric,
                    "mean_delta_full_minus_removed": float(clean.mean()) if len(clean) else "",
                    "std_delta": float(clean.std(ddof=1)) if len(clean) > 1 else "",
                    "full_v4_wins_folds": int((clean > 0).sum()) if len(clean) else "",
                    "removal_wins_folds": int((clean < 0).sum()) if len(clean) else "",
                }
            )
        ranked = pd.DataFrame(scored).sort_values("mean_delta_full_minus_removed", ascending=False, na_position="last")
        ranked["rank"] = range(1, len(ranked) + 1)
        rows.extend(ranked.to_dict(orient="records"))
    return pd.DataFrame(rows)


def update_registry(variants: dict[str, list[str]]) -> None:
    existing = pd.read_csv(REGISTRY, dtype=str).fillna("") if REGISTRY.exists() else pd.DataFrame()
    rows = []
    for variant_id, features in variants.items():
        for model_name, architecture in [("RF_SINGLE", "single-stage"), ("RF_HIER", "hierarchical")]:
            rows.append(
                {
                    "experiment_id": f"{variant_id}_{model_name}",
                    "model": "RandomForestClassifier",
                    "architecture": architecture,
                    "feature_variant": "V4",
                    "feature_count": str(len(features)),
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
            {"cell_type": "markdown", "metadata": {}, "source": ["# Phase D - V4 Feature-Family Ablation\n", "\n", "TRAIN-only V4 family-removal ablation using I1 group-aware weighting, fixed Phase A folds, fixed Random Forest hyperparameters, and default Stage 1 argmax.\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.feature_family_ablation import run_experiment\n", "# run_experiment()\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["import pandas as pd\n", "pd.read_csv('../data/modeling/feature_family_ablation_results_v1.csv')\n"]},
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def run_experiment() -> dict[str, object]:
    MODELING_DIR.mkdir(parents=True, exist_ok=True)
    inventory = feature_family_inventory()
    inventory.to_csv(INVENTORY_OUT, index=False)
    variants = ablation_variants(inventory)
    if len(variants[FULL_VARIANT]) != 74:
        raise ValueError("full V4 must contain exactly 74 features")
    data = load_variant("V4")
    assignments = load_assignments(data)
    data = data.merge(assignments, on="window_id", how="left", validate="one_to_one")
    if set(data["partition"].astype(str)) != {"train"}:
        raise ValueError("Phase D must use TRAIN only")
    if data.groupby("model_group_id")["fold"].nunique().max() != 1:
        raise ValueError("model_group_id crosses folds")

    rows = []
    for variant_id, features in variants.items():
        removal = "NONE_FULL_V4" if variant_id == FULL_VARIANT else variant_id.replace("FAM_V4_MINUS_", "").lower()
        rows.extend(fit_single(data, variant_id, features, removal))
        rows.extend(fit_hier(data, variant_id, features, removal))

    fold_results = pd.DataFrame(rows)
    fold_results.to_csv(FOLD_RESULTS, index=False)
    results = summarize_results(fold_results)
    results.to_csv(RESULTS, index=False)
    paired = paired_family_deltas(fold_results, variants)
    paired.to_csv(PAIRED, index=False)
    ranking = contribution_ranking(paired)
    ranking.to_csv(RANKING, index=False)
    update_registry(variants)
    write_notebook()
    return {
        "family_counts": inventory.groupby("feature_family")["feature_name"].count().to_dict(),
        "variant_count": len(variants),
        "full_v4_feature_count": len(variants[FULL_VARIANT]),
        "folds_reused": str(CV_ASSIGNMENTS),
        "imbalance_condition": I1_CONDITION,
        "results": str(RESULTS),
        "paired": str(PAIRED),
        "ranking": str(RANKING),
        "inventory": str(INVENTORY_OUT),
        "validation_loaded": False,
        "holdout_loaded": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Phase D TRAIN-only V4 feature-family ablation")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if args.run:
        print(json.dumps(run_experiment(), indent=2, sort_keys=True))
        return
    parser.error("choose --run")


if __name__ == "__main__":
    main()
