from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import ParameterSampler
from sklearn.pipeline import Pipeline

try:
    from bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT, load_assignments, load_variant
    from bgp_incident_detection.imbalance_model_experiment import group_aware_weights
    from bgp_incident_detection.model_baselines import (
        INCIDENT_LABELS,
        REGISTRY,
        SEED,
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
        INCIDENT_LABELS,
        REGISTRY,
        SEED,
        class_prob_frame,
        macro_f1,
        mrr,
        per_class_f1,
        top2_accuracy,
    )
    from src.bgp_incident_detection.train_batch_engine import source_commit


MODELING_DIR = Path("data/modeling")
LOCAL_RESULTS = MODELING_DIR / "rf_local_refinement_results_v1.csv"
LOCAL_PAIRED = MODELING_DIR / "rf_local_refinement_paired_comparison_v1.csv"
STABILITY_SHORTLIST = MODELING_DIR / "rf_stability_shortlist_v1.csv"
MULTISEED_RESULTS = MODELING_DIR / "rf_multiseed_stability_results_v1.csv"
SEED_SENSITIVITY = MODELING_DIR / "rf_seed_sensitivity_v1.csv"
FINAL_COMPARISON = MODELING_DIR / "rf_h2_final_comparison_v1.csv"
LOCAL_FOLD_RESULTS = MODELING_DIR / "rf_local_refinement_fold_results_v1.csv"
STABILITY_FOLD_RESULTS = MODELING_DIR / "rf_multiseed_stability_fold_results_v1.csv"
STABILITY_SEED_RESULTS = MODELING_DIR / "rf_multiseed_stability_seed_results_v1.csv"
NOTEBOOK = Path("notebooks/48_rf_local_refinement_and_stability.ipynb")
REFINED_CONFIG = Path("config/final_model_candidate_v2_1_rf_refined.yaml")

FEATURE_VARIANT = "V4"
FEATURE_COUNT = 74
IMBALANCE_CONDITION = "I1"
ARCHITECTURE = "RF_MULTICLASS_STAGE2"
LOCAL_SEARCH_BUDGET = 25
LOCAL_SEARCH_SEED = 20260828
RF_STABILITY_SEEDS = [20260828, 20260829, 20260830, 20260831, 20260901]
MAX_STABILITY_SHORTLIST = 3
H2_CANDIDATE_ID = "RF_REFINED_TRAIN_CANDIDATE"

PHASE_H_WINNER = {
    "n_estimators": 800,
    "max_depth": 40,
    "max_features": 0.25,
    "min_samples_leaf": 4,
    "min_samples_split": 5,
    "criterion": "entropy",
    "bootstrap": False,
}

LOCAL_PARAMETER_SPACE = {
    "n_estimators": [600, 800, 1000, 1200],
    "max_depth": [30, 35, 40, 45, 50],
    "max_features": [0.20, 0.25, 0.30, 0.35],
    "min_samples_leaf": [3, 4, 5, 6],
    "min_samples_split": [4, 5, 6, 8],
    "criterion": ["entropy", "log_loss"],
    "bootstrap": [False],
}


def parameter_hash(params: dict[str, Any]) -> str:
    payload = json.dumps(params, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def load_stage2_train_data() -> pd.DataFrame:
    df = load_variant(FEATURE_VARIANT)
    assignments = load_assignments(df)
    data = df.merge(assignments, on="window_id", how="left", validate="one_to_one")
    data = data[data["label"].isin(INCIDENT_LABELS)].copy()
    if set(data["partition"].astype(str)) != {"train"}:
        raise ValueError("Phase H2 must use TRAIN incident rows only")
    if len(FEATURES_BY_VARIANT[FEATURE_VARIANT]) != FEATURE_COUNT:
        raise ValueError("Phase H2 must use exactly 74 frozen V4 features")
    if data.groupby("model_group_id")["fold"].nunique().max() != 1:
        raise ValueError("grouped CV violation: incident crosses folds")
    return data


def local_parameter_candidates(budget: int = LOCAL_SEARCH_BUDGET, seed: int = LOCAL_SEARCH_SEED) -> list[dict[str, Any]]:
    if budget > LOCAL_SEARCH_BUDGET:
        raise ValueError("local search budget cannot exceed 25")
    candidates = [PHASE_H_WINNER.copy()]
    seen = {parameter_hash(PHASE_H_WINNER)}
    sampler = ParameterSampler(LOCAL_PARAMETER_SPACE, n_iter=budget * 4, random_state=seed)
    for params in sampler:
        normalized = dict(params)
        normalized["bootstrap"] = False
        h = parameter_hash(normalized)
        if h in seen:
            continue
        candidates.append(normalized)
        seen.add(h)
        if len(candidates) == budget:
            break
    if len(candidates) != budget:
        raise RuntimeError(f"unable to build fixed local search budget: {len(candidates)} != {budget}")
    return candidates


def rf_pipeline(params: dict[str, Any], rf_seed: int) -> Pipeline:
    model_params = {
        **params,
        "class_weight": None,
        "random_state": rf_seed,
        "n_jobs": -1,
    }
    return Pipeline([("imputer", SimpleImputer(strategy="median")), ("model", RandomForestClassifier(**model_params))])


def ranked_frame(scores: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, row in scores.iterrows():
        pairs = sorted([(label, row[f"p_{label.lower()}"]) for label in INCIDENT_LABELS], key=lambda item: item[1], reverse=True)
        out = row.to_dict()
        out["predicted_class"] = pairs[0][0]
        out["true_class_rank"] = [label for label, _ in pairs].index(row["true_class"]) + 1
        rows.append(out)
    return pd.DataFrame(rows)


def aggregate_incident_scores(scores: pd.DataFrame) -> pd.DataFrame:
    rows = []
    group_cols = ["candidate_id", "parameter_hash", "rf_seed", "incident_uid"]
    for keys, group in scores.groupby(group_cols):
        candidate_id, h, rf_seed, incident_uid = keys
        rows.append(
            {
                "candidate_id": candidate_id,
                "parameter_hash": h,
                "rf_seed": int(rf_seed),
                "incident_uid": incident_uid,
                "fold": int(group["fold"].iloc[0]),
                "true_class": group["true_class"].iloc[0],
                "p_hijack": float(group["p_hijack"].mean()),
                "p_leak": float(group["p_leak"].mean()),
                "p_outage": float(group["p_outage"].mean()),
            }
        )
    return pd.DataFrame(rows)


def metrics_for_frame(frame: pd.DataFrame) -> dict[str, Any]:
    ranked = ranked_frame(frame)
    y_true = ranked["true_class"].tolist()
    y_pred = ranked["predicted_class"].tolist()
    probs = ranked[["p_hijack", "p_leak", "p_outage"]].copy()
    probs.columns = INCIDENT_LABELS
    out: dict[str, Any] = {
        "macro_f1": macro_f1(y_true, y_pred, INCIDENT_LABELS),
        "top1": float((ranked["true_class"] == ranked["predicted_class"]).mean()),
        "top2": top2_accuracy(y_true, probs),
        "mrr": mrr(y_true, probs),
        "mean_true_class_rank": float(ranked["true_class_rank"].mean()),
        "confusion_matrix": json.dumps(confusion_matrix(y_true, y_pred, labels=INCIDENT_LABELS).tolist()),
    }
    out.update(per_class_f1(y_true, y_pred, INCIDENT_LABELS))
    return out


def evaluate_config(data: pd.DataFrame, candidate_id: str, params: dict[str, Any], rf_seed: int) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    features = FEATURES_BY_VARIANT[FEATURE_VARIANT]
    score_rows: list[dict[str, Any]] = []
    fold_rows: list[dict[str, Any]] = []
    fit_times: list[float] = []
    inference_times: list[float] = []
    for fold in sorted(data["fold"].unique()):
        train = data[data["fold"] != fold].copy()
        test = data[data["fold"] == fold].copy()
        model = rf_pipeline(params, rf_seed)
        started = time.perf_counter()
        model.fit(train[features], train["label"], model__sample_weight=group_aware_weights(train))
        fit_time = time.perf_counter() - started
        started = time.perf_counter()
        probs = class_prob_frame(list(model.classes_), model.predict_proba(test[features]), INCIDENT_LABELS)
        inference_time = time.perf_counter() - started
        fit_times.append(fit_time)
        inference_times.append(inference_time)
        fold_scores = []
        for pos, idx in enumerate(test.index):
            row = {
                "candidate_id": candidate_id,
                "parameter_hash": parameter_hash(params),
                "rf_seed": rf_seed,
                "window_id": data.loc[idx, "window_id"],
                "incident_uid": data.loc[idx, "incident_uid"],
                "fold": int(fold),
                "true_class": data.loc[idx, "label"],
                "p_hijack": float(probs.iloc[pos]["HIJACK"]),
                "p_leak": float(probs.iloc[pos]["LEAK"]),
                "p_outage": float(probs.iloc[pos]["OUTAGE"]),
            }
            score_rows.append(row)
            fold_scores.append(row)
        fold_incident = aggregate_incident_scores(pd.DataFrame(fold_scores))
        fold_metrics = metrics_for_frame(fold_incident)
        fold_rows.append(
            {
                "candidate_id": candidate_id,
                "parameter_hash": parameter_hash(params),
                "rf_seed": rf_seed,
                "fold": int(fold),
                "incident_macro_f1": fold_metrics["macro_f1"],
                "incident_top1": fold_metrics["top1"],
                "incident_top2": fold_metrics["top2"],
                "incident_mrr": fold_metrics["mrr"],
                "incident_hijack_f1": fold_metrics["hijack_f1"],
                "incident_leak_f1": fold_metrics["leak_f1"],
                "incident_outage_f1": fold_metrics["outage_f1"],
                "window_macro_f1": metrics_for_frame(pd.DataFrame(fold_scores))["macro_f1"],
            }
        )
    scores = pd.DataFrame(score_rows)
    incident_scores = aggregate_incident_scores(scores)
    window_metrics = metrics_for_frame(scores)
    incident_metrics = metrics_for_frame(incident_scores)
    result = {
        "candidate_id": candidate_id,
        "parameter_hash": parameter_hash(params),
        "phase": "H2",
        "feature_variant": FEATURE_VARIANT,
        "feature_count": FEATURE_COUNT,
        "imbalance_condition": IMBALANCE_CONDITION,
        "architecture": ARCHITECTURE,
        "rf_seed": rf_seed,
        "parameters_json": json.dumps(params, sort_keys=True),
        "window_macro_f1": window_metrics["macro_f1"],
        "incident_macro_f1": incident_metrics["macro_f1"],
        "incident_top1": incident_metrics["top1"],
        "incident_top2": incident_metrics["top2"],
        "incident_mrr": incident_metrics["mrr"],
        "mean_true_class_rank": incident_metrics["mean_true_class_rank"],
        "incident_hijack_f1": incident_metrics["hijack_f1"],
        "incident_leak_f1": incident_metrics["leak_f1"],
        "incident_outage_f1": incident_metrics["outage_f1"],
        "incident_macro_f1_fold_std": float(pd.Series([row["incident_macro_f1"] for row in fold_rows]).std(ddof=0)),
        "fit_time_seconds": round(float(np.sum(fit_times)), 3),
        "inference_time_seconds": round(float(np.sum(inference_times)), 3),
    }
    return result, fold_rows


def paired_against_phase_h(results: pd.DataFrame, fold_results: pd.DataFrame) -> pd.DataFrame:
    baseline = results[results["candidate_id"].eq("PHASE_H_WINNER")].iloc[0]
    baseline_folds = fold_results[fold_results["candidate_id"].eq("PHASE_H_WINNER")].set_index("fold")
    rows = []
    for _, row in results.iterrows():
        candidate_folds = fold_results[fold_results["candidate_id"].eq(row["candidate_id"])].set_index("fold")
        deltas = candidate_folds["incident_macro_f1"] - baseline_folds["incident_macro_f1"]
        rows.append(
            {
                "candidate_id": row["candidate_id"],
                "parameter_hash": row["parameter_hash"],
                "incident_macro_f1_delta": row["incident_macro_f1"] - baseline["incident_macro_f1"],
                "incident_mrr_delta": row["incident_mrr"] - baseline["incident_mrr"],
                "incident_top2_delta": row["incident_top2"] - baseline["incident_top2"],
                "incident_top1_delta": row["incident_top1"] - baseline["incident_top1"],
                "hijack_f1_delta": row["incident_hijack_f1"] - baseline["incident_hijack_f1"],
                "leak_f1_delta": row["incident_leak_f1"] - baseline["incident_leak_f1"],
                "outage_f1_delta": row["incident_outage_f1"] - baseline["incident_outage_f1"],
                "window_macro_f1_delta": row["window_macro_f1"] - baseline["window_macro_f1"],
                "folds_improved": int((deltas > 0).sum()),
                "mean_fold_delta": float(deltas.mean()),
                "min_fold_delta": float(deltas.min()),
                "max_fold_delta": float(deltas.max()),
            }
        )
    return pd.DataFrame(rows)


def shortlist_configs(results: pd.DataFrame, paired: pd.DataFrame, max_count: int = MAX_STABILITY_SHORTLIST) -> pd.DataFrame:
    merged = results.merge(paired, on=["candidate_id", "parameter_hash"], how="left")
    phase_h = merged[merged["candidate_id"].eq("PHASE_H_WINNER")]
    best = merged.sort_values(
        ["incident_macro_f1", "incident_mrr", "incident_top2", "incident_macro_f1_fold_std", "fit_time_seconds"],
        ascending=[False, False, False, True, True],
    ).head(1)
    efficient = merged.sort_values(
        ["incident_macro_f1", "fit_time_seconds", "incident_macro_f1_fold_std"],
        ascending=[False, True, True],
    ).head(max_count + 3)
    combined = pd.concat([phase_h, best, efficient], ignore_index=True).drop_duplicates("candidate_id", keep="first")
    combined = combined.sort_values(
        ["candidate_id"],
        key=lambda col: col.map(lambda value: 0 if value == "PHASE_H_WINNER" else 1),
    )
    combined = combined.head(max_count).copy()
    combined["shortlist_rank"] = range(1, len(combined) + 1)
    combined["stability_role"] = combined["candidate_id"].map(
        lambda value: "ORIGINAL_PHASE_H_WINNER" if value == "PHASE_H_WINNER" else "LOCAL_REFINEMENT_CANDIDATE"
    )
    combined["rationale"] = combined.apply(shortlist_rationale, axis=1)
    return combined


def shortlist_rationale(row: pd.Series) -> str:
    if row["candidate_id"] == "PHASE_H_WINNER":
        return "Original Phase H winner included as required reproducibility anchor."
    if row["incident_macro_f1_delta"] > 0.005:
        return "Local candidate improves incident Macro F1 enough to justify stability testing."
    return "Local candidate offers a possible stability/runtime tradeoff for multi-seed testing."


def stability_summary(seed_rows: pd.DataFrame, fold_rows: pd.DataFrame, shortlist: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for candidate_id, group in seed_rows.groupby("candidate_id"):
        folds = fold_rows[fold_rows["candidate_id"].eq(candidate_id)]
        params = group["parameters_json"].iloc[0]
        rows.append(
            {
                "candidate_id": candidate_id,
                "parameter_hash": group["parameter_hash"].iloc[0],
                "parameters_json": params,
                "stability_seeds": json.dumps(RF_STABILITY_SEEDS),
                "mean_incident_macro_f1": group["incident_macro_f1"].mean(),
                "std_incident_macro_f1": group["incident_macro_f1"].std(ddof=0),
                "min_incident_macro_f1": group["incident_macro_f1"].min(),
                "max_incident_macro_f1": group["incident_macro_f1"].max(),
                "mean_mrr": group["incident_mrr"].mean(),
                "std_mrr": group["incident_mrr"].std(ddof=0),
                "mean_top2": group["incident_top2"].mean(),
                "mean_top1": group["incident_top1"].mean(),
                "hijack_f1_mean": group["incident_hijack_f1"].mean(),
                "hijack_f1_std": group["incident_hijack_f1"].std(ddof=0),
                "leak_f1_mean": group["incident_leak_f1"].mean(),
                "leak_f1_std": group["incident_leak_f1"].std(ddof=0),
                "outage_f1_mean": group["incident_outage_f1"].mean(),
                "outage_f1_std": group["incident_outage_f1"].std(ddof=0),
                "window_macro_f1_mean": group["window_macro_f1"].mean(),
                "window_macro_f1_std": group["window_macro_f1"].std(ddof=0),
                "fold_seed_incident_macro_f1_mean": folds["incident_macro_f1"].mean(),
                "fold_seed_incident_macro_f1_std": folds["incident_macro_f1"].std(ddof=0),
                "mean_fit_time_seconds": group["fit_time_seconds"].mean(),
                "mean_inference_time_seconds": group["inference_time_seconds"].mean(),
            }
        )
    return pd.DataFrame(rows).merge(shortlist[["candidate_id", "stability_role"]], on="candidate_id", how="left")


def seed_sensitivity(seed_rows: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for candidate_id, group in seed_rows.groupby("candidate_id"):
        best = group.sort_values("incident_macro_f1", ascending=False).iloc[0]
        worst = group.sort_values("incident_macro_f1", ascending=True).iloc[0]
        macro_mean = group["incident_macro_f1"].mean()
        macro_std = group["incident_macro_f1"].std(ddof=0)
        rows.append(
            {
                "candidate_id": candidate_id,
                "parameter_hash": group["parameter_hash"].iloc[0],
                "best_seed": int(best["rf_seed"]),
                "worst_seed": int(worst["rf_seed"]),
                "macro_f1_range": group["incident_macro_f1"].max() - group["incident_macro_f1"].min(),
                "mrr_range": group["incident_mrr"].max() - group["incident_mrr"].min(),
                "top2_range": group["incident_top2"].max() - group["incident_top2"].min(),
                "macro_f1_cv": float(macro_std / macro_mean) if macro_mean else np.nan,
                "mrr_cv": float(group["incident_mrr"].std(ddof=0) / group["incident_mrr"].mean()) if group["incident_mrr"].mean() else np.nan,
            }
        )
    return pd.DataFrame(rows)


def select_h2_candidate(stability: pd.DataFrame) -> tuple[pd.Series, str, str]:
    phase_h = stability[stability["candidate_id"].eq("PHASE_H_WINNER")].iloc[0]
    scored = stability.copy()
    scored["balance_penalty"] = scored[["hijack_f1_mean", "leak_f1_mean", "outage_f1_mean"]].max(axis=1) - scored[["hijack_f1_mean", "leak_f1_mean", "outage_f1_mean"]].min(axis=1)
    scored["selection_score"] = (
        scored["mean_incident_macro_f1"]
        + 0.1 * scored["mean_mrr"]
        + 0.05 * scored["mean_top2"]
        - 0.02 * scored["std_incident_macro_f1"]
        - 0.01 * scored["balance_penalty"]
        - 0.001 * (scored["mean_fit_time_seconds"] / max(float(scored["mean_fit_time_seconds"].max()), 1.0))
    )
    best = scored.sort_values(["selection_score", "mean_incident_macro_f1"], ascending=False).iloc[0]
    delta = best["mean_incident_macro_f1"] - phase_h["mean_incident_macro_f1"]
    if delta >= 0.01 and best["mean_mrr"] >= phase_h["mean_mrr"] - 0.002:
        classification = "MEANINGFUL_REFINEMENT"
        recommendation = "PROMOTE_PHASE_H2_RF"
    elif delta >= 0.002 and best["mean_mrr"] >= phase_h["mean_mrr"] - 0.005:
        classification = "MARGINAL_REFINEMENT"
        recommendation = "PROMOTE_PHASE_H2_RF"
    else:
        classification = "NO_MEANINGFUL_IMPROVEMENT"
        recommendation = "KEEP_PHASE_H_RF"
        best = phase_h
    return best, classification, recommendation


def final_comparison(stability: pd.DataFrame, selected: pd.Series, classification: str, recommendation: str) -> pd.DataFrame:
    rows = []
    phase_h = stability[stability["candidate_id"].eq("PHASE_H_WINNER")].iloc[0]
    for label, row in [("Phase H winner", phase_h), ("Phase H2 selected candidate", selected)]:
        rows.append(
            {
                "comparison_member": label,
                "candidate_id": row["candidate_id"],
                "parameter_hash": row["parameter_hash"],
                "hyperparameters": row["parameters_json"],
                "mean_incident_macro_f1": row["mean_incident_macro_f1"],
                "std_incident_macro_f1": row["std_incident_macro_f1"],
                "incident_top1": row["mean_top1"],
                "incident_top2": row["mean_top2"],
                "incident_mrr": row["mean_mrr"],
                "hijack_f1": row["hijack_f1_mean"],
                "leak_f1": row["leak_f1_mean"],
                "outage_f1": row["outage_f1_mean"],
                "window_macro_f1": row["window_macro_f1_mean"],
                "runtime_seconds": row["mean_fit_time_seconds"],
                "relative_runtime_vs_phase_h": row["mean_fit_time_seconds"] / phase_h["mean_fit_time_seconds"],
                "stability": f"seed_std={row['std_incident_macro_f1']:.6f}; fold_seed_std={row['fold_seed_incident_macro_f1_std']:.6f}",
                "h2_result_classification": classification,
                "recommendation": recommendation,
            }
        )
    return pd.DataFrame(rows)


def yaml_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float, np.integer, np.floating)):
        return str(value)
    return json.dumps(str(value))


def render_yaml(data: Any, indent: int = 0) -> list[str]:
    pad = " " * indent
    if isinstance(data, dict):
        lines = []
        for key, item in data.items():
            if isinstance(item, (dict, list)):
                lines.append(f"{pad}{key}:")
                lines.extend(render_yaml(item, indent + 2))
            else:
                lines.append(f"{pad}{key}: {yaml_scalar(item)}")
        return lines
    if isinstance(data, list):
        lines = []
        for item in data:
            if isinstance(item, (dict, list)):
                lines.append(f"{pad}-")
                lines.extend(render_yaml(item, indent + 2))
            else:
                lines.append(f"{pad}- {yaml_scalar(item)}")
        return lines
    return [f"{pad}{yaml_scalar(data)}"]


def write_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(render_yaml(data)) + "\n", encoding="utf-8")


def write_refined_config(selected: pd.Series, classification: str, recommendation: str) -> None:
    params = json.loads(selected["parameters_json"])
    write_yaml(
        REFINED_CONFIG,
        {
            "candidate_id": H2_CANDIDATE_ID,
            "status": "RF_REFINED_TRAIN_CANDIDATE",
            "recommendation": recommendation,
            "h2_result_classification": classification,
            "selected_source_candidate_id": selected["candidate_id"],
            "selected_hyperparameters": {**params, "class_weight": None},
            "feature_variant": FEATURE_VARIANT,
            "feature_count": FEATURE_COUNT,
            "imbalance_condition": IMBALANCE_CONDITION,
            "seed_policy": {
                "local_search_seed": LOCAL_SEARCH_SEED,
                "stability_rf_seeds": RF_STABILITY_SEEDS,
                "fold_assignments": "data/modeling/baseline_v1_grouped_cv_assignments_v1.csv",
            },
            "grouped_folds": "Existing frozen grouped folds reused; no fold regeneration.",
            "incident_aggregation": "mean class probability across all eligible windows for the incident",
            "ranking_rule": "sort P(Hijack), P(Leak), P(Outage) descending",
            "train_multiseed_results": {
                "mean_incident_macro_f1": float(selected["mean_incident_macro_f1"]),
                "std_incident_macro_f1": float(selected["std_incident_macro_f1"]),
                "mean_mrr": float(selected["mean_mrr"]),
                "mean_top2": float(selected["mean_top2"]),
                "mean_top1": float(selected["mean_top1"]),
                "hijack_f1_mean": float(selected["hijack_f1_mean"]),
                "leak_f1_mean": float(selected["leak_f1_mean"]),
                "outage_f1_mean": float(selected["outage_f1_mean"]),
                "window_macro_f1_mean": float(selected["window_macro_f1_mean"]),
                "mean_fit_time_seconds": float(selected["mean_fit_time_seconds"]),
            },
            "validation_accessed": False,
            "final_holdout_accessed": False,
            "stage1_status": "UNRESOLVED_EXPERIMENTAL_AUXILIARY",
            "phase_i_xgboost_pending": True,
            "source_commit": source_commit(),
        },
    )


def update_registry(local_results: pd.DataFrame, stability: pd.DataFrame, recommendation: str) -> None:
    existing = pd.read_csv(REGISTRY, dtype=str).fillna("") if REGISTRY.exists() else pd.DataFrame()
    rows = []
    for _, row in local_results.iterrows():
        rows.append(
            {
                "experiment_id": f"PHASEH2_RF_LOCAL_{row['candidate_id']}_{row['parameter_hash']}",
                "phase": "H2",
                "model": "RandomForestClassifier",
                "architecture": ARCHITECTURE,
                "feature_variant": FEATURE_VARIANT,
                "feature_count": str(FEATURE_COUNT),
                "imbalance_condition": IMBALANCE_CONDITION,
                "parameter_hash": row["parameter_hash"],
                "parameters_json": row["parameters_json"],
                "seed": str(row["rf_seed"]),
                "status": "COMPLETED",
                "result_artifact": str(LOCAL_RESULTS),
                "source_commit": source_commit(),
            }
        )
    for _, row in stability.iterrows():
        rows.append(
            {
                "experiment_id": f"PHASEH2_RF_MULTI_SEED_{row['candidate_id']}_{row['parameter_hash']}",
                "phase": "H2",
                "model": "RandomForestClassifier",
                "architecture": ARCHITECTURE,
                "feature_variant": FEATURE_VARIANT,
                "feature_count": str(FEATURE_COUNT),
                "imbalance_condition": IMBALANCE_CONDITION,
                "parameter_hash": row["parameter_hash"],
                "parameters_json": row["parameters_json"],
                "seed": json.dumps(RF_STABILITY_SEEDS),
                "status": "COMPLETED",
                "result_artifact": str(MULTISEED_RESULTS),
                "source_commit": source_commit(),
            }
        )
    rows.append(
        {
            "experiment_id": "PHASEH2_RF_REFINED_SELECTION",
            "phase": "H2",
            "model": "RandomForestClassifier",
            "architecture": ARCHITECTURE,
            "feature_variant": FEATURE_VARIANT,
            "feature_count": str(FEATURE_COUNT),
            "imbalance_condition": IMBALANCE_CONDITION,
            "seed": json.dumps(RF_STABILITY_SEEDS),
            "status": recommendation,
            "result_artifact": str(FINAL_COMPARISON),
            "source_commit": source_commit(),
        }
    )
    combined = pd.concat([existing, pd.DataFrame(rows)], ignore_index=True, sort=False) if len(existing) else pd.DataFrame(rows)
    combined = combined.drop_duplicates("experiment_id", keep="last")
    combined.to_csv(REGISTRY, index=False)


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    notebook = {
        "cells": [
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": [
                    "# Phase H2 - RF Local Refinement and Multi-Seed Stability\n",
                    "\n",
                    "TRAIN-only local RF refinement around the Phase H winner. Validation and Final Holdout remain sealed. XGBoost is not run here.\n",
                ],
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": ["from bgp_incident_detection.rf_refinement_stability import run_h2\n", "# run_h2()\n"],
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": ["import pandas as pd\n", "pd.read_csv('../data/modeling/rf_h2_final_comparison_v1.csv')\n"],
            },
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def run_h2(local_budget: int = LOCAL_SEARCH_BUDGET) -> dict[str, Any]:
    data = load_stage2_train_data()
    local_results = pd.read_csv(LOCAL_RESULTS).to_dict("records") if LOCAL_RESULTS.exists() else []
    local_folds = pd.read_csv(LOCAL_FOLD_RESULTS).to_dict("records") if LOCAL_FOLD_RESULTS.exists() else []
    local_candidates = local_parameter_candidates(local_budget, LOCAL_SEARCH_SEED)
    for idx, params in enumerate(local_candidates):
        candidate_id = "PHASE_H_WINNER" if idx == 0 else f"H2_LOCAL_{idx:03d}"
        if any(row["candidate_id"] == candidate_id for row in local_results):
            print(f"Local refinement {idx + 1}/{len(local_candidates)}: {candidate_id} already complete", flush=True)
            continue
        print(f"Local refinement {idx + 1}/{len(local_candidates)}: {candidate_id} {parameter_hash(params)}", flush=True)
        result, folds = evaluate_config(data, candidate_id, params, LOCAL_SEARCH_SEED)
        local_results.append(result)
        local_folds.extend(folds)
        pd.DataFrame(local_results).to_csv(LOCAL_RESULTS, index=False)
        pd.DataFrame(local_folds).to_csv(LOCAL_FOLD_RESULTS, index=False)
    local_results_df = pd.DataFrame(local_results).sort_values(
        ["incident_macro_f1", "incident_mrr", "incident_top2", "incident_macro_f1_fold_std", "fit_time_seconds"],
        ascending=[False, False, False, True, True],
    )
    local_fold_df = pd.DataFrame(local_folds)
    paired = paired_against_phase_h(local_results_df, local_fold_df)
    shortlist = shortlist_configs(local_results_df, paired)
    seed_results = pd.read_csv(STABILITY_SEED_RESULTS).to_dict("records") if STABILITY_SEED_RESULTS.exists() else []
    seed_folds = pd.read_csv(STABILITY_FOLD_RESULTS).to_dict("records") if STABILITY_FOLD_RESULTS.exists() else []
    for _, row in shortlist.iterrows():
        params = json.loads(row["parameters_json"])
        for seed in RF_STABILITY_SEEDS:
            if any(existing["candidate_id"] == row["candidate_id"] and int(existing["rf_seed"]) == seed for existing in seed_results):
                print(f"Stability {row['candidate_id']} seed={seed} already complete", flush=True)
                continue
            if seed == LOCAL_SEARCH_SEED:
                local_match = local_results_df[local_results_df["candidate_id"].eq(row["candidate_id"])]
                local_fold_match = local_fold_df[local_fold_df["candidate_id"].eq(row["candidate_id"])]
                if len(local_match) == 1 and len(local_fold_match) == 5:
                    print(f"Stability {row['candidate_id']} seed={seed} reused from local refinement", flush=True)
                    seed_results.append(local_match.iloc[0].to_dict())
                    seed_folds.extend(local_fold_match.to_dict("records"))
                    pd.DataFrame(seed_results).to_csv(STABILITY_SEED_RESULTS, index=False)
                    pd.DataFrame(seed_folds).to_csv(STABILITY_FOLD_RESULTS, index=False)
                    continue
            print(f"Stability {row['candidate_id']} seed={seed}", flush=True)
            result, folds = evaluate_config(data, row["candidate_id"], params, seed)
            seed_results.append(result)
            seed_folds.extend(folds)
            pd.DataFrame(seed_results).to_csv(STABILITY_SEED_RESULTS, index=False)
            pd.DataFrame(seed_folds).to_csv(STABILITY_FOLD_RESULTS, index=False)
    seed_results_df = pd.DataFrame(seed_results)
    seed_fold_df = pd.DataFrame(seed_folds)
    stability = stability_summary(seed_results_df, seed_fold_df, shortlist)
    sensitivity = seed_sensitivity(seed_results_df)
    selected, classification, recommendation = select_h2_candidate(stability)
    final = final_comparison(stability, selected, classification, recommendation)

    MODELING_DIR.mkdir(parents=True, exist_ok=True)
    local_results_df.to_csv(LOCAL_RESULTS, index=False)
    local_fold_df.to_csv(LOCAL_FOLD_RESULTS, index=False)
    paired.to_csv(LOCAL_PAIRED, index=False)
    shortlist.to_csv(STABILITY_SHORTLIST, index=False)
    stability.to_csv(MULTISEED_RESULTS, index=False)
    seed_fold_df.to_csv(STABILITY_FOLD_RESULTS, index=False)
    sensitivity.to_csv(SEED_SENSITIVITY, index=False)
    final.to_csv(FINAL_COMPARISON, index=False)
    write_refined_config(selected, classification, recommendation)
    update_registry(local_results_df, stability, recommendation)
    write_notebook()
    return {
        "local_configurations_evaluated": len(local_results_df),
        "stability_configurations": shortlist["candidate_id"].nunique(),
        "stability_seeds": RF_STABILITY_SEEDS,
        "selected_candidate_id": selected["candidate_id"],
        "selected_parameter_hash": selected["parameter_hash"],
        "recommendation": recommendation,
        "h2_result_classification": classification,
        "mean_incident_macro_f1": float(selected["mean_incident_macro_f1"]),
        "mean_mrr": float(selected["mean_mrr"]),
        "mean_top2": float(selected["mean_top2"]),
        "validation_accessed": False,
        "final_holdout_accessed": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Phase H2 TRAIN-only RF local refinement and stability analysis")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--local-budget", type=int, default=LOCAL_SEARCH_BUDGET)
    args = parser.parse_args()
    if args.run:
        print(json.dumps(run_h2(args.local_budget), indent=2, sort_keys=True))
        return
    parser.error("choose --run")


if __name__ == "__main__":
    main()
