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
from sklearn.metrics import confusion_matrix, f1_score
from sklearn.model_selection import ParameterSampler
from sklearn.pipeline import Pipeline

try:
    from bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT, load_assignments, load_variant
    from bgp_incident_detection.imbalance_model_experiment import group_aware_weights
    from bgp_incident_detection.model_baselines import (
        INCIDENT_LABELS,
        REGISTRY,
        RF_HYPERPARAMETERS,
        SEED,
        class_prob_frame,
        macro_f1,
        mrr,
        per_class_f1,
        top2_accuracy,
    )
    from bgp_incident_detection.model_lock_planning import VALIDATION_PROTOCOL as V1_VALIDATION_PROTOCOL
    from bgp_incident_detection.train_batch_engine import source_commit
except ModuleNotFoundError:
    from src.bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT, load_assignments, load_variant
    from src.bgp_incident_detection.imbalance_model_experiment import group_aware_weights
    from src.bgp_incident_detection.model_baselines import (
        INCIDENT_LABELS,
        REGISTRY,
        RF_HYPERPARAMETERS,
        SEED,
        class_prob_frame,
        macro_f1,
        mrr,
        per_class_f1,
        top2_accuracy,
    )
    from src.bgp_incident_detection.model_lock_planning import VALIDATION_PROTOCOL as V1_VALIDATION_PROTOCOL
    from src.bgp_incident_detection.train_batch_engine import source_commit


MODELING_DIR = Path("data/modeling")
SEARCH_RESULTS = MODELING_DIR / "rf_hyperparameter_search_results_v1.csv"
PAIRED_COMPARISON = MODELING_DIR / "rf_hyperparameter_paired_comparison_v1.csv"
SHORTLIST = MODELING_DIR / "rf_hyperparameter_shortlist_v1.csv"
OOF_SCORES = MODELING_DIR / "rf_hyperparameter_oof_scores_v1.parquet"
FOLD_RESULTS = MODELING_DIR / "rf_hyperparameter_fold_results_v1.csv"
NOTEBOOK = Path("notebooks/47_rf_hyperparameter_optimization.ipynb")
TUNED_CANDIDATE_CONFIG = Path("config/final_model_candidate_v2_tuned.yaml")
VALIDATION_PROTOCOL_V2 = Path("config/validation_confirmation_protocol_v2.yaml")

SEARCH_BUDGET = 40
SEARCH_METHOD = "fixed randomized search with baseline included"
FEATURE_VARIANT = "V4"
FEATURE_COUNT = 74
IMBALANCE_CONDITION = "I1"
ARCHITECTURE = "RF_MULTICLASS_STAGE2"
TUNED_CANDIDATE_ID = "RF_TUNED_LOCK_CANDIDATE_V1"

PARAMETER_SPACE = {
    "n_estimators": [200, 400, 600, 800],
    "max_depth": [None, 12, 20, 30, 40],
    "min_samples_split": [2, 5, 10, 20],
    "min_samples_leaf": [1, 2, 4, 8],
    "max_features": ["sqrt", "log2", 0.25, 0.5],
    "bootstrap": [True, False],
    "criterion": ["gini", "entropy", "log_loss"],
}

BASELINE_PARAMS = {
    "n_estimators": 200,
    "max_depth": None,
    "min_samples_split": 2,
    "min_samples_leaf": 1,
    "max_features": "sqrt",
    "bootstrap": True,
    "criterion": "gini",
}


def xgboost_available() -> bool:
    try:
        import xgboost  # noqa: F401
    except Exception:
        return False
    return True


def load_stage2_train_data() -> pd.DataFrame:
    df = load_variant(FEATURE_VARIANT)
    assignments = load_assignments(df)
    data = df.merge(assignments, on="window_id", how="left", validate="one_to_one")
    data = data[data["label"].isin(INCIDENT_LABELS)].copy()
    if set(data["partition"].astype(str)) != {"train"}:
        raise ValueError("Phase H must use TRAIN incident rows only")
    if len(FEATURES_BY_VARIANT[FEATURE_VARIANT]) != FEATURE_COUNT:
        raise ValueError("Phase H must use exactly the frozen V4 74-feature schema")
    if data.groupby("model_group_id")["fold"].nunique().max() != 1:
        raise ValueError("grouped CV violation: an incident crosses folds")
    return data


def parameter_hash(params: dict[str, Any]) -> str:
    payload = json.dumps(params, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def parameter_candidates(search_budget: int = SEARCH_BUDGET, seed: int = SEED) -> list[dict[str, Any]]:
    candidates = [BASELINE_PARAMS.copy()]
    seen = {parameter_hash(BASELINE_PARAMS)}
    sampler = ParameterSampler(PARAMETER_SPACE, n_iter=search_budget * 3, random_state=seed)
    for params in sampler:
        normalized = dict(params)
        h = parameter_hash(normalized)
        if h in seen:
            continue
        candidates.append(normalized)
        seen.add(h)
        if len(candidates) == search_budget:
            break
    if len(candidates) != search_budget:
        raise RuntimeError(f"unable to build fixed search budget: {len(candidates)} != {search_budget}")
    return candidates


def rf_pipeline(params: dict[str, Any]) -> Pipeline:
    rf_params = {
        **RF_HYPERPARAMETERS,
        **params,
        "class_weight": None,
        "random_state": SEED,
        "n_jobs": -1,
    }
    return Pipeline([("imputer", SimpleImputer(strategy="median")), ("model", RandomForestClassifier(**rf_params))])


def score_row(source: pd.Series, candidate_id: str, fold: int, params: dict[str, Any], probs: pd.Series) -> dict[str, Any]:
    return {
        "candidate_id": candidate_id,
        "parameter_hash": parameter_hash(params),
        "window_id": source["window_id"],
        "incident_uid": source["incident_uid"],
        "fold": fold,
        "true_class": source["label"],
        "p_hijack": float(probs["HIJACK"]),
        "p_leak": float(probs["LEAK"]),
        "p_outage": float(probs["OUTAGE"]),
    }


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
    for keys, group in scores.groupby(["candidate_id", "parameter_hash", "incident_uid"]):
        candidate_id, h, incident_uid = keys
        rows.append(
            {
                "candidate_id": candidate_id,
                "parameter_hash": h,
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


def evaluate_candidate(data: pd.DataFrame, candidate_number: int, params: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    features = FEATURES_BY_VARIANT[FEATURE_VARIANT]
    candidate_id = "RF_BASELINE_V4_I1" if candidate_number == 0 else f"RF_SEARCH_{candidate_number:03d}"
    score_rows: list[dict[str, Any]] = []
    fold_rows: list[dict[str, Any]] = []
    fit_times: list[float] = []
    inference_times: list[float] = []
    for fold in sorted(data["fold"].unique()):
        train = data[data["fold"] != fold].copy()
        test = data[data["fold"] == fold].copy()
        model = rf_pipeline(params)
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
            row = score_row(data.loc[idx], candidate_id, int(fold), params, probs.iloc[pos])
            score_rows.append(row)
            fold_scores.append(row)
        fold_window = pd.DataFrame(fold_scores)
        fold_incident = aggregate_incident_scores(fold_window)
        fold_metrics = metrics_for_frame(fold_incident)
        fold_rows.append(
            {
                "candidate_id": candidate_id,
                "parameter_hash": parameter_hash(params),
                "fold": int(fold),
                "incident_macro_f1": fold_metrics["macro_f1"],
                "incident_top2": fold_metrics["top2"],
                "incident_mrr": fold_metrics["mrr"],
            }
        )
    window_metrics = metrics_for_frame(pd.DataFrame(score_rows))
    incident_metrics = metrics_for_frame(aggregate_incident_scores(pd.DataFrame(score_rows)))
    result = {
        "candidate_id": candidate_id,
        "parameter_hash": parameter_hash(params),
        "phase": "H",
        "feature_variant": FEATURE_VARIANT,
        "feature_count": FEATURE_COUNT,
        "imbalance_condition": IMBALANCE_CONDITION,
        "architecture": ARCHITECTURE,
        "search_method": SEARCH_METHOD,
        "search_budget": SEARCH_BUDGET,
        "random_seed": SEED,
        "parameters_json": json.dumps(params, sort_keys=True),
        "window_macro_f1": window_metrics["macro_f1"],
        "incident_macro_f1": incident_metrics["macro_f1"],
        "incident_hijack_f1": incident_metrics["hijack_f1"],
        "incident_leak_f1": incident_metrics["leak_f1"],
        "incident_outage_f1": incident_metrics["outage_f1"],
        "incident_top1": incident_metrics["top1"],
        "incident_top2": incident_metrics["top2"],
        "incident_mrr": incident_metrics["mrr"],
        "mean_true_class_rank": incident_metrics["mean_true_class_rank"],
        "incident_macro_f1_fold_std": float(pd.Series([r["incident_macro_f1"] for r in fold_rows]).std(ddof=0)),
        "incident_mrr_fold_std": float(pd.Series([r["incident_mrr"] for r in fold_rows]).std(ddof=0)),
        "fit_time_seconds": round(float(np.sum(fit_times)), 3),
        "inference_time_seconds": round(float(np.sum(inference_times)), 3),
        "xgboost_available": "YES" if xgboost_available() else "NO",
    }
    return score_rows, fold_rows, result


def paired_comparison(results: pd.DataFrame, fold_results: pd.DataFrame) -> pd.DataFrame:
    baseline = results[results["candidate_id"].eq("RF_BASELINE_V4_I1")].iloc[0]
    rows = []
    for _, row in results.iterrows():
        candidate = row["candidate_id"]
        candidate_folds = fold_results[fold_results["candidate_id"].eq(candidate)].set_index("fold")
        baseline_folds = fold_results[fold_results["candidate_id"].eq("RF_BASELINE_V4_I1")].set_index("fold")
        fold_deltas = candidate_folds["incident_macro_f1"] - baseline_folds["incident_macro_f1"]
        rows.append(
            {
                "candidate_id": candidate,
                "parameter_hash": row["parameter_hash"],
                "incident_macro_f1_delta": row["incident_macro_f1"] - baseline["incident_macro_f1"],
                "mrr_delta": row["incident_mrr"] - baseline["incident_mrr"],
                "top2_delta": row["incident_top2"] - baseline["incident_top2"],
                "hijack_f1_delta": row["incident_hijack_f1"] - baseline["incident_hijack_f1"],
                "leak_f1_delta": row["incident_leak_f1"] - baseline["incident_leak_f1"],
                "outage_f1_delta": row["incident_outage_f1"] - baseline["incident_outage_f1"],
                "folds_improved_incident_macro_f1": int((fold_deltas > 0).sum()),
                "mean_fold_incident_macro_f1_delta": float(fold_deltas.mean()),
                "min_fold_incident_macro_f1_delta": float(fold_deltas.min()),
                "max_fold_incident_macro_f1_delta": float(fold_deltas.max()),
            }
        )
    return pd.DataFrame(rows)


def select_shortlist(results: pd.DataFrame, paired: pd.DataFrame) -> pd.DataFrame:
    merged = results.merge(paired, on=["candidate_id", "parameter_hash"], how="left")
    ranked = merged.sort_values(
        ["incident_macro_f1", "incident_mrr", "incident_top2", "incident_macro_f1_fold_std", "fit_time_seconds"],
        ascending=[False, False, False, True, True],
    ).head(5).copy()
    baseline = merged[merged["candidate_id"].eq("RF_BASELINE_V4_I1")].iloc[0]
    rationales = []
    for _, row in ranked.iterrows():
        if row["candidate_id"] == "RF_BASELINE_V4_I1":
            rationales.append("Baseline retained for comparison; simple and already strong.")
        elif row["incident_macro_f1_delta"] > 0 and row["incident_mrr_delta" if "incident_mrr_delta" in row else "mrr_delta"] >= -0.002:
            rationales.append("Top TRAIN incident Macro F1 with acceptable ranking/stability tradeoff.")
        else:
            rationales.append("Shortlisted by TRAIN incident Macro F1 but requires caution versus baseline complexity.")
    ranked["shortlist_rank"] = range(1, len(ranked) + 1)
    ranked["baseline_incident_macro_f1"] = baseline["incident_macro_f1"]
    ranked["rationale"] = rationales
    return ranked


def recommended_candidate(shortlist: pd.DataFrame) -> pd.Series:
    candidates = shortlist.copy()
    candidates["complexity_penalty"] = candidates["fit_time_seconds"] / max(float(candidates["fit_time_seconds"].max()), 1.0)
    candidates["selection_score"] = (
        candidates["incident_macro_f1"]
        + 0.1 * candidates["incident_mrr"]
        + 0.05 * candidates["incident_top2"]
        - 0.01 * candidates["incident_macro_f1_fold_std"]
        - 0.002 * candidates["complexity_penalty"]
    )
    return candidates.sort_values(["selection_score", "incident_macro_f1"], ascending=False).iloc[0]


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
        lines: list[str] = []
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


def write_candidate_config(best: pd.Series) -> None:
    params = json.loads(best["parameters_json"])
    write_yaml(
        TUNED_CANDIDATE_CONFIG,
        {
            "candidate_id": TUNED_CANDIDATE_ID,
            "candidate_status": "TUNED_TRAIN_CV_CANDIDATE",
            "architecture": "multiclass_stage2_random_forest",
            "task": "Hijack vs Leak vs Outage",
            "feature_variant": FEATURE_VARIANT,
            "feature_count": FEATURE_COUNT,
            "feature_names_order": FEATURES_BY_VARIANT[FEATURE_VARIANT],
            "imbalance_treatment": "I1 incident-aware weighting",
            "i1_weighting_formula": "sample_weight = 1 / number_of_training_windows_for_the_same model_group_id within the training fold",
            "rf_hyperparameters": {**params, "class_weight": None, "random_state": SEED, "n_jobs": -1},
            "probability_aggregation": "incident_probability = mean class probability across all eligible windows for that incident",
            "ranking_rule": "sort P(Hijack), P(Leak), P(Outage) descending",
            "random_seed": SEED,
            "train_cv_performance": {
                "incident_macro_f1": float(best["incident_macro_f1"]),
                "incident_mrr": float(best["incident_mrr"]),
                "incident_top2": float(best["incident_top2"]),
                "incident_top1": float(best["incident_top1"]),
                "incident_hijack_f1": float(best["incident_hijack_f1"]),
                "incident_leak_f1": float(best["incident_leak_f1"]),
                "incident_outage_f1": float(best["incident_outage_f1"]),
                "window_macro_f1": float(best["window_macro_f1"]),
                "incident_macro_f1_fold_std": float(best["incident_macro_f1_fold_std"]),
                "fit_time_seconds": float(best["fit_time_seconds"]),
            },
            "validation_accessed": False,
            "final_holdout_status": "SEALED",
            "source_commit": source_commit(),
        },
    )


def write_validation_protocol_v2() -> None:
    write_yaml(
        VALIDATION_PROTOCOL_V2,
        {
            "protocol_version": "v2",
            "candidate_under_test": TUNED_CANDIDATE_ID,
            "candidate_source": str(TUNED_CANDIDATE_CONFIG),
            "supersedes_candidate_for_validation": "RF_LOCK_CANDIDATE_V1",
            "baseline_protocol_reference": str(V1_VALIDATION_PROTOCOL),
            "validation_status": "NOT_ACCESSED",
            "final_holdout_status": "SEALED",
            "single_primary_validation_evaluation_only": True,
            "locked_decisions": {
                "feature_variant": FEATURE_VARIANT,
                "imbalance_treatment": "I1",
                "architecture": ARCHITECTURE,
                "ranking_aggregation": "mean incident probability",
            },
            "primary_metrics": ["incident_level_macro_f1", "incident_level_mrr", "incident_level_top2_accuracy"],
            "secondary_metrics": ["window_macro_f1", "hijack_f1", "leak_f1", "outage_f1", "top1_accuracy", "confusion_matrix"],
            "acceptance_criteria": {
                "principle": "Same criteria as v1; do not change criteria because tuning results changed.",
                "minimum_incident_macro_f1": 0.6,
                "minimum_incident_mrr": 0.75,
                "minimum_incident_top2_accuracy": 0.85,
                "schema_or_provenance_failure": "FAIL",
                "catastrophic_class_failure": "FAIL if any incident class has F1 == 0",
                "review_band": "REVIEW if primary metrics fall below floors without schema/provenance failure; do not tune on Validation.",
            },
            "forbidden_validation_search": [
                "feature variants",
                "imbalance strategies",
                "expert architectures",
                "Random Forest hyperparameters",
                "Stage 1 thresholds",
                "ranking weights",
            ],
        },
    )


def update_registry(results: pd.DataFrame) -> None:
    existing = pd.read_csv(REGISTRY, dtype=str).fillna("") if REGISTRY.exists() else pd.DataFrame()
    rows = []
    for _, row in results.iterrows():
        rows.append(
            {
                "experiment_id": f"PHASEH_{row['candidate_id']}_{row['parameter_hash']}",
                "phase": "H",
                "model": "RandomForestClassifier",
                "architecture": ARCHITECTURE,
                "feature_variant": FEATURE_VARIANT,
                "feature_count": str(FEATURE_COUNT),
                "imbalance_condition": IMBALANCE_CONDITION,
                "parameter_hash": row["parameter_hash"],
                "parameters_json": row["parameters_json"],
                "cv_scheme": "Existing Phase A 5-fold grouped CV by model_group_id",
                "seed": str(SEED),
                "status": "COMPLETED",
                "result_artifact": str(SEARCH_RESULTS),
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
                "source": ["# Phase H - TRAIN-only RF Hyperparameter Optimization\n", "\n", "Hyperparameters are the only variable. Validation and Final Holdout remain sealed.\n"],
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": ["from bgp_incident_detection.rf_hyperparameter_optimization import run_search\n", "# run_search()\n"],
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": ["import pandas as pd\n", "pd.read_csv('../data/modeling/rf_hyperparameter_shortlist_v1.csv')\n"],
            },
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def run_search(search_budget: int = SEARCH_BUDGET) -> dict[str, Any]:
    data = load_stage2_train_data()
    all_scores: list[dict[str, Any]] = []
    all_folds: list[dict[str, Any]] = []
    all_results: list[dict[str, Any]] = []
    candidates = parameter_candidates(search_budget=search_budget, seed=SEED)
    for number, params in enumerate(candidates):
        print(f"Evaluating {number + 1}/{len(candidates)}: {parameter_hash(params)}", flush=True)
        scores, folds, result = evaluate_candidate(data, number, params)
        all_scores.extend(scores)
        all_folds.extend(folds)
        all_results.append(result)
    scores_df = pd.DataFrame(all_scores)
    scores_df.to_parquet(OOF_SCORES, index=False)
    folds_df = pd.DataFrame(all_folds)
    folds_df.to_csv(FOLD_RESULTS, index=False)
    results_df = pd.DataFrame(all_results).sort_values(
        ["incident_macro_f1", "incident_mrr", "incident_top2", "incident_macro_f1_fold_std", "fit_time_seconds"],
        ascending=[False, False, False, True, True],
    )
    results_df.to_csv(SEARCH_RESULTS, index=False)
    paired = paired_comparison(results_df, folds_df)
    paired.to_csv(PAIRED_COMPARISON, index=False)
    shortlist = select_shortlist(results_df, paired)
    best = recommended_candidate(shortlist)
    shortlist["recommended_candidate"] = shortlist["candidate_id"].eq(best["candidate_id"])
    shortlist.to_csv(SHORTLIST, index=False)
    write_candidate_config(best)
    write_validation_protocol_v2()
    update_registry(results_df)
    write_notebook()
    baseline = results_df[results_df["candidate_id"].eq("RF_BASELINE_V4_I1")].iloc[0]
    return {
        "evaluated_configurations": len(results_df),
        "search_method": SEARCH_METHOD,
        "search_budget": search_budget,
        "recommended_candidate": TUNED_CANDIDATE_ID,
        "recommended_search_candidate_id": best["candidate_id"],
        "parameter_hash": best["parameter_hash"],
        "hyperparameters": json.loads(best["parameters_json"]),
        "incident_macro_f1": float(best["incident_macro_f1"]),
        "incident_top1": float(best["incident_top1"]),
        "incident_top2": float(best["incident_top2"]),
        "incident_mrr": float(best["incident_mrr"]),
        "window_macro_f1": float(best["window_macro_f1"]),
        "baseline_incident_macro_f1": float(baseline["incident_macro_f1"]),
        "incident_macro_f1_delta": float(best["incident_macro_f1"] - baseline["incident_macro_f1"]),
        "xgboost_available": "YES" if xgboost_available() else "NO",
        "validation_accessed": False,
        "holdout_accessed": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Phase H TRAIN-only RF hyperparameter optimization")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--search-budget", type=int, default=SEARCH_BUDGET)
    args = parser.parse_args()
    if args.run:
        print(json.dumps(run_search(args.search_budget), indent=2, sort_keys=True))
        return
    parser.error("choose --run")


if __name__ == "__main__":
    main()
