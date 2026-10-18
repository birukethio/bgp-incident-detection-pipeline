from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.metrics import confusion_matrix, log_loss
from sklearn.model_selection import ParameterSampler
from sklearn.pipeline import Pipeline

try:
    from bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT, load_assignments, load_variant
    from bgp_incident_detection.imbalance_model_experiment import group_aware_weights
    from bgp_incident_detection.model_baselines import (
        INCIDENT_LABELS,
        REGISTRY,
        SEED,
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
        macro_f1,
        mrr,
        per_class_f1,
        top2_accuracy,
    )
    from src.bgp_incident_detection.train_batch_engine import source_commit


MODELING_DIR = Path("data/modeling")
ENVIRONMENT = MODELING_DIR / "xgboost_environment_v1.csv"
WEIGHT_AUDIT = MODELING_DIR / "xgboost_weight_semantics_audit_v1.csv"
SEARCH_RESULTS = MODELING_DIR / "xgboost_hyperparameter_search_results_v1.csv"
SEARCH_FOLD_RESULTS = MODELING_DIR / "xgboost_hyperparameter_fold_results_v1.csv"
SHORTLIST = MODELING_DIR / "xgboost_shortlist_v1.csv"
MULTISEED_STABILITY = MODELING_DIR / "xgboost_multiseed_stability_v1.csv"
MULTISEED_SEED_RESULTS = MODELING_DIR / "xgboost_multiseed_seed_results_v1.csv"
MULTISEED_FOLD_RESULTS = MODELING_DIR / "xgboost_multiseed_fold_results_v1.csv"
RF_XGB_COMPARISON = MODELING_DIR / "rf_vs_xgboost_comparison_v1.csv"
RF_XGB_PAIRED = MODELING_DIR / "rf_vs_xgboost_paired_fold_v1.csv"
FINAL_SELECTION = MODELING_DIR / "final_algorithm_selection_v1.csv"
RF_STABILITY_RESULTS = MODELING_DIR / "rf_multiseed_stability_results_v1.csv"
RF_STABILITY_FOLD_RESULTS = MODELING_DIR / "rf_multiseed_stability_fold_results_v1.csv"
NOTEBOOK = Path("notebooks/49_xgboost_algorithm_comparison.ipynb")
RF_LOCKED_CONFIG = Path("config/final_model_candidate_v3_rf_locked_for_validation.yaml")
XGB_LOCKED_CONFIG = Path("config/final_model_candidate_v3_xgb_locked_for_validation.yaml")
VALIDATION_PROTOCOL_V3 = Path("config/validation_confirmation_protocol_v3.yaml")

FEATURE_VARIANT = "V4"
FEATURE_COUNT = 74
IMBALANCE_CONDITION = "I1"
ARCHITECTURE = "MULTICLASS_STAGE2"
TASK = "HIJACK_LEAK_OUTAGE"
SEARCH_BUDGET = 40
SEARCH_SEED = 20260828
XGB_STABILITY_SEEDS = [20260828, 20260829, 20260830, 20260831, 20260901]
MAX_SHORTLIST = 5
MAX_STABILITY_CANDIDATES = 3
XGB_BASELINE_ID = "XGB_BASELINE_V4_I1"
XGB_SELECTED_ID = "XGB_TUNED_TRAIN_CANDIDATE_V1"
RF_COMPARATOR_ID = "RF_REFINED_TRAIN_CANDIDATE"
STAGE1_STATUS = "UNRESOLVED_EXPERIMENTAL_AUXILIARY"

RF_REFINED_REFERENCE = {
    "incident_macro_f1": 0.784588,
    "incident_macro_f1_std": 0.001342,
    "top1": 0.787513,
    "top2": 0.932931,
    "mrr": 0.882578,
    "hijack_f1": 0.721923,
    "leak_f1": 0.841110,
    "outage_f1": 0.790732,
    "window_macro_f1": 0.679524,
    "fit_time": 399.19,
    "inference_time": np.nan,
    "mean_true_class_rank": np.nan,
}

RF_REFINED_PARAMS = {
    "n_estimators": 1200,
    "max_depth": 40,
    "max_features": 0.3,
    "min_samples_leaf": 6,
    "min_samples_split": 6,
    "bootstrap": False,
    "criterion": "log_loss",
    "class_weight": None,
}

RF_REFINED_SOURCE_CANDIDATE_ID = "H2_LOCAL_001"

BASELINE_PARAMS = {
    "n_estimators": 400,
    "max_depth": 6,
    "learning_rate": 0.1,
    "subsample": 1.0,
    "colsample_bytree": 1.0,
    "min_child_weight": 1,
    "gamma": 0,
    "reg_alpha": 0,
    "reg_lambda": 1.0,
}

PARAMETER_SPACE = {
    "n_estimators": [200, 400, 600, 800, 1000, 1200],
    "max_depth": [3, 4, 5, 6, 8, 10],
    "learning_rate": [0.01, 0.03, 0.05, 0.1, 0.2],
    "subsample": [0.6, 0.8, 1.0],
    "colsample_bytree": [0.5, 0.7, 0.85, 1.0],
    "min_child_weight": [1, 3, 5, 10],
    "gamma": [0, 0.1, 0.5, 1.0],
    "reg_alpha": [0, 0.01, 0.1, 1.0],
    "reg_lambda": [0.5, 1.0, 2.0, 5.0],
}


def xgboost_environment() -> pd.DataFrame:
    try:
        import xgboost

        available = True
        version = xgboost.__version__
        status = "AVAILABLE"
    except Exception as exc:  # pragma: no cover - environment dependent
        available = False
        version = ""
        status = f"UNAVAILABLE: {exc}"
    return pd.DataFrame(
        [
            {
                "package": "xgboost",
                "installed": available,
                "version": version,
                "python_version": sys.version.replace("\n", " "),
                "installation_command": "python -m pip install xgboost",
                "platform": platform.platform(),
                "status": status,
            }
        ]
    )


def require_xgboost():
    try:
        from xgboost import XGBClassifier
    except Exception as exc:  # pragma: no cover - environment dependent
        raise RuntimeError("PHASE_I_BLOCKED_XGBOOST_UNAVAILABLE") from exc
    return XGBClassifier


def parameter_hash(params: dict[str, Any]) -> str:
    payload = json.dumps(params, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def load_stage2_train_data() -> pd.DataFrame:
    df = load_variant(FEATURE_VARIANT)
    assignments = load_assignments(df)
    data = df.merge(assignments, on="window_id", how="left", validate="one_to_one")
    data = data[data["label"].isin(INCIDENT_LABELS)].copy()
    if set(data["partition"].astype(str)) != {"train"}:
        raise ValueError("Phase I must use TRAIN incident rows only")
    if len(FEATURES_BY_VARIANT[FEATURE_VARIANT]) != FEATURE_COUNT:
        raise ValueError("Phase I must use exactly the frozen V4 74-feature schema")
    if data.groupby("model_group_id")["fold"].nunique().max() != 1:
        raise ValueError("grouped CV violation: incident crosses folds")
    return data


def label_codes(labels: pd.Series) -> np.ndarray:
    mapping = {label: index for index, label in enumerate(INCIDENT_LABELS)}
    return labels.map(mapping).astype(int).to_numpy()


def ranked_frame(scores: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, row in scores.iterrows():
        pairs = sorted(
            [(label, row[f"p_{label.lower()}"]) for label in INCIDENT_LABELS],
            key=lambda item: item[1],
            reverse=True,
        )
        out = row.to_dict()
        out["predicted_class"] = pairs[0][0]
        out["true_class_rank"] = [label for label, _ in pairs].index(row["true_class"]) + 1
        rows.append(out)
    return pd.DataFrame(rows)


def aggregate_incident_scores(scores: pd.DataFrame) -> pd.DataFrame:
    rows = []
    group_cols = ["candidate_id", "parameter_hash", "xgb_seed", "incident_uid"]
    for keys, group in scores.groupby(group_cols):
        candidate_id, h, seed, incident_uid = keys
        rows.append(
            {
                "candidate_id": candidate_id,
                "parameter_hash": h,
                "xgb_seed": int(seed),
                "incident_uid": incident_uid,
                "fold": int(group["fold"].iloc[0]),
                "true_class": group["true_class"].iloc[0],
                "p_hijack": float(group["p_hijack"].mean()),
                "p_leak": float(group["p_leak"].mean()),
                "p_outage": float(group["p_outage"].mean()),
            }
        )
    return pd.DataFrame(rows)


def multiclass_brier(frame: pd.DataFrame) -> float:
    if frame.empty:
        return float("nan")
    y = label_codes(frame["true_class"])
    probs = frame[["p_hijack", "p_leak", "p_outage"]].to_numpy()
    one_hot = np.eye(len(INCIDENT_LABELS))[y]
    return float(np.mean(np.sum((probs - one_hot) ** 2, axis=1)))


def metrics_for_frame(frame: pd.DataFrame) -> dict[str, Any]:
    ranked = ranked_frame(frame)
    y_true = ranked["true_class"].tolist()
    y_pred = ranked["predicted_class"].tolist()
    probs = ranked[["p_hijack", "p_leak", "p_outage"]].copy()
    probs.columns = INCIDENT_LABELS
    y_numeric = label_codes(ranked["true_class"])
    out: dict[str, Any] = {
        "macro_f1": macro_f1(y_true, y_pred, INCIDENT_LABELS),
        "top1": float((ranked["true_class"] == ranked["predicted_class"]).mean()),
        "top2": top2_accuracy(y_true, probs),
        "mrr": mrr(y_true, probs),
        "mean_true_class_rank": float(ranked["true_class_rank"].mean()),
        "log_loss": float(log_loss(y_numeric, probs.to_numpy(), labels=[0, 1, 2])),
        "brier_score": multiclass_brier(ranked),
        "mean_max_class_confidence": float(probs.max(axis=1).mean()),
        "confidence_p25": float(probs.max(axis=1).quantile(0.25)),
        "confidence_p50": float(probs.max(axis=1).quantile(0.50)),
        "confidence_p75": float(probs.max(axis=1).quantile(0.75)),
        "confusion_matrix": json.dumps(confusion_matrix(y_true, y_pred, labels=INCIDENT_LABELS).tolist()),
    }
    out.update(per_class_f1(y_true, y_pred, INCIDENT_LABELS))
    return out


def xgb_pipeline(params: dict[str, Any], xgb_seed: int) -> Pipeline:
    XGBClassifier = require_xgboost()
    model_params = {
        **params,
        "objective": "multi:softprob",
        "num_class": len(INCIDENT_LABELS),
        "eval_metric": "mlogloss",
        "random_state": xgb_seed,
        "seed": xgb_seed,
        "n_jobs": max(os.cpu_count() or 1, 1),
        "tree_method": "hist",
        "verbosity": 0,
    }
    return Pipeline([("imputer", SimpleImputer(strategy="median")), ("model", XGBClassifier(**model_params))])


def parameter_candidates(search_budget: int = SEARCH_BUDGET, seed: int = SEARCH_SEED) -> list[dict[str, Any]]:
    if search_budget > SEARCH_BUDGET:
        raise ValueError("XGBoost search budget cannot exceed 40")
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
        raise RuntimeError(f"unable to build fixed XGBoost search budget: {len(candidates)} != {search_budget}")
    return candidates


def score_row(source: pd.Series, candidate_id: str, fold: int, params: dict[str, Any], seed: int, probs: np.ndarray) -> dict[str, Any]:
    return {
        "candidate_id": candidate_id,
        "parameter_hash": parameter_hash(params),
        "xgb_seed": seed,
        "window_id": source["window_id"],
        "incident_uid": source["incident_uid"],
        "fold": fold,
        "true_class": source["label"],
        "p_hijack": float(probs[0]),
        "p_leak": float(probs[1]),
        "p_outage": float(probs[2]),
    }


def evaluate_config(data: pd.DataFrame, candidate_id: str, params: dict[str, Any], xgb_seed: int) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    features = FEATURES_BY_VARIANT[FEATURE_VARIANT]
    score_rows: list[dict[str, Any]] = []
    fold_rows: list[dict[str, Any]] = []
    fit_times: list[float] = []
    inference_times: list[float] = []
    for fold in sorted(data["fold"].unique()):
        train = data[data["fold"] != fold].copy()
        test = data[data["fold"] == fold].copy()
        weights = group_aware_weights(train)
        model = xgb_pipeline(params, xgb_seed)
        started = time.perf_counter()
        model.fit(train[features], label_codes(train["label"]), model__sample_weight=weights)
        fit_time = time.perf_counter() - started
        started = time.perf_counter()
        probs = model.predict_proba(test[features])
        inference_time = time.perf_counter() - started
        fit_times.append(fit_time)
        inference_times.append(inference_time)
        fold_scores = []
        for pos, idx in enumerate(test.index):
            row = score_row(data.loc[idx], candidate_id, int(fold), params, xgb_seed, probs[pos])
            score_rows.append(row)
            fold_scores.append(row)
        fold_window = pd.DataFrame(fold_scores)
        fold_incident = aggregate_incident_scores(fold_window)
        fold_metrics = metrics_for_frame(fold_incident)
        fold_window_metrics = metrics_for_frame(fold_window)
        fold_rows.append(
            {
                "candidate_id": candidate_id,
                "parameter_hash": parameter_hash(params),
                "xgb_seed": xgb_seed,
                "fold": int(fold),
                "incident_macro_f1": fold_metrics["macro_f1"],
                "incident_top1": fold_metrics["top1"],
                "incident_top2": fold_metrics["top2"],
                "incident_mrr": fold_metrics["mrr"],
                "incident_hijack_f1": fold_metrics["hijack_f1"],
                "incident_leak_f1": fold_metrics["leak_f1"],
                "incident_outage_f1": fold_metrics["outage_f1"],
                "incident_log_loss": fold_metrics["log_loss"],
                "incident_brier_score": fold_metrics["brier_score"],
                "mean_true_class_rank": fold_metrics["mean_true_class_rank"],
                "window_macro_f1": fold_window_metrics["macro_f1"],
            }
        )
    scores = pd.DataFrame(score_rows)
    incident_scores = aggregate_incident_scores(scores)
    window_metrics = metrics_for_frame(scores)
    incident_metrics = metrics_for_frame(incident_scores)
    result = {
        "candidate_id": candidate_id,
        "parameter_hash": parameter_hash(params),
        "phase": "I",
        "feature_variant": FEATURE_VARIANT,
        "feature_count": FEATURE_COUNT,
        "imbalance_condition": IMBALANCE_CONDITION,
        "architecture": ARCHITECTURE,
        "task": TASK,
        "xgb_seed": xgb_seed,
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
        "incident_log_loss": incident_metrics["log_loss"],
        "incident_brier_score": incident_metrics["brier_score"],
        "mean_max_class_confidence": incident_metrics["mean_max_class_confidence"],
        "confidence_p25": incident_metrics["confidence_p25"],
        "confidence_p50": incident_metrics["confidence_p50"],
        "confidence_p75": incident_metrics["confidence_p75"],
        "incident_macro_f1_fold_std": float(pd.Series([row["incident_macro_f1"] for row in fold_rows]).std(ddof=0)),
        "fit_time_seconds": round(float(np.sum(fit_times)), 3),
        "inference_time_seconds": round(float(np.sum(inference_times)), 3),
    }
    return result, fold_rows


def weight_semantics_audit(data: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for fold in sorted(data["fold"].unique()):
        train = data[data["fold"] != fold].copy()
        weights = pd.Series(group_aware_weights(train), index=train.index)
        group_weight = weights.groupby(train["model_group_id"]).sum()
        rows.append(
            {
                "fold": int(fold),
                "train_rows": len(train),
                "train_incident_groups": train["model_group_id"].nunique(),
                "min_group_weight": float(group_weight.min()),
                "median_group_weight": float(group_weight.median()),
                "max_group_weight": float(group_weight.max()),
                "group_weight_semantics": "same group_aware_weights(train_fold) function used for RF and XGBoost; weights computed from training side only",
                "status": "PASS" if np.isclose(group_weight.min(), group_weight.max()) else "REVIEW",
            }
        )
    return pd.DataFrame(rows)


def run_search(data: pd.DataFrame, search_budget: int = SEARCH_BUDGET) -> tuple[pd.DataFrame, pd.DataFrame]:
    results = pd.read_csv(SEARCH_RESULTS).to_dict("records") if SEARCH_RESULTS.exists() else []
    folds = pd.read_csv(SEARCH_FOLD_RESULTS).to_dict("records") if SEARCH_FOLD_RESULTS.exists() else []
    completed = {row["candidate_id"] for row in results}
    for idx, params in enumerate(parameter_candidates(search_budget, SEARCH_SEED)):
        candidate_id = XGB_BASELINE_ID if idx == 0 else f"PHASEI_XGB_SEARCH_{idx:03d}"
        if candidate_id in completed:
            print(f"XGBoost search {idx + 1}/{search_budget}: {candidate_id} already complete", flush=True)
            continue
        print(f"XGBoost search {idx + 1}/{search_budget}: {candidate_id} {parameter_hash(params)}", flush=True)
        result, fold_rows = evaluate_config(data, candidate_id, params, SEARCH_SEED)
        results.append(result)
        folds.extend(fold_rows)
        pd.DataFrame(results).to_csv(SEARCH_RESULTS, index=False)
        pd.DataFrame(folds).to_csv(SEARCH_FOLD_RESULTS, index=False)
        completed.add(candidate_id)
    return pd.DataFrame(results), pd.DataFrame(folds)


def shortlist_configs(results: pd.DataFrame, max_count: int = MAX_SHORTLIST) -> pd.DataFrame:
    scored = results.copy()
    scored["class_balance_range"] = scored[["incident_hijack_f1", "incident_leak_f1", "incident_outage_f1"]].max(axis=1) - scored[
        ["incident_hijack_f1", "incident_leak_f1", "incident_outage_f1"]
    ].min(axis=1)
    scored = scored.sort_values(
        ["incident_macro_f1", "incident_mrr", "incident_top2", "incident_top1", "class_balance_range", "incident_macro_f1_fold_std", "fit_time_seconds"],
        ascending=[False, False, False, False, True, True, True],
    ).head(max_count)
    scored = scored.copy()
    scored["shortlist_rank"] = range(1, len(scored) + 1)
    scored["selection_basis"] = "incident Macro F1 primary; MRR/Top-2/class balance/fold stability/runtime secondary"
    return scored


def stability_summary(seed_rows: pd.DataFrame, fold_rows: pd.DataFrame, shortlist: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for candidate_id, group in seed_rows.groupby("candidate_id"):
        folds = fold_rows[fold_rows["candidate_id"].eq(candidate_id)]
        rows.append(
            {
                "candidate_id": candidate_id,
                "parameter_hash": group["parameter_hash"].iloc[0],
                "parameters_json": group["parameters_json"].iloc[0],
                "stability_seeds": json.dumps(XGB_STABILITY_SEEDS),
                "mean_incident_macro_f1": group["incident_macro_f1"].mean(),
                "std_incident_macro_f1": group["incident_macro_f1"].std(ddof=0),
                "mean_top1": group["incident_top1"].mean(),
                "mean_top2": group["incident_top2"].mean(),
                "mean_mrr": group["incident_mrr"].mean(),
                "hijack_f1_mean": group["incident_hijack_f1"].mean(),
                "hijack_f1_std": group["incident_hijack_f1"].std(ddof=0),
                "leak_f1_mean": group["incident_leak_f1"].mean(),
                "leak_f1_std": group["incident_leak_f1"].std(ddof=0),
                "outage_f1_mean": group["incident_outage_f1"].mean(),
                "outage_f1_std": group["incident_outage_f1"].std(ddof=0),
                "window_macro_f1_mean": group["window_macro_f1"].mean(),
                "incident_log_loss_mean": group["incident_log_loss"].mean(),
                "incident_brier_score_mean": group["incident_brier_score"].mean(),
                "mean_max_class_confidence": group["mean_max_class_confidence"].mean(),
                "mean_true_class_rank": group["mean_true_class_rank"].mean(),
                "fold_seed_incident_macro_f1_std": folds["incident_macro_f1"].std(ddof=0),
                "mean_fit_time_seconds": group["fit_time_seconds"].mean(),
                "mean_inference_time_seconds": group["inference_time_seconds"].mean(),
            }
        )
    out = pd.DataFrame(rows)
    return out.merge(shortlist[["candidate_id", "shortlist_rank"]], on="candidate_id", how="left")


def run_stability(data: pd.DataFrame, shortlist: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    seed_rows = pd.read_csv(MULTISEED_SEED_RESULTS).to_dict("records") if MULTISEED_SEED_RESULTS.exists() else []
    fold_rows = pd.read_csv(MULTISEED_FOLD_RESULTS).to_dict("records") if MULTISEED_FOLD_RESULTS.exists() else []
    for _, row in shortlist.head(MAX_STABILITY_CANDIDATES).iterrows():
        params = json.loads(row["parameters_json"])
        for seed in XGB_STABILITY_SEEDS:
            if any(existing["candidate_id"] == row["candidate_id"] and int(existing["xgb_seed"]) == seed for existing in seed_rows):
                print(f"XGBoost stability {row['candidate_id']} seed={seed} already complete", flush=True)
                continue
            if seed == SEARCH_SEED:
                search_match = row.to_dict()
                search_fold_match = pd.read_csv(SEARCH_FOLD_RESULTS)
                search_fold_match = search_fold_match[search_fold_match["candidate_id"].eq(row["candidate_id"])]
                if len(search_fold_match) == 5:
                    print(f"XGBoost stability {row['candidate_id']} seed={seed} reused from search", flush=True)
                    seed_rows.append(search_match)
                    fold_rows.extend(search_fold_match.to_dict("records"))
                    pd.DataFrame(seed_rows).to_csv(MULTISEED_SEED_RESULTS, index=False)
                    pd.DataFrame(fold_rows).to_csv(MULTISEED_FOLD_RESULTS, index=False)
                    continue
            print(f"XGBoost stability {row['candidate_id']} seed={seed}", flush=True)
            result, folds = evaluate_config(data, row["candidate_id"], params, seed)
            seed_rows.append(result)
            fold_rows.extend(folds)
            pd.DataFrame(seed_rows).to_csv(MULTISEED_SEED_RESULTS, index=False)
            pd.DataFrame(fold_rows).to_csv(MULTISEED_FOLD_RESULTS, index=False)
    seed_df = pd.DataFrame(seed_rows)
    fold_df = pd.DataFrame(fold_rows)
    stability = stability_summary(seed_df, fold_df, shortlist)
    return stability, seed_df, fold_df


def select_xgb_candidate(stability: pd.DataFrame) -> pd.Series:
    scored = stability.copy()
    scored["class_balance_range"] = scored[["hijack_f1_mean", "leak_f1_mean", "outage_f1_mean"]].max(axis=1) - scored[
        ["hijack_f1_mean", "leak_f1_mean", "outage_f1_mean"]
    ].min(axis=1)
    scored["selection_score"] = (
        scored["mean_incident_macro_f1"]
        + 0.08 * scored["mean_mrr"]
        + 0.03 * scored["mean_top2"]
        - 0.02 * scored["std_incident_macro_f1"]
        - 0.01 * scored["class_balance_range"]
        - 0.001 * (scored["mean_fit_time_seconds"] / max(float(scored["mean_fit_time_seconds"].max()), 1.0))
    )
    selected = scored.sort_values(["selection_score", "mean_incident_macro_f1"], ascending=False).iloc[0].copy()
    selected["candidate_id"] = XGB_SELECTED_ID
    return selected


def rf_reference_row() -> dict[str, Any]:
    if RF_STABILITY_RESULTS.exists():
        rf = pd.read_csv(RF_STABILITY_RESULTS)
        match = rf[rf["candidate_id"].eq(RF_REFINED_SOURCE_CANDIDATE_ID)]
        if len(match) == 1:
            row = match.iloc[0]
            return {
                "incident_macro_f1": row["mean_incident_macro_f1"],
                "incident_macro_f1_std": row["std_incident_macro_f1"],
                "top1": row["mean_top1"],
                "top2": row["mean_top2"],
                "mrr": row["mean_mrr"],
                "hijack_f1": row["hijack_f1_mean"],
                "leak_f1": row["leak_f1_mean"],
                "outage_f1": row["outage_f1_mean"],
                "window_macro_f1": row["window_macro_f1_mean"],
                "fit_time": row["mean_fit_time_seconds"],
                "inference_time": row["mean_inference_time_seconds"],
                "mean_true_class_rank": np.nan,
            }
    return RF_REFINED_REFERENCE.copy()


def rf_fold_reference() -> pd.DataFrame:
    if not RF_STABILITY_FOLD_RESULTS.exists():
        return pd.DataFrame()
    folds = pd.read_csv(RF_STABILITY_FOLD_RESULTS)
    folds = folds[folds["candidate_id"].eq(RF_REFINED_SOURCE_CANDIDATE_ID)].copy()
    if folds.empty:
        return pd.DataFrame()
    metrics = [
        "incident_macro_f1",
        "incident_hijack_f1",
        "incident_leak_f1",
        "incident_outage_f1",
        "incident_top1",
        "incident_top2",
        "incident_mrr",
    ]
    return folds.groupby("fold", as_index=False)[metrics].mean()


def compare_with_rf(selected: pd.Series, fold_df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    rf_reference = rf_reference_row()
    xgb_row = {
        "algorithm": "XGBoost",
        "configuration": XGB_SELECTED_ID,
        "incident_macro_f1": selected["mean_incident_macro_f1"],
        "macro_f1_std": selected["std_incident_macro_f1"],
        "hijack_f1": selected["hijack_f1_mean"],
        "leak_f1": selected["leak_f1_mean"],
        "outage_f1": selected["outage_f1_mean"],
        "top1": selected["mean_top1"],
        "top2": selected["mean_top2"],
        "mrr": selected["mean_mrr"],
        "mean_true_class_rank": selected["mean_true_class_rank"],
        "window_macro_f1": selected["window_macro_f1_mean"],
        "fit_time": selected["mean_fit_time_seconds"],
        "inference_time": selected["mean_inference_time_seconds"],
        "multiclass_log_loss": selected["incident_log_loss_mean"],
        "multiclass_brier_score": selected["incident_brier_score_mean"],
        "mean_max_class_confidence": selected["mean_max_class_confidence"],
        "seed_stability": f"std_incident_macro_f1={selected['std_incident_macro_f1']:.6f}",
    }
    rf_row = {
        "algorithm": "RandomForest",
        "configuration": RF_COMPARATOR_ID,
        "incident_macro_f1": rf_reference["incident_macro_f1"],
        "macro_f1_std": rf_reference["incident_macro_f1_std"],
        "hijack_f1": rf_reference["hijack_f1"],
        "leak_f1": rf_reference["leak_f1"],
        "outage_f1": rf_reference["outage_f1"],
        "top1": rf_reference["top1"],
        "top2": rf_reference["top2"],
        "mrr": rf_reference["mrr"],
        "mean_true_class_rank": rf_reference["mean_true_class_rank"],
        "window_macro_f1": rf_reference["window_macro_f1"],
        "fit_time": rf_reference["fit_time"],
        "inference_time": rf_reference["inference_time"],
        "multiclass_log_loss": np.nan,
        "multiclass_brier_score": np.nan,
        "mean_max_class_confidence": np.nan,
        "seed_stability": f"std_incident_macro_f1={rf_reference['incident_macro_f1_std']:.6f}",
    }
    comparison = pd.DataFrame([rf_row, xgb_row])

    selected_source = selected.get("selected_source_candidate_id", "")
    source_id = selected_source if selected_source else selected.get("source_candidate_id", "")
    xgb_folds = fold_df[fold_df["candidate_id"].eq(source_id if source_id else selected.name)]
    rf_folds = rf_fold_reference()
    rows = []
    for fold, group in xgb_folds.groupby("fold"):
        mean_group = group.mean(numeric_only=True)
        if rf_folds.empty:
            rf_fold_values = {
                "incident_macro_f1": rf_reference["incident_macro_f1"],
                "incident_hijack_f1": rf_reference["hijack_f1"],
                "incident_leak_f1": rf_reference["leak_f1"],
                "incident_outage_f1": rf_reference["outage_f1"],
                "incident_top1": rf_reference["top1"],
                "incident_top2": rf_reference["top2"],
                "incident_mrr": rf_reference["mrr"],
            }
        else:
            rf_match = rf_folds[rf_folds["fold"].eq(fold)].iloc[0]
            rf_fold_values = {
                "incident_macro_f1": rf_match["incident_macro_f1"],
                "incident_hijack_f1": rf_match["incident_hijack_f1"],
                "incident_leak_f1": rf_match["incident_leak_f1"],
                "incident_outage_f1": rf_match["incident_outage_f1"],
                "incident_top1": rf_match["incident_top1"],
                "incident_top2": rf_match["incident_top2"],
                "incident_mrr": rf_match["incident_mrr"],
            }
        row = {"fold": int(fold)}
        for metric, rf_value in rf_fold_values.items():
            xgb_value = float(mean_group[metric])
            row[f"xgb_{metric}"] = xgb_value
            row[f"rf_{metric}"] = rf_value
            row[f"delta_{metric}"] = xgb_value - rf_value
        row["winner_incident_macro_f1"] = "XGBoost" if row["delta_incident_macro_f1"] > 0 else "RandomForest"
        rows.append(row)
    paired = pd.DataFrame(rows)
    if not paired.empty:
        summary = {
            "fold": "SUMMARY",
        }
        for metric in rf_fold_values:
            delta_col = f"delta_{metric}"
            summary[f"mean_{delta_col}"] = paired[delta_col].mean()
            summary[f"std_{delta_col}"] = paired[delta_col].std(ddof=0)
        summary["rf_fold_wins"] = int((paired["delta_incident_macro_f1"] <= 0).sum())
        summary["xgboost_fold_wins"] = int((paired["delta_incident_macro_f1"] > 0).sum())
        paired = pd.concat([paired, pd.DataFrame([summary])], ignore_index=True, sort=False)
    return comparison, paired


def final_decision(comparison: pd.DataFrame) -> tuple[str, str]:
    rf = comparison[comparison["algorithm"].eq("RandomForest")].iloc[0]
    xgb = comparison[comparison["algorithm"].eq("XGBoost")].iloc[0]
    macro_delta = xgb["incident_macro_f1"] - rf["incident_macro_f1"]
    mrr_delta = xgb["mrr"] - rf["mrr"]
    top2_delta = xgb["top2"] - rf["top2"]
    if macro_delta >= 0.01 and mrr_delta >= -0.002 and top2_delta >= -0.005:
        return "LOCK_XGBOOST", "XGBoost shows a meaningful TRAIN grouped-CV incident Macro F1 gain without material ranking loss."
    if abs(macro_delta) < 0.005 and abs(mrr_delta) < 0.005 and abs(top2_delta) < 0.005:
        return "ALGORITHMS_EFFECTIVELY_TIED_PREFER_SIMPLER", "TRAIN grouped-CV differences are tiny; prefer the simpler established RF candidate."
    return "LOCK_RANDOM_FOREST", "Refined RF remains stronger or more stable on the predeclared TRAIN grouped-CV selection criteria."


def final_selection_table(comparison: pd.DataFrame, decision: str, reason: str) -> pd.DataFrame:
    rows = []
    for _, row in comparison.iterrows():
        selected = (decision == "LOCK_XGBOOST" and row["algorithm"] == "XGBoost") or (
            decision in {"LOCK_RANDOM_FOREST", "ALGORITHMS_EFFECTIVELY_TIED_PREFER_SIMPLER"} and row["algorithm"] == "RandomForest"
        )
        rows.append(
            {
                "algorithm": row["algorithm"],
                "configuration": row["configuration"],
                "incident_macro_f1": row["incident_macro_f1"],
                "macro_f1_std": row["macro_f1_std"],
                "hijack_f1": row["hijack_f1"],
                "leak_f1": row["leak_f1"],
                "outage_f1": row["outage_f1"],
                "top1": row["top1"],
                "top2": row["top2"],
                "mrr": row["mrr"],
                "window_macro_f1": row["window_macro_f1"],
                "fit_time": row["fit_time"],
                "inference_time": row["inference_time"],
                "seed_stability": row["seed_stability"],
                "selected": selected,
                "selection_reason": reason if selected else "Not selected by Phase I TRAIN-only algorithm decision.",
            }
        )
    return pd.DataFrame(rows)


def yaml_scalar(value: Any) -> str:
    if value is None or (isinstance(value, float) and np.isnan(value)):
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


def write_locked_configs(selected_xgb: pd.Series, comparison: pd.DataFrame, decision: str, reason: str) -> Path:
    env = xgboost_environment().iloc[0]
    features = FEATURES_BY_VARIANT[FEATURE_VARIANT]
    selected_algorithm = "XGBoost" if decision == "LOCK_XGBOOST" else "RandomForest"
    selected_config = XGB_LOCKED_CONFIG if selected_algorithm == "XGBoost" else RF_LOCKED_CONFIG
    params = json.loads(selected_xgb["parameters_json"]) if selected_algorithm == "XGBoost" else RF_REFINED_PARAMS
    metrics_row = comparison[comparison["algorithm"].eq(selected_algorithm)].iloc[0]
    write_yaml(
        selected_config,
        {
            "candidate_id": "FINAL_STAGE2_MODEL_CANDIDATE_V3",
            "status": "ALGORITHM_SELECTED_TRAIN_ONLY_READY_FOR_VALIDATION",
            "phase_i_decision": decision,
            "selection_reason": reason,
            "algorithm": selected_algorithm,
            "algorithm_version": env["version"] if selected_algorithm == "XGBoost" else "scikit-learn RandomForestClassifier",
            "hyperparameters": params,
            "feature_variant": FEATURE_VARIANT,
            "feature_count": FEATURE_COUNT,
            "feature_list_order": features,
            "imbalance_condition": IMBALANCE_CONDITION,
            "weighting": "I1 incident-aware sample weights computed from the training side of each grouped-CV fold only",
            "seed_policy": {
                "search_seed": SEARCH_SEED,
                "stability_seeds": XGB_STABILITY_SEEDS if selected_algorithm == "XGBoost" else [20260828, 20260829, 20260830, 20260831, 20260901],
                "fold_assignments": "data/modeling/baseline_v1_grouped_cv_assignments_v1.csv",
            },
            "incident_probability_aggregation": "mean class probability across all eligible windows for the incident",
            "ranking_rule": "sort P(Hijack), P(Leak), P(Outage) descending",
            "train_grouped_cv_performance": {
                "incident_macro_f1": float(metrics_row["incident_macro_f1"]),
                "incident_macro_f1_std": float(metrics_row["macro_f1_std"]),
                "incident_top1": float(metrics_row["top1"]),
                "incident_top2": float(metrics_row["top2"]),
                "incident_mrr": float(metrics_row["mrr"]),
                "hijack_f1": float(metrics_row["hijack_f1"]),
                "leak_f1": float(metrics_row["leak_f1"]),
                "outage_f1": float(metrics_row["outage_f1"]),
                "window_macro_f1": float(metrics_row["window_macro_f1"]),
            },
            "stage1_status": STAGE1_STATUS,
            "validation_accessed": False,
            "final_holdout_accessed": False,
            "source_commit": source_commit(),
        },
    )
    write_yaml(
        VALIDATION_PROTOCOL_V3,
        {
            "protocol_id": "validation_confirmation_protocol_v3",
            "selected_candidate_config": str(selected_config),
            "selected_algorithm": selected_algorithm,
            "purpose": "single predeclared Validation confirmation of the Phase I selected candidate only",
            "validation_compares_algorithms": False,
            "primary_metrics": ["incident_macro_f1", "incident_mrr", "incident_top2"],
            "acceptance_criteria": {
                "incident_macro_f1_floor": 0.60,
                "incident_mrr_floor": 0.75,
                "incident_top2_floor": 0.85,
                "catastrophic_class_failure": "any incident class F1 == 0",
            },
            "forbidden_uses": [
                "algorithm comparison",
                "feature selection",
                "threshold tuning",
                "hyperparameter tuning",
                "model selection",
                "holdout access",
            ],
            "validation_accessed": False,
            "final_holdout_accessed": False,
            "source_commit": source_commit(),
        },
    )
    return selected_config


def update_registry(search_results: pd.DataFrame, stability: pd.DataFrame, decision: str) -> None:
    existing = pd.read_csv(REGISTRY, dtype=str).fillna("") if REGISTRY.exists() else pd.DataFrame()
    rows = []
    env = xgboost_environment().iloc[0]
    for _, row in search_results.iterrows():
        rows.append(
            {
                "experiment_id": "PHASEI_XGB_BASELINE" if row["candidate_id"] == XGB_BASELINE_ID else row["candidate_id"],
                "phase": "I",
                "model": "XGBClassifier",
                "architecture": ARCHITECTURE,
                "feature_variant": FEATURE_VARIANT,
                "feature_count": str(FEATURE_COUNT),
                "imbalance_condition": IMBALANCE_CONDITION,
                "parameter_hash": row["parameter_hash"],
                "parameters_json": row["parameters_json"],
                "seed": str(SEARCH_SEED),
                "status": "COMPLETED",
                "result_artifact": str(SEARCH_RESULTS),
                "source_commit": source_commit(),
                "xgboost_version": env["version"],
            }
        )
    for _, row in stability.iterrows():
        rows.append(
            {
                "experiment_id": f"PHASEI_XGB_MULTI_SEED_{row['candidate_id']}_{row['parameter_hash']}",
                "phase": "I",
                "model": "XGBClassifier",
                "architecture": ARCHITECTURE,
                "feature_variant": FEATURE_VARIANT,
                "feature_count": str(FEATURE_COUNT),
                "imbalance_condition": IMBALANCE_CONDITION,
                "parameter_hash": row["parameter_hash"],
                "parameters_json": row["parameters_json"],
                "seed": json.dumps(XGB_STABILITY_SEEDS),
                "status": "COMPLETED",
                "result_artifact": str(MULTISEED_STABILITY),
                "source_commit": source_commit(),
                "xgboost_version": env["version"],
            }
        )
    rows.extend(
        [
            {
                "experiment_id": "PHASEI_XGB_SELECTED_CANDIDATE",
                "phase": "I",
                "model": "XGBClassifier",
                "architecture": ARCHITECTURE,
                "feature_variant": FEATURE_VARIANT,
                "feature_count": str(FEATURE_COUNT),
                "imbalance_condition": IMBALANCE_CONDITION,
                "status": "COMPLETED",
                "result_artifact": str(MULTISEED_STABILITY),
                "source_commit": source_commit(),
            },
            {
                "experiment_id": "PHASEI_RF_VS_XGB_FINAL_TRAIN_COMPARISON",
                "phase": "I",
                "model": "RandomForestClassifier vs XGBClassifier",
                "architecture": ARCHITECTURE,
                "feature_variant": FEATURE_VARIANT,
                "feature_count": str(FEATURE_COUNT),
                "imbalance_condition": IMBALANCE_CONDITION,
                "status": decision,
                "result_artifact": str(RF_XGB_COMPARISON),
                "source_commit": source_commit(),
            },
        ]
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
                    "# Phase I - XGBoost Comparator and Final Algorithm Selection\n",
                    "\n",
                    "TRAIN-only XGBoost comparison against the Phase H2 refined Random Forest benchmark. Validation and Final Holdout remain sealed.\n",
                ],
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": ["from bgp_incident_detection.xgboost_algorithm_comparison import run_phase_i\n", "# run_phase_i()\n"],
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": ["import pandas as pd\n", "pd.read_csv('../data/modeling/final_algorithm_selection_v1.csv')\n"],
            },
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def run_phase_i(search_budget: int = SEARCH_BUDGET) -> dict[str, Any]:
    MODELING_DIR.mkdir(parents=True, exist_ok=True)
    env = xgboost_environment()
    env.to_csv(ENVIRONMENT, index=False)
    if not bool(env["installed"].iloc[0]):
        raise RuntimeError("PHASE_I_BLOCKED_XGBOOST_UNAVAILABLE")

    data = load_stage2_train_data()
    weight_audit = weight_semantics_audit(data)
    weight_audit.to_csv(WEIGHT_AUDIT, index=False)
    search_results, search_folds = run_search(data, search_budget)
    search_results = search_results.sort_values(
        ["incident_macro_f1", "incident_mrr", "incident_top2", "incident_macro_f1_fold_std", "fit_time_seconds"],
        ascending=[False, False, False, True, True],
    )
    search_results.to_csv(SEARCH_RESULTS, index=False)
    search_folds.to_csv(SEARCH_FOLD_RESULTS, index=False)
    shortlist = shortlist_configs(search_results)
    shortlist.to_csv(SHORTLIST, index=False)
    stability, seed_df, fold_df = run_stability(data, shortlist)
    stability = stability.sort_values(
        ["mean_incident_macro_f1", "mean_mrr", "mean_top2", "std_incident_macro_f1", "mean_fit_time_seconds"],
        ascending=[False, False, False, True, True],
    )
    selected_xgb = select_xgb_candidate(stability)
    selected_source_id = stability.sort_values(
        ["mean_incident_macro_f1", "mean_mrr", "mean_top2", "std_incident_macro_f1", "mean_fit_time_seconds"],
        ascending=[False, False, False, True, True],
    ).iloc[0]["candidate_id"]
    selected_xgb["selected_source_candidate_id"] = selected_source_id
    stability.to_csv(MULTISEED_STABILITY, index=False)
    seed_df.to_csv(MULTISEED_SEED_RESULTS, index=False)
    fold_df.to_csv(MULTISEED_FOLD_RESULTS, index=False)
    comparison, paired = compare_with_rf(selected_xgb, fold_df)
    decision, reason = final_decision(comparison)
    comparison.to_csv(RF_XGB_COMPARISON, index=False)
    paired.to_csv(RF_XGB_PAIRED, index=False)
    selection = final_selection_table(comparison, decision, reason)
    selection.to_csv(FINAL_SELECTION, index=False)
    selected_config = write_locked_configs(selected_xgb, comparison, decision, reason)
    update_registry(search_results, stability, decision)
    write_notebook()
    return {
        "xgboost_installed": True,
        "xgboost_version": str(env["version"].iloc[0]),
        "xgb_baseline_incident_macro_f1": float(search_results[search_results["candidate_id"].eq(XGB_BASELINE_ID)]["incident_macro_f1"].iloc[0]),
        "xgb_configurations_evaluated": int(search_results["candidate_id"].nunique()),
        "stability_configurations": shortlist.head(MAX_STABILITY_CANDIDATES)["candidate_id"].tolist(),
        "selected_xgb_source_candidate": str(selected_source_id),
        "selected_xgb_incident_macro_f1_mean": float(selected_xgb["mean_incident_macro_f1"]),
        "selected_xgb_incident_macro_f1_std": float(selected_xgb["std_incident_macro_f1"]),
        "selected_xgb_top1": float(selected_xgb["mean_top1"]),
        "selected_xgb_top2": float(selected_xgb["mean_top2"]),
        "selected_xgb_mrr": float(selected_xgb["mean_mrr"]),
        "algorithm_decision": decision,
        "locked_candidate_config": str(selected_config),
        "validation_accessed": False,
        "final_holdout_accessed": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Phase I TRAIN-only XGBoost comparison")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--search-budget", type=int, default=SEARCH_BUDGET)
    args = parser.parse_args()
    if args.run:
        print(json.dumps(run_phase_i(args.search_budget), indent=2, sort_keys=True))
        return
    parser.error("choose --run")


if __name__ == "__main__":
    main()
