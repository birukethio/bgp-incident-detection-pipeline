from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.model_selection import ParameterSampler

try:
    from bgp_incident_detection.model_baselines import REGISTRY
    from bgp_incident_detection.train_batch_engine import source_commit
    from bgp_incident_detection.xgboost_algorithm_comparison import (
        FEATURE_COUNT,
        FEATURE_VARIANT,
        FEATURES_BY_VARIANT,
        IMBALANCE_CONDITION,
        INCIDENT_LABELS,
        RF_COMPARATOR_ID,
        RF_REFINED_PARAMS,
        RF_REFINED_REFERENCE,
        SEARCH_SEED,
        STAGE1_STATUS,
        XGB_STABILITY_SEEDS,
        aggregate_incident_scores,
        compare_with_rf,
        evaluate_config,
        load_stage2_train_data,
        parameter_hash,
        require_xgboost,
        rf_reference_row,
        xgboost_environment,
    )
except ModuleNotFoundError:
    from src.bgp_incident_detection.model_baselines import REGISTRY
    from src.bgp_incident_detection.train_batch_engine import source_commit
    from src.bgp_incident_detection.xgboost_algorithm_comparison import (
        FEATURE_COUNT,
        FEATURE_VARIANT,
        FEATURES_BY_VARIANT,
        IMBALANCE_CONDITION,
        INCIDENT_LABELS,
        RF_COMPARATOR_ID,
        RF_REFINED_PARAMS,
        RF_REFINED_REFERENCE,
        SEARCH_SEED,
        STAGE1_STATUS,
        XGB_STABILITY_SEEDS,
        aggregate_incident_scores,
        compare_with_rf,
        evaluate_config,
        load_stage2_train_data,
        parameter_hash,
        require_xgboost,
        rf_reference_row,
        xgboost_environment,
    )


MODELING_DIR = Path("data/modeling")
LOCAL_RESULTS = MODELING_DIR / "xgb_local_refinement_results_v1.csv"
LOCAL_FOLD_RESULTS = MODELING_DIR / "xgb_local_refinement_fold_results_v1.csv"
LOCAL_PAIRED = MODELING_DIR / "xgb_local_refinement_paired_comparison_v1.csv"
STABILITY_SHORTLIST = MODELING_DIR / "xgb_stability_shortlist_v1.csv"
MULTISEED_RESULTS = MODELING_DIR / "xgb_multiseed_stability_results_v2.csv"
MULTISEED_SEED_RESULTS = MODELING_DIR / "xgb_multiseed_seed_results_v2.csv"
MULTISEED_FOLD_RESULTS = MODELING_DIR / "xgb_multiseed_fold_results_v2.csv"
SEED_SENSITIVITY = MODELING_DIR / "xgb_seed_sensitivity_v1.csv"
I2_FINAL_COMPARISON = MODELING_DIR / "xgb_i2_final_comparison_v1.csv"
I2_VS_RF = MODELING_DIR / "xgb_i2_vs_refined_rf_v1.csv"
REFINED_CONFIG = Path("config/final_model_candidate_v3_1_xgb_refined.yaml")
VALIDATION_PROTOCOL_V4 = Path("config/validation_confirmation_protocol_v4.yaml")
NOTEBOOK = Path("notebooks/50_xgboost_local_refinement_and_stability.ipynb")

PHASE_I_WINNER_ID = "PHASE_I_XGB_WINNER"
PHASE_I_SELECTED_ID = "XGB_TUNED_TRAIN_CANDIDATE_V1"
I2_SELECTED_ID = "XGB_REFINED_TRAIN_CANDIDATE"
LOCAL_SEARCH_BUDGET = 25
MAX_STABILITY_SHORTLIST = 5

PHASE_I_WINNER_PARAMS = {
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

LOCAL_PARAMETER_SPACE = {
    "n_estimators": [300, 400, 500, 600, 800],
    "max_depth": [4, 5, 6, 7, 8],
    "learning_rate": [0.05, 0.075, 0.10, 0.125],
    "subsample": [0.8, 0.9, 1.0],
    "colsample_bytree": [0.8, 0.9, 1.0],
    "min_child_weight": [1, 2, 3],
    "gamma": [0, 0.05, 0.1, 0.2],
    "reg_alpha": [0, 0.01, 0.05, 0.1],
    "reg_lambda": [0.5, 1.0, 1.5, 2.0],
}


def local_parameter_candidates(budget: int = LOCAL_SEARCH_BUDGET, seed: int = SEARCH_SEED) -> list[dict[str, Any]]:
    if budget > LOCAL_SEARCH_BUDGET:
        raise ValueError("Phase I2 local search budget cannot exceed 25")
    candidates = [PHASE_I_WINNER_PARAMS.copy()]
    seen = {parameter_hash(PHASE_I_WINNER_PARAMS)}
    sampler = ParameterSampler(LOCAL_PARAMETER_SPACE, n_iter=budget * 4, random_state=seed)
    for params in sampler:
        normalized = dict(params)
        h = parameter_hash(normalized)
        if h in seen:
            continue
        candidates.append(normalized)
        seen.add(h)
        if len(candidates) == budget:
            break
    if len(candidates) != budget:
        raise RuntimeError(f"unable to build fixed Phase I2 local budget: {len(candidates)} != {budget}")
    return candidates


def run_local_refinement(data: pd.DataFrame, local_budget: int = LOCAL_SEARCH_BUDGET) -> tuple[pd.DataFrame, pd.DataFrame]:
    results = pd.read_csv(LOCAL_RESULTS).to_dict("records") if LOCAL_RESULTS.exists() else []
    folds = pd.read_csv(LOCAL_FOLD_RESULTS).to_dict("records") if LOCAL_FOLD_RESULTS.exists() else []
    completed = {row["candidate_id"] for row in results}
    for idx, params in enumerate(local_parameter_candidates(local_budget, SEARCH_SEED)):
        candidate_id = PHASE_I_WINNER_ID if idx == 0 else f"PHASEI2_XGB_LOCAL_{idx:03d}"
        if candidate_id in completed:
            print(f"XGBoost I2 local {idx + 1}/{local_budget}: {candidate_id} already complete", flush=True)
            continue
        print(f"XGBoost I2 local {idx + 1}/{local_budget}: {candidate_id} {parameter_hash(params)}", flush=True)
        result, fold_rows = evaluate_config(data, candidate_id, params, SEARCH_SEED)
        results.append(result)
        folds.extend(fold_rows)
        pd.DataFrame(results).to_csv(LOCAL_RESULTS, index=False)
        pd.DataFrame(folds).to_csv(LOCAL_FOLD_RESULTS, index=False)
        completed.add(candidate_id)
    results_df = pd.DataFrame(results)
    folds_df = pd.DataFrame(folds)
    return results_df, folds_df


def paired_against_phase_i(results: pd.DataFrame, folds: pd.DataFrame) -> pd.DataFrame:
    base = results[results["candidate_id"].eq(PHASE_I_WINNER_ID)].iloc[0]
    base_folds = folds[folds["candidate_id"].eq(PHASE_I_WINNER_ID)].set_index("fold")
    rows = []
    for _, row in results.iterrows():
        candidate_folds = folds[folds["candidate_id"].eq(row["candidate_id"])].set_index("fold")
        deltas = candidate_folds["incident_macro_f1"] - base_folds["incident_macro_f1"]
        rows.append(
            {
                "candidate_id": row["candidate_id"],
                "parameter_hash": row["parameter_hash"],
                "incident_macro_f1_delta": row["incident_macro_f1"] - base["incident_macro_f1"],
                "incident_mrr_delta": row["incident_mrr"] - base["incident_mrr"],
                "incident_top1_delta": row["incident_top1"] - base["incident_top1"],
                "incident_top2_delta": row["incident_top2"] - base["incident_top2"],
                "hijack_f1_delta": row["incident_hijack_f1"] - base["incident_hijack_f1"],
                "leak_f1_delta": row["incident_leak_f1"] - base["incident_leak_f1"],
                "outage_f1_delta": row["incident_outage_f1"] - base["incident_outage_f1"],
                "window_macro_f1_delta": row["window_macro_f1"] - base["window_macro_f1"],
                "folds_improved": int((deltas > 0).sum()),
                "folds_declined": int((deltas < 0).sum()),
                "mean_fold_delta": float(deltas.mean()),
                "std_fold_delta": float(deltas.std(ddof=0)),
                "min_fold_delta": float(deltas.min()),
                "max_fold_delta": float(deltas.max()),
            }
        )
    return pd.DataFrame(rows)


def shortlist_configs(results: pd.DataFrame, paired: pd.DataFrame, max_count: int = MAX_STABILITY_SHORTLIST) -> pd.DataFrame:
    merged = results.merge(paired, on=["candidate_id", "parameter_hash"], how="left")
    phase_i = merged[merged["candidate_id"].eq(PHASE_I_WINNER_ID)]
    best = merged.sort_values(
        ["incident_macro_f1", "incident_mrr", "incident_top2", "incident_macro_f1_fold_std", "fit_time_seconds"],
        ascending=[False, False, False, True, True],
    ).head(1)
    efficient = merged.sort_values(
        ["incident_macro_f1", "fit_time_seconds", "incident_macro_f1_fold_std"],
        ascending=[False, True, True],
    ).head(max_count + 4)
    combined = pd.concat([phase_i, best, efficient], ignore_index=True).drop_duplicates("candidate_id", keep="first")
    combined = combined.sort_values(
        ["candidate_id"],
        key=lambda col: col.map(lambda value: 0 if value == PHASE_I_WINNER_ID else 1),
    ).head(max_count)
    combined = combined.copy()
    combined["shortlist_rank"] = range(1, len(combined) + 1)
    combined["stability_role"] = combined["candidate_id"].map(
        lambda value: "ORIGINAL_PHASE_I_WINNER" if value == PHASE_I_WINNER_ID else "LOCAL_REFINEMENT_CANDIDATE"
    )
    combined["rationale"] = combined.apply(shortlist_rationale, axis=1)
    return combined


def shortlist_rationale(row: pd.Series) -> str:
    if row["candidate_id"] == PHASE_I_WINNER_ID:
        return "Original Phase I winner included as required stability anchor."
    if row["incident_macro_f1_delta"] >= 0.005:
        return "Local candidate improves incident Macro F1 enough to justify stability testing."
    return "Local candidate provides a possible performance/runtime/stability tradeoff."


def run_stability(data: pd.DataFrame, shortlist: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    seed_rows = pd.read_csv(MULTISEED_SEED_RESULTS).to_dict("records") if MULTISEED_SEED_RESULTS.exists() else []
    fold_rows = pd.read_csv(MULTISEED_FOLD_RESULTS).to_dict("records") if MULTISEED_FOLD_RESULTS.exists() else []
    local_results = pd.read_csv(LOCAL_RESULTS) if LOCAL_RESULTS.exists() else pd.DataFrame()
    local_folds = pd.read_csv(LOCAL_FOLD_RESULTS) if LOCAL_FOLD_RESULTS.exists() else pd.DataFrame()
    for _, row in shortlist.iterrows():
        params = json.loads(row["parameters_json"])
        for seed in XGB_STABILITY_SEEDS:
            if any(existing["candidate_id"] == row["candidate_id"] and int(existing["xgb_seed"]) == seed for existing in seed_rows):
                print(f"XGBoost I2 stability {row['candidate_id']} seed={seed} already complete", flush=True)
                continue
            if seed == SEARCH_SEED and not local_results.empty:
                local_match = local_results[local_results["candidate_id"].eq(row["candidate_id"])]
                local_fold_match = local_folds[local_folds["candidate_id"].eq(row["candidate_id"])]
                if len(local_match) == 1 and len(local_fold_match) == 5:
                    print(f"XGBoost I2 stability {row['candidate_id']} seed={seed} reused from local refinement", flush=True)
                    seed_rows.append(local_match.iloc[0].to_dict())
                    fold_rows.extend(local_fold_match.to_dict("records"))
                    pd.DataFrame(seed_rows).to_csv(MULTISEED_SEED_RESULTS, index=False)
                    pd.DataFrame(fold_rows).to_csv(MULTISEED_FOLD_RESULTS, index=False)
                    continue
            print(f"XGBoost I2 stability {row['candidate_id']} seed={seed}", flush=True)
            result, folds = evaluate_config(data, row["candidate_id"], params, seed)
            seed_rows.append(result)
            fold_rows.extend(folds)
            pd.DataFrame(seed_rows).to_csv(MULTISEED_SEED_RESULTS, index=False)
            pd.DataFrame(fold_rows).to_csv(MULTISEED_FOLD_RESULTS, index=False)
    seed_df = pd.DataFrame(seed_rows)
    fold_df = pd.DataFrame(fold_rows)
    stability = stability_summary(seed_df, fold_df, shortlist)
    return stability, seed_df, fold_df


def is_deterministic(params: dict[str, Any], macro_std: float) -> bool:
    return bool(params.get("subsample") == 1.0 and params.get("colsample_bytree") == 1.0 and macro_std < 1e-12)


def stability_summary(seed_rows: pd.DataFrame, fold_rows: pd.DataFrame, shortlist: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for candidate_id, group in seed_rows.groupby("candidate_id"):
        folds = fold_rows[fold_rows["candidate_id"].eq(candidate_id)]
        params = json.loads(group["parameters_json"].iloc[0])
        macro_std = group["incident_macro_f1"].std(ddof=0)
        rows.append(
            {
                "candidate_id": candidate_id,
                "parameter_hash": group["parameter_hash"].iloc[0],
                "parameters_json": group["parameters_json"].iloc[0],
                "stability_seeds": json.dumps(XGB_STABILITY_SEEDS),
                "mean_incident_macro_f1": group["incident_macro_f1"].mean(),
                "std_incident_macro_f1": macro_std,
                "min_incident_macro_f1": group["incident_macro_f1"].min(),
                "max_incident_macro_f1": group["incident_macro_f1"].max(),
                "mean_top1": group["incident_top1"].mean(),
                "mean_top2": group["incident_top2"].mean(),
                "mean_mrr": group["incident_mrr"].mean(),
                "std_mrr": group["incident_mrr"].std(ddof=0),
                "hijack_f1_mean": group["incident_hijack_f1"].mean(),
                "hijack_f1_std": group["incident_hijack_f1"].std(ddof=0),
                "leak_f1_mean": group["incident_leak_f1"].mean(),
                "leak_f1_std": group["incident_leak_f1"].std(ddof=0),
                "outage_f1_mean": group["incident_outage_f1"].mean(),
                "outage_f1_std": group["incident_outage_f1"].std(ddof=0),
                "window_macro_f1_mean": group["window_macro_f1"].mean(),
                "window_macro_f1_std": group["window_macro_f1"].std(ddof=0),
                "mean_true_class_rank": group["mean_true_class_rank"].mean(),
                "fold_seed_incident_macro_f1_std": folds["incident_macro_f1"].std(ddof=0),
                "mean_fit_time_seconds": group["fit_time_seconds"].mean(),
                "mean_inference_time_seconds": group["inference_time_seconds"].mean(),
                "deterministic_status": "DETERMINISTIC_UNDER_EVALUATED_CONFIGURATION" if is_deterministic(params, macro_std) else "STOCHASTIC_OR_SEED_SENSITIVE",
            }
        )
    return pd.DataFrame(rows).merge(shortlist[["candidate_id", "shortlist_rank", "stability_role"]], on="candidate_id", how="left")


def seed_sensitivity(seed_rows: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for candidate_id, group in seed_rows.groupby("candidate_id"):
        params = json.loads(group["parameters_json"].iloc[0])
        best = group.sort_values("incident_macro_f1", ascending=False).iloc[0]
        worst = group.sort_values("incident_macro_f1", ascending=True).iloc[0]
        macro_range = group["incident_macro_f1"].max() - group["incident_macro_f1"].min()
        rows.append(
            {
                "candidate_id": candidate_id,
                "parameter_hash": group["parameter_hash"].iloc[0],
                "configuration": group["parameters_json"].iloc[0],
                "best_seed": int(best["xgb_seed"]),
                "worst_seed": int(worst["xgb_seed"]),
                "macro_f1_range": macro_range,
                "mrr_range": group["incident_mrr"].max() - group["incident_mrr"].min(),
                "top2_range": group["incident_top2"].max() - group["incident_top2"].min(),
                "deterministic": is_deterministic(params, group["incident_macro_f1"].std(ddof=0)),
                "deterministic_note": "DETERMINISTIC_UNDER_EVALUATED_CONFIGURATION" if is_deterministic(params, group["incident_macro_f1"].std(ddof=0)) else "",
            }
        )
    return pd.DataFrame(rows)


def select_i2_candidate(stability: pd.DataFrame) -> tuple[pd.Series, str, str]:
    phase_i = stability[stability["candidate_id"].eq(PHASE_I_WINNER_ID)].iloc[0]
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
    best = scored.sort_values(["selection_score", "mean_incident_macro_f1"], ascending=False).iloc[0]
    macro_delta = best["mean_incident_macro_f1"] - phase_i["mean_incident_macro_f1"]
    mrr_delta = best["mean_mrr"] - phase_i["mean_mrr"]
    top2_delta = best["mean_top2"] - phase_i["mean_top2"]
    min_class_delta = min(
        best["hijack_f1_mean"] - phase_i["hijack_f1_mean"],
        best["leak_f1_mean"] - phase_i["leak_f1_mean"],
        best["outage_f1_mean"] - phase_i["outage_f1_mean"],
    )
    runtime_ratio = best["mean_fit_time_seconds"] / max(float(phase_i["mean_fit_time_seconds"]), 1.0)
    if best["candidate_id"] != PHASE_I_WINNER_ID and macro_delta >= 0.01 and mrr_delta >= -0.002 and top2_delta >= -0.005 and min_class_delta >= -0.01:
        return best, "MEANINGFUL_REFINEMENT", "PROMOTE_PHASE_I2_XGB"
    if best["candidate_id"] != PHASE_I_WINNER_ID and macro_delta >= 0.003 and mrr_delta >= -0.003 and top2_delta >= -0.005 and min_class_delta >= -0.015 and runtime_ratio <= 1.75:
        return best, "MARGINAL_REFINEMENT", "PROMOTE_PHASE_I2_XGB"
    return phase_i, "NO_MEANINGFUL_IMPROVEMENT", "KEEP_PHASE_I_XGB"


def final_i2_comparison(stability: pd.DataFrame, selected: pd.Series, classification: str, recommendation: str) -> pd.DataFrame:
    phase_i = stability[stability["candidate_id"].eq(PHASE_I_WINNER_ID)].iloc[0]
    rows = []
    for label, row in [("Phase I winner", phase_i), ("Phase I2 selected candidate", selected)]:
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
                "mean_true_class_rank": row["mean_true_class_rank"],
                "runtime_seconds": row["mean_fit_time_seconds"],
                "inference_time_seconds": row["mean_inference_time_seconds"],
                "relative_runtime_vs_phase_i": row["mean_fit_time_seconds"] / max(float(phase_i["mean_fit_time_seconds"]), 1.0),
                "deterministic_status": row["deterministic_status"],
                "refinement_classification": classification,
                "recommendation": recommendation,
            }
        )
    return pd.DataFrame(rows)


def i2_vs_rf(selected: pd.Series) -> pd.DataFrame:
    rf_ref = rf_reference_row() if Path("data/modeling/rf_multiseed_stability_results_v1.csv").exists() else RF_REFINED_REFERENCE
    rows = [
        {
            "algorithm": "RandomForest",
            "configuration": RF_COMPARATOR_ID,
            "incident_macro_f1": rf_ref["incident_macro_f1"],
            "incident_top1": rf_ref["top1"],
            "incident_top2": rf_ref["top2"],
            "incident_mrr": rf_ref["mrr"],
            "hijack_f1": rf_ref["hijack_f1"],
            "leak_f1": rf_ref["leak_f1"],
            "outage_f1": rf_ref["outage_f1"],
            "window_macro_f1": rf_ref["window_macro_f1"],
            "fit_time_seconds": rf_ref["fit_time"],
            "inference_time_seconds": rf_ref["inference_time"],
        },
        {
            "algorithm": "XGBoost",
            "configuration": I2_SELECTED_ID,
            "incident_macro_f1": selected["mean_incident_macro_f1"],
            "incident_top1": selected["mean_top1"],
            "incident_top2": selected["mean_top2"],
            "incident_mrr": selected["mean_mrr"],
            "hijack_f1": selected["hijack_f1_mean"],
            "leak_f1": selected["leak_f1_mean"],
            "outage_f1": selected["outage_f1_mean"],
            "window_macro_f1": selected["window_macro_f1_mean"],
            "fit_time_seconds": selected["mean_fit_time_seconds"],
            "inference_time_seconds": selected["mean_inference_time_seconds"],
        },
    ]
    out = pd.DataFrame(rows)
    xgb_row = out[out["algorithm"].eq("XGBoost")].iloc[0]
    rf_row = out[out["algorithm"].eq("RandomForest")].iloc[0]
    delta_row = {"algorithm": "DELTA_XGB_MINUS_RF", "configuration": "Phase I2 confirmatory comparison"}
    for col in out.select_dtypes(include=[np.number]).columns:
        delta_row[col] = xgb_row[col] - rf_row[col]
    return pd.concat([out, pd.DataFrame([delta_row])], ignore_index=True, sort=False)


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


def write_refined_config(selected: pd.Series, classification: str, recommendation: str) -> None:
    params = json.loads(selected["parameters_json"])
    env = xgboost_environment().iloc[0]
    write_yaml(
        REFINED_CONFIG,
        {
            "candidate_id": I2_SELECTED_ID,
            "status": "XGB_REFINED_TRAIN_CANDIDATE",
            "recommendation": recommendation,
            "refinement_classification": classification,
            "selected_source_candidate_id": selected["candidate_id"],
            "xgboost_version": env["version"],
            "selected_hyperparameters": params,
            "objective": "multi:softprob",
            "num_class": len(INCIDENT_LABELS),
            "eval_metric": "mlogloss",
            "feature_variant": FEATURE_VARIANT,
            "feature_count": FEATURE_COUNT,
            "feature_schema_version": "V4 frozen 74-feature Behavioral + CAIDA + RPKI schema",
            "imbalance_condition": IMBALANCE_CONDITION,
            "weighting": "I1 incident-aware sample weights computed from training rows only in each fold",
            "seed_policy": {
                "local_search_seed": SEARCH_SEED,
                "stability_seeds": XGB_STABILITY_SEEDS,
                "fold_assignments": "data/modeling/baseline_v1_grouped_cv_assignments_v1.csv",
            },
            "grouped_fold_semantics": "Existing grouped folds reused; no incident crosses TRAIN/test folds.",
            "incident_aggregation": "mean class probability across all eligible windows for each incident",
            "ranking_rule": "sort P(Hijack), P(Leak), P(Outage) descending",
            "train_multiseed_results": {
                "mean_incident_macro_f1": float(selected["mean_incident_macro_f1"]),
                "std_incident_macro_f1": float(selected["std_incident_macro_f1"]),
                "mean_top1": float(selected["mean_top1"]),
                "mean_top2": float(selected["mean_top2"]),
                "mean_mrr": float(selected["mean_mrr"]),
                "hijack_f1_mean": float(selected["hijack_f1_mean"]),
                "leak_f1_mean": float(selected["leak_f1_mean"]),
                "outage_f1_mean": float(selected["outage_f1_mean"]),
                "window_macro_f1_mean": float(selected["window_macro_f1_mean"]),
                "mean_fit_time_seconds": float(selected["mean_fit_time_seconds"]),
                "mean_inference_time_seconds": float(selected["mean_inference_time_seconds"]),
                "deterministic_status": selected["deterministic_status"],
            },
            "stage1_status": STAGE1_STATUS,
            "validation_accessed": False,
            "final_holdout_accessed": False,
            "source_commit": source_commit(),
        },
    )
    write_yaml(
        VALIDATION_PROTOCOL_V4,
        {
            "protocol_id": "validation_confirmation_protocol_v4",
            "selected_candidate_config": str(REFINED_CONFIG),
            "selected_candidate": I2_SELECTED_ID,
            "selected_algorithm": "XGBoost",
            "purpose": "single predeclared Validation confirmation of the one selected XGBoost candidate",
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
            "stage1_status": STAGE1_STATUS,
            "validation_accessed": False,
            "final_holdout_accessed": False,
            "source_commit": source_commit(),
        },
    )


def update_registry(local_results: pd.DataFrame, stability: pd.DataFrame, recommendation: str) -> None:
    existing = pd.read_csv(REGISTRY, dtype=str).fillna("") if REGISTRY.exists() else pd.DataFrame()
    rows = []
    for _, row in local_results.iterrows():
        rows.append(
            {
                "experiment_id": f"PHASEI2_XGB_LOCAL_{row['candidate_id']}_{row['parameter_hash']}",
                "phase": "I2",
                "model": "XGBClassifier",
                "architecture": "MULTICLASS_STAGE2",
                "feature_variant": FEATURE_VARIANT,
                "feature_count": str(FEATURE_COUNT),
                "imbalance_condition": IMBALANCE_CONDITION,
                "parameter_hash": row["parameter_hash"],
                "parameters_json": row["parameters_json"],
                "seed": str(SEARCH_SEED),
                "status": "COMPLETED",
                "result_artifact": str(LOCAL_RESULTS),
                "source_commit": source_commit(),
            }
        )
    for _, row in stability.iterrows():
        rows.append(
            {
                "experiment_id": f"PHASEI2_XGB_MULTI_SEED_{row['candidate_id']}_{row['parameter_hash']}",
                "phase": "I2",
                "model": "XGBClassifier",
                "architecture": "MULTICLASS_STAGE2",
                "feature_variant": FEATURE_VARIANT,
                "feature_count": str(FEATURE_COUNT),
                "imbalance_condition": IMBALANCE_CONDITION,
                "parameter_hash": row["parameter_hash"],
                "parameters_json": row["parameters_json"],
                "seed": json.dumps(XGB_STABILITY_SEEDS),
                "status": "COMPLETED",
                "result_artifact": str(MULTISEED_RESULTS),
                "source_commit": source_commit(),
            }
        )
    rows.append(
        {
            "experiment_id": "PHASEI2_XGB_FINAL_SELECTION",
            "phase": "I2",
            "model": "XGBClassifier",
            "architecture": "MULTICLASS_STAGE2",
            "feature_variant": FEATURE_VARIANT,
            "feature_count": str(FEATURE_COUNT),
            "imbalance_condition": IMBALANCE_CONDITION,
            "seed": json.dumps(XGB_STABILITY_SEEDS),
            "status": recommendation,
            "result_artifact": str(I2_FINAL_COMPARISON),
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
                    "# Phase I2 - XGBoost Local Refinement and Multi-Seed Stability\n",
                    "\n",
                    "TRAIN-only local refinement around the Phase I XGBoost winner. Validation and Final Holdout remain sealed.\n",
                ],
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": ["from bgp_incident_detection.xgboost_refinement_stability import run_phase_i2\n", "# run_phase_i2()\n"],
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": ["import pandas as pd\n", "pd.read_csv('../data/modeling/xgb_i2_final_comparison_v1.csv')\n"],
            },
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def run_phase_i2(local_budget: int = LOCAL_SEARCH_BUDGET) -> dict[str, Any]:
    require_xgboost()
    MODELING_DIR.mkdir(parents=True, exist_ok=True)
    data = load_stage2_train_data()
    local_results, local_folds = run_local_refinement(data, local_budget)
    local_results = local_results.sort_values(
        ["incident_macro_f1", "incident_mrr", "incident_top2", "incident_macro_f1_fold_std", "fit_time_seconds"],
        ascending=[False, False, False, True, True],
    )
    local_results.to_csv(LOCAL_RESULTS, index=False)
    local_folds.to_csv(LOCAL_FOLD_RESULTS, index=False)
    paired = paired_against_phase_i(local_results, local_folds)
    paired.to_csv(LOCAL_PAIRED, index=False)
    shortlist = shortlist_configs(local_results, paired)
    shortlist.to_csv(STABILITY_SHORTLIST, index=False)
    stability, seed_df, fold_df = run_stability(data, shortlist)
    stability = stability.sort_values(
        ["mean_incident_macro_f1", "mean_mrr", "mean_top2", "std_incident_macro_f1", "mean_fit_time_seconds"],
        ascending=[False, False, False, True, True],
    )
    selected, classification, recommendation = select_i2_candidate(stability)
    stability.to_csv(MULTISEED_RESULTS, index=False)
    seed_df.to_csv(MULTISEED_SEED_RESULTS, index=False)
    fold_df.to_csv(MULTISEED_FOLD_RESULTS, index=False)
    sensitivity = seed_sensitivity(seed_df)
    sensitivity.to_csv(SEED_SENSITIVITY, index=False)
    final = final_i2_comparison(stability, selected, classification, recommendation)
    final.to_csv(I2_FINAL_COMPARISON, index=False)
    i2_vs_rf(selected).to_csv(I2_VS_RF, index=False)
    write_refined_config(selected, classification, recommendation)
    update_registry(local_results, stability, recommendation)
    write_notebook()
    return {
        "local_configurations_evaluated": int(local_results["candidate_id"].nunique()),
        "best_single_seed_candidate": str(local_results.iloc[0]["candidate_id"]),
        "stability_configurations": shortlist["candidate_id"].tolist(),
        "stability_seeds": XGB_STABILITY_SEEDS,
        "selected_candidate_id": str(selected["candidate_id"]),
        "recommendation": recommendation,
        "refinement_classification": classification,
        "mean_incident_macro_f1": float(selected["mean_incident_macro_f1"]),
        "std_incident_macro_f1": float(selected["std_incident_macro_f1"]),
        "mean_mrr": float(selected["mean_mrr"]),
        "mean_top2": float(selected["mean_top2"]),
        "validation_accessed": False,
        "final_holdout_accessed": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Phase I2 TRAIN-only XGBoost local refinement and stability analysis")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--local-budget", type=int, default=LOCAL_SEARCH_BUDGET)
    args = parser.parse_args()
    if args.run:
        print(json.dumps(run_phase_i2(args.local_budget), indent=2, sort_keys=True))
        return
    parser.error("choose --run")


if __name__ == "__main__":
    main()
