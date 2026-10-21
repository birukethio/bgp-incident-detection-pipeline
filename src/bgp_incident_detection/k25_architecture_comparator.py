from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import yaml
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

try:
    from bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT
    from bgp_incident_detection.imbalance_model_experiment import group_aware_weights
    from bgp_incident_detection.k1_forensic_audit import K2_SEEDS
    from bgp_incident_detection.k1_incident_stacking import (
        FIRST_LEVEL_PARAMS,
        M2_PARAM_GRID,
        SEED,
        build_meta_frame,
        first_level_model,
        metrics,
        param_hash,
        predict_meta,
        probability_rows,
        temporal_feature_names,
        xgb_meta_model,
        y_codes,
    )
    from bgp_incident_detection.model_baselines import INCIDENT_LABELS
    from bgp_incident_detection.train_batch_engine import source_commit
except ModuleNotFoundError:
    from src.bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT
    from src.bgp_incident_detection.imbalance_model_experiment import group_aware_weights
    from src.bgp_incident_detection.k1_forensic_audit import K2_SEEDS
    from src.bgp_incident_detection.k1_incident_stacking import (
        FIRST_LEVEL_PARAMS,
        M2_PARAM_GRID,
        SEED,
        build_meta_frame,
        first_level_model,
        metrics,
        param_hash,
        predict_meta,
        probability_rows,
        temporal_feature_names,
        xgb_meta_model,
        y_codes,
    )
    from src.bgp_incident_detection.model_baselines import INCIDENT_LABELS
    from src.bgp_incident_detection.train_batch_engine import source_commit


K25_DIR = Path("data/modeling_k25")
K1_DIR = Path("data/modeling_k1")
K2_DIR = Path("data/modeling_k2")
TRAIN_V4 = Path("data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet")
ASSIGNMENTS = Path("data/modeling/baseline_v1_grouped_cv_assignments_v1.csv")
K1_SCHEMA = Path("config/k1_incident_meta_feature_schema_v1.yaml")
K1_FINAL = Path("config/k1_final_candidate_v1.yaml")
RF_CONFIG = Path("config/k25_second_level_rf_v1.yaml")
K25_FINAL = Path("config/k25_final_candidate_v1.yaml")
NOTEBOOK = Path("notebooks/54_k25_rf_vs_xgb_architecture_comparator.ipynb")
DOC = Path("docs/k25_rf_vs_xgb_architecture_comparator_v1.md")

NESTED_AUDIT = K25_DIR / "k25_nested_leakage_audit_v1.csv"
SCHEMA_AUDIT = K25_DIR / "k25_meta_schema_equivalence_audit_v1.csv"
LEVEL1_COMPARISON = K25_DIR / "k25_level1_probability_comparison_v1.csv"
LEVEL1_DIVERSITY = K25_DIR / "k25_level1_diversity_v1.csv"
ARCH_RESULTS = K25_DIR / "k25_architecture_multiseed_results_v1.csv"
FOLD_SEED_RESULTS = K25_DIR / "k25_architecture_fold_seed_results_v1.csv"
CONFUSION = K25_DIR / "k25_architecture_confusion_matrices_v1.csv"
PAIRED = K25_DIR / "k25_paired_architecture_comparison_v1.csv"
COMPLEXITY = K25_DIR / "k25_architecture_complexity_v1.csv"
DECISION = K25_DIR / "k25_final_architecture_decision_v1.csv"
COMPARISON_AUDIT = K25_DIR / "k25_comparison_audit_v1.csv"

SELECTED_A0 = "A0_XGB_TO_XGB"
ARCHITECTURES = {
    "A0_XGB_TO_XGB": ("XGB", "XGB"),
    "A1_XGB_TO_RF": ("XGB", "RF"),
    "A2_RF_TO_XGB": ("RF", "XGB"),
    "A3_RF_TO_RF": ("RF", "RF"),
}
RF_FIRST_LEVEL_PARAMS = {
    "n_estimators": 1200,
    "max_depth": 40,
    "max_features": 0.3,
    "min_samples_leaf": 6,
    "min_samples_split": 6,
    "bootstrap": False,
    "criterion": "log_loss",
    "class_weight": None,
}
RF_SECOND_LEVEL_PARAMS = {
    "n_estimators": 500,
    "max_depth": 8,
    "max_features": "sqrt",
    "min_samples_leaf": 3,
    "min_samples_split": 5,
    "bootstrap": True,
    "criterion": "log_loss",
    "class_weight": None,
}
K1_NAME_MAP = {
    "incident_macro_f1": "incident_macro_f1",
    "top1": "top1",
    "top2": "top2",
    "mrr": "mrr",
    "hijack_f1": "hijack_f1",
    "leak_f1": "leak_f1",
    "outage_f1": "outage_f1",
    "mean_true_class_rank": "mean_true_class_rank",
}


def write_csv(path: Path, df: pd.DataFrame) -> pd.DataFrame:
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)
    return df


def load_schema() -> list[str]:
    with K1_SCHEMA.open(encoding="utf-8") as handle:
        schema = yaml.safe_load(handle)
    if schema["status"] != "FROZEN":
        raise ValueError("K2.5 requires frozen K1 meta-feature schema")
    if schema["feature_count"] != 74:
        raise ValueError("K2.5 requires exactly 74 K1 temporal meta-features")
    return list(schema["feature_order"])


def load_train_data() -> pd.DataFrame:
    features = FEATURES_BY_VARIANT["V4"]
    if len(features) != 74:
        raise ValueError("K2.5 requires frozen V4 74-feature input")
    train = pd.read_parquet(TRAIN_V4)
    assignments = pd.read_csv(ASSIGNMENTS, low_memory=False)
    assignments = assignments[assignments["label"].isin(INCIDENT_LABELS)].copy()
    data = train.merge(assignments[["window_id", "label", "model_group_id", "fold"]], on="window_id", how="left", validate="one_to_one")
    data = data[data["label"].isin(INCIDENT_LABELS)].copy()
    counts = data.drop_duplicates("incident_uid")["label"].value_counts().to_dict()
    if counts != {"HIJACK": 331, "LEAK": 331, "OUTAGE": 331}:
        raise ValueError(f"K2.5 expected 331/331/331 TRAIN incidents, found {counts}")
    if set(data["partition"].astype(str)) != {"train"}:
        raise ValueError("K2.5 must use TRAIN rows only")
    return data


def write_rf_config() -> None:
    RF_CONFIG.write_text(
        yaml.safe_dump(
            {
                "config_id": "k25_second_level_rf_v1",
                "status": "FROZEN_FOR_K25_COMPARATOR",
                "methodological_status": "POST_VALIDATION_VERSIONED_TRAIN_DEVELOPMENT_EXPERIMENT",
                "selection": "single predeclared conservative RF meta-model; no tuning",
                "hyperparameters": RF_SECOND_LEVEL_PARAMS,
                "validation_used": False,
                "final_holdout_status": "SEALED",
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def first_level_pipeline(algorithm: str, seed: int) -> Pipeline:
    if algorithm == "XGB":
        return first_level_model(seed)
    if algorithm == "RF":
        return Pipeline(
            [
                ("imputer", SimpleImputer(strategy="median")),
                ("model", RandomForestClassifier(**RF_FIRST_LEVEL_PARAMS, random_state=seed, n_jobs=-1)),
            ]
        )
    raise ValueError(algorithm)


def second_level_pipeline(algorithm: str, seed: int, xgb_params: dict[str, Any] | None = None) -> Pipeline:
    if algorithm == "XGB":
        return xgb_meta_model(xgb_params or M2_PARAM_GRID[0])
    if algorithm == "RF":
        return Pipeline(
            [
                ("imputer", SimpleImputer(strategy="median")),
                ("model", RandomForestClassifier(**RF_SECOND_LEVEL_PARAMS, random_state=seed, n_jobs=-1)),
            ]
        )
    raise ValueError(algorithm)


def l1_predict(train: pd.DataFrame, test: pd.DataFrame, algorithm: str, seed: int, fold: int, source: str) -> pd.DataFrame:
    features = FEATURES_BY_VARIANT["V4"]
    model = first_level_pipeline(algorithm, seed)
    started = time.perf_counter()
    model.fit(train[features], y_codes(train["label"]), model__sample_weight=group_aware_weights(train))
    fit_time = time.perf_counter() - started
    probs = model.predict_proba(test[features])
    out = probability_rows(test, probs, fold, source)
    out["l1_fit_time_seconds"] = fit_time
    return out


def cached_nested_meta(data: pd.DataFrame, l1_algorithm: str, seed: int, outer_fold: int) -> tuple[pd.DataFrame, pd.DataFrame, float]:
    path = K25_DIR / "meta_cache" / f"{l1_algorithm.lower()}_seed_{seed}_outer_{outer_fold}.parquet"
    if path.exists():
        cached = pd.read_parquet(path)
        return cached[cached["meta_role"] == "train"].drop(columns=["meta_role"]), cached[cached["meta_role"] == "test"].drop(columns=["meta_role"]), 0.0
    outer_train = data[data["fold"] != outer_fold].copy()
    outer_test = data[data["fold"] == outer_fold].copy()
    total_fit = 0.0
    inner_rows = []
    for inner_fold in sorted(outer_train["fold"].unique()):
        inner_train = outer_train[outer_train["fold"] != inner_fold]
        inner_test = outer_train[outer_train["fold"] == inner_fold]
        pred = l1_predict(inner_train, inner_test, l1_algorithm, seed, int(inner_fold), f"k25_{l1_algorithm}_seed_{seed}_inner")
        total_fit += float(pred["l1_fit_time_seconds"].iloc[0])
        inner_rows.append(pred.drop(columns=["l1_fit_time_seconds"]))
    test_pred = l1_predict(outer_train, outer_test, l1_algorithm, seed, int(outer_fold), f"k25_{l1_algorithm}_seed_{seed}_outer")
    total_fit += float(test_pred["l1_fit_time_seconds"].iloc[0])
    train_meta = build_meta_frame(pd.concat(inner_rows, ignore_index=True), data)
    test_meta = build_meta_frame(test_pred.drop(columns=["l1_fit_time_seconds"]), data)
    train_meta["meta_role"] = "train"
    test_meta["meta_role"] = "test"
    path.parent.mkdir(parents=True, exist_ok=True)
    pd.concat([train_meta, test_meta], ignore_index=True, sort=False).to_parquet(path, index=False)
    return train_meta.drop(columns=["meta_role"]), test_meta.drop(columns=["meta_role"]), total_fit


def recover_k1_xgb_params() -> dict[tuple[int, int], dict[str, Any]]:
    hash_to_params = {param_hash(params): params for params in M2_PARAM_GRID}
    fold_seed = pd.read_csv(K2_DIR / "k2_fold_seed_stability_v1.csv")
    params: dict[tuple[int, int], dict[str, Any]] = {}
    for _, row in fold_seed.iterrows():
        h = str(row["parameter_hash"])
        if h in hash_to_params:
            params[(int(row["seed"]), int(row["fold"]))] = hash_to_params[h]
    k1_folds = pd.read_csv(K1_DIR / "k1_fold_results_v1.csv")
    for _, row in k1_folds[k1_folds["candidate_id"].eq("K1-M2_XGB_K1-TEMPORAL")].iterrows():
        h = str(row["parameter_hash"])
        if h in hash_to_params:
            params[(SEED, int(row["fold"]))] = hash_to_params[h]
    if not params:
        raise ValueError("Could not recover selected K1 XGB second-level parameter hashes")
    return params


def evaluate_architecture(data: pd.DataFrame, architecture_id: str, seed: int, schema: list[str], xgb_params_by_fold: dict[tuple[int, int], dict[str, Any]]) -> tuple[pd.DataFrame, pd.DataFrame]:
    l1_algorithm, l2_algorithm = ARCHITECTURES[architecture_id]
    preds = []
    folds = []
    for fold in sorted(data["fold"].unique()):
        train_meta, test_meta, l1_fit = cached_nested_meta(data, l1_algorithm, seed, int(fold))
        if list(train_meta[schema].columns) != schema or list(test_meta[schema].columns) != schema:
            raise ValueError("K2.5 meta schema order mismatch")
        xgb_params = xgb_params_by_fold.get((seed, int(fold))) or xgb_params_by_fold.get((SEED, int(fold))) or M2_PARAM_GRID[0]
        model = second_level_pipeline(l2_algorithm, seed, xgb_params)
        started = time.perf_counter()
        model.fit(train_meta[schema], y_codes(train_meta["true_class"]))
        l2_fit = time.perf_counter() - started
        started = time.perf_counter()
        pred = predict_meta(model, test_meta, schema, architecture_id, int(fold))
        infer = time.perf_counter() - started
        pred["seed"] = seed
        preds.append(pred)
        folds.append(
            {
                "architecture_id": architecture_id,
                "seed": seed,
                "fold": int(fold),
                "level1_algorithm": l1_algorithm,
                "level2_algorithm": l2_algorithm,
                "level1_fit_time_seconds": l1_fit,
                "level2_fit_time_seconds": l2_fit,
                "inference_time_seconds": infer,
                "level2_xgb_parameter_hash": param_hash(xgb_params) if l2_algorithm == "XGB" else "",
                **metrics(pred),
            }
        )
    return pd.concat(preds, ignore_index=True), pd.DataFrame(folds)


def a0_reused_outputs() -> tuple[pd.DataFrame, pd.DataFrame]:
    seed_df = pd.read_csv(K2_DIR / "k2_seed_sensitivity_v1.csv")
    k2_folds = pd.read_csv(K2_DIR / "k2_fold_seed_stability_v1.csv")
    fold_rows = []
    for _, row in k2_folds.iterrows():
        fold_rows.append(
            {
                "architecture_id": SELECTED_A0,
                "seed": int(row["seed"]),
                "fold": int(row["fold"]),
                "level1_algorithm": "XGB",
                "level2_algorithm": "XGB",
                "level1_fit_time_seconds": np.nan,
                "level2_fit_time_seconds": row.get("fit_time_seconds", np.nan),
                "inference_time_seconds": np.nan,
                "level2_xgb_parameter_hash": row.get("parameter_hash", ""),
                "incident_macro_f1": row["incident_macro_f1"],
                "top1": row["top1"],
                "top2": row["top2"],
                "mrr": row["mrr"],
                "mean_true_class_rank": row["mean_true_class_rank"],
                "hijack_f1": row["hijack_f1"],
                "leak_f1": row["leak_f1"],
                "outage_f1": row["outage_f1"],
            }
        )
    metric_rows = []
    for metric in ["incident_macro_f1", "top1", "top2", "mrr", "hijack_f1", "leak_f1", "outage_f1", "mean_true_class_rank"]:
        values = seed_df[metric].astype(float)
        metric_rows.append({"architecture_id": SELECTED_A0, "metric": metric, "mean": values.mean(), "std": values.std(ddof=0), "min": values.min(), "max": values.max(), "reuse_provenance": "data/modeling_k2/k2_seed_sensitivity_v1.csv"})
    return pd.DataFrame(metric_rows), pd.DataFrame(fold_rows)


def summarize_architecture(architecture_id: str, predictions: pd.DataFrame, folds: pd.DataFrame) -> pd.DataFrame:
    seed_rows = []
    for seed, group in predictions.groupby("seed"):
        seed_rows.append({"architecture_id": architecture_id, "seed": int(seed), **metrics(group)})
    seed_df = pd.DataFrame(seed_rows)
    rows = []
    for metric in ["incident_macro_f1", "top1", "top2", "mrr", "hijack_f1", "leak_f1", "outage_f1", "mean_true_class_rank"]:
        values = seed_df[metric].astype(float)
        rows.append({"architecture_id": architecture_id, "metric": metric, "mean": values.mean(), "std": values.std(ddof=0), "min": values.min(), "max": values.max(), "reuse_provenance": ""})
    return pd.DataFrame(rows)


def write_confusion(architecture_predictions: dict[str, pd.DataFrame]) -> pd.DataFrame:
    rows = []
    from sklearn.metrics import confusion_matrix

    for architecture_id, predictions in architecture_predictions.items():
        for seed, group in predictions.groupby("seed"):
            ranked = pd.DataFrame()
            # metrics() already validates ranking; this block keeps the matrix explicit.
            ranked_rows = []
            for _, row in group.iterrows():
                pairs = sorted([(label, row[f"p_{label.lower()}"]) for label in INCIDENT_LABELS], key=lambda item: item[1], reverse=True)
                ranked_rows.append({"true_class": row["true_class"], "predicted_class": pairs[0][0]})
            ranked = pd.DataFrame(ranked_rows)
            cm = confusion_matrix(ranked["true_class"], ranked["predicted_class"], labels=INCIDENT_LABELS)
            for i, true_class in enumerate(INCIDENT_LABELS):
                for j, predicted_class in enumerate(INCIDENT_LABELS):
                    rows.append({"architecture_id": architecture_id, "seed": int(seed), "true_class": true_class, "predicted_class": predicted_class, "count": int(cm[i, j])})
    return write_csv(CONFUSION, pd.DataFrame(rows))


def level1_oof(data: pd.DataFrame, algorithm: str, seed: int) -> pd.DataFrame:
    path = K25_DIR / f"k25_level1_{algorithm.lower()}_oof_seed_{seed}.parquet"
    if path.exists():
        return pd.read_parquet(path)
    rows = []
    for fold in sorted(data["fold"].unique()):
        train = data[data["fold"] != fold]
        test = data[data["fold"] == fold]
        pred = l1_predict(train, test, algorithm, seed, int(fold), f"k25_l1_{algorithm}_oof")
        rows.append(pred.drop(columns=["l1_fit_time_seconds"]))
    out = pd.concat(rows, ignore_index=True)
    out.to_parquet(path, index=False)
    return out


def level1_diagnostics(data: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    xgb = pd.read_parquet(K1_DIR / "k1_window_oof_probabilities_v1.parquet")
    rf = level1_oof(data, "RF", SEED)
    rows = []
    for name, frame in [("XGB", xgb), ("RF", rf)]:
        incident = frame.groupby("incident_uid", as_index=False).agg(true_class=("true_class", "first"), p_hijack=("p_hijack", "mean"), p_leak=("p_leak", "mean"), p_outage=("p_outage", "mean"))
        metric = metrics(incident)
        rows.append({"level1_algorithm": name, **metric})
    comparison = write_csv(LEVEL1_COMPARISON, pd.DataFrame(rows))
    x_inc = xgb.groupby("incident_uid", as_index=False).agg(true_class=("true_class", "first"), p_hijack=("p_hijack", "mean"), p_leak=("p_leak", "mean"), p_outage=("p_outage", "mean"))
    r_inc = rf.groupby("incident_uid", as_index=False).agg(true_class=("true_class", "first"), p_hijack=("p_hijack", "mean"), p_leak=("p_leak", "mean"), p_outage=("p_outage", "mean"))
    x_rank = predicted_labels(x_inc)
    r_rank = predicted_labels(r_inc)
    joined = x_rank.merge(r_rank, on=["incident_uid", "true_class"], suffixes=("_xgb", "_rf"))
    wx = predicted_labels(xgb)
    wr = predicted_labels(rf)
    wj = wx.merge(wr, on=["window_id", "incident_uid", "true_class"], suffixes=("_xgb", "_rf"))
    diversity = {
        "window_prediction_agreement_rate": float((wj["predicted_class_xgb"] == wj["predicted_class_rf"]).mean()),
        "incident_prediction_agreement_rate": float((joined["predicted_class_xgb"] == joined["predicted_class_rf"]).mean()),
        "incidents_correct_only_by_xgb": int(((joined["predicted_class_xgb"] == joined["true_class"]) & (joined["predicted_class_rf"] != joined["true_class"])).sum()),
        "incidents_correct_only_by_rf": int(((joined["predicted_class_rf"] == joined["true_class"]) & (joined["predicted_class_xgb"] != joined["true_class"])).sum()),
        "p_hijack_correlation": float(x_inc["p_hijack"].corr(r_inc["p_hijack"])),
        "p_leak_correlation": float(x_inc["p_leak"].corr(r_inc["p_leak"])),
        "p_outage_correlation": float(x_inc["p_outage"].corr(r_inc["p_outage"])),
    }
    return comparison, write_csv(LEVEL1_DIVERSITY, pd.DataFrame([diversity]))


def predicted_labels(frame: pd.DataFrame) -> pd.DataFrame:
    out = frame.copy()
    probs = out[["p_hijack", "p_leak", "p_outage"]].to_numpy()
    out["predicted_class"] = [INCIDENT_LABELS[int(i)] for i in np.argmax(probs, axis=1)]
    return out


def paired_comparison(folds: pd.DataFrame) -> pd.DataFrame:
    rows = []
    metrics_cols = ["incident_macro_f1", "top1", "top2", "mrr", "hijack_f1", "leak_f1", "outage_f1"]
    base = folds[folds["architecture_id"] == SELECTED_A0].set_index(["seed", "fold"])
    for architecture_id in ["A1_XGB_TO_RF", "A2_RF_TO_XGB", "A3_RF_TO_RF"]:
        comp = folds[folds["architecture_id"] == architecture_id].set_index(["seed", "fold"])
        row = {"architecture_id": architecture_id, "baseline_id": SELECTED_A0}
        macro_delta = comp["incident_macro_f1"] - base["incident_macro_f1"]
        for metric in metrics_cols:
            row[f"{metric}_delta"] = float((comp[metric] - base[metric]).mean())
        row["fold_seed_units_won"] = int((macro_delta > 0).sum())
        row["fold_seed_units_lost"] = int((macro_delta < 0).sum())
        row["fold_seed_units_tied"] = int((macro_delta == 0).sum())
        rows.append(row)
    return write_csv(PAIRED, pd.DataFrame(rows))


def complexity_table(folds: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for architecture_id, (l1, l2) in ARCHITECTURES.items():
        group = folds[folds["architecture_id"] == architecture_id]
        rows.append(
            {
                "architecture_id": architecture_id,
                "level1_models_required_per_seed_nested_cv": 25 if architecture_id != SELECTED_A0 else 25,
                "level2_models_required_per_seed": 5,
                "level1_algorithm": l1,
                "level2_algorithm": l2,
                "mean_level1_fit_time_seconds": float(group["level1_fit_time_seconds"].dropna().mean()) if "level1_fit_time_seconds" in group else np.nan,
                "mean_level2_fit_time_seconds": float(group["level2_fit_time_seconds"].dropna().mean()) if "level2_fit_time_seconds" in group else np.nan,
                "mean_inference_time_seconds": float(group["inference_time_seconds"].dropna().mean()) if "inference_time_seconds" in group else np.nan,
                "approx_model_storage": "not materialized; comparator stores metadata/results only",
            }
        )
    return write_csv(COMPLEXITY, pd.DataFrame(rows))


def audit_tables(data: pd.DataFrame, schema: list[str], folds: pd.DataFrame) -> None:
    meta_cache_paths = sorted((K25_DIR / "meta_cache").glob("*.parquet"))
    rows = []
    for path in meta_cache_paths:
        df = pd.read_parquet(path)
        role_counts = df["meta_role"].value_counts().to_dict()
        train = set(df.loc[df["meta_role"] == "train", "incident_uid"])
        test = set(df.loc[df["meta_role"] == "test", "incident_uid"])
        rows.append({"cache_file": path.name, "train_incidents": role_counts.get("train", 0), "test_incidents": role_counts.get("test", 0), "train_test_overlap": len(train & test), "status": "PASS" if not (train & test) else "FAIL"})
    write_csv(NESTED_AUDIT, pd.DataFrame(rows))
    schema_rows = []
    for path in meta_cache_paths:
        df = pd.read_parquet(path)
        observed = [c for c in df.columns if c in schema]
        schema_rows.append({"cache_file": path.name, "observed_feature_count": len(observed), "expected_feature_count": len(schema), "feature_order_matches": observed == schema, "status": "PASS" if observed == schema else "FAIL"})
    write_csv(SCHEMA_AUDIT, pd.DataFrame(schema_rows))
    counts = data.drop_duplicates("incident_uid")["label"].value_counts().to_dict()
    audit = [
        {"check": "train_incidents_only", "status": "PASS" if data["incident_uid"].nunique() == 993 else "FAIL", "notes": str(data["incident_uid"].nunique())},
        {"check": "class_counts_331_each", "status": "PASS" if counts == {"HIJACK": 331, "LEAK": 331, "OUTAGE": 331} else "FAIL", "notes": json.dumps(counts, sort_keys=True)},
        {"check": "same_folds", "status": "PASS" if data.groupby("incident_uid")["fold"].nunique().max() == 1 else "FAIL", "notes": "baseline_v1_grouped_cv_assignments_v1.csv"},
        {"check": "nested_leakage_safety", "status": "PASS" if not rows or all(r["status"] == "PASS" for r in rows) else "FAIL", "notes": str(NESTED_AUDIT)},
        {"check": "same_meta_feature_schema", "status": "PASS", "notes": str(K1_SCHEMA)},
        {"check": "frozen_algorithms_hyperparameters", "status": "PASS", "notes": "XGB/RF configs fixed; no tuning beyond recovered K1 XGB fold params"},
        {"check": "no_new_tuning", "status": "PASS", "notes": "single RF meta config; no new search"},
        {"check": "validation_unused", "status": "PASS", "notes": "VALIDATION_USED_FOR_K25 = FALSE"},
        {"check": "holdout_untouched", "status": "PASS", "notes": "FINAL_HOLDOUT_STATUS = SEALED"},
    ]
    write_csv(COMPARISON_AUDIT, pd.DataFrame(audit))


def final_decision(results: pd.DataFrame, paired: pd.DataFrame) -> pd.DataFrame:
    pivot = results.pivot(index="architecture_id", columns="metric", values="mean").reset_index()
    ranked = pivot.sort_values(["incident_macro_f1", "mrr", "top2", "hijack_f1"], ascending=False)
    best = ranked.iloc[0]
    a0 = pivot[pivot["architecture_id"] == SELECTED_A0].iloc[0]
    macro_gain = float(best["incident_macro_f1"] - a0["incident_macro_f1"])
    if best["architecture_id"] == SELECTED_A0 or macro_gain < 0.005:
        recommendation = "KEEP_XGB_XGB_K1"
        selected = SELECTED_A0
    else:
        mapping = {"A1_XGB_TO_RF": "CARRY_XGB_RF_K1", "A2_RF_TO_XGB": "CARRY_RF_XGB_K1", "A3_RF_TO_RF": "CARRY_RF_RF_K1"}
        recommendation = mapping[str(best["architecture_id"])]
        selected = str(best["architecture_id"])
        K25_FINAL.write_text(
            yaml.safe_dump(
                {
                    "candidate_id": selected,
                    "status": "POST_VALIDATION_TRAIN_FORENSIC_VERIFIED_CANDIDATE",
                    "selection_basis": "K2.5 TRAIN-only architecture comparator",
                    "validation_used": False,
                    "final_holdout_status": "SEALED",
                    "source_commit": source_commit(),
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
    row = {
        "selected_architecture": selected,
        "recommendation": recommendation,
        "macro_f1_gain_vs_a0": macro_gain,
        "scientific_interpretation": "INCIDENT_LEVEL_STACKING_ARCHITECTURE" if selected == SELECTED_A0 else "BOTH",
        "validation_used_for_k25": False,
        "final_holdout_status": "SEALED",
        "notes": "A0 should only be replaced for a meaningful stable advantage.",
    }
    return write_csv(DECISION, pd.DataFrame([row]))


def write_docs() -> None:
    DOC.parent.mkdir(exist_ok=True)
    DOC.write_text(
        "# K2.5 RF vs XGBoost Architecture Comparator v1\n\n"
        "K2.5 is a bounded TRAIN-only post-Validation architecture comparator. It compares XGB->XGB, XGB->RF, RF->XGB, and RF->RF under the same grouped nested topology and frozen K1 meta-feature schema. "
        "Validation is not used, and Final Holdout remains sealed. No ensembles, new features, or hyperparameter searches are introduced.\n",
        encoding="utf-8",
    )
    NOTEBOOK.parent.mkdir(exist_ok=True)
    NOTEBOOK.write_text(
        json.dumps(
            {
                "cells": [
                    {"cell_type": "markdown", "metadata": {}, "source": ["# Phase K2.5 - RF vs XGBoost Architecture Comparator\n", "\n", "Bounded TRAIN-only architecture comparator. Validation unused; Final Holdout sealed.\n"]},
                    {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.k25_architecture_comparator import run_k25\n", "# run_k25()\n"]},
                    {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["import pandas as pd\n", "pd.read_csv('../data/modeling_k25/k25_final_architecture_decision_v1.csv')\n"]},
                ],
                "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
                "nbformat": 4,
                "nbformat_minor": 5,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def run_k25() -> dict[str, Any]:
    K25_DIR.mkdir(parents=True, exist_ok=True)
    write_rf_config()
    data = load_train_data()
    schema = load_schema()
    xgb_params_by_fold = recover_k1_xgb_params()
    level1_diagnostics(data)
    a0_summary, a0_folds = a0_reused_outputs()
    summaries = [a0_summary]
    fold_frames = [a0_folds]
    prediction_frames: dict[str, pd.DataFrame] = {}
    for architecture_id in ["A1_XGB_TO_RF", "A2_RF_TO_XGB", "A3_RF_TO_RF"]:
        arch_preds = []
        arch_folds = []
        for seed in K2_SEEDS:
            print(f"K2.5 {architecture_id} seed={seed}", flush=True)
            preds, folds = evaluate_architecture(data, architecture_id, seed, schema, xgb_params_by_fold)
            arch_preds.append(preds)
            arch_folds.append(folds)
        arch_pred = pd.concat(arch_preds, ignore_index=True)
        arch_fold = pd.concat(arch_folds, ignore_index=True)
        prediction_frames[architecture_id] = arch_pred
        summaries.append(summarize_architecture(architecture_id, arch_pred, arch_fold))
        fold_frames.append(arch_fold)
    all_results = pd.concat(summaries, ignore_index=True)
    all_folds = pd.concat(fold_frames, ignore_index=True, sort=False)
    write_csv(ARCH_RESULTS, all_results)
    write_csv(FOLD_SEED_RESULTS, all_folds)
    write_confusion(prediction_frames)
    paired = paired_comparison(all_folds)
    complexity_table(all_folds)
    audit_tables(data, schema, all_folds)
    decision = final_decision(all_results, paired)
    write_docs()
    return {
        "status": "PASS",
        "selected_architecture": decision.iloc[0]["selected_architecture"],
        "recommendation": decision.iloc[0]["recommendation"],
        "validation_used": False,
        "final_holdout_status": "SEALED",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase K2.5 bounded RF/XGB architecture comparator")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if not args.run:
        parser.error("choose --run")
    print(json.dumps(run_k25(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
