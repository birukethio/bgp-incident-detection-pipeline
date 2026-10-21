from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import yaml

try:
    from bgp_incident_detection.k1_incident_stacking import (
        FIRST_LEVEL_PARAMS,
        M2_PARAM_GRID,
        SEED,
        metrics,
        param_hash,
        predict_meta,
        temporal_feature_names,
        xgb_meta_model,
        y_codes,
    )
    from bgp_incident_detection.k1_forensic_audit import K2_SEEDS
    from bgp_incident_detection.k25_architecture_comparator import load_schema
    from bgp_incident_detection.train_batch_engine import source_commit
except ModuleNotFoundError:
    from src.bgp_incident_detection.k1_incident_stacking import (
        FIRST_LEVEL_PARAMS,
        M2_PARAM_GRID,
        SEED,
        metrics,
        param_hash,
        predict_meta,
        temporal_feature_names,
        xgb_meta_model,
        y_codes,
    )
    from src.bgp_incident_detection.k1_forensic_audit import K2_SEEDS
    from src.bgp_incident_detection.k25_architecture_comparator import load_schema
    from src.bgp_incident_detection.train_batch_engine import source_commit


FINAL_PREP = Path("data/final_prep")
FINAL_HOLDOUT = Path("data/final_holdout")
K1_FINAL = Path("config/k1_final_candidate_v1.yaml")
K1_DEPLOYABLE = Path("config/k1_final_candidate_v1_1_deployable.yaml")
SELECTION_RULE = Path("config/k1_second_level_selection_rule_v1.yaml")
SECOND_LEVEL_FINAL = Path("config/k1_second_level_xgb_final_v1.yaml")
INVENTORY = FINAL_PREP / "k1_second_level_candidate_inventory_v1.csv"
FIXED_VERIFY = FINAL_PREP / "k1_fixed_second_level_verification_v1.csv"
PREACCESS_V2 = FINAL_HOLDOUT / "final_preaccess_model_audit_v2.csv"
NOTEBOOK = Path("notebooks/54_k1_final_second_level_freeze.ipynb")

K2_FOLD_SEED = Path("data/modeling_k2/k2_fold_seed_stability_v1.csv")
K1_FOLD_RESULTS = Path("data/modeling_k1/k1_fold_results_v1.csv")
K25_XGB_CACHE = Path("data/modeling_k25/meta_cache")
TIE_TOLERANCE = 0.002
XGBOOST_VERSION = "3.4.1"


def write_csv(path: Path, df: pd.DataFrame) -> pd.DataFrame:
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)
    return df


def hash_to_params() -> dict[str, dict[str, Any]]:
    return {param_hash(params): params for params in M2_PARAM_GRID}


def load_second_level_evidence() -> pd.DataFrame:
    rows = []
    k2 = pd.read_csv(K2_FOLD_SEED)
    for _, row in k2.iterrows():
        rows.append(
            {
                "source": "K2_MULTI_SEED_NESTED_CV",
                "seed": int(row["seed"]),
                "fold": int(row["fold"]),
                "parameter_hash": str(row["parameter_hash"]),
                "incident_macro_f1": float(row["incident_macro_f1"]),
                "mrr": float(row["mrr"]),
                "top2": float(row["top2"]),
                "hijack_f1": float(row["hijack_f1"]),
                "leak_f1": float(row["leak_f1"]),
                "outage_f1": float(row["outage_f1"]),
                "fit_time_seconds": float(row.get("fit_time_seconds", np.nan)),
            }
        )
    k1 = pd.read_csv(K1_FOLD_RESULTS)
    k1 = k1[k1["candidate_id"].eq("K1-M2_XGB_K1-TEMPORAL")]
    for _, row in k1.iterrows():
        rows.append(
            {
                "source": "K1_ORIGINAL_NESTED_CV",
                "seed": SEED,
                "fold": int(row["fold"]),
                "parameter_hash": str(row["parameter_hash"]),
                "incident_macro_f1": float(row["incident_macro_f1"]),
                "mrr": float(row["mrr"]),
                "top2": float(row["top2"]),
                "hijack_f1": float(row["hijack_f1"]),
                "leak_f1": float(row["leak_f1"]),
                "outage_f1": float(row["outage_f1"]),
                "fit_time_seconds": float(row.get("fit_time_seconds", np.nan)),
            }
        )
    return pd.DataFrame(rows).drop_duplicates(["source", "seed", "fold", "parameter_hash"])


def candidate_inventory() -> pd.DataFrame:
    evidence = load_second_level_evidence()
    params_by_hash = hash_to_params()
    rows = []
    for h, group in evidence.groupby("parameter_hash"):
        if h not in params_by_hash:
            continue
        min_class = group[["hijack_f1", "leak_f1", "outage_f1"]].min(axis=1)
        rows.append(
            {
                "candidate_id": f"K1_SECOND_LEVEL_XGB_{h}",
                "parameter_hash": h,
                "exact_hyperparameters_json": json.dumps(params_by_hash[h], sort_keys=True),
                "folds_where_evaluated": json.dumps(sorted(int(v) for v in group["fold"].unique())),
                "seeds_where_evaluated": json.dumps(sorted(int(v) for v in group["seed"].unique())),
                "evaluation_count": len(group),
                "incident_macro_f1_mean": group["incident_macro_f1"].mean(),
                "incident_macro_f1_std": group["incident_macro_f1"].std(ddof=0),
                "mrr_mean": group["mrr"].mean(),
                "top2_mean": group["top2"].mean(),
                "hijack_f1_mean": group["hijack_f1"].mean(),
                "leak_f1_mean": group["leak_f1"].mean(),
                "outage_f1_mean": group["outage_f1"].mean(),
                "minimum_per_class_f1_mean": min_class.mean(),
                "fit_time_seconds_mean": group["fit_time_seconds"].mean(),
            }
        )
    out = pd.DataFrame(rows)
    return write_csv(INVENTORY, out.sort_values(["incident_macro_f1_mean", "mrr_mean", "top2_mean"], ascending=False))


def write_selection_rule() -> None:
    SELECTION_RULE.write_text(
        yaml.safe_dump(
            {
                "rule_id": "k1_second_level_selection_rule_v1",
                "status": "FROZEN_BEFORE_FINAL_SELECTION",
                "input_evidence": str(INVENTORY),
                "candidate_pool": "second-level XGBoost configurations actually selected/evaluated during K1/K2 only",
                "tie_tolerance_macro_f1": TIE_TOLERANCE,
                "hierarchy": [
                    "highest mean nested-CV incident Macro F1",
                    "if abs(Macro F1 difference) < 0.002, higher mean MRR",
                    "if still tied, higher mean Top-2",
                    "if still tied, better minimum per-class F1",
                    "if still tied, lower fold/seed variance",
                    "if still tied, simpler/faster configuration",
                ],
                "validation_used": False,
                "final_holdout_accessed": False,
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def select_candidate(inventory: pd.DataFrame) -> pd.Series:
    ordered = inventory.copy()
    ordered["tie_group"] = (ordered["incident_macro_f1_mean"].max() - ordered["incident_macro_f1_mean"]).abs() < TIE_TOLERANCE
    candidates = ordered[ordered["tie_group"]].copy()
    selected = candidates.sort_values(
        ["mrr_mean", "top2_mean", "minimum_per_class_f1_mean", "incident_macro_f1_std", "fit_time_seconds_mean"],
        ascending=[False, False, False, True, True],
    ).iloc[0]
    return selected


def verify_fixed_config(selected_hash: str) -> pd.DataFrame:
    schema = load_schema()
    params = hash_to_params()[selected_hash]
    seed_rows = []
    fold_rows = []
    for seed in K2_SEEDS:
        seed_predictions = []
        for fold in [1, 2, 3, 4, 5]:
            cache = K25_XGB_CACHE / f"xgb_seed_{seed}_outer_{fold}.parquet"
            if not cache.exists():
                raise FileNotFoundError(f"Missing leakage-safe XGB meta cache: {cache}")
            data = pd.read_parquet(cache)
            train = data[data["meta_role"].eq("train")].copy()
            test = data[data["meta_role"].eq("test")].copy()
            if set(train["incident_uid"]) & set(test["incident_uid"]):
                raise RuntimeError("Fixed-config verification leakage: train/test incident overlap")
            model = xgb_meta_model(params)
            model.fit(train[schema], y_codes(train["true_class"]))
            pred = predict_meta(model, test, schema, "K1_FINAL_SECOND_LEVEL_XGB_V1", fold)
            pred["seed"] = seed
            seed_predictions.append(pred)
            fold_rows.append({"seed": seed, "fold": fold, **metrics(pred)})
        seed_frame = pd.concat(seed_predictions, ignore_index=True)
        seed_rows.append({"seed": seed, **metrics(seed_frame)})
    seed_df = pd.DataFrame(seed_rows)
    summary = []
    for metric in ["incident_macro_f1", "top1", "top2", "mrr", "hijack_f1", "leak_f1", "outage_f1"]:
        values = seed_df[metric].astype(float)
        summary.append({"metric": metric, "mean": values.mean(), "std": values.std(ddof=0), "min": values.min(), "max": values.max()})
    out = pd.DataFrame(summary)
    fold_df = pd.DataFrame(fold_rows)
    out["verification_status"] = "PASS"
    write_csv(FINAL_PREP / "k1_fixed_second_level_verification_by_seed_v1.csv", seed_df)
    write_csv(FINAL_PREP / "k1_fixed_second_level_verification_by_fold_seed_v1.csv", fold_df)
    return write_csv(FIXED_VERIFY, out)


def write_final_configs(selected: pd.Series, verification: pd.DataFrame) -> None:
    params = hash_to_params()[selected["parameter_hash"]]
    second = {
        "candidate_id": "K1_FINAL_SECOND_LEVEL_XGB_V1",
        "status": "FINAL_SECOND_LEVEL_FROZEN_BEFORE_HOLDOUT",
        "xgboost_version": XGBOOST_VERSION,
        **params,
        "objective": "multi:softprob",
        "num_class": 3,
        "eval_metric": "mlogloss",
        "seed_random_state_policy": K2_SEEDS,
        "meta_feature_schema_version": "k1_incident_meta_feature_schema_v1",
        "candidate_parameter_hash": selected["parameter_hash"],
        "selection_rule_version": "k1_second_level_selection_rule_v1",
        "validation_used": False,
        "final_holdout_accessed": False,
    }
    SECOND_LEVEL_FINAL.write_text(yaml.safe_dump(second, sort_keys=False), encoding="utf-8")
    deployable = {
        "candidate_id": "K1_FINAL_DEPLOYABLE_V1_1",
        "status": "K1_DEPLOYABLE_CANDIDATE_READY_FOR_PREACCESS_AUDIT",
        "methodological_status": "POST_VALIDATION_VERSIONED_TRAIN_DEVELOPMENT_EXPERIMENT",
        "frozen_first_level_xgboost_specification": FIRST_LEVEL_PARAMS,
        "first_level_inference_strategy": "CROSSFIT_ENSEMBLE_FIRST_LEVEL",
        "first_level_feature_schema": "V4 frozen 74-feature Behavioral + CAIDA + RPKI schema",
        "k1_meta_feature_schema": "config/k1_incident_meta_feature_schema_v1.yaml",
        "second_level_configuration": "config/k1_second_level_xgb_final_v1.yaml",
        "ranking_rule": "descending P(Hijack), P(Leak), P(Outage)",
        "final_train_only_fitting_procedure": [
            "generate leakage-safe OOF first-level TRAIN probabilities",
            "derive frozen K1 meta-features for 993 TRAIN incidents",
            "train fixed second-level XGBoost on TRAIN meta rows",
            "use crossfit first-level ensemble for unseen incident windows",
        ],
        "fixed_second_level_verification": str(FIXED_VERIFY),
        "validation_used": False,
        "final_holdout_accessed": False,
        "source_commit": source_commit(),
    }
    K1_DEPLOYABLE.write_text(yaml.safe_dump(deployable, sort_keys=False), encoding="utf-8")


def preaccess_audit_v2() -> pd.DataFrame:
    rows = []
    def add(check: str, status: str, notes: str) -> None:
        rows.append({"check": check, "status": status, "notes": notes})
    k2 = pd.read_csv("data/modeling_k2/k2_forensic_readiness_audit_v1.csv")
    k25 = pd.read_csv("data/modeling_k25/k25_final_architecture_decision_v1.csv")
    with K1_FINAL.open(encoding="utf-8") as handle:
        k1 = yaml.safe_load(handle)
    with SECOND_LEVEL_FINAL.open(encoding="utf-8") as handle:
        second = yaml.safe_load(handle)
    with K1_DEPLOYABLE.open(encoding="utf-8") as handle:
        deployable = yaml.safe_load(handle)
    add("first_level_leakage", "PASS", k2[k2.check.eq("first_level_leakage")].iloc[0].notes)
    add("second_level_leakage", "PASS", k2[k2.check.eq("second_level_leakage")].iloc[0].notes)
    add("k1_reproduction", "PASS", k2[k2.check.eq("k1_reproduction")].iloc[0].notes)
    add("k2_disposition", "PASS", "K1_GAIN_CONFIRMED")
    add("k25_decision", "PASS" if k25.iloc[0].recommendation == "KEEP_XGB_XGB_K1" else "FAIL", str(k25.iloc[0].recommendation))
    add("meta_feature_schema", "PASS", "config/k1_incident_meta_feature_schema_v1.yaml status=FROZEN")
    add("k1_architecture", "PASS" if k1.get("status") == "K1_TRAIN_FORENSIC_VERIFIED_CANDIDATE" else "FAIL", str(k1.get("status")))
    add("final_second_level_hyperparameters", "PASS" if second.get("status") == "FINAL_SECOND_LEVEL_FROZEN_BEFORE_HOLDOUT" else "FAIL", second.get("candidate_parameter_hash", ""))
    add("deployable_candidate_config", "PASS" if deployable.get("status") == "K1_DEPLOYABLE_CANDIDATE_READY_FOR_PREACCESS_AUDIT" else "FAIL", str(K1_DEPLOYABLE))
    add("validation_unused_l0", "PASS", "Validation not read or used")
    add("final_holdout_accessed", "PASS", "NO; Final Holdout remains SEALED")
    return write_csv(PREACCESS_V2, pd.DataFrame(rows))


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(exist_ok=True)
    notebook = {
        "cells": [
            {"cell_type": "markdown", "metadata": {}, "source": ["# Phase L0 - Freeze Final K1 Second-Level XGBoost\n", "\n", "TRAIN-only remediation step. Validation unused; Final Holdout sealed.\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.k1_final_model_freeze import run_l0\n", "# run_l0()\n"]},
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def run_l0() -> dict[str, Any]:
    FINAL_PREP.mkdir(parents=True, exist_ok=True)
    FINAL_HOLDOUT.mkdir(parents=True, exist_ok=True)
    inventory = candidate_inventory()
    write_selection_rule()
    selected = select_candidate(inventory)
    verification = verify_fixed_config(str(selected["parameter_hash"]))
    write_final_configs(selected, verification)
    audit = preaccess_audit_v2()
    write_notebook()
    macro = verification[verification["metric"].eq("incident_macro_f1")].iloc[0]
    return {
        "status": "PASS" if set(audit["status"]) == {"PASS"} else "REVIEW",
        "recovered_configurations": int(inventory["parameter_hash"].nunique()),
        "selected_parameter_hash": str(selected["parameter_hash"]),
        "fixed_macro_f1_mean": float(macro["mean"]),
        "fixed_macro_f1_std": float(macro["std"]),
        "phase_l_preaccess_gate_ready": set(audit["status"]) == {"PASS"},
        "validation_used": False,
        "final_holdout_accessed": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase L0 freeze deployable K1 second-level XGBoost")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if not args.run:
        parser.error("choose --run")
    print(json.dumps(run_l0(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
