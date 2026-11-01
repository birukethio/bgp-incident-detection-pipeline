from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow
import sklearn
import xgboost
import yaml
from sklearn.impute import SimpleImputer
from sklearn.metrics import f1_score, precision_recall_fscore_support
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier


ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
TRAIN = ROOT / "data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet"
ASSIGNMENTS = ROOT / "data/modeling/baseline_v1_grouped_cv_assignments_v1.csv"
SCHEMA = ROOT / "data/tti_pilot/reconstructed_level1_v1/feature_schema_v4.json"
CONFIG = ROOT / "config/final_model_candidate_v3_1_xgb_refined.yaml"
HISTORICAL_SEEDS = ROOT / "data/modeling/xgb_multiseed_seed_results_v2.csv"
REFERENCE_OOF = ROOT / "data/modeling_k1/k1_window_oof_probabilities_v1.parquet"

EXPECTED_HASHES = {
    TRAIN: "b9a6490a13a3146266c86e605a75e92f30c167e4181d60e28732ebaced9a24ad",
    ASSIGNMENTS: "4fa06415be3233c808a2bd0169a345c6c29088082ca7d3f0d3792fb9d506a355",
    SCHEMA: "38ca70a2aa50a39172f2a90d1c893fdd08dfa38a49b3e5945b19d9cab2a202f3",
    CONFIG: "a7fac0c315df80f23c73ab69cc28f74d9105873806d169d95d329fb8704a6aae",
}
LABELS = ["HIJACK", "LEAK", "OUTAGE"]
SEEDS = [20260828, 20260829, 20260830, 20260831, 20260901]
BOOTSTRAP_SEED = 20260828
BOOTSTRAP_RESAMPLES = 2000
METRIC_TOLERANCE = 1e-12
PROBABILITY_TOLERANCE = 1e-6

XGB_PARAMS = {
    "n_estimators": 600,
    "max_depth": 6,
    "learning_rate": 0.125,
    "subsample": 0.9,
    "colsample_bytree": 0.9,
    "min_child_weight": 1,
    "gamma": 0,
    "reg_alpha": 0.01,
    "reg_lambda": 2.0,
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_inputs() -> pd.DataFrame:
    rows = []
    for path, expected in EXPECTED_HASHES.items():
        actual = sha256_file(path)
        rows.append({"path": str(path.relative_to(ROOT)), "expected_sha256": expected, "actual_sha256": actual, "status": "PASS" if actual == expected else "FAIL"})
    frame = pd.DataFrame(rows)
    frame.to_csv(OUT / "input_hash_verification_v1.csv", index=False)
    if not frame["status"].eq("PASS").all():
        raise RuntimeError("Frozen input hash verification failed.")
    return frame


def load_data() -> tuple[pd.DataFrame, dict[str, list[str]]]:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    if len(schema) != 74:
        raise RuntimeError("Frozen schema is not 74 features.")
    behavioral, caida, rpki = schema[:44], schema[44:58], schema[58:74]
    subsets = {
        "full_v4": schema,
        "minus_caida": behavioral + rpki,
        "minus_rpki": behavioral + caida,
        "minus_behavioral": caida + rpki,
        "behavioral_only": behavioral,
    }
    expected_counts = {"full_v4": 74, "minus_caida": 60, "minus_rpki": 58, "minus_behavioral": 30, "behavioral_only": 44}
    if {name: len(cols) for name, cols in subsets.items()} != expected_counts:
        raise RuntimeError("Feature subset count mismatch.")

    data = pd.read_parquet(TRAIN)
    assignments = pd.read_csv(ASSIGNMENTS, low_memory=False)
    assignments = assignments[assignments["label"].isin(LABELS)][["window_id", "label", "model_group_id", "fold"]].copy()
    data = data.merge(assignments, on="window_id", how="left", validate="one_to_one")
    data = data[data["label"].isin(LABELS)].copy()
    data["fold"] = data["fold"].astype(int)
    if len(data) != 68031 or data["incident_uid"].nunique() != 993:
        raise RuntimeError("TRAIN row or incident count mismatch.")
    counts = data.drop_duplicates("incident_uid")["label"].value_counts().to_dict()
    if counts != {"HIJACK": 331, "LEAK": 331, "OUTAGE": 331}:
        raise RuntimeError(f"TRAIN class balance mismatch: {counts}")
    if set(data["partition"].astype(str)) != {"train"}:
        raise RuntimeError("A non-TRAIN partition was loaded.")
    if data.groupby("incident_uid")["fold"].nunique().max() != 1:
        raise RuntimeError("Incident-grouped fold violation.")
    if any(col not in data.columns for col in schema):
        raise RuntimeError("Frozen feature columns are missing.")
    return data, subsets


def model(seed: int) -> Pipeline:
    params = {
        **XGB_PARAMS,
        "objective": "multi:softprob",
        "num_class": 3,
        "eval_metric": "mlogloss",
        "random_state": seed,
        "seed": seed,
        "tree_method": "hist",
        "n_jobs": -1,
        "verbosity": 0,
    }
    return Pipeline([("imputer", SimpleImputer(strategy="median")), ("model", XGBClassifier(**params))])


def codes(labels: pd.Series) -> np.ndarray:
    return labels.map({label: idx for idx, label in enumerate(LABELS)}).astype(int).to_numpy()


def metrics(frame: pd.DataFrame) -> dict[str, float]:
    y_true = frame["true_class"].tolist()
    y_pred = frame["predicted_class"].tolist()
    probs = frame[["p_hijack", "p_leak", "p_outage"]].to_numpy()
    true_codes = np.array([LABELS.index(value) for value in y_true])
    order = np.argsort(-probs, axis=1)
    ranks = np.array([int(np.where(order[i] == true_codes[i])[0][0]) + 1 for i in range(len(frame))])
    _, _, f1, _ = precision_recall_fscore_support(y_true, y_pred, labels=LABELS, zero_division=0)
    return {
        "incident_macro_f1": float(f1_score(y_true, y_pred, labels=LABELS, average="macro", zero_division=0)),
        "incident_top1": float(np.mean(np.array(y_true) == np.array(y_pred))),
        "incident_top2": float(np.mean(ranks <= 2)),
        "incident_mrr": float(np.mean(1.0 / ranks)),
        "incident_hijack_f1": float(f1[0]),
        "incident_leak_f1": float(f1[1]),
        "incident_outage_f1": float(f1[2]),
    }


def aggregate_incidents(windows: pd.DataFrame) -> pd.DataFrame:
    grouped = windows.groupby(["configuration", "seed", "incident_uid", "fold", "true_class"], as_index=False)[["p_hijack", "p_leak", "p_outage"]].mean()
    grouped["predicted_class"] = np.array(LABELS)[grouped[["p_hijack", "p_leak", "p_outage"]].to_numpy().argmax(axis=1)]
    return grouped


def run_configuration(data: pd.DataFrame, name: str, features: list[str], seed: int) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, float]]:
    rows = []
    started = time.perf_counter()
    for fold in sorted(data["fold"].unique()):
        train = data[data["fold"] != fold].copy()
        test = data[data["fold"] == fold].copy()
        weights = 1.0 / train.groupby("model_group_id")["window_id"].transform("count").astype(float).to_numpy()
        fitted = model(seed)
        fitted.fit(train[features], codes(train["label"]), model__sample_weight=weights)
        probabilities = fitted.predict_proba(test[features])
        fold_rows = test[["window_id", "incident_uid", "fold", "label"]].copy()
        fold_rows = fold_rows.rename(columns={"label": "true_class"})
        fold_rows.insert(0, "seed", seed)
        fold_rows.insert(0, "configuration", name)
        fold_rows["p_hijack"] = probabilities[:, 0]
        fold_rows["p_leak"] = probabilities[:, 1]
        fold_rows["p_outage"] = probabilities[:, 2]
        fold_rows["predicted_class"] = np.array(LABELS)[probabilities.argmax(axis=1)]
        rows.append(fold_rows)
    windows = pd.concat(rows, ignore_index=True)
    incidents = aggregate_incidents(windows)
    result = {"configuration": name, "feature_count": len(features), "seed": seed, **metrics(incidents), "runtime_seconds": time.perf_counter() - started}
    return windows, incidents, result


def historical_seed_rows() -> pd.DataFrame:
    historical = pd.read_csv(HISTORICAL_SEEDS)
    return historical[historical["candidate_id"].eq("PHASEI2_XGB_LOCAL_004")].copy()


def baseline_gate(windows: pd.DataFrame, incidents: pd.DataFrame, results: pd.DataFrame) -> pd.DataFrame:
    historical = historical_seed_rows()
    columns = ["incident_macro_f1", "incident_top1", "incident_top2", "incident_mrr", "incident_hijack_f1", "incident_leak_f1", "incident_outage_f1"]
    rows = []
    for seed in SEEDS:
        observed = results[results["seed"].eq(seed)].iloc[0]
        expected = historical[historical["xgb_seed"].eq(seed)].iloc[0]
        row = {"seed": seed}
        passed = True
        for col in columns:
            delta = float(observed[col]) - float(expected[col])
            row[f"historical_{col}"] = float(expected[col])
            row[f"reproduced_{col}"] = float(observed[col])
            row[f"delta_{col}"] = delta
            passed &= abs(delta) <= METRIC_TOLERANCE
        row["metric_status"] = "PASS" if passed else "FAIL"
        rows.append(row)

    principal = windows[windows["seed"].eq(SEEDS[0])].copy()
    reference = pd.read_parquet(REFERENCE_OOF)
    keys = ["window_id", "incident_uid", "fold", "true_class"]
    merged = reference[keys + ["p_hijack", "p_leak", "p_outage"]].merge(principal[keys + ["p_hijack", "p_leak", "p_outage"]], on=keys, suffixes=("_historical", "_reproduced"), validate="one_to_one")
    historical_probs = merged[[f"p_{label}_historical" for label in ["hijack", "leak", "outage"]]].to_numpy()
    reproduced_probs = merged[[f"p_{label}_reproduced" for label in ["hijack", "leak", "outage"]]].to_numpy()
    max_diff = float(np.abs(historical_probs - reproduced_probs).max())
    agreement = float(np.mean(historical_probs.argmax(axis=1) == reproduced_probs.argmax(axis=1)))
    for row in rows:
        row["probability_comparison_available"] = row["seed"] == SEEDS[0]
        row["max_abs_probability_difference"] = max_diff if row["seed"] == SEEDS[0] else np.nan
        row["predicted_class_agreement"] = agreement if row["seed"] == SEEDS[0] else np.nan
        row["probability_status"] = ("PASS" if max_diff <= PROBABILITY_TOLERANCE and agreement == 1.0 else "FAIL") if row["seed"] == SEEDS[0] else "NOT_AVAILABLE_HISTORICAL_PROBABILITIES_NOT_PRESERVED"
        row["overall_status"] = "PASS" if row["metric_status"] == "PASS" and row["probability_status"] != "FAIL" else "FAIL"
    gate = pd.DataFrame(rows)
    gate.to_csv(OUT / "baseline_reproduction_gate_v1.csv", index=False)
    return gate


def summarize(seed_results: pd.DataFrame) -> pd.DataFrame:
    metric_cols = ["incident_macro_f1", "incident_top1", "incident_top2", "incident_mrr", "incident_hijack_f1", "incident_leak_f1", "incident_outage_f1"]
    rows = []
    for name, group in seed_results.groupby("configuration", sort=False):
        row = {"configuration": name, "feature_count": int(group["feature_count"].iloc[0]), "seed_count": len(group)}
        for col in metric_cols:
            row[col] = float(group[col].mean())
            row[f"{col}_seed_std"] = float(group[col].std(ddof=0))
        rows.append(row)
    return pd.DataFrame(rows)


def paired_bootstrap(incidents: pd.DataFrame) -> pd.DataFrame:
    rng = np.random.default_rng(BOOTSTRAP_SEED)
    ids = np.array(sorted(incidents["incident_uid"].unique()))
    samples = rng.integers(0, len(ids), size=(BOOTSTRAP_RESAMPLES, len(ids)))
    full = incidents[incidents["configuration"].eq("full_v4")]

    def prediction_codes(frame: pd.DataFrame, seed: int) -> tuple[np.ndarray, np.ndarray]:
        ordered = frame[frame["seed"].eq(seed)].set_index("incident_uid").loc[ids]
        true = ordered["true_class"].map({label: idx for idx, label in enumerate(LABELS)}).to_numpy(dtype=np.int8)
        predicted = ordered["predicted_class"].map({label: idx for idx, label in enumerate(LABELS)}).to_numpy(dtype=np.int8)
        return true, predicted

    def macro_f1_codes(true: np.ndarray, predicted: np.ndarray, sampled: np.ndarray | None = None) -> float:
        if sampled is not None:
            true = true[sampled]
            predicted = predicted[sampled]
        matrix = np.bincount(true.astype(np.int64) * 3 + predicted.astype(np.int64), minlength=9).reshape(3, 3)
        scores = []
        for label in range(3):
            tp = float(matrix[label, label])
            fp = float(matrix[:, label].sum() - tp)
            fn = float(matrix[label, :].sum() - tp)
            denominator = 2.0 * tp + fp + fn
            scores.append(0.0 if denominator == 0 else 2.0 * tp / denominator)
        return float(np.mean(scores))

    rows = []
    for ablated_name in ["minus_caida", "minus_rpki", "minus_behavioral", "behavioral_only"]:
        ablated = incidents[incidents["configuration"].eq(ablated_name)]
        seed_arrays = []
        for seed in SEEDS:
            full_true, full_predicted = prediction_codes(full, seed)
            ablated_true, ablated_predicted = prediction_codes(ablated, seed)
            if not np.array_equal(full_true, ablated_true):
                raise RuntimeError(f"Paired labels differ for {ablated_name}, seed {seed}.")
            seed_arrays.append((full_true, full_predicted, ablated_predicted))
        observed_seed_deltas = [
            macro_f1_codes(true, full_predicted) - macro_f1_codes(true, ablated_predicted)
            for true, full_predicted, ablated_predicted in seed_arrays
        ]
        replicate_deltas = [
            float(np.mean([
                macro_f1_codes(true, full_predicted, sampled) - macro_f1_codes(true, ablated_predicted, sampled)
                for true, full_predicted, ablated_predicted in seed_arrays
            ]))
            for sampled in samples
        ]
        values = np.asarray(replicate_deltas)
        rows.append({
            "comparison": f"full_v4_minus_{ablated_name}",
            "observed_mean_seed_delta_macro_f1": float(np.mean(observed_seed_deltas)),
            "bootstrap_ci_lower_95": float(np.quantile(values, 0.025)),
            "bootstrap_ci_upper_95": float(np.quantile(values, 0.975)),
            "bootstrap_resamples": BOOTSTRAP_RESAMPLES,
            "bootstrap_seed": BOOTSTRAP_SEED,
            "resampling_unit": "incident_uid",
            "multiplicity_status": "EXPLORATORY_NO_HOLM_TEST",
        })
    return pd.DataFrame(rows)


def environment_manifest() -> pd.DataFrame:
    return pd.DataFrame([
        {"item": "execution_label", "value": "POST-FEEDBACK SUPPLEMENTARY TRAIN-ONLY XGBOOST ABLATION EXPERIMENT"},
        {"item": "python", "value": sys.version.replace("\n", " ")},
        {"item": "platform", "value": platform.platform()},
        {"item": "xgboost", "value": xgboost.__version__},
        {"item": "scikit_learn", "value": sklearn.__version__},
        {"item": "numpy", "value": np.__version__},
        {"item": "pandas", "value": pd.__version__},
        {"item": "pyarrow", "value": pyarrow.__version__},
        {"item": "cpu_count", "value": os.cpu_count()},
        {"item": "seeds", "value": json.dumps(SEEDS)},
        {"item": "bootstrap_seed", "value": BOOTSTRAP_SEED},
        {"item": "bootstrap_resamples", "value": BOOTSTRAP_RESAMPLES},
        {"item": "validation_accessed", "value": False},
        {"item": "final_holdout_accessed", "value": False},
    ])


def output_checksums() -> None:
    excluded = {"output_checksums_v1.csv"}
    rows = []
    for path in sorted(OUT.iterdir()):
        if path.is_file() and path.name not in excluded and path.name != "__pycache__":
            rows.append({"file": path.name, "sha256": sha256_file(path), "bytes": path.stat().st_size})
    pd.DataFrame(rows).to_csv(OUT / "output_checksums_v1.csv", index=False)


def run_baseline(data: pd.DataFrame, subsets: dict[str, list[str]]) -> None:
    window_frames, incident_frames, result_rows = [], [], []
    for seed in SEEDS:
        print(f"baseline full_v4 seed={seed}", flush=True)
        windows, incidents, result = run_configuration(data, "full_v4", subsets["full_v4"], seed)
        window_frames.append(windows)
        incident_frames.append(incidents)
        result_rows.append(result)
    windows = pd.concat(window_frames, ignore_index=True)
    incidents = pd.concat(incident_frames, ignore_index=True)
    results = pd.DataFrame(result_rows)
    windows.to_parquet(OUT / "baseline_window_oof_predictions_v1.parquet", index=False)
    incidents.to_parquet(OUT / "baseline_incident_oof_predictions_v1.parquet", index=False)
    results.to_csv(OUT / "baseline_seed_metrics_v1.csv", index=False)
    gate = baseline_gate(windows, incidents, results)
    if not gate["overall_status"].eq("PASS").all():
        output_checksums()
        raise RuntimeError("Baseline reproduction gate failed; ablations are blocked.")
    (OUT / "baseline_gate_passed.flag").write_text("PASS\n", encoding="utf-8")
    output_checksums()


def run_ablations(data: pd.DataFrame, subsets: dict[str, list[str]]) -> None:
    if not (OUT / "baseline_gate_passed.flag").exists():
        raise RuntimeError("Baseline gate has not passed.")
    baseline_windows = pd.read_parquet(OUT / "baseline_window_oof_predictions_v1.parquet")
    baseline_incidents = pd.read_parquet(OUT / "baseline_incident_oof_predictions_v1.parquet")
    baseline_results = pd.read_csv(OUT / "baseline_seed_metrics_v1.csv")
    window_frames, incident_frames = [baseline_windows], [baseline_incidents]
    result_rows = baseline_results.to_dict("records")
    for name in ["minus_caida", "minus_rpki", "minus_behavioral", "behavioral_only"]:
        for seed in SEEDS:
            print(f"ablation {name} seed={seed}", flush=True)
            windows, incidents, result = run_configuration(data, name, subsets[name], seed)
            window_frames.append(windows)
            incident_frames.append(incidents)
            result_rows.append(result)
    windows = pd.concat(window_frames, ignore_index=True)
    incidents = pd.concat(incident_frames, ignore_index=True)
    seed_results = pd.DataFrame(result_rows)
    windows.to_parquet(OUT / "xgb_ablation_window_oof_predictions_v1.parquet", index=False)
    incidents.to_parquet(OUT / "xgb_ablation_incident_oof_predictions_v1.parquet", index=False)
    seed_results.to_csv(OUT / "xgb_ablation_seed_metrics_v1.csv", index=False)
    summarize(seed_results).to_csv(OUT / "xgb_ablation_summary_metrics_v1.csv", index=False)
    paired_bootstrap(incidents).to_csv(OUT / "xgb_ablation_paired_bootstrap_v1.csv", index=False)
    output_checksums()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=["baseline", "ablations", "bootstrap"], required=True)
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    verify_inputs()
    environment_manifest().to_csv(OUT / "environment_manifest_v1.csv", index=False)
    data, subsets = load_data()
    if args.phase == "baseline":
        run_baseline(data, subsets)
    elif args.phase == "ablations":
        run_ablations(data, subsets)
    else:
        incidents = pd.read_parquet(OUT / "xgb_ablation_incident_oof_predictions_v1.parquet")
        paired_bootstrap(incidents).to_csv(OUT / "xgb_ablation_paired_bootstrap_v1.csv", index=False)
        output_checksums()


if __name__ == "__main__":
    main()
