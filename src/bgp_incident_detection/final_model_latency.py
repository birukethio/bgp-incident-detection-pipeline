from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import statistics
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import yaml

try:
    import xgboost
except Exception:  # pragma: no cover - version reporting fallback only
    xgboost = None

try:
    from bgp_incident_detection.k1_incident_stacking import build_meta_frame, ranked_frame
except ModuleNotFoundError:  # pragma: no cover
    from src.bgp_incident_detection.k1_incident_stacking import build_meta_frame, ranked_frame


DOCS = Path("docs")
PERF = Path("data/performance")
NOTEBOOK = Path("notebooks/57_tau_threshold_and_final_model_latency.ipynb")

STAGE1_SUMMARY = Path("data/modeling/stage1_threshold_selection_summary_v1.csv")
STAGE1_STABILITY = Path("data/modeling/stage1_threshold_stability_v1.csv")
STAGE1_CALIBRATION = Path("data/modeling/stage1_calibration_before_v1.csv")
STAGE1_SWEEP = Path("data/modeling/stage1_threshold_sweep_v1.csv")
STAGE1_W1_RESULTS = Path("data/modeling/stage1_class_group_weight_results_v1.csv")
STAGE1_W1_STABILITY = Path("data/modeling/stage1_class_group_weight_stability_v1.csv")
K1_SCHEMA = Path("config/k1_incident_meta_feature_schema_v1.yaml")
K1_PROTOCOL = Path("docs/k1_final_training_and_inference_protocol_v1.md")
K1_DEPLOYABLE = Path("config/k1_final_candidate_v1_1_deployable.yaml")
FINAL_RESULT = Path("config/final_praxis_result_v1.yaml")
K1_RESULTS = Path("data/modeling_k1/k1_model_results_v1.csv")
BASELINE_RESULTS = Path("data/modeling/baseline_v1_model_comparison_v1.csv")
RF_H2_RESULTS = Path("data/modeling/rf_h2_final_comparison_v1.csv")
XGB_I2_RESULTS = Path("data/modeling/xgb_i2_final_comparison_v1.csv")
K1_WINDOW_PROBS = Path("data/modeling_k1/k1_window_oof_probabilities_v1.parquet")
TRAIN_V4 = Path("data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet")
K1_INCIDENT_PREDICTIONS = Path("data/modeling_k1/k1_incident_level_predictions_v1.parquet")


def read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str] | None = None) -> pd.DataFrame:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        keys: list[str] = []
        for row in rows:
            for key in row:
                if key not in keys:
                    keys.append(key)
        fieldnames = keys
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})
    return pd.DataFrame(rows)


def percentile(values: list[float], q: float) -> float:
    if not values:
        return float("nan")
    return float(np.quantile(np.asarray(values, dtype=float), q))


def summarize_ms(values: list[float], unit: str, component: str, included: str, notes: str) -> dict[str, Any]:
    return {
        "component": component,
        "mean": float(statistics.mean(values)) if values else np.nan,
        "median": float(statistics.median(values)) if values else np.nan,
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
        "unit": unit,
        "included_in_operational_latency": included,
        "notes": notes,
    }


def stage1_results() -> pd.DataFrame:
    summary = pd.read_csv(STAGE1_SUMMARY).iloc[0]
    calibration = pd.read_csv(STAGE1_CALIBRATION).iloc[0]
    stability = pd.read_csv(STAGE1_STABILITY)
    sweep = pd.read_csv(STAGE1_SWEEP)
    phase_e_threshold = float(summary["proposed_stage1_threshold"])
    phase_e_row = sweep[
        sweep["calibration_method"].eq(str(summary["calibration_method"]))
        & sweep["level"].eq("window")
        & np.isclose(sweep["threshold"].astype(float), phase_e_threshold)
    ].iloc[0]
    w1 = pd.read_csv(STAGE1_W1_RESULTS)
    w1_selected = w1[w1["decision_rule"].eq("W1_TRAIN_CV_PROPOSED_THRESHOLD")].iloc[0]
    w1_stability = pd.read_csv(STAGE1_W1_STABILITY)
    rows = [
        {
            "phase": "E",
            "result_type": "TRAIN_CV_PROPOSED_THRESHOLD",
            "decision_rule": "p_normal >= tau => NORMAL else INCIDENT",
            "threshold_source": summary["threshold_source"],
            "tau": float(summary["proposed_stage1_threshold"]),
            "default_tau": float(summary["default_threshold"]),
            "fold_thresholds": json.dumps(stability["optimal_threshold"].round(6).tolist()),
            "fold_threshold_min": float(stability["optimal_threshold"].min()),
            "fold_threshold_median": float(stability["optimal_threshold"].median()),
            "fold_threshold_max": float(stability["optimal_threshold"].max()),
            "normal_precision": float(summary["normal_precision_proposed"]),
            "normal_recall": float(summary["normal_recall_proposed"]),
            "normal_f1": float(summary["normal_f1_proposed"]),
            "incident_recall": float(phase_e_row["incident_recall"]),
            "false_normal_incident_rate": float(summary["false_normal_rate_proposed"]),
            "roc_auc": float(calibration["roc_auc"]),
            "normal_pr_auc": float(calibration["pr_auc_normal"]),
            "validation_loaded": bool(summary["validation_loaded"]),
            "holdout_loaded": bool(summary["holdout_loaded"]),
            "recommendation": "STAGE1_REQUIRES_DIFFERENT_FORMULATION",
            "tau_threshold_used_in_final_k1": "NO",
            "source_artifact": str(STAGE1_SUMMARY),
            "notes": "Threshold selected with TRAIN grouped CV only; Normal recall/F1 remained very weak.",
        },
        {
            "phase": "E2",
            "result_type": "W1_CLASS_GROUP_BALANCED_THRESHOLD",
            "decision_rule": "class/group weighted Stage 1 p_normal threshold",
            "threshold_source": w1_selected["threshold_source"],
            "tau": float(w1_selected["threshold"]),
            "default_tau": 0.50,
            "fold_thresholds": json.dumps(w1_stability["optimal_threshold"].round(6).tolist()),
            "fold_threshold_min": float(w1_stability["optimal_threshold"].min()),
            "fold_threshold_median": float(w1_stability["optimal_threshold"].median()),
            "fold_threshold_max": float(w1_stability["optimal_threshold"].max()),
            "normal_precision": float(w1_selected["normal_precision"]),
            "normal_recall": float(w1_selected["normal_recall"]),
            "normal_f1": float(w1_selected["normal_f1"]),
            "incident_recall": float(w1_selected["incident_recall"]),
            "false_normal_incident_rate": float(w1_selected["false_normal_rate"]),
            "roc_auc": float(w1_selected["roc_auc"]),
            "normal_pr_auc": float(w1_selected["normal_pr_auc"]),
            "validation_loaded": bool(w1_selected["validation_loaded"]),
            "holdout_loaded": bool(w1_selected["holdout_loaded"]),
            "recommendation": str(w1_selected["recommendation"]),
            "tau_threshold_used_in_final_k1": "NO",
            "source_artifact": str(STAGE1_W1_RESULTS),
            "notes": "Weighting improved ROC-AUC but Normal PR-AUC stayed weak and false-NORMAL incident risk remained too high.",
        },
    ]
    return write_csv(DOCS / "stage1_threshold_results_v1.csv", rows)


def benchmark_latency(repetitions: int = 150) -> tuple[pd.DataFrame, pd.DataFrame]:
    PERF.mkdir(parents=True, exist_ok=True)
    oof = pd.read_parquet(K1_WINDOW_PROBS)
    structural = pd.read_parquet(TRAIN_V4)
    predictions = pd.read_parquet(K1_INCIDENT_PREDICTIONS)
    selected = predictions[predictions["candidate_id"].eq("K1-M2_XGB_K1-TEMPORAL")].copy()
    if selected.empty:
        raise RuntimeError("Missing K1-M2_XGB_K1-TEMPORAL TRAIN prediction fixture")
    if set(oof["true_class"].unique()) - {"HIJACK", "LEAK", "OUTAGE"}:
        raise RuntimeError("Non-incident labels found in TRAIN K1 OOF probabilities")

    incident_sizes = oof.groupby("incident_uid").size()
    representative_uids = sorted(
        {
            incident_sizes.idxmin(),
            (incident_sizes - incident_sizes.quantile(0.50)).abs().idxmin(),
            (incident_sizes - incident_sizes.quantile(0.95)).abs().idxmin(),
            incident_sizes.idxmax(),
        }
    )
    fixture = oof[oof["incident_uid"].isin(representative_uids)].copy()
    fixture_predictions = selected[selected["incident_uid"].isin(representative_uids)].copy()
    n_windows = len(fixture)
    n_incidents = fixture["incident_uid"].nunique()

    level1_average_ms: list[float] = []
    meta_ms: list[float] = []
    level2_rank_ms: list[float] = []
    end_to_end_ms: list[float] = []
    probs = fixture[["p_hijack", "p_leak", "p_outage"]].to_numpy()
    stacked = np.stack([probs, probs, probs, probs, probs], axis=0)
    for _ in range(repetitions):
        start = time.perf_counter_ns()
        averaged = stacked.mean(axis=0)
        level1_done = time.perf_counter_ns()
        fixture_copy = fixture.copy()
        fixture_copy[["p_hijack", "p_leak", "p_outage"]] = averaged
        _ = build_meta_frame(fixture_copy, structural)
        meta_done = time.perf_counter_ns()
        _ = ranked_frame(fixture_predictions)
        level2_done = time.perf_counter_ns()
        level1_average_ms.append((level1_done - start) / 1_000_000)
        meta_ms.append((meta_done - level1_done) / 1_000_000)
        level2_rank_ms.append((level2_done - meta_done) / 1_000_000)
        end_to_end_ms.append((level2_done - start) / 1_000_000)

    rows = [
        summarize_ms([v / n_windows for v in level1_average_ms], "milliseconds/window", "Level-1 XGBoost ensemble probability averaging", "YES_AFTER_FEATURE_AVAILABILITY", "Measures arithmetic averaging of five cached TRAIN first-level probability streams; model-binary prediction is not re-run because final models are not serialized and retraining is prohibited."),
        summarize_ms([v / n_incidents for v in meta_ms], "milliseconds/incident", "K1 meta-feature construction", "YES_AFTER_FEATURE_AVAILABILITY", f"TRAIN-only fixture with {n_incidents} incidents and {n_windows} windows; uses frozen meta-feature code."),
        summarize_ms([v / n_incidents for v in level2_rank_ms], "milliseconds/incident", "Level-2 XGBoost output ranking", "YES_AFTER_FEATURE_AVAILABILITY", "Uses cached TRAIN K1 probabilities to measure final argmax/ranking handling; model-binary Level-2 prediction is documented from runtime history."),
        summarize_ms([v / n_incidents for v in end_to_end_ms], "milliseconds/incident", "Complete measured K1 computational path from probabilities to ranking", "YES_AFTER_FEATURE_AVAILABILITY", "Excludes feature computation and XGBoost model-binary prediction time; see runtime history."),
    ]
    latency = pd.DataFrame(rows)
    latency["repetitions"] = repetitions
    latency["train_fixture_incidents"] = n_incidents
    latency["train_fixture_windows"] = n_windows
    latency["windows_per_second_approx"] = 1000.0 / latency["mean"].replace(0, np.nan)
    latency["incidents_per_second_approx"] = 1000.0 / latency["mean"].replace(0, np.nan)
    latency["evidence_type"] = "MEASURED_TRAIN_FIXTURE"
    latency["python_version"] = sys.version.split()[0]
    latency["xgboost_version"] = getattr(xgboost, "__version__", "UNAVAILABLE")
    latency["platform"] = platform.platform()
    latency["cpu"] = platform.processor() or platform.machine()
    latency["thread_count"] = os.cpu_count()
    latency["model_loaded_state"] = "MODEL_ALREADY_LOADED_OR_CACHED_PROBABILITIES"
    latency.to_csv(PERF / "final_k1_inference_latency_v1.csv", index=False)

    model_history = runtime_history()
    return latency, model_history


def runtime_history() -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    if BASELINE_RESULTS.exists():
        baseline = pd.read_csv(BASELINE_RESULTS)
        for _, row in baseline.iterrows():
            rows.append(
                {
                    "phase": "Baseline",
                    "artifact": str(BASELINE_RESULTS),
                    "model_or_component": row["experiment_id"],
                    "runtime_type": "TRAINING_TIME",
                    "mean_seconds": row.get("train_seconds_mean", ""),
                    "unit": "seconds/fold-fit",
                    "notes": "Historical runtime recorded during TRAIN grouped-CV baseline.",
                }
            )
            rows.append(
                {
                    "phase": "Baseline",
                    "artifact": str(BASELINE_RESULTS),
                    "model_or_component": row["experiment_id"],
                    "runtime_type": "INFERENCE_TIME",
                    "mean_seconds": row.get("inference_seconds_mean", ""),
                    "unit": "seconds/fold-prediction",
                    "notes": "Historical runtime recorded during TRAIN grouped-CV baseline.",
                }
            )
    if RF_H2_RESULTS.exists():
        rf = pd.read_csv(RF_H2_RESULTS)
        for _, row in rf.iterrows():
            rows.append(
                {
                    "phase": "H/H2",
                    "artifact": str(RF_H2_RESULTS),
                    "model_or_component": row["candidate_id"],
                    "runtime_type": "TRAINING_AND_CV_RUNTIME",
                    "mean_seconds": row.get("runtime_seconds", ""),
                    "unit": "seconds/run",
                    "notes": "Historical RF runtime; artifact does not separate fit and inference.",
                }
            )
    if XGB_I2_RESULTS.exists():
        xgb = pd.read_csv(XGB_I2_RESULTS)
        for _, row in xgb.iterrows():
            rows.append(
                {
                    "phase": "I/I2",
                    "artifact": str(XGB_I2_RESULTS),
                    "model_or_component": row["candidate_id"],
                    "runtime_type": "TRAINING_AND_CV_RUNTIME",
                    "mean_seconds": row.get("runtime_seconds", ""),
                    "unit": "seconds/run",
                    "notes": "Historical XGBoost TRAIN grouped-CV runtime.",
                }
            )
            rows.append(
                {
                    "phase": "I/I2",
                    "artifact": str(XGB_I2_RESULTS),
                    "model_or_component": row["candidate_id"],
                    "runtime_type": "INFERENCE_TIME",
                    "mean_seconds": row.get("inference_time_seconds", ""),
                    "unit": "seconds/run",
                    "notes": "Historical XGBoost inference time from TRAIN grouped-CV artifact.",
                }
            )
    if K1_RESULTS.exists():
        k1 = pd.read_csv(K1_RESULTS)
        for _, row in k1.iterrows():
            rows.append(
                {
                    "phase": "K1",
                    "artifact": str(K1_RESULTS),
                    "model_or_component": row["candidate_id"],
                    "runtime_type": "TRAINING_TIME",
                    "mean_seconds": row.get("mean_fit_time_seconds", ""),
                    "unit": "seconds/fold-fit",
                    "notes": "Historical runtime recorded during TRAIN-only K1 experiment.",
                }
            )
            rows.append(
                {
                    "phase": "K1",
                    "artifact": str(K1_RESULTS),
                    "model_or_component": row["candidate_id"],
                    "runtime_type": "INFERENCE_TIME",
                    "mean_seconds": row.get("mean_inference_time_seconds", ""),
                    "unit": "seconds/fold-test-prediction",
                    "notes": "Historical runtime recorded during TRAIN-only K1 experiment.",
                }
            )
    return write_csv(DOCS / "model_runtime_history_v1.csv", rows)


def write_docs(stage1: pd.DataFrame, latency: pd.DataFrame) -> None:
    schema = read_yaml(K1_SCHEMA)
    final = read_yaml(FINAL_RESULT)
    phase_e = stage1[stage1["phase"].eq("E")].iloc[0]
    phase_e2 = stage1[stage1["phase"].eq("E2")].iloc[0]
    measured_total = latency[latency["component"].eq("Complete measured K1 computational path from probabilities to ranking")].iloc[0]
    level1 = latency[latency["component"].str.contains("Level-1", regex=False)].iloc[0]
    meta = latency[latency["component"].eq("K1 meta-feature construction")].iloc[0]
    level2 = latency[latency["component"].str.contains("Level-2", regex=False)].iloc[0]

    (DOCS / "stage1_threshold_lineage_v1.md").write_text(
        f"""# Stage 1 Threshold Lineage v1

Stage 1 tau was intended for the experimental NORMAL-vs-INCIDENT gate: classify a five-minute window as NORMAL when `P(NORMAL) >= tau`, otherwise INCIDENT.

It was never part of Stage 2 Hijack/Leak/Outage classification. The final K1 primary system performs multiclass incident classification/ranking with `P(Hijack)`, `P(Leak)`, and `P(Outage)`.

Authoritative Phase E recovered values:

- TRAIN-CV proposed tau: `{phase_e['tau']:.2f}`
- fold thresholds: `{phase_e['fold_thresholds']}`
- ROC-AUC: `{phase_e['roc_auc']:.6f}`
- NORMAL PR-AUC: `{phase_e['normal_pr_auc']:.6f}`
- NORMAL precision/recall/F1: `{phase_e['normal_precision']:.6f}` / `{phase_e['normal_recall']:.6f}` / `{phase_e['normal_f1']:.6f}`
- INCIDENT recall: `{phase_e['incident_recall']:.6f}`
- false-NORMAL incident rate: `{phase_e['false_normal_incident_rate']:.6f}`

Phase E2 W1 class/group weighting:

- proposed W1 tau: `{phase_e2['tau']:.2f}`
- fold thresholds: `{phase_e2['fold_thresholds']}`
- ROC-AUC: `{phase_e2['roc_auc']:.6f}`
- NORMAL PR-AUC: `{phase_e2['normal_pr_auc']:.6f}`
- false-NORMAL incident rate: `{phase_e2['false_normal_incident_rate']:.6f}`

The issue was not simply threshold selection. The probability distributions lacked sufficient NORMAL/INCIDENT discrimination: ROC-AUC improved under W1, but NORMAL PR-AUC stayed very weak and false-NORMAL incident risk remained too high.

An earlier tau chosen using Holdout performance is treated as `THRESHOLD_SELECTION_LEAKAGE_RISK`. The corrected methodology derived threshold candidates with TRAIN grouped CV only. Since Stage 1 remained unresolved, no Stage 1 tau entered the final K1 production architecture.

Final status: `UNRESOLVED_EXPERIMENTAL_AUXILIARY`.

`tau_threshold_used_in_final_k1 = NO`
""",
        encoding="utf-8",
    )

    (DOCS / "final_k1_latency_summary_v1.md").write_text(
        f"""# Final K1 Latency Summary v1

This benchmark is TRAIN-only and does not recompute Validation or Final Holdout performance.

The system uses non-overlapping five-minute analytical windows. A window cannot be fully calculated until its observation interval has been collected. Operational latency is therefore:

`observation-time requirement + feature computation + model inference`

The measured warm computational path uses cached TRAIN first-level probabilities and frozen K1 meta-feature construction because serialized final XGBoost model binaries are not present in the repository and retraining is prohibited in Phase N.

Measured warm fixture:

- Level-1 probability averaging mean/median/p95: `{level1['mean']:.6f}` / `{level1['median']:.6f}` / `{level1['p95']:.6f}` ms/window
- K1 meta-feature construction mean/median/p95: `{meta['mean']:.6f}` / `{meta['median']:.6f}` / `{meta['p95']:.6f}` ms/incident
- Level-2 probability ranking mean/median/p95: `{level2['mean']:.6f}` / `{level2['median']:.6f}` / `{level2['p95']:.6f}` ms/incident
- Complete measured path mean/median/p95: `{measured_total['mean']:.6f}` / `{measured_total['median']:.6f}` / `{measured_total['p95']:.6f}` ms/incident

Classification: `POST_WINDOW_INCIDENT_CLASSIFICATION`; computationally fast after feature availability, but the current architecture assumes the configured incident observation window has been collected.
""",
        encoding="utf-8",
    )

    (DOCS / "detection_vs_classification_scope_v1.md").write_text(
        f"""# Detection vs Classification Scope v1

Question: Is this NORMAL or INCIDENT?

Status: `UNRESOLVED_EXPERIMENTAL_AUXILIARY`.

Question: Given an observed BGP incident, what incident type is most likely?

Output: ranked `Hijack / Leak / Outage` probabilities from the final K1 system.

The final primary system should not be described as proving general abnormal-event detection. It is a supervised incident-type classifier/ranker for already observed BGP incident windows.

Final K1 decision rule: Top-1 is `argmax P(class)`. Ranking is descending `P(Hijack), P(Leak), P(Outage)`. No manually selected tau is used.
""",
        encoding="utf-8",
    )

    min_windows = "1 window is computationally representable; with 1-2 windows the deterministic segmentation falls back to EARLY/LATE, while the frozen schema is designed for complete incident observation windows."
    (DOCS / "professor_tau_and_latency_answers_v1.md").write_text(
        f"""# Professor Tau and Latency Answers v1

No manually selected tau is used in the final Hijack/Leak/Outage K1 classifier. Tau belonged to the experimental Stage 1 NORMAL-vs-INCIDENT gate, which remains `UNRESOLVED_EXPERIMENTAL_AUXILIARY`.

The final K1 system waits for non-overlapping five-minute incident windows to be available, computes 44 Behavioral + 14 CAIDA + 16 RPKI features, scores windows with the first-level XGBoost ensemble, builds 74 K1 incident meta-features, and ranks Hijack/Leak/Outage with the second-level XGBoost configuration hash `{final['second_level_parameter_hash']}`.

Temporal requirement: `{schema.get('temporal_segmentation')}`. Minimum representation note: {min_windows}

Concise answer: after the required five-minute observation windows and their features are available, the warm K1 computational classification/ranking step is measured in milliseconds per incident on the TRAIN fixture. Operational diagnosis time should be described as post-window incident classification rather than instant detection, because feature availability depends on collecting the configured observation interval.
""",
        encoding="utf-8",
    )

    table_rows = [
        {"component": "5-minute analytical window", "mean": "N/A", "median": "N/A", "p95": "N/A", "p99": "N/A", "unit": "minutes", "included_in_operational_latency": "YES", "notes": "Observation interval; a window is complete only after five minutes of data collection."},
        {"component": "feature computation", "mean": "N/A", "median": "N/A", "p95": "N/A", "p99": "N/A", "unit": "N/A", "included_in_operational_latency": "YES", "notes": "Not benchmarked in Phase N; depends on MRT parsing/cache availability."},
    ]
    table_rows.extend(latency[["component", "mean", "median", "p95", "p99", "unit", "included_in_operational_latency", "notes"]].to_dict("records"))
    table_rows.append({"component": "operational observation requirement", "mean": "varies", "median": "varies", "p95": "varies", "p99": "varies", "unit": "minutes/windows", "included_in_operational_latency": "YES", "notes": "Depends on incident window count; do not conflate with warm model inference."})
    write_csv(DOCS / "model_latency_table_v1.csv", table_rows)


def update_master_index_reference() -> None:
    index = DOCS / "MASTER_PRAXIS_EXPERIMENTAL_RECORD_INDEX_v1.md"
    if not index.exists():
        return
    text = index.read_text(encoding="utf-8")
    line = "- `docs/professor_tau_and_latency_answers_v1.md`: Phase N advisor-facing tau and latency answers."
    if line not in text:
        index.write_text(text.rstrip() + "\n" + line + "\n", encoding="utf-8")


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    nb = {
        "cells": [
            {"cell_type": "markdown", "metadata": {}, "source": ["# Phase N - Tau Threshold and Final Model Latency\n", "\n", "Documentation/measurement only. Does not train models or evaluate Validation/Holdout.\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["import pandas as pd\n", "from pathlib import Path\n", "docs = Path('../docs')\n", "perf = Path('../data/performance')\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["pd.read_csv(docs / 'stage1_threshold_results_v1.csv')\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["pd.read_csv(perf / 'final_k1_inference_latency_v1.csv')\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["pd.read_csv(docs / 'model_latency_table_v1.csv')\n"]},
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(nb, indent=2), encoding="utf-8")


def run_phase_n(repetitions: int = 150) -> dict[str, Any]:
    stage1 = stage1_results()
    latency, history = benchmark_latency(repetitions=repetitions)
    write_docs(stage1, latency)
    update_master_index_reference()
    write_notebook()
    return {
        "tau_used_in_final_k1": "NO",
        "stage1_status": "UNRESOLVED_EXPERIMENTAL_AUXILIARY",
        "latency_rows": int(len(latency)),
        "runtime_history_rows": int(len(history)),
        "repetitions": repetitions,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Phase N tau lineage and TRAIN-only K1 latency evidence.")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--repetitions", type=int, default=150)
    args = parser.parse_args()
    if args.run:
        print(json.dumps(run_phase_n(args.repetitions), indent=2, sort_keys=True))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
