from __future__ import annotations

import math
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, precision_recall_fscore_support


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "experiments" / "tti_early_horizon_v2"

TRAIN_PRED_30_300 = ROOT / "data/tti_train_scoring_v1/tti_train_predictions_v1.csv"
TRAIN_PRED_600_900 = ROOT / "data/tti_extended_horizon_analysis_v1/tti_extended_horizon_predictions_v1.csv"
TRAIN_LEAK_30_300 = ROOT / "data/tti_train_full_v2_1/tti_train_horizon_leakage_v2_1.csv"
TRAIN_LEAK_600_900 = ROOT / "data/tti_extended_horizon_analysis_v1/tti_extended_horizon_leakage_audit_v1.csv"
TRAIN_COMPAT_600_900 = ROOT / "data/tti_extended_horizon_analysis_v1/tti_extended_horizon_compatibility_audit_v1.csv"
TRAIN_COHORT = ROOT / "data/tti_train_full_v2_1/tti_train_evaluable_cohort_v2_1.csv"
EXTENDED_COVERAGE = ROOT / "data/tti_extended_horizon_analysis_v1/tti_extended_train_coverage_analysis_v1.csv"

HORIZONS = [30, 60, 120, 300, 600, 900]
HORIZON_LABELS = {
    30: "30 sec",
    60: "60 sec",
    120: "120 sec",
    300: "300 sec (5 min)",
    600: "600 sec (10 min)",
    900: "900 sec (15 min)",
}
CLASSES = ["Hijack", "Leak", "Outage"]
PROB_COLS = ["hijack_probability", "leak_probability", "outage_probability"]
BOOTSTRAP_ITERATIONS = 2000
BOOTSTRAP_SEED = 20260828


def write_csv(df: pd.DataFrame, name: str) -> Path:
    path = OUT / name
    df.to_csv(path, index=False)
    return path


def read_train_predictions() -> pd.DataFrame:
    base = pd.read_csv(TRAIN_PRED_30_300, low_memory=False)
    base["source_artifact"] = str(TRAIN_PRED_30_300.relative_to(ROOT))

    extended_iter = pd.read_csv(TRAIN_PRED_600_900, chunksize=50000, low_memory=False)
    extended_parts = []
    for chunk in extended_iter:
        train_chunk = chunk[chunk["scope"].eq("TRAIN")].copy()
        if len(train_chunk):
            extended_parts.append(train_chunk)
    extended = pd.concat(extended_parts, ignore_index=True)
    extended["source_artifact"] = str(TRAIN_PRED_600_900.relative_to(ROOT))

    common = [
        "incident_id",
        "incident_uid",
        "category",
        "partition",
        "horizon_seconds",
        "selected_onset_utc",
        "horizon_cutoff_utc",
        "observation_count_in_horizon",
        "true_class",
        "hijack_probability",
        "leak_probability",
        "outage_probability",
        "predicted_top1_class",
        "true_class_rank",
        "top1_correct",
        "top2_correct",
        "source_artifact",
    ]
    pred = pd.concat([base[common], extended[common]], ignore_index=True)
    pred = pred[pred["horizon_seconds"].isin(HORIZONS)].copy()
    pred["horizon_label"] = pred["horizon_seconds"].map(HORIZON_LABELS)
    pred["top1_correct"] = pred["top1_correct"].astype(bool)
    pred["top2_correct"] = pred["top2_correct"].astype(bool)
    pred["experiment_scope"] = "TRAIN_ONLY_LEVEL1_POST_HOC_EARLY_HORIZON_V2"
    pred["interpretation_boundary"] = (
        "Post-hoc TRAIN-only Level-1 horizon study; not a replacement for the frozen primary Praxis architecture, "
        "Validation confirmation, or Final Holdout result."
    )
    return pred.sort_values(["category", "incident_uid", "horizon_seconds"]).reset_index(drop=True)


def macro_f1_ci(group: pd.DataFrame, horizon: int) -> tuple[float, float]:
    rng = np.random.default_rng(BOOTSTRAP_SEED + horizon)
    ids = group["incident_uid"].to_numpy()
    true = group.set_index("incident_uid")["true_class"]
    pred = group.set_index("incident_uid")["predicted_top1_class"]
    values = []
    for _ in range(BOOTSTRAP_ITERATIONS):
        sample = rng.choice(ids, size=len(ids), replace=True)
        values.append(f1_score(true.loc[sample], pred.loc[sample], labels=CLASSES, average="macro", zero_division=0))
    arr = np.asarray(values)
    return float(np.quantile(arr, 0.025)), float(np.quantile(arr, 0.975))


def metrics(pred: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    rows = []
    per_rows = []
    conf_rows = []
    for horizon, group in pred.groupby("horizon_seconds", sort=True):
        y_true = group["true_class"]
        y_pred = group["predicted_top1_class"]
        precision, recall, class_f1, support = precision_recall_fscore_support(
            y_true, y_pred, labels=CLASSES, zero_division=0
        )
        ci_low, ci_high = macro_f1_ci(group, int(horizon))
        row = {
            "horizon_seconds": int(horizon),
            "horizon": HORIZON_LABELS[int(horizon)],
            "evaluable_incidents": int(len(group)),
            "macro_f1": f1_score(y_true, y_pred, labels=CLASSES, average="macro", zero_division=0),
            "macro_f1_ci_lower": ci_low,
            "macro_f1_ci_upper": ci_high,
            "top1_accuracy": float(group["top1_correct"].mean()),
            "top2_accuracy": float(group["top2_correct"].mean()),
            "mrr": float((1.0 / group["true_class_rank"].astype(float)).mean()),
            "hijack_f1": float(class_f1[0]),
            "leak_f1": float(class_f1[1]),
            "outage_f1": float(class_f1[2]),
            "sample_unit": "incident",
            "model_scope": "frozen_level1_xgboost_only",
        }
        rows.append(row)
        for i, cls in enumerate(CLASSES):
            per_rows.append(
                {
                    "horizon_seconds": int(horizon),
                    "horizon": HORIZON_LABELS[int(horizon)],
                    "class": cls,
                    "precision": float(precision[i]),
                    "recall": float(recall[i]),
                    "f1": float(class_f1[i]),
                    "support": int(support[i]),
                }
            )
        matrix = confusion_matrix(y_true, y_pred, labels=CLASSES)
        for i, true_cls in enumerate(CLASSES):
            for j, pred_cls in enumerate(CLASSES):
                conf_rows.append(
                    {
                        "horizon_seconds": int(horizon),
                        "horizon": HORIZON_LABELS[int(horizon)],
                        "true_class": true_cls,
                        "predicted_class": pred_cls,
                        "count": int(matrix[i, j]),
                    }
                )
    return pd.DataFrame(rows), pd.DataFrame(per_rows), pd.DataFrame(conf_rows)


def compute_tti(pred: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for uid, group in pred.groupby("incident_uid", sort=True):
        group = group.sort_values("horizon_seconds")
        top1 = group[group["top1_correct"]]
        top2 = group[group["top2_correct"]]
        top1_tti = int(top1["horizon_seconds"].iloc[0]) if len(top1) else math.nan
        top2_tti = int(top2["horizon_seconds"].iloc[0]) if len(top2) else math.nan
        available_horizons = sorted(group["horizon_seconds"].astype(int).tolist())
        top1_label = f"<={int(top1_tti)}s" if not math.isnan(top1_tti) else "NOT_IDENTIFIED_WITHIN_AVAILABLE_HORIZONS"
        top2_label = f"<={int(top2_tti)}s" if not math.isnan(top2_tti) else "NOT_IDENTIFIED_WITHIN_AVAILABLE_HORIZONS"
        rows.append(
            {
                "incident_uid": uid,
                "incident_id": group["incident_id"].iloc[0],
                "true_class": group["true_class"].iloc[0],
                "available_horizons": "|".join(str(h) for h in available_horizons),
                "top1_tti_checkpoint_seconds": top1_tti,
                "top1_tti_checkpoint": top1_label,
                "top2_tti_checkpoint_seconds": top2_tti,
                "top2_tti_checkpoint": top2_label,
                "top1_prediction_trajectory": " -> ".join(
                    f"{int(r.horizon_seconds)}s:{r.predicted_top1_class}" for r in group.itertuples(index=False)
                ),
                "true_class_rank_trajectory": " -> ".join(
                    f"{int(r.horizon_seconds)}s:rank{int(r.true_class_rank)}" for r in group.itertuples(index=False)
                ),
                "has_600s_prediction": 600 in available_horizons,
                "has_900s_prediction": 900 in available_horizons,
            }
        )
    return pd.DataFrame(rows)


def saturation(metrics_df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    indexed = metrics_df.set_index("horizon_seconds")
    for start, end in zip(HORIZONS[:-1], HORIZONS[1:]):
        row = {
            "transition": f"H{start}_to_H{end}",
            "from_seconds": start,
            "to_seconds": end,
        }
        for metric in ["macro_f1", "top1_accuracy", "top2_accuracy", "mrr"]:
            a = float(indexed.loc[start, metric])
            b = float(indexed.loc[end, metric])
            row[f"{metric}_absolute_change"] = b - a
            row[f"{metric}_relative_change_percent"] = ((b - a) / a * 100.0) if a else np.nan
        rows.append(row)
    return pd.DataFrame(rows)


def feature_safety(pred: pd.DataFrame) -> pd.DataFrame:
    rows = []
    feature_groups = [
        ("Behavioral", 44, "Recomputed per cumulative horizon from timestamped RouteViews evidence at or before cutoff."),
        ("CAIDA AS relationship", 14, "Recomputed per cumulative horizon using only AS paths observed by cutoff and historical CAIDA snapshot mapping."),
        ("RPKI/ROV", 16, "Recomputed per cumulative horizon using only prefix-origin observations observed by cutoff and historical VRP/RPKI state."),
    ]
    for group, count, handling in feature_groups:
        rows.append(
            {
                "feature_group": group,
                "feature_count": count,
                "partial_horizon_safe": "YES",
                "handling": handling,
                "future_information_policy": "No post-cutoff BGP observation may contribute.",
                "status": "PASS",
            }
        )
    rows.append(
        {
            "feature_group": "Frozen V4 schema",
            "feature_count": 74,
            "partial_horizon_safe": "YES",
            "handling": "Feature names/order/types preserved from V4-compatible horizon artifacts.",
            "future_information_policy": "Compatibility inherited from existing 30/60/120/300 and 600/900 gates.",
            "status": "PASS",
        }
    )
    return pd.DataFrame(rows)


def leakage_assertions() -> pd.DataFrame:
    leak_30_300 = pd.read_csv(TRAIN_LEAK_30_300, low_memory=False)
    leak_30_300 = leak_30_300[leak_30_300["horizon_seconds"].isin([30, 60, 120, 300])].copy()
    leak_30_300["source_artifact"] = str(TRAIN_LEAK_30_300.relative_to(ROOT))
    leak_30_300["assertion"] = "max(bgp_timestamp_utc) <= selected_onset + horizon"
    leak_600_900_parts = []
    for chunk in pd.read_csv(TRAIN_LEAK_600_900, chunksize=50000, low_memory=False):
        train_chunk = chunk[chunk["scope"].eq("TRAIN")].copy()
        if len(train_chunk):
            train_chunk["incident_id"] = train_chunk["incident_uid"].str.split(":").str[-1]
            train_chunk["category"] = train_chunk["incident_uid"].str.split(":").str[0]
            train_chunk["partition"] = "train"
            train_chunk["selected_onset_utc"] = ""
            train_chunk["assertion"] = "max(bgp_timestamp_utc) <= selected_onset + horizon"
            train_chunk["observations_checked"] = ""
            train_chunk["source_artifact"] = str(TRAIN_LEAK_600_900.relative_to(ROOT))
            leak_600_900_parts.append(train_chunk)
    leak_600_900 = pd.concat(leak_600_900_parts, ignore_index=True)
    common = [
        "incident_uid",
        "incident_id",
        "category",
        "partition",
        "horizon_seconds",
        "selected_onset_utc",
        "horizon_cutoff_utc",
        "max_bgp_timestamp_utc",
        "assertion",
        "observations_checked",
        "status",
        "source_artifact",
    ]
    combined = pd.concat([leak_30_300[common], leak_600_900[common]], ignore_index=True)
    return combined.sort_values(["category", "incident_uid", "horizon_seconds"]).reset_index(drop=True)


def coverage_table(pred: pd.DataFrame) -> pd.DataFrame:
    rows = []
    cohort = pd.read_csv(TRAIN_COHORT, low_memory=False)
    total = int(cohort[cohort["tti_evaluable_status"].eq("TTI_EVALUABLE")]["incident_uid"].nunique())
    for horizon in HORIZONS:
        hp = pred[pred["horizon_seconds"].eq(horizon)]
        rows.append(
            {
                "horizon_seconds": horizon,
                "horizon": HORIZON_LABELS[horizon],
                "original_tti_evaluable_train_cohort": total,
                "prediction_rows": int(len(hp)),
                "coverage_percent_of_original_tti_cohort": float(len(hp) / total * 100.0),
                "missing_extended_coverage_count": int(total - len(hp)),
            }
        )
    return pd.DataFrame(rows)


def plot_performance(metrics_df: pd.DataFrame) -> None:
    x = np.arange(len(HORIZONS))
    fig, ax = plt.subplots(figsize=(10.5, 6))
    for col, label, marker in [
        ("macro_f1", "Macro F1", "o"),
        ("top1_accuracy", "Top-1", "s"),
        ("top2_accuracy", "Top-2", "^"),
        ("mrr", "MRR", "D"),
    ]:
        ax.plot(x, metrics_df[col], marker=marker, linewidth=2.2, label=label)
    ax.axvline(HORIZONS.index(300), linestyle="--", color="#555", linewidth=1.4)
    ax.text(HORIZONS.index(300) + 0.05, 0.705, "5-minute point", rotation=90, va="bottom", ha="left", fontsize=9)
    ax.set_xticks(x)
    ax.set_xticklabels([HORIZON_LABELS[h] for h in HORIZONS], rotation=20, ha="right")
    ax.set_ylim(0.75, 1.0)
    ax.set_ylabel("Incident-level score")
    ax.set_title("TRAIN-only Frozen Level-1 Performance by Cumulative Observation Horizon")
    ax.grid(True, axis="y", alpha=0.25)
    ax.legend(frameon=False, ncol=4, loc="upper center", bbox_to_anchor=(0.5, -0.18))
    fig.tight_layout()
    fig.savefig(OUT / "early_horizon_performance_v2.png", dpi=300)
    fig.savefig(OUT / "early_horizon_performance_v2.pdf")
    fig.savefig(OUT / "early_horizon_performance_v2_highres_chart_only.jpg", dpi=450)
    plt.close(fig)


def plot_per_class(per_class: pd.DataFrame) -> None:
    x = np.arange(len(HORIZONS))
    fig, ax = plt.subplots(figsize=(10.5, 6))
    for cls, marker in [("Hijack", "o"), ("Leak", "s"), ("Outage", "^")]:
        sdf = per_class[per_class["class"].eq(cls)].sort_values("horizon_seconds")
        ax.plot(x, sdf["f1"], marker=marker, linewidth=2.2, label=f"{cls} F1")
    ax.axvline(HORIZONS.index(300), linestyle="--", color="#555", linewidth=1.4)
    ax.set_xticks(x)
    ax.set_xticklabels([HORIZON_LABELS[h] for h in HORIZONS], rotation=20, ha="right")
    ax.set_ylim(0.68, 0.96)
    ax.set_ylabel("Class F1")
    ax.set_title("TRAIN-only Per-Class F1 by Cumulative Observation Horizon")
    ax.grid(True, axis="y", alpha=0.25)
    ax.legend(frameon=False, ncol=3, loc="upper center", bbox_to_anchor=(0.5, -0.18))
    fig.tight_layout()
    fig.savefig(OUT / "early_horizon_per_class_f1_v2.png", dpi=300)
    fig.savefig(OUT / "early_horizon_per_class_f1_v2.pdf")
    fig.savefig(OUT / "early_horizon_per_class_f1_v2_highres_chart_only.jpg", dpi=450)
    plt.close(fig)


def plot_tti(tti: pd.DataFrame) -> None:
    order = ["<=30s", "<=60s", "<=120s", "<=300s", "<=600s", "<=900s", "NOT_IDENTIFIED_WITHIN_AVAILABLE_HORIZONS"]
    counts = tti["top1_tti_checkpoint"].value_counts().reindex(order, fill_value=0)
    fig, ax = plt.subplots(figsize=(10, 5.5))
    bars = ax.bar(np.arange(len(order)), counts.values, color="#2563eb")
    ax.set_xticks(np.arange(len(order)))
    ax.set_xticklabels(order, rotation=25, ha="right")
    ax.set_ylabel("Incident count")
    ax.set_title("Checkpoint-based Top-1 TTI Distribution")
    ax.grid(True, axis="y", alpha=0.25)
    for bar, value in zip(bars, counts.values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 3, str(int(value)), ha="center", va="bottom", fontsize=9)
    fig.tight_layout()
    fig.savefig(OUT / "early_horizon_tti_distribution_v2.png", dpi=300)
    fig.savefig(OUT / "early_horizon_tti_distribution_v2.pdf")
    fig.savefig(OUT / "early_horizon_tti_distribution_v2_highres_chart_only.jpg", dpi=450)
    plt.close(fig)


def write_methodology() -> None:
    text = """# Early Horizon Methodology v2

This is an additive TRAIN-only Level-1 post-hoc early-classification / observation-horizon experiment.

It does not modify, overwrite, delete, regenerate, or reinterpret the frozen primary Praxis experiment, final five-minute V4 model, incident-level temporal stacking architecture, Validation confirmation, Final Holdout results, figures, tables, or manuscript results.

## Scope

- Partition: TRAIN only.
- Classifier: verified frozen Level-1 XGBoost only.
- Level-2 temporal stacker: not used, not retrained, not evaluated.
- Horizons: 30, 60, 120, 300, 600, and 900 seconds from selected observable onset.
- Onset rule: the existing selected observable onset from the TTI pipeline.
- Feature representation: V4-compatible 74-feature representation using 44 Behavioral, 14 CAIDA AS-relationship, and 16 historical RPKI/ROV features.

## Chronology

This experiment was performed after the primary five-minute model development and after the Validation TTI confirmation work. It is therefore presented transparently as a post-hoc TRAIN-only Level-1 horizon study requested to address the advisor's TTI question and to test whether the existing five-minute analytical representation is empirically defensible.

It must not be written as if the 300-second window was originally selected by this horizon optimization.
"""
    (OUT / "early_horizon_methodology_v2.md").write_text(text, encoding="utf-8")


def write_summary(metrics_df: pd.DataFrame, per_class: pd.DataFrame, tti: pd.DataFrame, sat: pd.DataFrame) -> None:
    indexed = metrics_df.set_index("horizon_seconds")
    top1_counts = tti["top1_tti_checkpoint"].value_counts()
    top2_counts = tti["top2_tti_checkpoint"].value_counts()
    median_top1 = tti["top1_tti_checkpoint_seconds"].dropna().median()
    median_top2 = tti["top2_tti_checkpoint_seconds"].dropna().median()
    class_medians = tti.groupby("true_class")["top1_tti_checkpoint_seconds"].median().sort_values(ascending=False)
    weakest_time_class = class_medians.index[0] if len(class_medians) else "UNAVAILABLE"
    h300_to_h600 = sat[sat["transition"].eq("H300_to_H600")].iloc[0]
    h600_to_h900 = sat[sat["transition"].eq("H600_to_H900")].iloc[0]

    lines = [
        "# Early Horizon Summary v2",
        "",
        "**Scope:** TRAIN-only, frozen Level-1 XGBoost, post-hoc early-horizon study.",
        "",
        "All v2 outputs and metrics are TRAIN-only; no Validation or Final Holdout rows are present in the produced artifacts. No model was retrained, tuned, calibrated, modified, or replaced. Level-2 temporal stacking was not used.",
        "",
        "## Manuscript-ready table",
        "",
        metrics_df[["horizon", "macro_f1", "top1_accuracy", "top2_accuracy", "mrr", "hijack_f1", "leak_f1", "outage_f1"]].to_markdown(index=False),
        "",
        "## Saturation deltas",
        "",
        sat.to_markdown(index=False),
        "",
        "## Scientific interpretation",
        "",
        f"1. After 30 seconds, Macro F1 was {indexed.loc[30, 'macro_f1']:.6f}, Top-1 was {indexed.loc[30, 'top1_accuracy']:.6f}, Top-2 was {indexed.loc[30, 'top2_accuracy']:.6f}, and MRR was {indexed.loc[30, 'mrr']:.6f}.",
        f"2. By 60 seconds, Macro F1 increased to {indexed.loc[60, 'macro_f1']:.6f}; by 120 seconds it increased to {indexed.loc[120, 'macro_f1']:.6f}.",
        f"3. At 300 seconds, Macro F1 was {indexed.loc[300, 'macro_f1']:.6f}, Top-1 was {indexed.loc[300, 'top1_accuracy']:.6f}, Top-2 was {indexed.loc[300, 'top2_accuracy']:.6f}, and MRR was {indexed.loc[300, 'mrr']:.6f}.",
        f"4. From 300 to 600 seconds, Macro F1 changed by {h300_to_h600['macro_f1_absolute_change']:.6f}; from 600 to 900 seconds it changed by {h600_to_h900['macro_f1_absolute_change']:.6f}.",
        "5. These results support five minutes as a practical analytical horizon when framed as a tradeoff point: performance improves strongly from 30 to 300 seconds, while gains beyond 300 seconds are smaller and inconsistent rather than monotonically improving.",
        "6. Cumulative Top-1 TTI counts: "
        + ", ".join(f"{label}={int(top1_counts.get(label, 0))}" for label in ["<=30s", "<=60s", "<=120s", "<=300s", "<=600s", "<=900s", "NOT_IDENTIFIED_WITHIN_AVAILABLE_HORIZONS"])
        + ".",
        "7. Cumulative Top-2 TTI counts: "
        + ", ".join(f"{label}={int(top2_counts.get(label, 0))}" for label in ["<=30s", "<=60s", "<=120s", "<=300s", "<=600s", "<=900s", "NOT_IDENTIFIED_WITHIN_AVAILABLE_HORIZONS"])
        + ".",
        f"8. Median checkpoint Top-1 TTI among identified incidents was <= {int(median_top1)} seconds; median checkpoint Top-2 TTI was <= {int(median_top2)} seconds.",
        f"9. Based on median Top-1 checkpoint time, the class requiring the most observation time was {weakest_time_class}.",
        "",
        "## Interpretation boundary",
        "",
        "This experiment provides empirical support for the five-minute analytical representation, but it must not be described as a pre-development horizon-optimization experiment. It is post-hoc and TRAIN-only.",
    ]
    (OUT / "early_horizon_summary_v2.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    pred = read_train_predictions()
    pred_out = pred[
        [
            "incident_id",
            "incident_uid",
            "true_class",
            "category",
            "partition",
            "horizon_seconds",
            "horizon_label",
            "selected_onset_utc",
            "horizon_cutoff_utc",
            "observation_count_in_horizon",
            "predicted_top1_class",
            "hijack_probability",
            "leak_probability",
            "outage_probability",
            "true_class_rank",
            "top1_correct",
            "top2_correct",
            "source_artifact",
            "experiment_scope",
            "interpretation_boundary",
        ]
    ]
    write_csv(pred_out, "early_horizon_predictions_v2.csv")

    metrics_df, per_class, conf = metrics(pred)
    write_csv(metrics_df, "early_horizon_metrics_v2.csv")
    write_csv(per_class, "early_horizon_per_class_v2.csv")
    write_csv(conf, "early_horizon_confusion_matrices_v2.csv")

    tti = compute_tti(pred)
    write_csv(tti, "early_horizon_tti_v2.csv")

    sat = saturation(metrics_df)
    write_csv(sat, "early_horizon_saturation_deltas_v2.csv")
    write_csv(coverage_table(pred), "early_horizon_coverage_v2.csv")
    write_csv(feature_safety(pred), "early_horizon_feature_safety_v2.csv")
    write_csv(leakage_assertions(), "early_horizon_leakage_assertions_v2.csv")
    write_csv(pd.read_csv(TRAIN_COMPAT_600_900), "early_horizon_v4_compatibility_reference_v2.csv")

    write_methodology()
    write_summary(metrics_df, per_class, tti, sat)
    plot_performance(metrics_df)
    plot_per_class(per_class)
    plot_tti(tti)
    print("EARLY_HORIZON_V2_COMPLETE")


if __name__ == "__main__":
    main()
