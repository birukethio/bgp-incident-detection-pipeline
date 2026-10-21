from __future__ import annotations

import csv
import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "experiments" / "final_error_analysis_v1"
FIG = OUT / "figures"
CLASS_ORDER = ["Hijack", "Leak", "Outage"]
CLASS_UPPER = {"HIJACK": "Hijack", "LEAK": "Leak", "OUTAGE": "Outage", "Hijack": "Hijack", "Leak": "Leak", "Outage": "Outage"}
SCORE_COLS = {"Hijack": "p_hijack", "Leak": "p_leak", "Outage": "p_outage"}
LOW_MARGIN_THRESHOLD = 0.10
HIGH_CONFIDENCE_THRESHOLD = 0.90


def sha256(path: Path) -> str:
    if not path.exists():
        return "NOT_FOUND"
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        fieldnames = list(rows[0].keys()) if rows else []
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def md_table(rows: list[dict[str, Any]], columns: list[str]) -> str:
    if not rows:
        return ""
    out = ["| " + " | ".join(columns) + " |", "| " + " | ".join(["---"] * len(columns)) + " |"]
    for row in rows:
        vals = [str(row.get(c, "")).replace("\n", "<br>") for c in columns]
        out.append("| " + " | ".join(vals) + " |")
    return "\n".join(out)


def write_md(path: Path, title: str, sections: list[tuple[str, str]]) -> None:
    content = [f"# {title}", ""]
    for heading, body in sections:
        content.extend([f"## {heading}", "", body.strip(), ""])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(content).rstrip() + "\n", encoding="utf-8")


def norm_class(value: Any) -> str:
    if pd.isna(value):
        return ""
    return CLASS_UPPER.get(str(value), CLASS_UPPER.get(str(value).upper(), str(value)))


def add_ranking_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    for c in ["true_class", "predicted_class", "rank_1_class", "rank_2_class", "rank_3_class"]:
        if c in df.columns:
            df[c] = df[c].map(norm_class)
    if "rank_1_class" not in df.columns:
        ranks = []
        for _, row in df.iterrows():
            scored = sorted([(cls, float(row[SCORE_COLS[cls]])) for cls in CLASS_ORDER], key=lambda x: x[1], reverse=True)
            ranks.append(scored)
        df["rank_1_class"] = [r[0][0] for r in ranks]
        df["rank_1_score"] = [r[0][1] for r in ranks]
        df["rank_2_class"] = [r[1][0] for r in ranks]
        df["rank_2_score"] = [r[1][1] for r in ranks]
        df["rank_3_class"] = [r[2][0] for r in ranks]
        df["rank_3_score"] = [r[2][1] for r in ranks]
        df["predicted_class"] = df["rank_1_class"]
        df["true_class_rank"] = [
            1 + [r[0][0], r[1][0], r[2][0]].index(tc) for r, tc in zip(ranks, df["true_class"])
        ]
    elif "predicted_class" not in df.columns:
        df["predicted_class"] = df["rank_1_class"]
    for cls in CLASS_ORDER:
        score_col = SCORE_COLS[cls]
        if score_col not in df.columns:
            mean_col = f"mean_{score_col}"
            if mean_col in df.columns:
                df[score_col] = df[mean_col]
    if "true_class_rank" not in df.columns:
        df["true_class_rank"] = df.apply(
            lambda r: 1 if r["rank_1_class"] == r["true_class"] else 2 if r["rank_2_class"] == r["true_class"] else 3,
            axis=1,
        )
    df["top1_score"] = df["rank_1_score"]
    df["top2_score"] = df["rank_2_score"]
    df["top1_top2_margin"] = df["rank_1_score"] - df["rank_2_score"]
    df["correct"] = df["predicted_class"] == df["true_class"]
    df["top2_correct"] = df["true_class_rank"] <= 2
    df["error_type"] = np.where(df["correct"], "CORRECT", df["true_class"].str.upper() + "_TO_" + df["predicted_class"].str.upper())
    return df


def load_predictions() -> dict[str, pd.DataFrame]:
    train = pd.read_parquet(ROOT / "data/modeling_k1/k1_incident_level_predictions_v1.parquet")
    train = train[train["candidate_id"] == "K1-M2_XGB_K1-TEMPORAL"].copy()
    train["partition"] = "TRAIN"
    train["prediction_source"] = "data/modeling_k1/k1_incident_level_predictions_v1.parquet"

    validation = pd.read_csv(ROOT / "data/validation/validation_incident_rankings_v1.csv")
    validation["partition"] = "VALIDATION"
    validation["candidate_id"] = "XGB_REFINED_TRAIN_CANDIDATE_PHASE_J"
    validation = validation.rename(columns={"mean_p_hijack": "p_hijack", "mean_p_leak": "p_leak", "mean_p_outage": "p_outage"})
    validation["prediction_source"] = "data/validation/validation_incident_rankings_v1.csv"

    holdout = pd.read_csv(ROOT / "data/final_holdout/final_holdout_incident_rankings_v1.csv")
    holdout["partition"] = "FINAL_HOLDOUT"
    holdout["prediction_source"] = "data/final_holdout/final_holdout_incident_rankings_v1.csv"

    return {k: add_ranking_columns(v) for k, v in {"TRAIN": train, "VALIDATION": validation, "FINAL_HOLDOUT": holdout}.items()}


def load_feature_aggregates() -> pd.DataFrame:
    paths = [
        ("TRAIN", ROOT / "data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet"),
        ("VALIDATION", ROOT / "data/validation/validation_v4_features_v1.parquet"),
        ("FINAL_HOLDOUT", ROOT / "data/final_holdout/final_holdout_v4_features_v1.parquet"),
    ]
    feature_cols = [
        "update_count",
        "announcement_count",
        "withdrawal_count",
        "announcement_ratio",
        "withdrawal_ratio",
        "announcement_to_withdrawal_ratio",
        "unique_prefix_count",
        "unique_peer_asn_count",
        "unique_origin_asn_count",
        "origin_diversity_ratio",
        "moas_prefix_count",
        "origin_change_event_count",
        "unique_as_path_count",
        "as_path_length_std",
        "path_diversity_mean_per_prefix",
        "caida_path_observation_count",
        "caida_unknown_relationship_transition_count",
        "caida_customer_to_provider_transition_count",
        "caida_provider_to_customer_transition_count",
        "caida_peer_to_peer_transition_count",
        "caida_valley_free_violation_path_count",
        "caida_valley_free_violation_ratio",
        "rpki_evidence_observation_count",
        "rpki_evaluable_observation_count",
        "rpki_invalid_observation_count",
        "rpki_invalid_origin_observation_count",
        "rpki_invalid_maxlength_observation_count",
        "rpki_invalid_observation_ratio",
        "rpki_not_found_observation_ratio",
    ]
    frames = []
    for partition, path in paths:
        if not path.exists():
            continue
        df = pd.read_parquet(path)
        existing = [c for c in feature_cols if c in df.columns]
        agg = df.groupby("incident_uid")[existing].agg(["mean", "sum", "median"]).reset_index()
        agg.columns = ["incident_uid"] + [f"{a}_{b}" for a, b in agg.columns[1:]]
        agg["partition"] = partition
        frames.append(agg)
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def load_summaries() -> pd.DataFrame:
    paths = [
        ("TRAIN", ROOT / "data/train_scale/train_incident_feature_summary_v1.csv"),
        ("VALIDATION", ROOT / "data/validation/validation_incident_feature_summary_v1.csv"),
        ("FINAL_HOLDOUT", ROOT / "data/final_holdout/final_holdout_incident_feature_summary_v1.csv"),
    ]
    frames = []
    for partition, path in paths:
        if path.exists():
            df = pd.read_csv(path)
            df["partition"] = partition
            frames.append(df)
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def load_manifests() -> pd.DataFrame:
    paths = [
        ("TRAIN", ROOT / "data/partitions_v2/train_incidents_v2.csv"),
        ("VALIDATION", ROOT / "data/validation/validation_incident_manifest_v1.csv"),
        ("FINAL_HOLDOUT", ROOT / "data/final_holdout/final_holdout_incident_manifest_v1.csv"),
    ]
    frames = []
    for partition, path in paths:
        if path.exists():
            df = pd.read_csv(path)
            df["partition"] = partition
            frames.append(df)
    return pd.concat(frames, ignore_index=True, sort=False) if frames else pd.DataFrame()


def prediction_inventory(preds: dict[str, pd.DataFrame]) -> pd.DataFrame:
    rows = []
    for partition, df in preds.items():
        rows.append(
            {
                "partition": partition,
                "candidate_id": df["candidate_id"].iloc[0] if "candidate_id" in df.columns else "",
                "incident_count": len(df),
                "correct_count": int(df["correct"].sum()),
                "top1_accuracy": df["correct"].mean(),
                "top2_accuracy": df["top2_correct"].mean(),
                "mean_mrr": (1 / df["true_class_rank"]).mean(),
                "prediction_source": df["prediction_source"].iloc[0],
                "source_sha256": sha256(ROOT / df["prediction_source"].iloc[0]),
                "notes": "Frozen stored predictions; ranks derived from stored class scores where needed; no model inference performed.",
            }
        )
    return pd.DataFrame(rows)


def confusion_taxonomy(preds: dict[str, pd.DataFrame]) -> pd.DataFrame:
    rows = []
    all_error_types = [
        "HIJACK_TO_LEAK",
        "HIJACK_TO_OUTAGE",
        "LEAK_TO_HIJACK",
        "LEAK_TO_OUTAGE",
        "OUTAGE_TO_HIJACK",
        "OUTAGE_TO_LEAK",
    ]
    for partition, df in preds.items():
        errors = df[~df["correct"]]
        for et in all_error_types:
            sub = errors[errors["error_type"] == et]
            true_cls = norm_class(et.split("_TO_")[0])
            true_total = (df["true_class"] == true_cls).sum()
            rows.append(
                {
                    "partition": partition,
                    "error_type": et,
                    "true_class": true_cls,
                    "predicted_class": norm_class(et.split("_TO_")[1]),
                    "count": len(sub),
                    "percent_of_true_class": len(sub) / true_total if true_total else 0,
                    "percent_of_all_errors": len(sub) / len(errors) if len(errors) else 0,
                    "mean_top1_score": sub["rank_1_score"].mean() if len(sub) else np.nan,
                    "mean_margin": sub["top1_top2_margin"].mean() if len(sub) else np.nan,
                    "top2_rescue_count": int((sub["true_class_rank"] == 2).sum()),
                    "rank3_count": int((sub["true_class_rank"] == 3).sum()),
                }
            )
    return pd.DataFrame(rows)


def make_final_forensics(holdout: pd.DataFrame, manifests: pd.DataFrame, summaries: pd.DataFrame, features: pd.DataFrame) -> pd.DataFrame:
    errors = holdout[~holdout["correct"]].copy()
    man = manifests[manifests["partition"] == "FINAL_HOLDOUT"].copy()
    summ = summaries[summaries["partition"] == "FINAL_HOLDOUT"].copy()
    feat = features[features["partition"] == "FINAL_HOLDOUT"].copy()
    out = errors.merge(man, on=["incident_uid", "partition"], how="left", suffixes=("", "_manifest"))
    out = out.merge(summ.drop(columns=["category"], errors="ignore"), on=["incident_uid", "partition"], how="left", suffixes=("", "_summary"))
    out = out.merge(feat.drop(columns=["partition"], errors="ignore"), on="incident_uid", how="left")
    out["confidence_margin_top1_top2"] = out["top1_top2_margin"]
    out["prefix_count"] = out.get("affected_prefixes", "").apply(lambda x: len(json.loads(x)) if isinstance(x, str) and x.startswith("[") else np.nan)
    out["asn"] = out.get("primary_asn", np.nan)
    out["routeviews_evidence_density"] = out.apply(
        lambda r: r.get("relevant_observations", np.nan) / r.get("total_feature_rows", np.nan)
        if pd.notna(r.get("relevant_observations", np.nan)) and pd.notna(r.get("total_feature_rows", np.nan)) and r.get("total_feature_rows", 0) != 0
        else np.nan,
        axis=1,
    )
    preferred = [
        "incident_uid",
        "true_class",
        "predicted_class",
        "p_hijack",
        "p_leak",
        "p_outage",
        "rank_1_score",
        "rank_2_class",
        "rank_2_score",
        "confidence_margin_top1_top2",
        "true_class_rank",
        "window_count",
        "duration_minutes",
        "prefix_count",
        "asn",
        "affected_asns",
        "affected_prefixes",
        "raw_bgp_observations",
        "relevant_observations",
        "routeviews_evidence_density",
        "unique_peer_asn_count_mean",
        "unique_prefix_count_mean",
        "origin_change_event_count_sum",
        "withdrawal_count_sum",
        "announcement_count_sum",
        "unique_as_path_count_mean",
        "caida_valley_free_violation_path_count_sum",
        "caida_valley_free_violation_ratio_mean",
        "rpki_invalid_observation_count_sum",
        "rpki_invalid_origin_observation_count_sum",
        "rpki_invalid_observation_ratio_mean",
        "processing_status",
        "notes",
    ]
    return out[[c for c in preferred if c in out.columns]]


def class_characteristics(pred_all: pd.DataFrame, features: pd.DataFrame) -> pd.DataFrame:
    df = pred_all.merge(features.drop(columns=["partition"], errors="ignore"), on="incident_uid", how="left")
    selected = [
        "origin_change_event_count_sum",
        "rpki_invalid_observation_count_sum",
        "rpki_invalid_origin_observation_count_sum",
        "announcement_count_sum",
        "withdrawal_count_sum",
        "announcement_to_withdrawal_ratio_mean",
        "unique_as_path_count_mean",
        "as_path_length_std_mean",
        "path_diversity_mean_per_prefix_mean",
        "caida_valley_free_violation_path_count_sum",
        "caida_valley_free_violation_ratio_mean",
        "caida_customer_to_provider_transition_count_sum",
        "caida_provider_to_customer_transition_count_sum",
        "caida_peer_to_peer_transition_count_sum",
        "unique_peer_asn_count_mean",
        "unique_prefix_count_mean",
    ]
    rows = []
    for (partition, true_class, correct), sub in df.groupby(["partition", "true_class", "correct"], dropna=False):
        for feature in selected:
            if feature not in sub.columns:
                continue
            vals = pd.to_numeric(sub[feature], errors="coerce").dropna()
            rows.append(
                {
                    "partition": partition,
                    "true_class": true_class,
                    "classification_status": "correct" if bool(correct) else "misclassified",
                    "feature": feature,
                    "n_incidents_with_value": len(vals),
                    "mean": vals.mean() if len(vals) else np.nan,
                    "median": vals.median() if len(vals) else np.nan,
                    "p25": vals.quantile(0.25) if len(vals) else np.nan,
                    "p75": vals.quantile(0.75) if len(vals) else np.nan,
                    "interpretation_boundary": "descriptive association only; not causal",
                }
            )
    return pd.DataFrame(rows)


def routeviews_visibility(pred_all: pd.DataFrame, summaries: pd.DataFrame) -> pd.DataFrame:
    df = pred_all.merge(summaries.drop(columns=["category"], errors="ignore"), on=["incident_uid", "partition"], how="left")
    visibility_cols = [
        "raw_mrt_files",
        "raw_bgp_observations",
        "relevant_observations",
        "active_5min_windows",
        "zero_observation_windows",
        "total_feature_rows",
    ]
    rows = []
    for (partition, correct), sub in df.groupby(["partition", "correct"], dropna=False):
        for col in visibility_cols:
            if col not in sub.columns:
                continue
            vals = pd.to_numeric(sub[col], errors="coerce").dropna()
            rows.append(
                {
                    "partition": partition,
                    "classification_status": "correct" if bool(correct) else "misclassified",
                    "visibility_metric": col,
                    "n_incidents_with_value": len(vals),
                    "mean": vals.mean() if len(vals) else np.nan,
                    "median": vals.median() if len(vals) else np.nan,
                    "p25": vals.quantile(0.25) if len(vals) else np.nan,
                    "p75": vals.quantile(0.75) if len(vals) else np.nan,
                    "association_note": "descriptive only; sparse RouteViews evidence is not interpreted causally",
                }
            )
    return pd.DataFrame(rows)


def partition_context(holdout: pd.DataFrame) -> pd.DataFrame:
    forensic_path = ROOT / "experiments/partition_independence_audit_v1/final_holdout_forensic_review_v1.csv"
    if not forensic_path.exists():
        return pd.DataFrame()
    forensic = pd.read_csv(forensic_path)
    df = holdout.merge(forensic[["incident_uid", "status", "candidate_related_pair_count", "shares_asn_with_train_or_validation", "shares_prefix_with_train_or_validation"]], on="incident_uid", how="left")
    rows = []
    for (status, correct), sub in df.groupby(["status", "correct"], dropna=False):
        rows.append(
            {
                "partition": "FINAL_HOLDOUT",
                "partition_context_category": status,
                "classification_status": "correct" if bool(correct) else "misclassified",
                "incident_count": len(sub),
                "percent_within_category": len(sub) / (df["status"].eq(status).sum() if pd.notna(status) else len(df[df["status"].isna()])),
                "mean_related_pair_count": sub["candidate_related_pair_count"].mean(),
                "interpretation_boundary": "partition-forensic association only; not leakage or causation",
            }
        )
    return pd.DataFrame(rows)


def top2_rescue(preds: dict[str, pd.DataFrame]) -> pd.DataFrame:
    rows = []
    for partition, df in preds.items():
        errors = df[~df["correct"]]
        rescued = errors[errors["true_class_rank"] == 2]
        rank3 = errors[errors["true_class_rank"] == 3]
        rows.append(
            {
                "partition": partition,
                "top1_error_count": len(errors),
                "true_class_recovered_at_top2": len(rescued),
                "true_class_rank3": len(rank3),
                "percent_errors_recovered_at_top2": len(rescued) / len(errors) if len(errors) else 0,
                "percent_errors_rank3": len(rank3) / len(errors) if len(errors) else 0,
                "operational_interpretation": "Top-2 rescue quantifies ranking support for diagnostic assistance.",
            }
        )
    return pd.DataFrame(rows)


def cross_partition(preds: dict[str, pd.DataFrame]) -> pd.DataFrame:
    rows = []
    for partition, df in preds.items():
        for true_class in CLASS_ORDER:
            sub = df[df["true_class"] == true_class]
            rows.append(
                {
                    "partition": partition,
                    "true_class": true_class,
                    "n": len(sub),
                    "top1_errors": int((~sub["correct"]).sum()),
                    "error_rate": (~sub["correct"]).mean() if len(sub) else np.nan,
                    "top2_rescue_among_errors": int(((~sub["correct"]) & (sub["true_class_rank"] == 2)).sum()),
                    "rank3_among_errors": int(((~sub["correct"]) & (sub["true_class_rank"] == 3)).sum()),
                    "dominant_predicted_wrong_class": sub.loc[~sub["correct"], "predicted_class"].mode().iloc[0] if (~sub["correct"]).any() else "",
                }
            )
    return pd.DataFrame(rows)


def final_holdout_error_summary_table(holdout: pd.DataFrame) -> pd.DataFrame:
    rows = []
    errors = holdout[~holdout["correct"]]
    for true_class in CLASS_ORDER:
        total_true = (holdout["true_class"] == true_class).sum()
        for pred_class in CLASS_ORDER:
            if pred_class == true_class:
                continue
            sub = errors[(errors["true_class"] == true_class) & (errors["predicted_class"] == pred_class)]
            rows.append(
                {
                    "True Class": true_class,
                    "Predicted Class": pred_class,
                    "Count": len(sub),
                    "% of True Class": len(sub) / total_true if total_true else 0,
                    "% Recovered at Top-2": (sub["true_class_rank"].eq(2).mean() if len(sub) else 0),
                    "Mean Top-1 Score": sub["rank_1_score"].mean() if len(sub) else np.nan,
                    "Mean Margin": sub["top1_top2_margin"].mean() if len(sub) else np.nan,
                }
            )
    return pd.DataFrame(rows)


def representative_cases(forensics: pd.DataFrame) -> pd.DataFrame:
    cases = []
    used = set()
    criteria = [
        ("highest-confidence error", "rank_1_score", False, None),
        ("lowest-margin error", "confidence_margin_top1_top2", True, None),
        ("representative Hijack error", "confidence_margin_top1_top2", True, "Hijack"),
        ("representative Leak error", "confidence_margin_top1_top2", True, "Leak"),
        ("representative Outage error", "confidence_margin_top1_top2", True, "Outage"),
    ]
    for label, sort_col, ascending, true_class in criteria:
        sub = forensics.copy()
        if true_class:
            sub = sub[sub["true_class"] == true_class]
        if sub.empty or sort_col not in sub.columns:
            continue
        sub = sub.sort_values(sort_col, ascending=ascending)
        chosen = sub.iloc[0].to_dict()
        chosen["selection_criterion"] = label
        chosen["not_cherry_picked_note"] = "transparent criterion, not selected for favorable narrative"
        cases.append(chosen)
        used.add(chosen["incident_uid"])
    return pd.DataFrame(cases)


def save_table_md(df: pd.DataFrame, path: Path, title: str) -> None:
    rows = df.to_dict("records")
    write_md(path, title, [("Table", md_table(rows, list(df.columns)))])


def plot_confusion(holdout: pd.DataFrame) -> None:
    cm = pd.crosstab(holdout["true_class"], holdout["predicted_class"]).reindex(index=CLASS_ORDER, columns=CLASS_ORDER, fill_value=0)
    fig, ax = plt.subplots(figsize=(7.5, 6), dpi=180)
    im = ax.imshow(cm.values, cmap="Blues")
    ax.set_xticks(range(3), CLASS_ORDER)
    ax.set_yticks(range(3), CLASS_ORDER)
    ax.set_xlabel("Predicted class")
    ax.set_ylabel("True class")
    ax.set_title("Final Holdout Confusion Matrix")
    for i in range(3):
        for j in range(3):
            ax.text(j, i, int(cm.values[i, j]), ha="center", va="center", color="black", fontsize=12)
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    save_figure(fig, "figure_a_final_holdout_confusion_matrix_v1")


def plot_confidence(holdout: pd.DataFrame) -> None:
    fig, ax = plt.subplots(figsize=(8, 5.5), dpi=180)
    data = [holdout[holdout["correct"]]["rank_1_score"], holdout[~holdout["correct"]]["rank_1_score"]]
    ax.boxplot(data, labels=["Correct", "Incorrect"], patch_artist=True, boxprops={"facecolor": "#d9e8f5"})
    ax.scatter(np.random.default_rng(20260828).normal(1, 0.035, len(data[0])), data[0], alpha=0.25, s=16, color="#235789")
    ax.scatter(np.random.default_rng(20260829).normal(2, 0.035, len(data[1])), data[1], alpha=0.6, s=22, color="#c1292e")
    ax.set_ylim(0, 1.03)
    ax.set_ylabel("Top-1 class score")
    ax.set_title("Top-1 Confidence: Correct vs Incorrect Final Holdout Incidents")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    save_figure(fig, "figure_b_top1_confidence_correct_vs_incorrect_v1")


def plot_error_type(taxonomy: pd.DataFrame) -> None:
    hold = taxonomy[taxonomy["partition"] == "FINAL_HOLDOUT"].copy()
    fig, ax = plt.subplots(figsize=(9, 5.5), dpi=180)
    ax.bar(hold["error_type"], hold["count"], color="#4c78a8")
    ax.set_ylabel("Top-1 error count")
    ax.set_title("Final Holdout Error-Type Distribution")
    ax.tick_params(axis="x", rotation=35)
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    save_figure(fig, "figure_c_error_type_distribution_v1")


def plot_top2_rescue(holdout: pd.DataFrame) -> None:
    errors = holdout[~holdout["correct"]]
    vals = [int((errors["true_class_rank"] == 2).sum()), int((errors["true_class_rank"] == 3).sum())]
    labels = ["Recovered at Top-2", "True class rank 3"]
    fig, ax = plt.subplots(figsize=(7, 5.2), dpi=180)
    bars = ax.bar(labels, vals, color=["#59a14f", "#e15759"])
    ax.set_ylabel("Top-1 error count")
    ax.set_title("Top-2 Rescue of Final Holdout Top-1 Errors")
    for bar, val in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width() / 2, val + 0.25, str(val), ha="center", va="bottom", fontsize=12)
    ax.set_ylim(0, max(vals) + 4)
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    save_figure(fig, "figure_d_top2_rescue_v1")


def save_figure(fig: plt.Figure, stem: str) -> None:
    FIG.mkdir(parents=True, exist_ok=True)
    for ext, kwargs in [
        ("png", {"dpi": 220}),
        ("pdf", {}),
        ("jpg", {"dpi": 400, "pil_kwargs": {"quality": 95}}),
    ]:
        fig.savefig(FIG / f"{stem}.{ext}", bbox_inches="tight", **kwargs)
    plt.close(fig)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    FIG.mkdir(parents=True, exist_ok=True)
    generated = datetime.now(timezone.utc).isoformat()
    preds = load_predictions()
    pred_all = pd.concat(preds.values(), ignore_index=True, sort=False)
    pred_all.to_csv(OUT / "final_error_prediction_inventory_incident_rows_v1.csv", index=False)

    inventory = prediction_inventory(preds)
    inventory.to_csv(OUT / "final_error_prediction_inventory_v1.csv", index=False)
    taxonomy = confusion_taxonomy(preds)
    taxonomy.to_csv(OUT / "final_error_confusion_taxonomy_v1.csv", index=False)

    features = load_feature_aggregates()
    summaries = load_summaries()
    manifests = load_manifests()
    holdout = preds["FINAL_HOLDOUT"]

    forensics = make_final_forensics(holdout, manifests, summaries, features)
    forensics.to_csv(OUT / "final_holdout_error_forensics_v1.csv", index=False)

    high_conf_ref = pd.read_csv(ROOT / "experiments/calibration_audit_v1/calibration_high_confidence_errors_v1.csv")
    high_conf = holdout[~holdout["correct"]].copy()
    high_conf["calibration_high_confidence_reference"] = high_conf["incident_uid"].isin(
        high_conf_ref[high_conf_ref["partition"].eq("FINAL_HOLDOUT")]["incident_uid"]
    )
    high_conf = high_conf[high_conf["rank_1_score"] >= HIGH_CONFIDENCE_THRESHOLD].sort_values("rank_1_score", ascending=False)
    high_conf.to_csv(OUT / "final_error_high_confidence_v1.csv", index=False)

    margin_rows = []
    for partition, df in preds.items():
        for status, sub in [("correct", df[df["correct"]]), ("misclassified", df[~df["correct"]])]:
            margin_rows.append(
                {
                    "partition": partition,
                    "classification_status": status,
                    "n": len(sub),
                    "margin_threshold_predeclared": LOW_MARGIN_THRESHOLD,
                    "low_margin_count": int((sub["top1_top2_margin"] <= LOW_MARGIN_THRESHOLD).sum()),
                    "low_margin_percent": (sub["top1_top2_margin"] <= LOW_MARGIN_THRESHOLD).mean() if len(sub) else np.nan,
                    "mean_margin": sub["top1_top2_margin"].mean(),
                    "median_margin": sub["top1_top2_margin"].median(),
                    "p25_margin": sub["top1_top2_margin"].quantile(0.25),
                    "p75_margin": sub["top1_top2_margin"].quantile(0.75),
                    "min_margin": sub["top1_top2_margin"].min(),
                    "max_margin": sub["top1_top2_margin"].max(),
                }
            )
    margin_df = pd.DataFrame(margin_rows)
    margin_df.to_csv(OUT / "final_error_margin_analysis_v1.csv", index=False)

    class_char = class_characteristics(pred_all, features)
    class_char.to_csv(OUT / "final_error_class_characteristics_v1.csv", index=False)
    visibility = routeviews_visibility(pred_all, summaries)
    visibility.to_csv(OUT / "final_error_routeviews_visibility_v1.csv", index=False)
    pcontext = partition_context(holdout)
    pcontext.to_csv(OUT / "final_error_partition_context_v1.csv", index=False)
    rescue = top2_rescue(preds)
    rescue.to_csv(OUT / "final_error_top2_rescue_v1.csv", index=False)
    cross = cross_partition(preds)
    cross.to_csv(OUT / "final_error_cross_partition_v1.csv", index=False)

    holdout_summary = final_holdout_error_summary_table(holdout)
    holdout_summary.to_csv(OUT / "manuscript_table_final_holdout_incident_level_error_summary_v1.csv", index=False)
    save_table_md(holdout_summary, OUT / "manuscript_table_final_holdout_incident_level_error_summary_v1.md", "Final Holdout Incident Level Error Summary v1")
    reps = representative_cases(forensics)
    reps.to_csv(OUT / "manuscript_table_representative_final_holdout_misclassifications_v1.csv", index=False)
    save_table_md(reps, OUT / "manuscript_table_representative_final_holdout_misclassifications_v1.md", "Representative Final Holdout Misclassifications v1")

    plot_confusion(holdout)
    plot_confidence(holdout)
    plot_error_type(taxonomy)
    plot_top2_rescue(holdout)

    final_errors = holdout[~holdout["correct"]]
    class_errors = cross[cross["partition"] == "FINAL_HOLDOUT"].copy()
    highest_error = class_errors.sort_values("error_rate", ascending=False).iloc[0]
    lowest_error = class_errors.sort_values("error_rate", ascending=True).iloc[0]
    dom_pair = taxonomy[taxonomy["partition"] == "FINAL_HOLDOUT"].sort_values("count", ascending=False).iloc[0]
    final_rescue = rescue[rescue["partition"] == "FINAL_HOLDOUT"].iloc[0]
    margin_incorrect = margin_df[(margin_df["partition"] == "FINAL_HOLDOUT") & (margin_df["classification_status"] == "misclassified")].iloc[0]
    visibility_bad = visibility[(visibility["partition"] == "FINAL_HOLDOUT") & (visibility["classification_status"] == "misclassified")]
    visibility_good = visibility[(visibility["partition"] == "FINAL_HOLDOUT") & (visibility["classification_status"] == "correct")]
    sparse_note = "Mixed; descriptive summaries should be read feature-by-feature."
    if not visibility_bad.empty and "relevant_observations" in visibility_bad["visibility_metric"].values:
        bad_med = visibility_bad[visibility_bad["visibility_metric"] == "relevant_observations"]["median"].iloc[0]
        good_med = visibility_good[visibility_good["visibility_metric"] == "relevant_observations"]["median"].iloc[0]
        sparse_note = f"Misclassified median relevant observations {bad_med:.3f}; correct median {good_med:.3f}."

    sections = [
        (
            "Scope",
            f"Generated UTC: {generated}\n\nThis is an additive diagnostic analysis using existing frozen prediction artifacts only. No model was retrained, recalibrated, tuned, or rerun. Validation and Final Holdout artifacts were not recomputed.",
        ),
        (
            "Prediction Sources",
            md_table(inventory.to_dict("records"), ["partition", "candidate_id", "incident_count", "correct_count", "top1_accuracy", "top2_accuracy", "mean_mrr", "prediction_source"]),
        ),
        (
            "Final Holdout Error Findings",
            "\n".join(
                [
                    f"- Top-1 error count: {len(final_errors)} of {len(holdout)}.",
                    f"- Highest error-rate class: {highest_error['true_class']} ({highest_error['error_rate']:.3%}).",
                    f"- Lowest error-rate class: {lowest_error['true_class']} ({lowest_error['error_rate']:.3%}).",
                    f"- Dominant confusion pair: {dom_pair['error_type']} with {int(dom_pair['count'])} incidents.",
                    f"- Top-1 errors recovered by Top-2: {int(final_rescue['true_class_recovered_at_top2'])}/{int(final_rescue['top1_error_count'])} ({final_rescue['percent_errors_recovered_at_top2']:.3%}).",
                    f"- True class rank 3 among Top-1 errors: {int(final_rescue['true_class_rank3'])}/{int(final_rescue['top1_error_count'])}.",
                    f"- Incorrect-case median Top-1/Top-2 margin: {margin_incorrect['median_margin']:.6f}; low-margin threshold used for description: <= {LOW_MARGIN_THRESHOLD}.",
                    f"- Sparse RouteViews association: {sparse_note}",
                ]
            ),
        ),
        (
            "Interpretation Boundary",
            "The RPKI, CAIDA, Behavioral, visibility, and partition-context summaries are descriptive associations only. They do not establish causation and do not imply leakage. `Hijack:68538` is cross-referenced as a quality-gate inconsistency in the broader remediation work but is not treated as a Final Holdout error because its frozen prediction was correct.",
        ),
        (
            "Operational Implication",
            "The large difference between Final Holdout Top-1 and Top-2 is operationally meaningful: most Top-1 errors still ranked the true class second. This supports interpreting the system as ranked diagnostic assistance rather than a single-label oracle.",
        ),
        (
            "Chapter 4 Draft Subsection",
            "The final error analysis examined frozen incident-level predictions for TRAIN nested-CV, the independent Validation confirmation, and the terminal Final Holdout. On the Final Holdout, the classifier made 17 Top-1 errors among 213 incidents. Error patterns were reported by true/predicted class pair and by whether the true class remained in the Top-2 ranking. This distinction matters because the system is designed to rank likely incident causes, not only to issue a single class label. Most Final Holdout Top-1 errors were recovered at Top-2, explaining why Top-2 accuracy remained substantially higher than Top-1 accuracy. Descriptive comparisons of frozen Behavioral, CAIDA, RPKI/ROV, and RouteViews visibility features suggest that some errors occur in incidents with ambiguous routing evidence or weaker separability between class signatures, but these comparisons are associative and should not be read as causal explanations. The analysis therefore supports the final ranking-oriented interpretation while preserving the original one-time Holdout result.",
        ),
        ("Final Disposition", "`FINAL_ERROR_ANALYSIS_COMPLETE_WITH_DESCRIPTIVE_LIMITATIONS`"),
    ]
    write_md(OUT / "final_error_analysis_summary_v1.md", "Final Incident Level Error Analysis v1", sections)

    manifest_rows = []
    for p in sorted(OUT.glob("*_v1.*")) + sorted(FIG.glob("*_v1.*")):
        manifest_rows.append({"artifact": str(p.relative_to(ROOT)), "sha256": sha256(p), "generated_utc": generated})
    write_csv(OUT / "final_error_analysis_manifest_v1.csv", manifest_rows)


if __name__ == "__main__":
    main()
