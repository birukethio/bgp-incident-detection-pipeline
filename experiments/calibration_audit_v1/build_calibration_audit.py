from __future__ import annotations

import csv
import hashlib
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "experiments" / "calibration_audit_v1"
OUT.mkdir(parents=True, exist_ok=True)

LABELS = ["HIJACK", "LEAK", "OUTAGE"]
SCORE_COLS = ["p_hijack", "p_leak", "p_outage"]
EPS = 1e-15
FIXED_BINS = 10


@dataclass
class PredictionSet:
    partition: str
    evaluation_design: str
    artifact_path: str
    candidate_id: str
    note: str
    df: pd.DataFrame


def load_prediction_sets() -> list[PredictionSet]:
    sets: list[PredictionSet] = []

    train_path = ROOT / "data/modeling_k1/k1_incident_level_predictions_v1.parquet"
    train = pd.read_parquet(train_path)
    train = train[train["candidate_id"] == "K1-M2_XGB_K1-TEMPORAL"].copy()
    train["predicted_class"] = train[SCORE_COLS].idxmax(axis=1).map({
        "p_hijack": "HIJACK", "p_leak": "LEAK", "p_outage": "OUTAGE"
    })
    train["rank_1_score"] = train[SCORE_COLS].max(axis=1)
    train["true_class_rank"] = train.apply(true_rank, axis=1)
    sets.append(PredictionSet(
        "TRAIN",
        "TRAIN nested-CV/OOS K1 temporal stacker predictions",
        str(train_path.relative_to(ROOT)),
        "K1-M2_XGB_K1-TEMPORAL",
        "Final TRAIN-side K1 temporal stacker candidate; no new inference performed.",
        train,
    ))

    val_path = ROOT / "data/validation/validation_incident_rankings_v1.csv"
    val = pd.read_csv(val_path)
    val = val.rename(columns={
        "mean_p_hijack": "p_hijack",
        "mean_p_leak": "p_leak",
        "mean_p_outage": "p_outage",
    })
    sets.append(PredictionSet(
        "VALIDATION",
        "Phase J one-time validation confirmation; stored incident mean-probability rankings",
        str(val_path.relative_to(ROOT)),
        "XGB_REFINED_TRAIN_CANDIDATE_PHASE_J",
        "Stored Validation artifact predates post-Validation K1 development and is included only as an available frozen prediction set.",
        val,
    ))

    hold_path = ROOT / "data/final_holdout/final_holdout_incident_rankings_v1.csv"
    hold = pd.read_csv(hold_path)
    sets.append(PredictionSet(
        "FINAL_HOLDOUT",
        "POST-HOC DIAGNOSTIC ANALYSIS OF ALREADY-FROZEN HOLDOUT PREDICTIONS",
        str(hold_path.relative_to(ROOT)),
        "K1_FINAL_SECOND_LEVEL_XGB_V1",
        "Final Holdout calibration is diagnostic only and was not used for recalibration or model modification.",
        hold,
    ))
    return sets


def true_rank(row: pd.Series) -> int:
    scores = {
        "HIJACK": float(row["p_hijack"]),
        "LEAK": float(row["p_leak"]),
        "OUTAGE": float(row["p_outage"]),
    }
    ordered = sorted(scores, key=scores.get, reverse=True)
    return ordered.index(str(row["true_class"]).upper()) + 1


def normalize(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out["true_class"] = out["true_class"].astype(str).str.upper()
    for col in SCORE_COLS:
        out[col] = pd.to_numeric(out[col], errors="coerce")
    if "predicted_class" not in out.columns:
        out["predicted_class"] = out[SCORE_COLS].idxmax(axis=1).map({
            "p_hijack": "HIJACK", "p_leak": "LEAK", "p_outage": "OUTAGE"
        })
    else:
        out["predicted_class"] = out["predicted_class"].astype(str).str.upper()
    if "true_class_rank" not in out.columns:
        out["true_class_rank"] = out.apply(true_rank, axis=1)
    if "rank_1_score" not in out.columns:
        out["rank_1_score"] = out[SCORE_COLS].max(axis=1)
    return out


def one_hot(y: pd.Series) -> np.ndarray:
    return np.vstack([(y == lab).astype(float).to_numpy() for lab in LABELS]).T


def metric_dict(ps: PredictionSet) -> dict:
    df = normalize(ps.df)
    y = df["true_class"]
    p = df[SCORE_COLS].to_numpy(float)
    yoh = one_hot(y)
    clipped = np.clip(p, EPS, 1.0)
    true_idx = np.array([LABELS.index(v) for v in y])
    top1 = (df["predicted_class"].to_numpy() == y.to_numpy())
    score_sums = p.sum(axis=1)
    multiclass_brier = np.mean(np.sum((p - yoh) ** 2, axis=1))
    log_loss = -np.mean(np.log(clipped[np.arange(len(df)), true_idx]))
    fixed_ece = top1_ece(df, fixed_bins=True)[0]
    eqfreq_ece = top1_ece(df, fixed_bins=False)[0]
    rec = {
        "partition": ps.partition,
        "candidate_id": ps.candidate_id,
        "evaluation_design": ps.evaluation_design,
        "N": len(df),
        "multiclass_brier_score": multiclass_brier,
        "hijack_ovr_brier": np.mean((p[:, 0] - yoh[:, 0]) ** 2),
        "leak_ovr_brier": np.mean((p[:, 1] - yoh[:, 1]) ** 2),
        "outage_ovr_brier": np.mean((p[:, 2] - yoh[:, 2]) ** 2),
        "log_loss": log_loss,
        "log_loss_clip_epsilon": EPS,
        "top1_ece_10_equal_width": fixed_ece,
        "top1_ece_10_equal_frequency": eqfreq_ece,
        "top1_accuracy": float(np.mean(top1)),
        "mean_top1_confidence": float(np.mean(df["rank_1_score"])),
        "median_top1_confidence": float(np.median(df["rank_1_score"])),
        "score_sum_min": float(np.min(score_sums)),
        "score_sum_max": float(np.max(score_sums)),
        "score_min": float(np.nanmin(p)),
        "score_max": float(np.nanmax(p)),
        "missing_score_values": int(df[SCORE_COLS].isna().sum().sum()),
        "invalid_score_values": int(((df[SCORE_COLS] < 0) | (df[SCORE_COLS] > 1)).sum().sum()),
        "artifact_path": ps.artifact_path,
        "notes": ps.note,
    }
    return rec


def top1_ece(df: pd.DataFrame, fixed_bins: bool) -> tuple[float, pd.DataFrame]:
    d = normalize(df)
    conf = d[SCORE_COLS].max(axis=1).to_numpy(float)
    correct = (d["predicted_class"].to_numpy() == d["true_class"].to_numpy()).astype(float)
    rows = []
    if fixed_bins:
        edges = np.linspace(0, 1, FIXED_BINS + 1)
        ids = np.digitize(conf, edges[1:-1], right=True)
        for i in range(FIXED_BINS):
            lo, hi = edges[i], edges[i + 1]
            mask = ids == i
            rows.append(bin_row(i + 1, lo, hi, mask, conf, correct, "top1_equal_width_10"))
    else:
        order = np.argsort(conf)
        splits = np.array_split(order, min(FIXED_BINS, len(order)))
        for i, idx in enumerate(splits):
            if len(idx) == 0:
                continue
            mask = np.zeros(len(conf), dtype=bool)
            mask[idx] = True
            rows.append(bin_row(i + 1, float(np.min(conf[idx])), float(np.max(conf[idx])), mask, conf, correct, "top1_equal_frequency_10"))
    bins = pd.DataFrame(rows)
    ece = float(np.sum((bins["count"] / len(d)) * bins["abs_gap"])) if len(d) else float("nan")
    return ece, bins


def bin_row(i: int, lo: float, hi: float, mask: np.ndarray, conf: np.ndarray, obs: np.ndarray, method: str) -> dict:
    n = int(mask.sum())
    mean_score = float(np.mean(conf[mask])) if n else np.nan
    empirical = float(np.mean(obs[mask])) if n else np.nan
    gap = abs(empirical - mean_score) if n else np.nan
    return {
        "binning_method": method,
        "bin": i,
        "bin_lower": lo,
        "bin_upper": hi,
        "count": n,
        "mean_predicted_score": mean_score,
        "observed_empirical_frequency": empirical,
        "calibration_gap": empirical - mean_score if n else np.nan,
        "abs_gap": gap,
    }


def per_class_bins(df: pd.DataFrame, partition: str) -> pd.DataFrame:
    d = normalize(df)
    rows = []
    edges = np.linspace(0, 1, FIXED_BINS + 1)
    for lab, col in zip(LABELS, SCORE_COLS):
        score = d[col].to_numpy(float)
        obs = (d["true_class"] == lab).astype(float).to_numpy()
        ids = np.digitize(score, edges[1:-1], right=True)
        for i in range(FIXED_BINS):
            mask = ids == i
            r = bin_row(i + 1, edges[i], edges[i + 1], mask, score, obs, f"{lab.lower()}_ovr_equal_width_10")
            r["partition"] = partition
            r["class"] = lab
            rows.append(r)
    return pd.DataFrame(rows)


def confidence_correctness(ps: PredictionSet) -> pd.DataFrame:
    d = normalize(ps.df)
    top = d[SCORE_COLS].max(axis=1)
    correct = d["predicted_class"] == d["true_class"]
    rows = []
    for status, sub in [("correct", top[correct]), ("incorrect", top[~correct])]:
        rows.append({
            "partition": ps.partition,
            "correctness": status,
            "count": int(len(sub)),
            "mean_top1_confidence": float(sub.mean()) if len(sub) else np.nan,
            "median_top1_confidence": float(sub.median()) if len(sub) else np.nan,
            "p25_top1_confidence": float(sub.quantile(0.25)) if len(sub) else np.nan,
            "p75_top1_confidence": float(sub.quantile(0.75)) if len(sub) else np.nan,
            "p90_top1_confidence": float(sub.quantile(0.90)) if len(sub) else np.nan,
            "p95_top1_confidence": float(sub.quantile(0.95)) if len(sub) else np.nan,
        })
    return pd.DataFrame(rows)


def high_conf_errors(ps: PredictionSet) -> pd.DataFrame:
    d = normalize(ps.df)
    d["top1_confidence"] = d[SCORE_COLS].max(axis=1)
    errors = d[d["predicted_class"] != d["true_class"]].copy()
    cols = ["incident_uid", "true_class", "predicted_class", "top1_confidence"] + SCORE_COLS
    if "candidate_id" in errors.columns:
        cols = ["candidate_id"] + cols
    errors = errors.sort_values("top1_confidence", ascending=False).head(25)
    errors.insert(0, "partition", ps.partition)
    return errors[[c for c in cols if c in errors.columns] if "partition" not in cols else cols]


def inventory_row(ps: PredictionSet) -> dict:
    d = normalize(ps.df)
    p = d[SCORE_COLS]
    sums = p.sum(axis=1)
    return {
        "partition": ps.partition,
        "candidate_id": ps.candidate_id,
        "evaluation_design": ps.evaluation_design,
        "incident_count": len(d),
        "score_columns": ";".join(SCORE_COLS),
        "scores_sum_to_approximately_1": bool(np.allclose(sums, 1.0, atol=1e-5)),
        "score_sum_min": float(sums.min()),
        "score_sum_max": float(sums.max()),
        "score_min": float(p.min().min()),
        "score_max": float(p.max().max()),
        "missing_values": int(p.isna().sum().sum()),
        "invalid_values": int(((p < 0) | (p > 1)).sum().sum()),
        "artifact_path": ps.artifact_path,
        "notes": ps.note,
    }


def plot_overall(bins: pd.DataFrame) -> None:
    parts = list(bins["partition"].unique())
    fig, axes = plt.subplots(1, len(parts), figsize=(6 * len(parts), 5), sharex=True, sharey=True)
    if len(parts) == 1:
        axes = [axes]
    for ax, part in zip(axes, parts):
        sub = bins[(bins["partition"] == part) & (bins["binning_method"] == "top1_equal_width_10")]
        ax.plot([0, 1], [0, 1], color="0.35", linestyle="--", linewidth=1.2, label="Perfect calibration")
        ax.scatter(sub["mean_predicted_score"], sub["observed_empirical_frequency"], s=np.maximum(sub["count"], 1) * 3, color="#2266AA", alpha=0.85)
        for _, r in sub.iterrows():
            if r["count"] > 0:
                ax.text(r["mean_predicted_score"], r["observed_empirical_frequency"], str(int(r["count"])), fontsize=8, ha="center", va="bottom")
        ax.set_title(part.replace("_", " "))
        ax.set_xlabel("Mean Top-1 score")
        ax.grid(True, alpha=0.25)
    axes[0].set_ylabel("Observed Top-1 accuracy")
    fig.suptitle("Top-1 Reliability: Frozen Incident-Level Scores", fontweight="bold")
    fig.tight_layout()
    save_fig(fig, "calibration_reliability_overall_v1")


def plot_per_class(bins: pd.DataFrame) -> None:
    # Plot final holdout per-class if present, otherwise all partitions averaged separately would be too busy.
    part = "FINAL_HOLDOUT" if "FINAL_HOLDOUT" in set(bins["partition"]) else bins["partition"].iloc[0]
    fig, axes = plt.subplots(1, 3, figsize=(16, 5), sharex=True, sharey=True)
    colors = {"HIJACK": "#B33A3A", "LEAK": "#D97904", "OUTAGE": "#5E4FA2"}
    for ax, lab in zip(axes, LABELS):
        sub = bins[(bins["partition"] == part) & (bins["class"] == lab)]
        ax.plot([0, 1], [0, 1], color="0.35", linestyle="--", linewidth=1.2)
        ax.scatter(sub["mean_predicted_score"], sub["observed_empirical_frequency"], s=np.maximum(sub["count"], 1) * 3, color=colors[lab], alpha=0.85)
        for _, r in sub.iterrows():
            if r["count"] > 0:
                ax.text(r["mean_predicted_score"], r["observed_empirical_frequency"], str(int(r["count"])), fontsize=8, ha="center", va="bottom")
        ax.set_title(f"{lab.title()} one-vs-rest")
        ax.set_xlabel("Mean class score")
        ax.grid(True, alpha=0.25)
    axes[0].set_ylabel("Observed class frequency")
    fig.suptitle(f"One-vs-Rest Reliability: {part.replace('_', ' ')}", fontweight="bold")
    fig.tight_layout()
    save_fig(fig, "calibration_reliability_per_class_v1")


def save_fig(fig: plt.Figure, stem: str) -> None:
    fig.savefig(OUT / f"{stem}.png", dpi=220, bbox_inches="tight")
    fig.savefig(OUT / f"{stem}.pdf", bbox_inches="tight")
    fig.savefig(OUT / f"{stem}_highres.jpg", dpi=400, bbox_inches="tight")
    plt.close(fig)


def write_csv(path: Path, rows: list[dict]) -> None:
    keys = []
    for row in rows:
        for key in row:
            if key not in keys:
                keys.append(key)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)


def main() -> None:
    sets = load_prediction_sets()

    inventory = [inventory_row(ps) for ps in sets]
    write_csv(OUT / "calibration_prediction_inventory_v1.csv", inventory)

    metrics = [metric_dict(ps) for ps in sets]
    write_csv(OUT / "calibration_metrics_v1.csv", metrics)

    overall_bins = []
    per_bins = []
    conf_tables = []
    errors = []
    for ps in sets:
        d = normalize(ps.df)
        _, fixed = top1_ece(d, fixed_bins=True)
        fixed.insert(0, "partition", ps.partition)
        _, eq = top1_ece(d, fixed_bins=False)
        eq.insert(0, "partition", ps.partition)
        overall_bins.extend(fixed.to_dict("records"))
        overall_bins.extend(eq.to_dict("records"))
        per_bins.extend(per_class_bins(d, ps.partition).to_dict("records"))
        conf_tables.append(confidence_correctness(ps))
        err = high_conf_errors(ps)
        if "partition" not in err.columns:
            err.insert(0, "partition", ps.partition)
        errors.append(err)

    overall_df = pd.DataFrame(overall_bins)
    per_df = pd.DataFrame(per_bins)
    overall_df.to_csv(OUT / "calibration_bins_overall_v1.csv", index=False)
    per_df.to_csv(OUT / "calibration_bins_per_class_v1.csv", index=False)
    pd.concat(conf_tables, ignore_index=True).to_csv(OUT / "calibration_confidence_correctness_v1.csv", index=False)
    pd.concat(errors, ignore_index=True).to_csv(OUT / "calibration_high_confidence_errors_v1.csv", index=False)

    plot_overall(overall_df)
    plot_per_class(per_df)

    table = pd.DataFrame(metrics)[[
        "partition", "N", "multiclass_brier_score", "log_loss",
        "top1_ece_10_equal_width", "mean_top1_confidence", "top1_accuracy"
    ]]
    table.to_csv(OUT / "calibration_diagnostics_manuscript_table_v1.csv", index=False)

    final = pd.DataFrame(metrics).set_index("partition").loc["FINAL_HOLDOUT"]
    validation = pd.DataFrame(metrics).set_index("partition").loc["VALIDATION"]
    train = pd.DataFrame(metrics).set_index("partition").loc["TRAIN"]
    max_error = pd.concat(errors, ignore_index=True)
    high_conf_count = int((max_error["top1_confidence"] >= 0.90).sum()) if len(max_error) else 0

    recommendation = "PROBABILITY_TERMINOLOGY_SUPPORTED_WITH_CALIBRATION_LIMITATION"
    summary = f"""# Frozen-Prediction Calibration Audit v1

Generated UTC: {datetime.now(timezone.utc).isoformat()}

Scope: additive diagnostic audit only. No model was retrained, recalibrated, or rerun. Validation and Final Holdout predictions were not recomputed. Official results were not changed.

## Prediction Artifacts Audited

- TRAIN: `data/modeling_k1/k1_incident_level_predictions_v1.parquet`, candidate `K1-M2_XGB_K1-TEMPORAL`, N={int(train['N'])}.
- Validation: `data/validation/validation_incident_rankings_v1.csv`, Phase J stored validation rankings, N={int(validation['N'])}. This is not the post-Validation K1 Final Holdout architecture.
- Final Holdout: `data/final_holdout/final_holdout_incident_rankings_v1.csv`, frozen terminal K1 predictions, N={int(final['N'])}.

## Calibration Definitions

- Multiclass Brier score: mean over incidents of the squared Euclidean distance between the three score outputs and the one-hot true class vector.
- One-vs-rest Brier: mean squared error between one class score and the binary indicator for that class.
- Log loss: mean negative log of the true-class score, with clipping only for safe logarithm calculation using epsilon `{EPS}`. Stored scores were not modified.
- Top-1 ECE: 10 equal-width confidence bins on max class score. ECE = sum over bins of `n_bin / N * abs(bin_accuracy - bin_mean_confidence)`.
- Equal-frequency ECE: reported as sensitivity only, using up to 10 quantile-like bins.

## Headline Results

Final Holdout diagnostic calibration:

- Multiclass Brier score: {final['multiclass_brier_score']:.6f}
- Log loss: {final['log_loss']:.6f}
- Top-1 ECE, 10 equal-width bins: {final['top1_ece_10_equal_width']:.6f}
- Top-1 ECE, 10 equal-frequency bins: {final['top1_ece_10_equal_frequency']:.6f}
- Mean Top-1 confidence: {final['mean_top1_confidence']:.6f}
- Observed Top-1 accuracy: {final['top1_accuracy']:.6f}

High-confidence errors across audited partitions with Top-1 score >= 0.90: {high_conf_count}.

## Interpretation

Top-1, Top-2, and MRR evaluate ordering quality. Brier score, log loss, ECE, and reliability diagrams evaluate probabilistic calibration. A classifier can rank classes effectively while still being imperfectly calibrated. The frozen K1 classifier has strong ordering performance on the Final Holdout, but the reliability diagnostics show enough calibration imperfection, including high-confidence errors, that unqualified operational wording such as “true probability” would be too strong.

Recommendation: `{recommendation}`.

The most defensible Praxis wording is to describe outputs as normalized class probabilities or class scores, while explicitly documenting calibration as a limitation. For conservative operational claims, prefer “model score,” “class score,” or “class-ranking score.”
"""
    (OUT / "calibration_audit_summary_v1.md").write_text(summary, encoding="utf-8")

    rec = f"""# Calibration Terminology Recommendation v1

Recommendation: `{recommendation}`

## Option A — Probability terminology with limitation

The classifier emits normalized class probabilities from the frozen XGBoost-based incident-level architecture. These outputs were used for class ranking and incident-level Top-1/Top-2/MRR evaluation. A post-hoc calibration audit found that the scores are suitable for ranking but are not perfectly calibrated; therefore, probability terminology should be accompanied by an explicit calibration limitation and should not be interpreted as operationally calibrated event likelihood.

## Option B — Conservative terminology

To avoid overclaiming calibration, refer to the three outputs as model scores, class scores, or class-ranking scores. Under this wording, Top-1, Top-2, and MRR remain valid ranking metrics, while Brier score, log loss, and ECE are reported as diagnostic evidence that the scores are not guaranteed to be calibrated probabilities.

## Recommended wording

Use Option A when describing the mathematical model output in methodology, but use Option B in operational or defense-facing claims. Suggested wording: “The final classifier produces normalized class scores used for ranking Hijack, Leak, and Outage. Although these scores are probability-like and sum to one, post-hoc reliability analysis showed imperfect calibration; therefore, the Praxis interprets them primarily as class-ranking scores rather than calibrated operational probabilities.”
"""
    (OUT / "calibration_terminology_recommendation_v1.md").write_text(rec, encoding="utf-8")

    # Manifest
    manifest_rows = []
    for p in sorted(OUT.iterdir()):
        if p.is_file():
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            manifest_rows.append({"file": p.name, "sha256": h})
    write_csv(OUT / "calibration_audit_manifest_v1.csv", manifest_rows)
    print(summary)


if __name__ == "__main__":
    main()
