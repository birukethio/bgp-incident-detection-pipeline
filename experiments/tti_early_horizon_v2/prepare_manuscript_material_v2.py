from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "experiments" / "tti_early_horizon_v2"

METRICS = OUT / "early_horizon_metrics_v2.csv"
TTI_CUM = OUT / "early_horizon_tti_cumulative_v2.csv"
CLASS_TTI = OUT / "early_horizon_class_tti_v2.csv"
ACCOUNTING = OUT / "early_horizon_incident_accounting_v2.csv"
DENOMS = OUT / "early_horizon_horizon_denominators_v2.csv"
PER_CLASS = OUT / "early_horizon_per_class_v2.csv"
DISPOSITION = OUT / "early_horizon_final_disposition_v2.md"

HORIZONS = [30, 60, 120, 300, 600, 900]
HORIZON_LABELS = ["30 sec", "60 sec", "120 sec", "300 sec (5 min)", "600 sec (10 min)", "900 sec (15 min)"]


def safe_text(path: Path, text: str) -> None:
    if path.exists():
        raise FileExistsError(f"Refusing to overwrite existing artifact: {path}")
    path.write_text(text, encoding="utf-8")


def safe_csv(path: Path, df: pd.DataFrame) -> None:
    if path.exists():
        raise FileExistsError(f"Refusing to overwrite existing artifact: {path}")
    df.to_csv(path, index=False)


def safe_fig(fig: plt.Figure, stem: str) -> None:
    for suffix, kwargs in [
        (".png", {"dpi": 320}),
        (".pdf", {}),
        ("_highres_chart_only.jpg", {"dpi": 480}),
    ]:
        path = OUT / f"{stem}{suffix}"
        if path.exists():
            raise FileExistsError(f"Refusing to overwrite existing artifact: {path}")
    fig.savefig(OUT / f"{stem}.png", dpi=320)
    fig.savefig(OUT / f"{stem}.pdf")
    fig.savefig(OUT / f"{stem}_highres_chart_only.jpg", dpi=480)
    plt.close(fig)


def fmt(value: float) -> str:
    return f"{value:.6f}"


def make_tables(metrics: pd.DataFrame, tti: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    perf = metrics[
        ["horizon", "macro_f1", "top1_accuracy", "top2_accuracy", "mrr", "hijack_f1", "leak_f1", "outage_f1", "evaluable_incidents"]
    ].copy()
    perf = perf.rename(
        columns={
            "horizon": "Horizon",
            "macro_f1": "Macro F1",
            "top1_accuracy": "Top-1",
            "top2_accuracy": "Top-2",
            "mrr": "MRR",
            "hijack_f1": "Hijack F1",
            "leak_f1": "Leak F1",
            "outage_f1": "Outage F1",
            "evaluable_incidents": "n",
        }
    )
    safe_csv(OUT / "manuscript_horizon_performance_table_v2.csv", perf)
    safe_text(OUT / "manuscript_horizon_performance_table_v2.md", perf.to_markdown(index=False) + "\n")

    cum = tti[
        [
            "metric",
            "checkpoint",
            "newly_identified_count",
            "cumulative_identified_count",
            "eligible_denominator",
            "cumulative_identified_percent",
        ]
    ].copy()
    cum = cum.rename(
        columns={
            "metric": "Metric",
            "checkpoint": "Checkpoint",
            "newly_identified_count": "Newly identified",
            "cumulative_identified_count": "Cumulative identified",
            "eligible_denominator": "Denominator",
            "cumulative_identified_percent": "Cumulative percent",
        }
    )
    safe_csv(OUT / "manuscript_cumulative_tti_table_v2.csv", cum)
    safe_text(OUT / "manuscript_cumulative_tti_table_v2.md", cum.to_markdown(index=False) + "\n")
    return perf, cum


def plot_performance(metrics: pd.DataFrame) -> None:
    x = np.arange(len(metrics))
    fig, ax = plt.subplots(figsize=(11, 6.2))
    series = [
        ("macro_f1", "Macro F1", "o"),
        ("top1_accuracy", "Top-1", "s"),
        ("top2_accuracy", "Top-2", "^"),
        ("mrr", "MRR", "D"),
    ]
    for col, label, marker in series:
        ax.plot(x, metrics[col], marker=marker, linewidth=2.4, label=label)
        for xi, yi in zip(x, metrics[col]):
            ax.text(xi, yi + 0.004, f"{yi:.3f}", ha="center", va="bottom", fontsize=8)
    ax.axvline(3, linestyle="--", color="#444444", linewidth=1.3)
    ax.text(3.08, 0.762, "5-minute point", rotation=90, va="bottom", ha="left", fontsize=9)
    ax.set_xticks(x)
    ax.set_xticklabels(HORIZON_LABELS, rotation=18, ha="right")
    ax.set_ylim(0.75, 1.0)
    ax.set_ylabel("Incident-level score")
    ax.set_title("Level-1 Performance by Cumulative Observation Horizon")
    ax.grid(True, axis="y", alpha=0.25)
    ax.legend(frameon=False, ncol=4, loc="lower right")
    fig.tight_layout()
    safe_fig(fig, "manuscript_figure_early_horizon_performance_v2")


def plot_per_class(per_class: pd.DataFrame) -> None:
    x = np.arange(len(HORIZONS))
    fig, ax = plt.subplots(figsize=(11, 6.2))
    for cls, marker in [("Hijack", "o"), ("Leak", "s"), ("Outage", "^")]:
        sdf = per_class[per_class["class"].eq(cls)].sort_values("horizon_seconds")
        ax.plot(x, sdf["f1"], marker=marker, linewidth=2.4, label=f"{cls} F1")
        for xi, yi in zip(x, sdf["f1"]):
            ax.text(xi, yi + 0.004, f"{yi:.3f}", ha="center", va="bottom", fontsize=8)
    ax.axvline(3, linestyle="--", color="#444444", linewidth=1.3)
    ax.set_xticks(x)
    ax.set_xticklabels(HORIZON_LABELS, rotation=18, ha="right")
    ax.set_ylim(0.68, 0.95)
    ax.set_ylabel("Class F1")
    ax.set_title("Per-Class Level-1 F1 by Cumulative Observation Horizon")
    ax.grid(True, axis="y", alpha=0.25)
    ax.legend(frameon=False, ncol=3, loc="lower right")
    fig.tight_layout()
    safe_fig(fig, "manuscript_figure_early_horizon_per_class_f1_v2")


def plot_cumulative_tti(tti: pd.DataFrame) -> None:
    filtered = tti[tti["checkpoint"].str.startswith("<=", na=False)].copy()
    fig, ax = plt.subplots(figsize=(11, 6.2))
    x = np.arange(6)
    for metric, marker in [("Top-1", "o"), ("Top-2", "s")]:
        sdf = filtered[filtered["metric"].eq(metric)].sort_values("checkpoint_seconds")
        ax.plot(x, sdf["cumulative_identified_percent"], marker=marker, linewidth=2.6, label=metric)
        for xi, yi in zip(x, sdf["cumulative_identified_percent"]):
            ax.text(xi, yi + 0.6, f"{yi:.2f}%", ha="center", va="bottom", fontsize=8)
    ax.axvline(3, linestyle="--", color="#444444", linewidth=1.3)
    ax.set_xticks(x)
    ax.set_xticklabels(HORIZON_LABELS, rotation=18, ha="right")
    ax.set_ylim(76, 101)
    ax.set_ylabel("Cumulative incidents identified (%)")
    ax.set_title("Checkpoint-Based Cumulative TTI")
    ax.grid(True, axis="y", alpha=0.25)
    ax.legend(frameon=False, loc="lower right")
    fig.tight_layout()
    safe_fig(fig, "manuscript_figure_early_horizon_cumulative_tti_v2")


def chapter3_text() -> str:
    return """# Proposed Chapter 3 Insertion: Retrospective Early-Horizon TTI Methodology

**Suggested location:** Chapter 3, after the subsection describing five-minute V4 feature construction and before the final model-evaluation protocol.

To address time-to-identify concerns, an additive retrospective early-classification experiment was conducted after the primary five-minute architecture had already been developed. This analysis did not replace the final Praxis architecture and did not use the incident-level Level-2 temporal stacker. Instead, it evaluated the frozen Level-1 XGBoost classifier independently at cumulative observation horizons of 30, 60, 120, 300, 600, and 900 seconds from observable incident onset.

Observable onset was defined as `FIRST_POST_DOCUMENTED_EVENT_EVIDENCE`: the first incident-relevant RouteViews observation at or after the independently documented incident start. Timestamp-preserving RouteViews evidence was reconstructed so that each horizon used only observations with `bgp_timestamp_utc <= observable_onset + horizon`. For each horizon, the V4 feature representation was reconstructed using the same 44 Behavioral features, 14 historical CAIDA AS-relationship features, and 16 historical RPKI/ROV features used in the frozen Level-1 model. No feature definition, class ordering, onset rule, or historical snapshot mapping was changed for the early-horizon experiment.

The analysis was Level-1 only. The verified reconstructed five-model Level-1 XGBoost ensemble was applied without retraining, tuning, calibration, threshold selection, or model modification. Top-1 TTI was defined as the earliest evaluated checkpoint at which the Level-1 model's highest-probability class equaled the true incident class. Top-2 TTI was defined as the earliest checkpoint at which the true class appeared in the two highest-probability classes. Because predictions were evaluated only at discrete checkpoints, these values are checkpoint-based TTI estimates rather than continuous-time detection latencies.

Automated leakage assertions verified that no post-cutoff BGP observation contributed to an earlier horizon. The original TRAIN partition contained 993 incidents; 10 were excluded from TTI scoring under pre-existing methodology gates. Nine lacked incident-relevant timestamped RouteViews evidence under the frozen relevance predicates, and one did not have a valid post-documented-start observable onset. The resulting TTI denominator was 983 incidents. Extended 600-second and 900-second metrics used changing denominators because only 973 and 972 incidents, respectively, had sufficient extended temporal coverage.
"""


def chapter4_text(perf: pd.DataFrame, cum: pd.DataFrame) -> str:
    return f"""# Proposed Chapter 4 Insertion: Retrospective Early-Horizon Level-1 Results

**Suggested location:** Chapter 4, after final model-performance sections or as a short post-hoc TTI subsection before the operational-latency discussion.

The retrospective early-horizon experiment evaluated the frozen Level-1 XGBoost classifier at cumulative RouteViews-observable horizons of 30, 60, 120, 300, 600, and 900 seconds. This was a TRAIN-only, post-hoc analysis and was not used to modify the primary model, the Level-2 stacker, Validation results, or Final Holdout results.

The incident accounting was 993 TRAIN incidents to 983 TTI-evaluable incidents. The 10 exclusions were documented before scoring: nine incidents lacked incident-relevant timestamped RouteViews evidence under the frozen predicates, and one outage had unresolved observable onset. The 30-, 60-, 120-, and 300-second checkpoints used all 983 evaluable incidents. The 600-second and 900-second checkpoints had denominators of 973 and 972 incidents because not every TRAIN incident had sufficient extended temporal coverage.

**Early Level-1 Classification Performance by Observation Horizon**

{perf.to_markdown(index=False)}

**Checkpoint-Based Cumulative TTI**

{cum.to_markdown(index=False)}

Performance improved substantially through the first five minutes. Beyond 300 seconds, gains were small and inconsistent. Five minutes is therefore supported as a practical analytical tradeoff point, not a mathematically proven optimum.

The final verification disposition for the early-horizon package was `PASS_WITH_DOCUMENTED_EXCLUSIONS`. These results should be interpreted as a retrospective Level-1 analysis of evidence accumulation and not as a replacement for the final incident-level stacking architecture or the one-time Final Holdout result.
"""


def chapter5_text() -> str:
    return """# Proposed Chapter 5 Interpretation Paragraph for RQ3/H3

**Suggested location:** Chapter 5, in the RQ3/H3 interpretation or future-work/operationalization discussion.

The post-hoc early-horizon experiment provides additional evidence for the practical value of the five-minute analytical representation used in the final Praxis pipeline. The frozen Level-1 classifier already recovered substantial classification signal within 30 seconds, but performance continued to improve through 60, 120, and 300 seconds as additional RouteViews evidence accumulated. Gains beyond 300 seconds were small and inconsistent, which supports five minutes as a practical tradeoff between earlier classification and stronger route-evidence representation. This result should be interpreted cautiously because the experiment was retrospective, TRAIN-only, and Level-1 only; it does not replace the final incident-level stacking architecture or the untouched Final Holdout evaluation. Instead, it strengthens the methodological justification for five-minute analytical windows and identifies real-time incremental inference as an important future-work direction.
"""


def index_text() -> str:
    files = [
        "chapter3_tti_methodology_subsection_v2.md",
        "chapter4_early_horizon_results_subsection_v2.md",
        "chapter5_rq3_h3_tti_interpretation_v2.md",
        "manuscript_horizon_performance_table_v2.csv",
        "manuscript_horizon_performance_table_v2.md",
        "manuscript_cumulative_tti_table_v2.csv",
        "manuscript_cumulative_tti_table_v2.md",
        "manuscript_figure_early_horizon_performance_v2.png/pdf/highres_chart_only.jpg",
        "manuscript_figure_early_horizon_per_class_f1_v2.png/pdf/highres_chart_only.jpg",
        "manuscript_figure_early_horizon_cumulative_tti_v2.png/pdf/highres_chart_only.jpg",
    ]
    return "# Early Horizon Manuscript Material Index v2\n\n" + "\n".join(f"- `{name}`" for name in files) + "\n"


def main() -> None:
    metrics = pd.read_csv(METRICS)
    tti = pd.read_csv(TTI_CUM)
    per_class = pd.read_csv(PER_CLASS)
    perf_table, cum_table = make_tables(metrics, tti)
    plot_performance(metrics)
    plot_per_class(per_class)
    plot_cumulative_tti(tti)
    safe_text(OUT / "chapter3_tti_methodology_subsection_v2.md", chapter3_text())
    safe_text(OUT / "chapter4_early_horizon_results_subsection_v2.md", chapter4_text(perf_table, cum_table))
    safe_text(OUT / "chapter5_rq3_h3_tti_interpretation_v2.md", chapter5_text())
    safe_text(OUT / "early_horizon_manuscript_material_index_v2.md", index_text())
    print("EARLY_HORIZON_MANUSCRIPT_MATERIAL_V2_COMPLETE")


if __name__ == "__main__":
    main()
