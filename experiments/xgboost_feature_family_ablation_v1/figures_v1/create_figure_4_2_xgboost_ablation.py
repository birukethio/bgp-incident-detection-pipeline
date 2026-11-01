from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "experiments/xgboost_feature_family_ablation_v1/xgb_ablation_summary_metrics_v1.csv"
OUT = Path(__file__).resolve().parent

ORDER = ["full_v4", "minus_caida", "minus_rpki", "minus_behavioral", "behavioral_only"]
LABELS = {
    "full_v4": "Full V4\n(74 features)",
    "minus_caida": "Without CAIDA\n(60 features)",
    "minus_rpki": "Without RPKI/ROV\n(58 features)",
    "minus_behavioral": "Without behavioral BGP\n(30 features)",
    "behavioral_only": "Behavioral BGP only\n(44 features)",
}
EXPECTED = {
    "full_v4": 0.8056775087076607,
    "minus_caida": 0.7981479867299683,
    "minus_rpki": 0.7961777802117015,
    "minus_behavioral": 0.7619364350235698,
    "behavioral_only": 0.7858249927417094,
}
COLORS = ["#1F4E79", "#6F8FAF", "#8EA7BF", "#A8B4BE", "#4F6D7A"]


def main() -> None:
    data = pd.read_csv(SOURCE).set_index("configuration")
    values = [float(data.loc[name, "incident_macro_f1"]) for name in ORDER]
    for name, value in zip(ORDER, values):
        if abs(value - EXPECTED[name]) > 1e-12:
            raise RuntimeError(f"Saved metric mismatch for {name}: {value} != {EXPECTED[name]}")

    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 12,
            "axes.labelsize": 14,
            "xtick.labelsize": 11.5,
            "ytick.labelsize": 11.5,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "svg.fonttype": "none",
        }
    )

    fig, ax = plt.subplots(figsize=(11.2, 6.4), facecolor="white")
    ax.set_facecolor("white")
    x = range(len(ORDER))
    bars = ax.bar(x, values, width=0.66, color=COLORS, edgecolor="#243746", linewidth=0.8, zorder=3)

    ax.set_ylim(0.0, 0.9)
    ax.set_yticks([i / 10 for i in range(10)])
    ax.set_ylabel("Incident-level Macro-F1", color="#111111", labelpad=10)
    ax.set_xlabel("Feature configuration", color="#111111", labelpad=14)
    ax.set_xticks(list(x), [LABELS[name] for name in ORDER])
    ax.tick_params(axis="x", length=0, pad=10, colors="#111111")
    ax.tick_params(axis="y", colors="#111111")

    ax.yaxis.grid(True, color="#D8DEE4", linewidth=0.7, alpha=0.8, zorder=0)
    ax.xaxis.grid(False)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color("#59636E")
    ax.spines["bottom"].set_color("#59636E")

    for bar, value in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            value + 0.012,
            f"{value:.4f}",
            ha="center",
            va="bottom",
            fontsize=12.5,
            fontweight="bold",
            color="#111111",
        )

    ax.text(
        0.995,
        0.985,
        "Five-seed mean; TRAIN-only incident-grouped cross-validation",
        transform=ax.transAxes,
        ha="right",
        va="top",
        fontsize=10.5,
        color="#4A5560",
    )

    fig.subplots_adjust(left=0.105, right=0.985, top=0.96, bottom=0.245)
    stem = OUT / "figure_4_2_xgboost_feature_family_ablation"
    fig.savefig(stem.with_suffix(".png"), dpi=450, facecolor="white", bbox_inches="tight", pad_inches=0.08)
    fig.savefig(stem.with_suffix(".pdf"), facecolor="white", bbox_inches="tight", pad_inches=0.08)
    fig.savefig(stem.with_suffix(".svg"), facecolor="white", bbox_inches="tight", pad_inches=0.08)
    plt.close(fig)


if __name__ == "__main__":
    main()
