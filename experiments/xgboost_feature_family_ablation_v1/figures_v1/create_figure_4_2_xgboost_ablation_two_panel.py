from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.colors import TwoSlopeNorm
import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "experiments/xgboost_feature_family_ablation_v1/xgb_ablation_summary_metrics_v1.csv"
OUT = Path(__file__).resolve().parent

FULL = "full_v4"
ORDER = ["minus_caida", "minus_rpki", "minus_behavioral", "behavioral_only"]
ROW_LABELS = [
    "Without CAIDA\n(60 features)",
    "Without RPKI/ROV\n(58 features)",
    "Without behavioral BGP\n(30 features)",
    "Behavioral BGP only\n(44 features)",
]
CLASS_COLUMNS = ["incident_hijack_f1", "incident_leak_f1", "incident_outage_f1"]


def main() -> None:
    data = pd.read_csv(SOURCE).set_index("configuration")
    expected = {
        "full_v4": 0.8056775087076607,
        "minus_caida": 0.7981479867299683,
        "minus_rpki": 0.7961777802117015,
        "minus_behavioral": 0.7619364350235698,
        "behavioral_only": 0.7858249927417094,
    }
    for name, value in expected.items():
        observed = float(data.loc[name, "incident_macro_f1"])
        if abs(observed - value) > 1e-12:
            raise RuntimeError(f"Saved metric mismatch for {name}: {observed} != {value}")

    overall_delta = np.array(
        [float(data.loc[name, "incident_macro_f1"] - data.loc[FULL, "incident_macro_f1"]) for name in ORDER]
    )
    class_delta = np.array(
        [[float(data.loc[name, column] - data.loc[FULL, column]) for column in CLASS_COLUMNS] for name in ORDER]
    )

    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 11.5,
            "axes.titlesize": 13.5,
            "axes.labelsize": 12.5,
            "xtick.labelsize": 10.5,
            "ytick.labelsize": 10.5,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "svg.fonttype": "none",
        }
    )

    fig = plt.figure(figsize=(12.2, 6.1), facecolor="white")
    grid = fig.add_gridspec(1, 2, width_ratios=[1.02, 1.38], wspace=0.43)
    ax_left = fig.add_subplot(grid[0, 0])
    ax_right = fig.add_subplot(grid[0, 1])

    # Panel A: overall incident-level Macro-F1 change from the Full V4 reference.
    y = np.arange(len(ORDER))
    colors = ["#C94C4C", "#C94C4C", "#A93232", "#6F7F8E"]
    bars = ax_left.barh(y, overall_delta, color=colors, edgecolor="#333333", linewidth=0.6, height=0.54, zorder=3)
    ax_left.axvline(0, color="#394B59", linewidth=1.1, zorder=4)
    ax_left.set_yticks(y, ROW_LABELS)
    ax_left.invert_yaxis()
    ax_left.set_xlim(-0.052, 0.006)
    ax_left.set_xticks([-0.05, -0.04, -0.03, -0.02, -0.01, 0.00])
    ax_left.set_xlabel("Macro-F1 delta relative to Full V4")
    ax_left.set_title("A   Overall ablation impact", loc="left", fontweight="bold", pad=13)
    ax_left.xaxis.grid(True, color="#DDE2E6", linewidth=0.7, zorder=0)
    ax_left.yaxis.grid(False)
    ax_left.tick_params(axis="y", length=0, pad=8)
    for spine in ["top", "right", "left"]:
        ax_left.spines[spine].set_visible(False)
    ax_left.spines["bottom"].set_color("#66727D")

    for bar, value in zip(bars, overall_delta):
        is_large = abs(value) > 0.03
        ax_left.text(
            value + 0.0014 if is_large else value - 0.0012,
            bar.get_y() + bar.get_height() / 2,
            f"{value:+.6f}",
            ha="left" if is_large else "right",
            va="center",
            fontsize=10.5,
            fontweight="bold",
            color="white" if is_large else "#111111",
        )

    # Panel B: class-specific F1 changes from the same Full V4 reference.
    norm = TwoSlopeNorm(vmin=-0.075, vcenter=0.0, vmax=0.01)
    image = ax_right.imshow(class_delta, cmap="RdYlGn", norm=norm, aspect="auto")
    ax_right.set_xticks([0, 1, 2], ["Hijack F1 delta", "Leak F1 delta", "Outage F1 delta"])
    ax_right.set_yticks(y, ROW_LABELS)
    ax_right.set_title("B   Class-specific F1 delta", loc="left", fontweight="bold", pad=13)
    ax_right.tick_params(axis="both", length=0, pad=8)

    for row in range(class_delta.shape[0]):
        for column in range(class_delta.shape[1]):
            value = class_delta[row, column]
            ax_right.text(
                column,
                row,
                f"{value:+.6f}",
                ha="center",
                va="center",
                fontsize=10.1,
                fontweight="bold",
                color="white" if value < -0.045 else "#111111",
            )

    ax_right.set_xticks(np.arange(-0.5, 3, 1), minor=True)
    ax_right.set_yticks(np.arange(-0.5, 4, 1), minor=True)
    ax_right.grid(which="minor", color="white", linewidth=1.5)
    ax_right.tick_params(which="minor", bottom=False, left=False)
    for spine in ax_right.spines.values():
        spine.set_visible(False)

    colorbar = fig.colorbar(image, ax=ax_right, fraction=0.047, pad=0.035)
    colorbar.set_label("F1 delta", rotation=270, labelpad=17)
    colorbar.ax.tick_params(labelsize=9)
    colorbar.outline.set_edgecolor("#68737D")

    fig.text(
        0.5,
        0.035,
        f"Full V4 reference Macro-F1 = {float(data.loc[FULL, 'incident_macro_f1']):.6f}. Negative values indicate lower performance; paired confidence intervals are reported separately.",
        ha="center",
        va="center",
        fontsize=10.2,
        color="#4C5964",
    )
    fig.subplots_adjust(left=0.17, right=0.955, top=0.89, bottom=0.18)

    stem = OUT / "figure_4_2_xgboost_feature_family_ablation_two_panel"
    fig.savefig(stem.with_suffix(".png"), dpi=450, facecolor="white", bbox_inches="tight", pad_inches=0.08)
    fig.savefig(stem.with_suffix(".pdf"), facecolor="white", bbox_inches="tight", pad_inches=0.08)
    fig.savefig(stem.with_suffix(".svg"), facecolor="white", bbox_inches="tight", pad_inches=0.08)
    plt.close(fig)


if __name__ == "__main__":
    main()
