"""Create the manuscript-ready cross-source validation summary figure.

This is additive documentation only. It reads the frozen v1 agreement metrics and
does not alter the underlying cross-source validation artifacts.
"""

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.patches import FancyBboxPatch


ROOT = Path(__file__).resolve().parent
OUT = ROOT / "figures"
METRICS = ROOT / "cross_source_agreement_metrics_v1.csv"


def add_box(ax, x, y, width, height, text, facecolor="#F2F3F5"):
    box = FancyBboxPatch(
        (x, y),
        width,
        height,
        boxstyle="round,pad=0.012,rounding_size=0.015",
        linewidth=1.5,
        edgecolor="#3F4854",
        facecolor=facecolor,
    )
    ax.add_patch(box)
    ax.text(
        x + width / 2,
        y + height / 2,
        text,
        ha="center",
        va="center",
        fontsize=11.5,
        color="#20252B",
        linespacing=1.25,
    )


def main():
    metrics = pd.read_csv(METRICS)
    counts = (
        metrics.loc[metrics["metric"].eq("corroborated_incidents"), ["class", "value"]]
        .set_index("class")["value"]
        .astype(int)
        .to_dict()
    )
    classes = ["Hijack", "Leak", "Outage"]
    values = [counts.get(label, 0) for label in classes]
    assert values == [0, 1, 58], values

    fig = plt.figure(figsize=(14, 7.4), dpi=220, facecolor="white")
    grid = fig.add_gridspec(1, 2, width_ratios=[1.55, 1], wspace=0.11)

    # Panel A: deterministic cross-source validation workflow.
    ax = fig.add_subplot(grid[0, 0])
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    ax.text(0.01, 0.96, "A", fontsize=14, fontweight="bold", va="top")
    ax.text(0.055, 0.96, "Cross-source validation workflow", fontsize=15, fontweight="bold", va="top")

    boxes = [
        (0.08, 0.72, "Frozen Cloudflare corpus\n1,419 incidents"),
        (0.56, 0.72, "Independent non-Cloudflare\nsource artifacts"),
        (0.08, 0.43, "Predeclared same-event\nmatching rules"),
        (0.56, 0.43, "Deterministic H/L/O\nlabel mapping"),
        (0.32, 0.14, "Accepted same-event matches\nand agreement analysis"),
    ]
    for x, y, label in boxes:
        add_box(ax, x, y, 0.36, 0.15, label, "#F1F2F4" if y > 0.2 else "#E5E7EA")

    arrow = dict(arrowstyle="-|>", lw=1.7, color="#545E6A", mutation_scale=13)
    ax.annotate("", xy=(0.56, 0.795), xytext=(0.44, 0.795), arrowprops=arrow)
    ax.annotate("", xy=(0.26, 0.58), xytext=(0.26, 0.72), arrowprops=arrow)
    ax.annotate("", xy=(0.74, 0.58), xytext=(0.74, 0.72), arrowprops=arrow)
    ax.annotate("", xy=(0.42, 0.285), xytext=(0.26, 0.43), arrowprops=arrow)
    ax.annotate("", xy=(0.58, 0.285), xytext=(0.74, 0.43), arrowprops=arrow)

    ax.text(
        0.5,
        0.045,
        "Cloudflare was not counted as independent corroboration.\n"
        "Raw BGP observations and aggregate reports were excluded as labels.",
        ha="center",
        va="bottom",
        fontsize=9.5,
        color="#555D66",
    )

    # Panel B: class coverage. Counts are more informative than agreement rates
    # because two classes have almost no independently matched events.
    bx = fig.add_subplot(grid[0, 1])
    bx.text(-0.12, 1.045, "B", transform=bx.transAxes, fontsize=14, fontweight="bold", va="top")
    bx.set_title("Independently corroborated incidents", fontsize=15, fontweight="bold", pad=18)
    colors = ["#A8ADB3", "#737B84", "#343B43"]
    bars = bx.bar(classes, values, color=colors, width=0.62, edgecolor="#2F353B", linewidth=0.8)
    bx.set_ylim(0, 82)
    bx.set_ylabel("Accepted same-event matches", fontsize=11)
    bx.grid(axis="y", color="#D7DADF", linewidth=0.8, alpha=0.8)
    bx.set_axisbelow(True)
    bx.spines[["top", "right"]].set_visible(False)
    bx.tick_params(axis="both", labelsize=10.5)
    for bar, value in zip(bars, values):
        inside = value > 20
        bx.text(
            bar.get_x() + bar.get_width() / 2,
            value - 2.2 if inside else value + (1.2 if value else 0.8),
            str(value),
            ha="center",
            va="top" if inside else "bottom",
            fontsize=14,
            fontweight="bold",
            color="white" if inside else "#20252B",
        )

    bx.text(
        0.5,
        0.91,
        "CLASS-COVERAGE LIMITATION",
        transform=bx.transAxes,
        ha="center",
        va="center",
        fontsize=11,
        fontweight="bold",
        color="#20252B",
        bbox=dict(boxstyle="round,pad=0.35", facecolor="#ECEDEF", edgecolor="#686F77"),
    )
    bx.text(
        0.5,
        0.79,
        "The accepted corroboration set is dominated by Outage.\n"
        "It does not provide meaningful cross-source coverage\n"
        "for Hijack and provides only one Leak match.",
        transform=bx.transAxes,
        ha="center",
        va="center",
        fontsize=10.2,
        color="#3F464D",
        linespacing=1.35,
        bbox=dict(boxstyle="round,pad=0.45", facecolor="white", edgecolor="none", alpha=0.96),
    )

    fig.subplots_adjust(left=0.045, right=0.985, top=0.94, bottom=0.12)
    stem = OUT / "figure_cross_source_validation_architecture_and_coverage_v1"
    fig.savefig(stem.with_suffix(".png"), dpi=300, facecolor="white")
    fig.savefig(stem.with_suffix(".pdf"), facecolor="white")
    fig.savefig(stem.with_name(stem.name + "_highres_chart_only").with_suffix(".jpg"), dpi=600, facecolor="white")
    plt.close(fig)


if __name__ == "__main__":
    main()
