"""Create the manuscript-ready IEC disposition flow figure.

Documentation only: the figure summarizes frozen IEC accounting and gate status.
It does not execute reconstruction or model inference.
"""

from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch


ROOT = Path(__file__).resolve().parent
OUT = ROOT / "figures"


def box(ax, x, y, w, h, heading, detail, face="#F1F2F4", edge="#464D55"):
    patch = FancyBboxPatch(
        (x, y),
        w,
        h,
        boxstyle="round,pad=0.012,rounding_size=0.014",
        linewidth=1.5,
        edgecolor=edge,
        facecolor=face,
    )
    ax.add_patch(patch)
    ax.text(x + w / 2, y + h * 0.64, heading, ha="center", va="center", fontsize=12, fontweight="bold", color="#20252B")
    ax.text(x + w / 2, y + h * 0.31, detail, ha="center", va="center", fontsize=9.5, color="#424950", linespacing=1.2)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(15.2, 6.6), dpi=220, facecolor="white")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    # Main flow, intentionally title-free so Word controls figure numbering/title.
    stages = [
        (0.025, "73 candidates", "Non-Cloudflare\nsource-native events", "#F4F5F6"),
        (0.185, "Deterministic mapping", "Predeclared H/L/O\nrules; no model output", "#F4F5F6"),
        (0.345, "63 locked IEC", "16 Hijack | 17 Leak\n30 Outage", "#E9EAEC"),
        (0.505, "Reconstruction gate", "End-to-end equivalence\nrequired before scoring", "#E9EAEC"),
        (0.665, "0 evaluable", "Gate did not pass;\nno IEC inference", "#DDDFE2"),
        (0.825, "No scoring", "Metrics = NA\nnot model failure", "#D3D6D9"),
    ]
    w, h, y = 0.135, 0.26, 0.55
    for x, heading, detail, face in stages:
        box(ax, x, y, w, h, heading, detail, face)

    arrow = dict(arrowstyle="-|>", lw=1.7, color="#555D65", mutation_scale=14)
    for left, right in zip(stages[:-1], stages[1:]):
        ax.annotate("", xy=(right[0] - 0.008, y + h / 2), xytext=(left[0] + w + 0.008, y + h / 2), arrowprops=arrow)

    # Gate marker and final disposition.
    ax.text(0.585, 0.87, "EXECUTION GATE", ha="center", va="center", fontsize=9.5, fontweight="bold", color="#4B5259")
    ax.plot([0.585, 0.585], [0.83, 0.55], color="#686F77", linewidth=1.2, linestyle="--")

    final = FancyBboxPatch(
        (0.34, 0.19),
        0.32,
        0.17,
        boxstyle="round,pad=0.016,rounding_size=0.018",
        linewidth=1.8,
        edgecolor="#30363C",
        facecolor="#C9CDD1",
    )
    ax.add_patch(final)
    ax.text(0.5, 0.295, "SOURCE-SEPARATED IEC", ha="center", va="center", fontsize=11, color="#33393F")
    ax.text(0.5, 0.245, "INCONCLUSIVE", ha="center", va="center", fontsize=17, fontweight="bold", color="#171B1F")
    ax.annotate("", xy=(0.5, 0.36), xytext=(0.8925, 0.55), arrowprops=arrow)

    # Critical interpretation boundary.
    ax.text(
        0.5,
        0.075,
        "NOT SCORED  ≠  POOR PERFORMANCE",
        ha="center",
        va="center",
        fontsize=15,
        fontweight="bold",
        color="#1D2227",
    )
    ax.text(
        0.5,
        0.027,
        "The IEC produced no predictions or performance estimates because the reconstruction gate stopped execution before inference.",
        ha="center",
        va="center",
        fontsize=10.5,
        color="#4A5158",
    )

    fig.subplots_adjust(left=0.025, right=0.985, top=0.98, bottom=0.04)
    stem = OUT / "figure_iec_external_validation_disposition_flow_v1"
    fig.savefig(stem.with_suffix(".png"), dpi=300, facecolor="white")
    fig.savefig(stem.with_suffix(".pdf"), facecolor="white")
    fig.savefig(stem.with_name(stem.name + "_highres_chart_only").with_suffix(".jpg"), dpi=600, facecolor="white")
    plt.close(fig)


if __name__ == "__main__":
    main()
