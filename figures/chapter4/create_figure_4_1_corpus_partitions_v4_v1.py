from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Rectangle


OUT = Path(__file__).resolve().parent
STEM = "figure_4_1_final_corpus_partitions_v4_composition_v1"

INK = "#171717"
MUTED = "#565656"
LINE = "#858585"
LIGHT_LINE = "#C7C7C7"
PANEL = "#F6F6F6"
TRAIN_FILL = "#DEDEDE"
VALID_FILL = "#EBEBEB"
HOLDOUT_FILL = "#F5F5F5"
BEHAVIORAL = "#353535"
CAIDA = "#747474"
RPKI = "#A3A3A3"
WHITE = "#FFFFFF"


def rounded(ax, x, y, w, h, face, edge=LINE, radius=0.018, lw=1.25):
    box = FancyBboxPatch(
        (x, y), w, h,
        boxstyle=f"round,pad=0.006,rounding_size={radius}",
        facecolor=face, edgecolor=edge, linewidth=lw,
    )
    ax.add_patch(box)
    return box


def arrow(ax, start, end, color=LINE, lw=1.35, scale=12):
    ax.add_patch(FancyArrowPatch(
        start, end, arrowstyle="-|>", mutation_scale=scale,
        linewidth=lw, color=color, shrinkA=0, shrinkB=0,
    ))


def partition(ax, x, y, w, h, label, count, share, class_counts, purpose, face, band):
    rounded(ax, x, y, w, h, face)
    ax.add_patch(Rectangle((x, y + h - 0.035), w, 0.035, facecolor=band, edgecolor="none"))
    ax.text(x + 0.020, y + h - 0.076, label, ha="left", va="top",
            fontsize=11.7, fontweight="bold", color=INK)
    ax.text(x + 0.020, y + h - 0.145, f"{count:,}", ha="left", va="top",
            fontsize=23.5, fontweight="bold", color=INK)
    ax.text(x + 0.020, y + h - 0.211, f"incidents  |  {share}", ha="left", va="top",
            fontsize=9.7, color=MUTED)
    ax.plot([x + 0.020, x + w - 0.020], [y + 0.125, y + 0.125], color=LIGHT_LINE, lw=0.9)
    ax.text(x + 0.020, y + 0.096, class_counts, ha="left", va="top",
            fontsize=9.4, fontweight="bold", color=INK)
    ax.text(x + 0.020, y + 0.052, purpose, ha="left", va="top",
            fontsize=8.9, color=MUTED, linespacing=1.25)


def feature_block(ax, x, y, w, h, value, label, note, face, text_color=WHITE):
    rounded(ax, x, y, w, h, face, edge=face, radius=0.014, lw=0)
    ax.text(x + 0.024, y + h / 2, str(value), ha="left", va="center",
            fontsize=24, fontweight="bold", color=text_color)
    ax.text(x + 0.090, y + h / 2 + 0.018, label, ha="left", va="center",
            fontsize=11.2, fontweight="bold", color=text_color)
    ax.text(x + 0.090, y + h / 2 - 0.025, note, ha="left", va="center",
            fontsize=8.9, color=text_color)


def draw():
    fig, ax = plt.subplots(figsize=(15.5, 7.8), facecolor=WHITE)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    # Panel A: corpus and frozen partitions
    ax.text(0.040, 0.915, "A", ha="left", va="center", fontsize=11.5,
            fontweight="bold", color=WHITE,
            bbox=dict(boxstyle="square,pad=0.28", facecolor=INK, edgecolor=INK))
    ax.text(0.078, 0.915, "Frozen incident corpus and partitions", ha="left", va="center",
            fontsize=13.2, fontweight="bold", color=INK)

    corpus_x, corpus_y, corpus_w, corpus_h = 0.050, 0.610, 0.250, 0.205
    rounded(ax, corpus_x, corpus_y, corpus_w, corpus_h, PANEL)
    ax.text(corpus_x + 0.026, corpus_y + corpus_h - 0.047, "BALANCED CORPUS",
            ha="left", va="top", fontsize=9.7, fontweight="bold", color=MUTED)
    ax.text(corpus_x + 0.026, corpus_y + 0.100, "1,419", ha="left", va="center",
            fontsize=29, fontweight="bold", color=INK)
    ax.text(corpus_x + 0.129, corpus_y + 0.100, "independent incidents",
            ha="left", va="center", fontsize=10.4, color=MUTED)
    ax.text(corpus_x + 0.026, corpus_y + 0.040, "473 Hijack  |  473 Leak  |  473 Outage",
            ha="left", va="center", fontsize=9.7, fontweight="bold", color=INK)

    hub_x, hub_y = 0.365, 0.712
    arrow(ax, (corpus_x + corpus_w, hub_y), (hub_x, hub_y), color=INK, lw=1.5, scale=13)
    ax.text(0.333, hub_y + 0.035, "incident-level\nsplit", ha="center", va="bottom",
            fontsize=8.7, color=MUTED, linespacing=1.1)

    p_y, p_h = 0.270, 0.290
    p_gap = 0.016
    p_x0 = 0.050
    p_total = 0.550
    p_w = (p_total - 2 * p_gap) / 3
    p_xs = [p_x0, p_x0 + p_w + p_gap, p_x0 + 2 * (p_w + p_gap)]
    centers = [x + p_w / 2 for x in p_xs]
    branch_y = 0.590
    ax.plot([hub_x, hub_x], [hub_y, branch_y], color=LINE, lw=1.25)
    ax.plot([centers[0], centers[-1]], [branch_y, branch_y], color=LINE, lw=1.25)
    for center in centers:
        arrow(ax, (center, branch_y), (center, p_y + p_h + 0.008), color=LINE, lw=1.15, scale=11)

    partition(ax, p_xs[0], p_y, p_w, p_h, "TRAIN", 993, "70%",
              "331 H  |  331 L  |  331 O", "Development + grouped CV", TRAIN_FILL, "#303030")
    partition(ax, p_xs[1], p_y, p_w, p_h, "VALIDATION", 213, "15%",
              "71 H  |  71 L  |  71 O", "One-time confirmation", VALID_FILL, "#676767")
    partition(ax, p_xs[2], p_y, p_w, p_h, "FINAL HOLDOUT", 213, "15%",
              "71 H  |  71 L  |  71 O", "Terminal evaluation", HOLDOUT_FILL, "#999999")

    rounded(ax, 0.050, 0.145, 0.550, 0.070, "#EEEEEE", edge=LIGHT_LINE, radius=0.014, lw=1.0)
    ax.text(0.070, 0.180, "LEAKAGE CONTROL", ha="left", va="center",
            fontsize=9.4, fontweight="bold", color=INK)
    ax.text(0.190, 0.180, "No incident overlap; all windows inherit the parent incident partition",
            ha="left", va="center", fontsize=9.1, color=MUTED)

    # Divider between the dataset and representation panels.
    ax.plot([0.635, 0.635], [0.120, 0.920], color=LIGHT_LINE, lw=1.0)

    # Panel B: V4 feature composition
    ax.text(0.675, 0.915, "B", ha="left", va="center", fontsize=11.5,
            fontweight="bold", color=WHITE,
            bbox=dict(boxstyle="square,pad=0.28", facecolor=INK, edgecolor=INK))
    ax.text(0.713, 0.915, "Frozen V4 feature composition", ha="left", va="center",
            fontsize=13.2, fontweight="bold", color=INK)

    fx, fw = 0.675, 0.280
    feature_block(ax, fx, 0.660, fw, 0.135, 44, "Behavioral", "BGP dynamics and visibility", BEHAVIORAL)
    feature_block(ax, fx, 0.495, fw, 0.135, 14, "CAIDA", "AS relationships and policy context", CAIDA)
    feature_block(ax, fx, 0.330, fw, 0.135, 16, "RPKI / ROV", "Origin-authorization evidence", RPKI, text_color=INK)

    # Addition rail and total feature vector.
    rail_x = fx + 0.025
    ax.plot([rail_x, rail_x], [0.322, 0.807], color=LINE, lw=1.2)
    for cy in [0.7275, 0.5625, 0.3975]:
        ax.plot([rail_x, fx], [cy, cy], color=LINE, lw=1.2)
    ax.text(fx - 0.020, 0.5625, "+", ha="center", va="center",
            fontsize=18, fontweight="bold", color=INK)

    arrow(ax, (fx + fw / 2, 0.305), (fx + fw / 2, 0.255), color=INK, lw=1.5, scale=13)
    rounded(ax, fx, 0.135, fw, 0.105, INK, edge=INK, radius=0.015, lw=1.0)
    ax.text(fx + 0.028, 0.187, "74", ha="left", va="center",
            fontsize=28, fontweight="bold", color=WHITE)
    ax.text(fx + 0.100, 0.200, "V4 FEATURES", ha="left", va="center",
            fontsize=11.4, fontweight="bold", color=WHITE)
    ax.text(fx + 0.100, 0.164, "exact frozen model input schema", ha="left", va="center",
            fontsize=8.8, color=WHITE)

    fig.subplots_adjust(left=0.018, right=0.985, top=0.985, bottom=0.055)
    return fig


if __name__ == "__main__":
    fig = draw()
    fig.savefig(OUT / f"{STEM}.pdf", dpi=300, bbox_inches="tight", facecolor=WHITE)
    fig.savefig(OUT / f"{STEM}.png", dpi=300, bbox_inches="tight", facecolor=WHITE)
    fig.savefig(
        OUT / f"{STEM}_highres_chart_only.jpg",
        dpi=450, bbox_inches="tight", facecolor=WHITE,
        pil_kwargs={"quality": 97, "subsampling": 0},
    )
    plt.close(fig)
