from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Rectangle


OUT = Path(__file__).resolve().parent
STEM = "figure_3_leakage_safe_partitioning_grayscale_v3"

COLORS = {
    "ink": "#161616",
    "muted": "#525252",
    "line": "#8C8C8C",
    "corpus": "#F4F4F4",
    "train": "#E2E2E2",
    "train_accent": "#303030",
    "validation": "#ECECEC",
    "validation_accent": "#626262",
    "holdout": "#F5F5F5",
    "holdout_accent": "#8A8A8A",
    "rail": "#E8E8E8",
    "white": "#FFFFFF",
}


def rounded_box(ax, x, y, w, h, face, edge="#CAD2DE", radius=0.022, lw=1.15):
    patch = FancyBboxPatch(
        (x, y),
        w,
        h,
        boxstyle=f"round,pad=0.006,rounding_size={radius}",
        facecolor=face,
        edgecolor=edge,
        linewidth=lw,
        mutation_aspect=1,
    )
    ax.add_patch(patch)
    return patch


def partition_box(ax, x, y, w, h, face, accent, name, count, pct, detail, class_count):
    rounded_box(ax, x, y, w, h, face, edge="#777777", lw=1.25)
    ax.add_patch(Rectangle((x, y + h - 0.045), w, 0.045, facecolor=accent, edgecolor="none"))
    ax.text(x + 0.026, y + h - 0.105, name, ha="left", va="top",
            fontsize=13.8, fontweight="bold", color=COLORS["ink"])
    ax.text(x + 0.026, y + h - 0.192, f"{count:,}", ha="left", va="top",
            fontsize=27, fontweight="bold", color=COLORS["ink"])
    ax.text(x + 0.026, y + h - 0.267, f"incidents  |  {pct}", ha="left", va="top",
            fontsize=10.6, color=COLORS["muted"])
    ax.plot([x + 0.026, x + w - 0.026], [y + 0.185, y + 0.185],
            color="#C8D0DB", linewidth=0.9)
    ax.text(x + 0.026, y + 0.145, class_count, ha="left", va="top",
            fontsize=10.2, fontweight="bold", color=COLORS["ink"])
    ax.text(x + 0.026, y + 0.085, detail, ha="left", va="top",
            fontsize=9.7, color=COLORS["muted"], linespacing=1.35)


def draw():
    fig, ax = plt.subplots(figsize=(15.5, 6.5), facecolor="white")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    # Authoritative corpus
    cx, cy, cw, ch = 0.035, 0.315, 0.205, 0.45
    rounded_box(ax, cx, cy, cw, ch, COLORS["corpus"], edge="#777777", lw=1.25)
    ax.text(cx + 0.027, cy + ch - 0.070, "FROZEN CORPUS", ha="left", va="top",
            fontsize=10.2, fontweight="bold", color=COLORS["muted"])
    ax.text(cx + 0.027, cy + ch - 0.145, "1,419", ha="left", va="top",
            fontsize=31, fontweight="bold", color=COLORS["ink"])
    ax.text(cx + 0.027, cy + ch - 0.235, "independent incidents", ha="left", va="top",
            fontsize=11, color=COLORS["muted"])
    ax.plot([cx + 0.027, cx + cw - 0.027], [cy + 0.155, cy + 0.155],
            color="#C8D0DB", linewidth=0.9)
    ax.text(cx + 0.027, cy + 0.112, "473 Hijack", ha="left", va="top",
            fontsize=10.2, fontweight="bold", color=COLORS["ink"])
    ax.text(cx + 0.102, cy + 0.112, "473 Leak", ha="left", va="top",
            fontsize=10.2, fontweight="bold", color=COLORS["ink"])
    ax.text(cx + 0.027, cy + 0.058, "473 Outage", ha="left", va="top",
            fontsize=10.2, fontweight="bold", color=COLORS["ink"])

    # Split node and connectors
    split_x = 0.275
    ax.add_patch(FancyArrowPatch((cx + cw, cy + ch / 2), (split_x, cy + ch / 2),
                                 arrowstyle="-|>", mutation_scale=13,
                                 linewidth=1.5, color=COLORS["ink"]))
    ax.text(split_x + 0.002, cy + ch / 2 + 0.040, "incident-level\nassignment",
            ha="center", va="bottom", fontsize=9.2, color=COLORS["muted"], linespacing=1.15)

    gap = 0.016
    x0 = 0.315
    total_w = 0.65
    usable = total_w - 2 * gap
    widths = [usable / 3, usable / 3, usable / 3]
    xs = [x0, x0 + widths[0] + gap, x0 + widths[0] + gap + widths[1] + gap]
    centers = [xs[i] + widths[i] / 2 for i in range(3)]
    box_y, box_h = 0.315, 0.45

    junction_y = 0.84
    ax.plot([split_x, split_x], [cy + ch / 2, junction_y], color=COLORS["line"], lw=1.25)
    ax.plot([split_x, centers[-1]], [junction_y, junction_y], color=COLORS["line"], lw=1.25)
    for center in centers:
        ax.add_patch(FancyArrowPatch((center, junction_y), (center, box_y + box_h + 0.008),
                                     arrowstyle="-|>", mutation_scale=12,
                                     linewidth=1.25, color=COLORS["line"]))

    partition_box(
        ax, xs[0], box_y, widths[0], box_h,
        COLORS["train"], COLORS["train_accent"],
        "TRAIN", 993, "70%", "Model development\nand grouped / nested CV", "331 H  |  331 L  |  331 O",
    )
    partition_box(
        ax, xs[1], box_y, widths[1], box_h,
        COLORS["validation"], COLORS["validation_accent"],
        "VALIDATION", 213, "15%", "One-time\nconfirmation", "71 H  |  71 L  |  71 O",
    )
    partition_box(
        ax, xs[2], box_y, widths[2], box_h,
        COLORS["holdout"], COLORS["holdout_accent"],
        "FINAL HOLDOUT", 213, "15%", "Terminal evaluation\nafter model freeze", "71 H  |  71 L  |  71 O",
    )

    # Leakage-control boundary rail
    rx, ry, rw, rh = 0.315, 0.135, 0.65, 0.095
    rounded_box(ax, rx, ry, rw, rh, COLORS["rail"], edge="#C6CFDB", radius=0.018, lw=1.0)
    ax.text(rx + 0.025, ry + rh / 2, "LEAKAGE CONTROL", ha="left", va="center",
            fontsize=10.1, fontweight="bold", color=COLORS["ink"])
    ax.text(rx + 0.155, ry + rh / 2,
            "No incident UID overlap   |   Every future window and feature row inherits its incident partition",
            ha="left", va="center", fontsize=10.1, color=COLORS["muted"])

    fig.subplots_adjust(left=0.015, right=0.985, top=0.98, bottom=0.06)
    return fig


if __name__ == "__main__":
    fig = draw()
    fig.savefig(OUT / f"{STEM}.pdf", dpi=300, bbox_inches="tight", facecolor="white")
    fig.savefig(OUT / f"{STEM}.png", dpi=300, bbox_inches="tight", facecolor="white")
    fig.savefig(OUT / f"{STEM}_highres_chart_only.jpg", dpi=450, bbox_inches="tight",
                facecolor="white", pil_kwargs={"quality": 96, "subsampling": 0})
    plt.close(fig)
