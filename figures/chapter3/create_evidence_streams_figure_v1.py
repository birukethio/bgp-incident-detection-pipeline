from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch


OUT = Path(__file__).resolve().parent


COLORS = {
    "bgp": "#2F6B9A",
    "caida": "#3F7D57",
    "rpki": "#B55B2A",
    "model": "#4D4A8F",
    "rank": "#7A3E72",
    "boundary": "#4B5563",
    "line": "#2F3640",
    "fill": "#F7F9FC",
    "boundary_fill": "#F3F4F6",
}


def box(ax, x, y, w, h, title, lines, color, fontsize=10, title_size=11):
    patch = FancyBboxPatch(
        (x, y),
        w,
        h,
        boxstyle="round,pad=0.018,rounding_size=0.035",
        linewidth=1.35,
        edgecolor=color,
        facecolor="#FFFFFF",
        zorder=2,
    )
    ax.add_patch(patch)
    if h < 0.17:
        title_y = y + h * 0.66
        lines_y = y + h * 0.38
    else:
        title_y = y + h - 0.09
        lines_y = y + h - 0.19

    ax.text(
        x + w / 2,
        title_y,
        title,
        ha="center",
        va="top",
        fontsize=title_size,
        fontweight="bold",
        color=color,
        zorder=3,
    )
    ax.text(
        x + w / 2,
        lines_y,
        "\n".join(lines),
        ha="center",
        va="top",
        fontsize=fontsize,
        color="#111827",
        linespacing=1.18,
        zorder=3,
    )


def arrow(ax, start, end, color="#2F3640", rad=0.0, lw=1.6, zorder=1):
    ax.add_patch(
        FancyArrowPatch(
            start,
            end,
            arrowstyle="-|>",
            mutation_scale=14,
            linewidth=lw,
            color=color,
            connectionstyle=f"arc3,rad={rad}",
            zorder=zorder,
        )
    )


def draw(include_title=True):
    fig = plt.figure(figsize=(14.2, 8.7), facecolor="white")
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    if include_title:
        ax.text(
            0.5,
            0.955,
            "Three Evidence Streams for BGP Incident Classification and Ranking",
            ha="center",
            va="top",
            fontsize=20,
            fontweight="bold",
            color="#12233F",
        )
        ax.text(
            0.5,
            0.915,
            "Behavioral routing evidence, AS-policy context, and origin-authorization evidence combine under documented visibility and provenance boundaries.",
            ha="center",
            va="top",
            fontsize=11.5,
            color="#374151",
        )
        top_y = 0.81
    else:
        top_y = 0.88

    # Boundary rails.
    boundary_y = 0.035
    boundary_h = 0.125
    rail = FancyBboxPatch(
        (0.055, boundary_y),
        0.89,
        boundary_h,
        boxstyle="round,pad=0.012,rounding_size=0.025",
        linewidth=1.15,
        edgecolor=COLORS["boundary"],
        facecolor=COLORS["boundary_fill"],
        zorder=0,
    )
    ax.add_patch(rail)
    ax.text(
        0.075,
        boundary_y + boundary_h - 0.035,
        "Boundary conditions",
        fontsize=11.5,
        fontweight="bold",
        color=COLORS["boundary"],
        va="top",
    )
    ax.text(
        0.245,
        boundary_y + boundary_h - 0.035,
        "Public-collector visibility",
        fontsize=10.5,
        fontweight="bold",
        color="#111827",
        va="top",
    )
    ax.text(
        0.245,
        boundary_y + boundary_h - 0.071,
        "RouteViews-observable evidence; not enterprise-local telemetry.",
        fontsize=9.5,
        color="#374151",
        va="top",
    )
    ax.text(
        0.615,
        boundary_y + boundary_h - 0.035,
        "Label provenance",
        fontsize=10.5,
        fontweight="bold",
        color="#111827",
        va="top",
    )
    ax.text(
        0.615,
        boundary_y + boundary_h - 0.071,
        "External incident labels and audits define ground-truth boundaries.",
        fontsize=9.5,
        color="#374151",
        va="top",
    )

    # Source boxes.
    w = 0.245
    h = 0.28
    x_positions = [0.07, 0.3775, 0.685]
    y = top_y - h
    box(
        ax,
        x_positions[0],
        y,
        w,
        h,
        "BGP Behavioral Evidence",
        [
            "44 frozen features",
            "announcements, withdrawals",
            "origin/path/visibility dynamics",
            "5-minute analytical windows",
        ],
        COLORS["bgp"],
        fontsize=9.3,
    )
    box(
        ax,
        x_positions[1],
        y,
        w,
        h,
        "CAIDA AS-Policy Evidence",
        [
            "14 frozen features",
            "AS relationships and policy context",
            "valley-free / provider-customer",
            "historical snapshot aligned",
        ],
        COLORS["caida"],
        fontsize=9.3,
    )
    box(
        ax,
        x_positions[2],
        y,
        w,
        h,
        "RPKI / ROV Evidence",
        [
            "16 frozen features",
            "prefix-origin authorization",
            "VALID / INVALID / NotFound",
            "maxLength and mismatch signals",
        ],
        COLORS["rpki"],
        fontsize=9.3,
    )

    # Fusion and model boxes.
    feature_y = 0.345
    box(
        ax,
        0.22,
        feature_y,
        0.24,
        0.14,
        "Frozen V4 Feature Vector",
        ["74 ordered features", "schema-locked, leakage-checked"],
        "#374151",
        fontsize=10,
    )
    box(
        ax,
        0.54,
        feature_y,
        0.25,
        0.14,
        "Level-1 Incident Classifier",
        ["XGBoost H/L/O probabilities", "Hijack  •  Leak  •  Outage"],
        COLORS["model"],
        fontsize=10,
    )
    box(
        ax,
        0.35,
        0.19,
        0.3,
        0.125,
        "Classification and Ranking Output",
        ["Top-1 predicted class", "Top-2 ranking and MRR-ready scores"],
        COLORS["rank"],
        fontsize=10,
    )

    # Arrows from evidence streams.
    for x, c in zip(x_positions, [COLORS["bgp"], COLORS["caida"], COLORS["rpki"]]):
        arrow(ax, (x + w / 2, y), (0.34, feature_y + 0.14), color=c, rad=0.05 if x < 0.3 else (-0.05 if x > 0.6 else 0))
    arrow(ax, (0.465, feature_y + 0.07), (0.535, feature_y + 0.07), color=COLORS["line"], lw=1.8, zorder=4)
    arrow(ax, (0.665, feature_y), (0.58, 0.315), color=COLORS["model"], rad=-0.05, lw=1.8, zorder=4)

    # Boundary arrows.
    arrow(ax, (0.29, boundary_y + boundary_h), (0.29, feature_y), color=COLORS["boundary"], lw=1.1)
    arrow(ax, (0.68, boundary_y + boundary_h), (0.665, feature_y), color=COLORS["boundary"], lw=1.1)

    return fig


def main():
    base = OUT / "figure_3_evidence_streams_hlo_boundary_conditions_v1"
    fig = draw(include_title=True)
    fig.savefig(base.with_suffix(".pdf"), bbox_inches="tight")
    fig.savefig(base.with_suffix(".png"), dpi=300, bbox_inches="tight")
    plt.close(fig)

    chart = draw(include_title=False)
    chart.savefig(
        OUT / "figure_3_evidence_streams_hlo_boundary_conditions_v1_highres_chart_only.jpg",
        dpi=450,
        bbox_inches="tight",
        pil_kwargs={"quality": 95},
    )
    plt.close(chart)


if __name__ == "__main__":
    main()
