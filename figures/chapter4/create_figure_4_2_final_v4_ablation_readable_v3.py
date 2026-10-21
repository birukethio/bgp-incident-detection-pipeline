from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.colors import TwoSlopeNorm


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "docs" / "chapter4_feature_family_ablation_results_v1.csv"
OUT = ROOT / "figures" / "chapter4"
STEM = "figure_4_2_final_v4_ablation_readable_v3"

INK = "#171717"
MUTED = "#555555"
GRID = "#D4D4D4"
DARK = "#3D3D3D"
MID = "#8D8D8D"

LABELS = {
    "rpki_rov": "RPKI / ROV",
    "as_path_length_structure": "AS-path structure",
    "origin_change_moas_behavior": "Origin change / MOAS",
    "announcement_update_activity": "Announcement activity",
    "withdrawal_activity": "Withdrawal activity",
    "as_path_instability_path_change": "AS-path instability",
    "prefix_dynamics": "Prefix dynamics",
    "peer_visibility_behavior": "Peer visibility",
    "prepending_behavior": "Prepending behavior",
    "caida_as_relationship": "CAIDA relationships",
}


def load_data():
    table = pd.read_csv(SOURCE)
    full = table.loc[table["feature_family"] == "NONE_FULL_V4"].iloc[0]
    rows = table.loc[table["feature_family"] != "NONE_FULL_V4"].copy()
    rows["label"] = rows["feature_family"].map(LABELS)
    rows["macro_delta"] = pd.to_numeric(rows["delta_macro_f1_vs_full_v4"])
    for cls in ("hijack", "leak", "outage"):
        rows[f"{cls}_delta"] = pd.to_numeric(rows[f"{cls}_f1"]) - float(full[f"{cls}_f1"])
    rows = rows.sort_values("macro_delta", ascending=True).reset_index(drop=True)
    return rows, full


def draw():
    rows, full = load_data()
    y = np.arange(len(rows))

    fig = plt.figure(figsize=(13.5, 14.0), facecolor="white")
    gs = fig.add_gridspec(2, 1, height_ratios=[1.03, 1.0], hspace=0.40)
    ax_bar = fig.add_subplot(gs[0])
    ax_heat = fig.add_subplot(gs[1])

    # A. Horizontal delta chart
    values = rows["macro_delta"].to_numpy()
    bar_colors = [DARK if value < 0 else MID for value in values]
    ax_bar.barh(y, values, height=0.62, color=bar_colors, edgecolor="none")
    ax_bar.axvline(0, color=INK, linewidth=1.4)
    ax_bar.set_yticks(y, rows["label"], fontsize=13, color=INK)
    ax_bar.invert_yaxis()
    ax_bar.set_xlim(-0.0265, 0.0070)
    ax_bar.set_xlabel("Change in incident Macro F1 after removing the feature family",
                      fontsize=12.5, fontweight="bold", color=INK, labelpad=12)
    ax_bar.set_title("A   Overall incident Macro-F1 sensitivity", loc="left",
                     fontsize=16, fontweight="bold", color=INK, pad=16)
    ax_bar.grid(axis="x", color=GRID, linewidth=0.8)
    ax_bar.set_axisbelow(True)
    ax_bar.tick_params(axis="x", labelsize=11, colors=MUTED)
    ax_bar.tick_params(axis="y", length=0, pad=12)
    for side in ("top", "right", "left"):
        ax_bar.spines[side].set_visible(False)
    ax_bar.spines["bottom"].set_color(MID)

    for idx, value in enumerate(values):
        if value < 0:
            x, ha = value - 0.00045, "right"
        else:
            x, ha = value + 0.00045, "left"
        ax_bar.text(x, idx, f"{value:+.6f}", ha=ha, va="center",
                    fontsize=11.5, fontweight="bold", color=INK)

    ax_bar.text(
        0.5, -0.155,
        f"Full V4 reference: Macro F1 = {float(full['incident_macro_f1']):.6f} (74 features)"
        "   |   Negative delta = lower performance after removal",
        transform=ax_bar.transAxes, ha="center", va="top",
        fontsize=10.8, fontweight="bold", color=MUTED,
    )

    # B. Class-specific delta heatmap
    matrix = rows[["hijack_delta", "leak_delta", "outage_delta"]].to_numpy()
    limit = max(abs(matrix.min()), abs(matrix.max()))
    norm = TwoSlopeNorm(vmin=-limit, vcenter=0, vmax=limit)
    image = ax_heat.imshow(matrix, cmap="Greys_r", norm=norm, aspect="auto")
    ax_heat.set_xticks([0, 1, 2], ["Hijack F1 Δ", "Leak F1 Δ", "Outage F1 Δ"],
                       fontsize=13, fontweight="bold")
    ax_heat.xaxis.tick_top()
    ax_heat.tick_params(axis="x", length=0, pad=12)
    ax_heat.set_yticks(y, rows["label"], fontsize=13, color=INK)
    ax_heat.tick_params(axis="y", length=0, pad=12)
    ax_heat.set_title("B   Class-specific F1 sensitivity", loc="left",
                      fontsize=16, fontweight="bold", color=INK, pad=42)

    ax_heat.set_xticks(np.arange(-0.5, 3, 1), minor=True)
    ax_heat.set_yticks(np.arange(-0.5, len(rows), 1), minor=True)
    ax_heat.grid(which="minor", color="white", linewidth=2.0)
    ax_heat.tick_params(which="minor", bottom=False, left=False)
    for spine in ax_heat.spines.values():
        spine.set_color(MID)
        spine.set_linewidth(1.0)

    for row in range(matrix.shape[0]):
        for col in range(matrix.shape[1]):
            value = matrix[row, col]
            rgba = image.cmap(image.norm(value))
            lum = 0.2126 * rgba[0] + 0.7152 * rgba[1] + 0.0722 * rgba[2]
            color = "white" if lum < 0.48 else INK
            ax_heat.text(col, row, f"{value:+.6f}", ha="center", va="center",
                         fontsize=12, fontweight="bold", color=color)

    cbar = fig.colorbar(image, ax=ax_heat, fraction=0.025, pad=0.028)
    cbar.ax.tick_params(labelsize=10.5, colors=MUTED)
    cbar.set_label("F1 change after family removal", fontsize=11.5,
                   fontweight="bold", color=INK, labelpad=10)
    cbar.outline.set_edgecolor(MID)

    fig.subplots_adjust(left=0.255, right=0.925, top=0.955, bottom=0.065)
    return fig


if __name__ == "__main__":
    fig = draw()
    fig.savefig(OUT / f"{STEM}.pdf", dpi=300, bbox_inches="tight", facecolor="white")
    fig.savefig(OUT / f"{STEM}.png", dpi=300, bbox_inches="tight", facecolor="white")
    fig.savefig(
        OUT / f"{STEM}_highres_chart_only.jpg",
        dpi=450, bbox_inches="tight", facecolor="white",
        pil_kwargs={"quality": 97, "subsampling": 0},
    )
    plt.close(fig)
