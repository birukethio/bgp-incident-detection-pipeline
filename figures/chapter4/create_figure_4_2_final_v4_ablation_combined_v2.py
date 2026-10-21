from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.colors import TwoSlopeNorm
from matplotlib.patches import FancyBboxPatch


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "docs" / "chapter4_feature_family_ablation_results_v1.csv"
OUT = ROOT / "figures" / "chapter4"
STEM = "figure_4_2_final_v4_feature_family_ablation_combined_v2"

INK = "#171717"
MUTED = "#555555"
GRID = "#D1D1D1"
NEGATIVE = "#424242"
POSITIVE = "#A7A7A7"
PANEL_EDGE = "#8A8A8A"


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
    df = pd.read_csv(SOURCE)
    df = df[df["feature_family"] != "NONE_FULL_V4"].copy()
    df["label"] = df["feature_family"].map(LABELS)
    df["macro_delta"] = pd.to_numeric(df["delta_macro_f1_vs_full_v4"])

    full = pd.read_csv(SOURCE).query("feature_family == 'NONE_FULL_V4'").iloc[0]
    for cls in ["hijack", "leak", "outage"]:
        df[f"{cls}_delta"] = pd.to_numeric(df[f"{cls}_f1"]) - float(full[f"{cls}_f1"])

    df = df.sort_values("macro_delta", ascending=True).reset_index(drop=True)
    return df, full


def add_panel_frame(fig, ax, pad_x=0.015, pad_y=0.035):
    pos = ax.get_position()
    frame = FancyBboxPatch(
        (pos.x0 - pad_x, pos.y0 - pad_y),
        pos.width + 2 * pad_x,
        pos.height + 2 * pad_y,
        transform=fig.transFigure,
        boxstyle="round,pad=0.005,rounding_size=0.012",
        facecolor="none",
        edgecolor=PANEL_EDGE,
        linewidth=1.0,
        zorder=-1,
    )
    fig.patches.append(frame)


def draw():
    df, full = load_data()
    y = np.arange(len(df))

    fig = plt.figure(figsize=(16.0, 8.2), facecolor="white")
    gs = fig.add_gridspec(1, 2, width_ratios=[1.12, 1.0], wspace=0.30)
    ax_bar = fig.add_subplot(gs[0, 0])
    ax_heat = fig.add_subplot(gs[0, 1])

    # Panel A: change in incident Macro F1 after removing each family.
    colors = [NEGATIVE if v < 0 else POSITIVE for v in df["macro_delta"]]
    ax_bar.barh(y, df["macro_delta"], color=colors, height=0.62, edgecolor="none")
    ax_bar.axvline(0, color=INK, lw=1.1)
    ax_bar.set_yticks(y, df["label"], fontsize=10.0, color=INK)
    ax_bar.invert_yaxis()
    xmin = min(-0.025, df["macro_delta"].min() * 1.18)
    xmax = max(0.007, df["macro_delta"].max() * 1.35)
    ax_bar.set_xlim(xmin, xmax)
    ax_bar.set_xlabel("Change in incident Macro F1 after family removal", fontsize=10.5, color=INK)
    ax_bar.set_title("A   Overall Macro-F1 sensitivity", loc="left", pad=18,
                     fontsize=13, fontweight="bold", color=INK)
    ax_bar.grid(axis="x", color=GRID, lw=0.7)
    ax_bar.set_axisbelow(True)
    ax_bar.tick_params(axis="x", labelsize=9, colors=MUTED)
    ax_bar.tick_params(axis="y", length=0, pad=8)
    for spine in ["top", "right", "left"]:
        ax_bar.spines[spine].set_visible(False)
    ax_bar.spines["bottom"].set_color(PANEL_EDGE)

    span = xmax - xmin
    for i, value in enumerate(df["macro_delta"]):
        if value < 0:
            x = value - span * 0.012
            ha = "right"
        else:
            x = value + span * 0.012
            ha = "left"
        ax_bar.text(x, i, f"{value:+.6f}", ha=ha, va="center",
                    fontsize=8.8, fontweight="bold", color=INK)

    ax_bar.text(
        0.0, -0.085,
        f"Full V4 reference: Macro F1 = {float(full['incident_macro_f1']):.6f} (74 features)",
        transform=ax_bar.transAxes, ha="left", va="top", fontsize=9.1, color=MUTED,
    )

    # Panel B: class-specific F1 changes.
    matrix = df[["hijack_delta", "leak_delta", "outage_delta"]].to_numpy()
    lim = max(abs(matrix.min()), abs(matrix.max()))
    norm = TwoSlopeNorm(vmin=-lim, vcenter=0.0, vmax=lim)
    image = ax_heat.imshow(matrix, cmap="Greys_r", norm=norm, aspect="auto")
    ax_heat.set_xticks([0, 1, 2], ["Hijack F1 Δ", "Leak F1 Δ", "Outage F1 Δ"],
                       fontsize=10.1, fontweight="bold")
    ax_heat.xaxis.tick_top()
    ax_heat.tick_params(axis="x", length=0, pad=10)
    ax_heat.set_yticks(y, df["label"], fontsize=9.7)
    ax_heat.tick_params(axis="y", length=0, pad=8)
    ax_heat.set_title("B   Class-specific F1 sensitivity", loc="left", pad=48,
                      fontsize=13, fontweight="bold", color=INK)

    ax_heat.set_xticks(np.arange(-0.5, 3, 1), minor=True)
    ax_heat.set_yticks(np.arange(-0.5, len(df), 1), minor=True)
    ax_heat.grid(which="minor", color="white", linestyle="-", linewidth=1.5)
    ax_heat.tick_params(which="minor", bottom=False, left=False)
    for spine in ax_heat.spines.values():
        spine.set_color(PANEL_EDGE)
        spine.set_linewidth(0.8)

    for i in range(matrix.shape[0]):
        for j in range(matrix.shape[1]):
            value = matrix[i, j]
            rgba = image.cmap(image.norm(value))
            luminance = 0.2126 * rgba[0] + 0.7152 * rgba[1] + 0.0722 * rgba[2]
            text_color = "white" if luminance < 0.48 else INK
            ax_heat.text(j, i, f"{value:+.6f}", ha="center", va="center",
                         fontsize=8.8, fontweight="bold", color=text_color)

    cbar = fig.colorbar(image, ax=ax_heat, fraction=0.035, pad=0.035)
    cbar.ax.tick_params(labelsize=8.5, colors=MUTED)
    cbar.set_label("F1 change after removal", fontsize=9.2, color=INK)
    cbar.outline.set_edgecolor(PANEL_EDGE)

    fig.subplots_adjust(left=0.185, right=0.965, top=0.870, bottom=0.145)
    add_panel_frame(fig, ax_bar, pad_x=0.020, pad_y=0.055)
    add_panel_frame(fig, ax_heat, pad_x=0.020, pad_y=0.055)
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
