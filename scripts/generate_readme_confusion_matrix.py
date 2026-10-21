"""Generate the curated Final Holdout confusion matrix used in README.md."""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np


MATRIX = np.array(
    [
        [61, 9, 1],
        [5, 66, 0],
        [2, 0, 69],
    ]
)
CLASSES = ["Hijack", "Leak", "Outage"]


def main() -> None:
    output = Path(__file__).resolve().parents[1] / "docs/assets/final_holdout_confusion_matrix.png"

    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 14,
            "axes.labelsize": 16,
            "xtick.labelsize": 14,
            "ytick.labelsize": 14,
        }
    )

    fig, ax = plt.subplots(figsize=(8.4, 6.8), constrained_layout=True)
    image = ax.imshow(MATRIX, cmap="Blues", vmin=0, vmax=MATRIX.max())

    ax.set_xticks(range(len(CLASSES)), labels=CLASSES)
    ax.set_yticks(range(len(CLASSES)), labels=CLASSES)
    ax.set_xlabel("Predicted class", labelpad=12)
    ax.set_ylabel("True class", labelpad=12)

    threshold = MATRIX.max() / 2
    for row in range(MATRIX.shape[0]):
        for column in range(MATRIX.shape[1]):
            value = MATRIX[row, column]
            ax.text(
                column,
                row,
                f"{value}",
                ha="center",
                va="center",
                color="white" if value > threshold else "black",
                fontsize=22,
                fontweight="bold",
            )

    colorbar = fig.colorbar(image, ax=ax, shrink=0.82, pad=0.04)
    colorbar.set_label("Incident count", rotation=270, labelpad=24)

    for spine in ax.spines.values():
        spine.set_linewidth(1.1)
        spine.set_color("#374151")

    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")
    fig.savefig(output, dpi=300, bbox_inches="tight", facecolor="white")
    plt.close(fig)


if __name__ == "__main__":
    main()
