from __future__ import annotations

import csv
import textwrap
from pathlib import Path
from typing import Iterable

from PIL import Image, ImageDraw, ImageFont


ROOT = Path("/Users/biruk/Documents/New project")
DOCS = ROOT / "docs"
FIGURES = ROOT / "figures/chapter4"

THRESHOLD_RESULTS_SOURCE = ROOT / "docs/stage1_threshold_results_v1.csv"
THRESHOLD_SELECTION_SOURCE = ROOT / "data/modeling/stage1_threshold_selection_summary_v1.csv"
THRESHOLD_STABILITY_SOURCE = ROOT / "data/modeling/stage1_threshold_stability_v1.csv"
W1_RESULTS_SOURCE = ROOT / "data/modeling/stage1_class_group_weight_results_v1.csv"
W1_PROBABILITY_SOURCE = ROOT / "data/modeling/stage1_class_group_weight_probability_comparison_v1.csv"
W0_OOF_SOURCE = ROOT / "data/modeling/stage1_oof_probabilities_v1.parquet"
W1_OOF_SOURCE = ROOT / "data/modeling/stage1_class_group_weight_oof_probabilities_v1.parquet"

RESULTS_OUT = DOCS / "chapter4_stage1_results_v1.csv"
AUDIT_OUT = DOCS / "chapter4_section_4_5_evidence_audit_v1.csv"
CAPTIONS_OUT = DOCS / "chapter4_section_4_5_figure_captions_v1.md"
PAPER_TEXT_OUT = DOCS / "chapter4_section_4_5_paper_figure_text_v1.md"

THRESHOLD_FIG = FIGURES / "figure_4_stage1_threshold_stability_v1.png"
THRESHOLD_FIG_PDF = FIGURES / "figure_4_stage1_threshold_stability_v1.pdf"
THRESHOLD_FIG_JPG = FIGURES / "figure_4_stage1_threshold_stability_v1_highres_chart_only.jpg"
ROC_PR_FIG = FIGURES / "figure_4_stage1_roc_pr_weighting_v1.png"
ROC_PR_FIG_PDF = FIGURES / "figure_4_stage1_roc_pr_weighting_v1.pdf"
ROC_PR_FIG_JPG = FIGURES / "figure_4_stage1_roc_pr_weighting_v1_highres_chart_only.jpg"

COLORS = {
    "ink": "#17212B",
    "muted": "#5F6B7A",
    "grid": "#D8DEE6",
    "axis": "#9AA6B2",
    "blue": "#2F6F95",
    "green": "#3A9B79",
    "amber": "#E8A336",
    "purple": "#6B5FB5",
    "red": "#B94644",
}


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    candidates = [
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/System/Library/Fonts/Supplemental/Times New Roman Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Times New Roman.ttf",
    ]
    for candidate in candidates:
        if Path(candidate).exists():
            return ImageFont.truetype(candidate, size)
    return ImageFont.load_default()


F_TITLE = font(43, True)
F_SUB = font(22)
F_SMALL = font(18)
F_TINY = font(15)
F_BOLD = font(20, True)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, object]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def fmt(value: float | str, places: int = 6) -> str:
    if value == "NA" or value == "":
        return "NA"
    return f"{float(value):.{places}f}"


def draw_wrapped(draw: ImageDraw.ImageDraw, xy: tuple[int, int], text: str, width: int, font_obj, fill: str, spacing: int = 5) -> int:
    wrapped = "\n".join(textwrap.wrap(text, width=width))
    draw.multiline_text(xy, wrapped, font=font_obj, fill=fill, spacing=spacing)
    bbox = draw.multiline_textbbox(xy, wrapped, font=font_obj, spacing=spacing)
    return bbox[3]


def base_canvas(title: str, subtitle: str) -> tuple[Image.Image, ImageDraw.ImageDraw]:
    img = Image.new("RGB", (2400, 1500), "white")
    draw = ImageDraw.Draw(img)
    draw.text((100, 70), title, font=F_TITLE, fill=COLORS["ink"])
    draw_wrapped(draw, (102, 135), subtitle, 145, F_SUB, COLORS["muted"])
    draw.line((100, 225, 2300, 225), fill=COLORS["grid"], width=3)
    return img, draw


def save_outputs(img: Image.Image, png: Path, pdf: Path) -> None:
    png.parent.mkdir(parents=True, exist_ok=True)
    img.save(png, "PNG", optimize=True)
    img.save(pdf, "PDF", resolution=200.0)


def save_jpg(img: Image.Image, jpg: Path) -> None:
    jpg.parent.mkdir(parents=True, exist_ok=True)
    img.save(jpg, "JPEG", quality=96, subsampling=0, optimize=True, dpi=(300, 300))


def parquet_curves_recoverable() -> tuple[bool, str]:
    try:
        import importlib.util

        has_engine = importlib.util.find_spec("pyarrow") is not None or importlib.util.find_spec("fastparquet") is not None
    except Exception:
        has_engine = False
    if not W0_OOF_SOURCE.exists() or not W1_OOF_SOURCE.exists():
        return False, "OOF probability Parquet files are not both present."
    if not has_engine:
        return False, "OOF probability Parquet files exist, but no pyarrow/fastparquet engine is available in this runtime; curves were not regenerated."
    return True, "OOF probability Parquet files and a Parquet engine are available."


def load_stage1_rows() -> tuple[list[dict[str, object]], list[dict[str, object]], list[float], tuple[bool, str]]:
    threshold_rows = read_csv(THRESHOLD_RESULTS_SOURCE)
    initial = next(r for r in threshold_rows if r["phase"] == "E")
    w1 = next(r for r in threshold_rows if r["phase"] == "E2")
    stability_rows = [r for r in read_csv(THRESHOLD_STABILITY_SOURCE) if r["calibration_method"] == "C0_NONE"]
    stability_rows.sort(key=lambda r: int(r["fold"]))
    fold_taus = [float(r["optimal_threshold"]) for r in stability_rows]
    curves_status = parquet_curves_recoverable()

    result_rows = [
        {
            "experiment": "Initial Stage 1 TRAIN-CV",
            "tau": fmt(initial["tau"]),
            "roc_auc": fmt(initial["roc_auc"]),
            "pr_auc": fmt(initial["normal_pr_auc"]),
            "normal_precision": fmt(initial["normal_precision"]),
            "normal_recall": fmt(initial["normal_recall"]),
            "normal_f1": fmt(initial["normal_f1"]),
            "false_normal_incident_rate": fmt(initial["false_normal_incident_rate"]),
            "evaluation_scope": "TRAIN-only grouped CV; Stage 1 Normal-vs-Incident; tau not used in final K1 classifier",
            "source_artifact": initial["source_artifact"],
        },
        {
            "experiment": "W1 class-and-group weighted Stage 1",
            "tau": fmt(w1["tau"]),
            "roc_auc": fmt(w1["roc_auc"]),
            "pr_auc": fmt(w1["normal_pr_auc"]),
            "normal_precision": fmt(w1["normal_precision"]),
            "normal_recall": fmt(w1["normal_recall"]),
            "normal_f1": fmt(w1["normal_f1"]),
            "false_normal_incident_rate": fmt(w1["false_normal_incident_rate"]),
            "evaluation_scope": "TRAIN-only grouped CV; W1 class-and-group weighted Stage 1; tau not used in final K1 classifier",
            "source_artifact": w1["source_artifact"],
        },
    ]
    audit_rows: list[dict[str, object]] = []
    for source_row, experiment in [(initial, "Initial Stage 1 TRAIN-CV"), (w1, "W1 class-and-group weighted Stage 1")]:
        for metric in ["tau", "roc_auc", "normal_pr_auc", "normal_precision", "normal_recall", "normal_f1", "false_normal_incident_rate"]:
            output_metric = "pr_auc" if metric == "normal_pr_auc" else metric
            audit_rows.append({
                "metric": output_metric,
                "value": fmt(source_row[metric]),
                "experiment": experiment,
                "source_file": rel(THRESHOLD_RESULTS_SOURCE),
                "source_field_or_row": f"phase={source_row['phase']}; field={metric}; backing_source={source_row['source_artifact']}",
                "authoritative_status": "PASS_AUTHORITATIVE_TRAIN_ONLY",
            })
    for row in stability_rows:
        audit_rows.append({
            "metric": "fold_optimal_tau",
            "value": fmt(row["optimal_threshold"]),
            "experiment": "Initial Stage 1 fold threshold stability",
            "source_file": rel(THRESHOLD_STABILITY_SOURCE),
            "source_field_or_row": f"fold={row['fold']}; calibration_method=C0_NONE; field=optimal_threshold",
            "authoritative_status": "PASS_AUTHORITATIVE_TRAIN_ONLY",
        })
    audit_rows.append({
        "metric": "roc_pr_curve_recovery",
        "value": "RECOVERABLE" if curves_status[0] else "SUMMARY_METRICS_ONLY",
        "experiment": "Stage 1 ROC/PR weighting comparison",
        "source_file": f"{rel(W0_OOF_SOURCE)}; {rel(W1_OOF_SOURCE)}",
        "source_field_or_row": curves_status[1],
        "authoritative_status": "PASS_NO_FABRICATED_CURVES",
    })
    return result_rows, audit_rows, fold_taus, curves_status


def draw_threshold_stability(fold_taus: list[float]) -> None:
    img, draw = base_canvas(
        "Stage 1 Threshold Stability",
        "Fold-specific TRAIN-CV optimal tau values for the initial Stage 1 Normal-vs-Incident experiment. The final proposed tau was 0.06.",
    )
    left, top, right, bottom = 220, 330, 2240, 1130
    ymin, ymax = 0.0, 0.75
    for step in range(0, 6):
        val = ymax * step / 5
        y = bottom - int((val - ymin) / (ymax - ymin) * (bottom - top))
        draw.line((left, y, right, y), fill=COLORS["grid"], width=2)
        draw.text((145, y - 12), f"{val:.2f}", font=F_TINY, fill=COLORS["muted"])
    draw.line((left, top, left, bottom), fill=COLORS["axis"], width=3)
    draw.line((left, bottom, right, bottom), fill=COLORS["axis"], width=3)
    proposed = 0.06
    proposed_y = bottom - int((proposed - ymin) / (ymax - ymin) * (bottom - top))
    draw.line((left, proposed_y, right, proposed_y), fill=COLORS["red"], width=4)
    draw.text((right - 355, proposed_y - 38), "Final proposed tau = 0.06", font=F_BOLD, fill=COLORS["red"])
    gap = (right - left) / len(fold_taus)
    points: list[tuple[int, int]] = []
    for i, tau in enumerate(fold_taus, start=1):
        x = int(left + gap * (i - 0.5))
        y = bottom - int((tau - ymin) / (ymax - ymin) * (bottom - top))
        points.append((x, y))
    draw.line(points, fill=COLORS["blue"], width=5)
    for i, (x, y) in enumerate(points, start=1):
        draw.ellipse((x - 18, y - 18, x + 18, y + 18), fill=COLORS["blue"])
        draw.text((x - 33, y - 55), f"{fold_taus[i-1]:.2f}", font=F_BOLD, fill=COLORS["ink"])
        draw.text((x - 35, bottom + 30), f"Fold {i}", font=F_SMALL, fill=COLORS["ink"])
    draw.text((100, 1270), "Wide variation across folds shows that Stage 1 threshold selection was unstable and remained auxiliary.", font=F_SMALL, fill=COLORS["muted"])
    draw.text((100, 1440), f"Source: {rel(THRESHOLD_STABILITY_SOURCE)}; {rel(THRESHOLD_RESULTS_SOURCE)}", font=F_TINY, fill=COLORS["muted"])
    save_outputs(img, THRESHOLD_FIG, THRESHOLD_FIG_PDF)


def draw_threshold_stability_jpg(fold_taus: list[float]) -> None:
    img = Image.new("RGB", (3600, 2400), "white")
    draw = ImageDraw.Draw(img)
    left, top, right, bottom = 340, 280, 3400, 1900
    ymin, ymax = 0.0, 0.75
    for step in range(0, 6):
        val = ymax * step / 5
        y = bottom - int((val - ymin) / (ymax - ymin) * (bottom - top))
        draw.line((left, y, right, y), fill=COLORS["grid"], width=3)
        draw.text((220, y - 16), f"{val:.2f}", font=font(24), fill=COLORS["muted"])
    draw.line((left, top, left, bottom), fill=COLORS["axis"], width=5)
    draw.line((left, bottom, right, bottom), fill=COLORS["axis"], width=5)
    proposed_y = bottom - int(0.06 / ymax * (bottom - top))
    draw.line((left, proposed_y, right, proposed_y), fill=COLORS["red"], width=6)
    gap = (right - left) / len(fold_taus)
    points = []
    for i, tau in enumerate(fold_taus, start=1):
        x = int(left + gap * (i - 0.5))
        y = bottom - int(tau / ymax * (bottom - top))
        points.append((x, y))
    draw.line(points, fill=COLORS["blue"], width=8)
    for i, (x, y) in enumerate(points, start=1):
        draw.ellipse((x - 28, y - 28, x + 28, y + 28), fill=COLORS["blue"])
        draw.text((x - 50, y - 83), f"{fold_taus[i-1]:.2f}", font=font(31, True), fill=COLORS["ink"])
        draw.text((x - 52, bottom + 58), f"Fold {i}", font=font(31), fill=COLORS["ink"])
    save_jpg(img, THRESHOLD_FIG_JPG)


def draw_auc_comparison(rows: list[dict[str, object]], curves_status: tuple[bool, str]) -> None:
    img, draw = base_canvas(
        "Stage 1 ROC and Precision-Recall Evidence",
        "TRAIN-only Stage 1 comparison of initial weighting and W1 class-and-group weighting. Actual curves were not regenerated; the figure uses authoritative summary AUC metrics.",
    )
    left, top, right, bottom = 210, 350, 2240, 1130
    ymax = 0.80
    for step in range(0, 5):
        val = ymax * step / 4
        y = bottom - int(val / ymax * (bottom - top))
        draw.line((left, y, right, y), fill=COLORS["grid"], width=2)
        draw.text((145, y - 12), f"{val:.2f}", font=F_TINY, fill=COLORS["muted"])
    draw.line((left, top, left, bottom), fill=COLORS["axis"], width=3)
    draw.line((left, bottom, right, bottom), fill=COLORS["axis"], width=3)
    series = [
        ("ROC-AUC", "roc_auc", COLORS["green"]),
        ("Normal PR-AUC", "pr_auc", COLORS["purple"]),
    ]
    group_w = (right - left) / 2
    bar_w = 170
    for i, row in enumerate(rows):
        gx = left + i * group_w + 240
        for j, (label, field, color) in enumerate(series):
            value = float(row[field])
            x0 = gx + j * (bar_w + 75)
            y0 = bottom - int(value / ymax * (bottom - top))
            draw.rounded_rectangle((x0, y0, x0 + bar_w, bottom), radius=11, fill=color)
            draw.text((x0 - 8, y0 - 38), f"{value:.6f}", font=F_BOLD, fill=COLORS["ink"])
        label = "Initial\nStage 1" if row["experiment"].startswith("Initial") else "W1 weighted\nStage 1"
        draw.multiline_text((gx + 95, bottom + 30), label, font=F_SMALL, fill=COLORS["ink"], spacing=5, align="center")
    legend_x = 100
    for label, _, color in series:
        draw.rounded_rectangle((legend_x, 1265, legend_x + 42, 1292), radius=5, fill=color)
        draw.text((legend_x + 54, 1260), label, font=F_SMALL, fill=COLORS["ink"])
        legend_x += 260
    draw.text((100, 1350), "W1 improved ROC-AUC, but Normal PR-AUC remained very low; Stage 1 was not used as the final K1 hard gate.", font=F_SMALL, fill=COLORS["muted"])
    draw.text((100, 1440), f"Source: {rel(THRESHOLD_RESULTS_SOURCE)}; curve status: summary metrics only", font=F_TINY, fill=COLORS["muted"])
    save_outputs(img, ROC_PR_FIG, ROC_PR_FIG_PDF)


def draw_auc_comparison_jpg(rows: list[dict[str, object]]) -> None:
    img = Image.new("RGB", (3600, 2400), "white")
    draw = ImageDraw.Draw(img)
    left, top, right, bottom = 340, 260, 3400, 1900
    ymax = 0.80
    for step in range(0, 5):
        val = ymax * step / 4
        y = bottom - int(val / ymax * (bottom - top))
        draw.line((left, y, right, y), fill=COLORS["grid"], width=3)
        draw.text((220, y - 16), f"{val:.2f}", font=font(24), fill=COLORS["muted"])
    draw.line((left, top, left, bottom), fill=COLORS["axis"], width=5)
    draw.line((left, bottom, right, bottom), fill=COLORS["axis"], width=5)
    series = [
        ("ROC-AUC", "roc_auc", COLORS["green"]),
        ("Normal PR-AUC", "pr_auc", COLORS["purple"]),
    ]
    group_w = (right - left) / 2
    bar_w = 280
    for i, row in enumerate(rows):
        gx = left + i * group_w + 360
        for j, (_, field, color) in enumerate(series):
            value = float(row[field])
            x0 = gx + j * (bar_w + 110)
            y0 = bottom - int(value / ymax * (bottom - top))
            draw.rounded_rectangle((x0, y0, x0 + bar_w, bottom), radius=18, fill=color)
            draw.text((x0 - 15, y0 - 58), f"{value:.6f}", font=font(30, True), fill=COLORS["ink"])
        label = "Initial Stage 1" if row["experiment"].startswith("Initial") else "W1 weighted Stage 1"
        draw.text((gx + 155, bottom + 58), label, font=font(32, True), fill=COLORS["ink"])
    legend_x = 1220
    for label, _, color in series:
        draw.rounded_rectangle((legend_x, 2130, legend_x + 70, 2173), radius=8, fill=color)
        draw.text((legend_x + 90, 2124), label, font=font(30), fill=COLORS["ink"])
        legend_x += 420
    save_jpg(img, ROC_PR_FIG_JPG)


def write_captions(curves_status: tuple[bool, str]) -> None:
    curve_text = "Actual ROC/PR curves were not regenerated. The out-of-fold probability Parquet files exist, but no Parquet engine was available in the current runtime, so Figure 4.x uses authoritative summary AUC metrics only."
    if curves_status[0]:
        curve_text = "Actual ROC/PR curves were recoverable from out-of-fold probability artifacts."
    text = f"""# Section 4.5 Figure Captions v1

## Figure 4.x Stage 1 Threshold Stability

This figure shows fold-specific optimal tau values for the initial TRAIN-only Stage 1 Normal-vs-Incident experiment. The fold thresholds were 0.06, 0.62, 0.32, 0.32, and 0.45, while the final TRAIN-CV proposed tau was 0.06. The spread across folds documents threshold instability. Stage 1 remained experimental and auxiliary, and tau was not used in the final K1 classifier.

## Figure 4.x Stage 1 ROC and Precision-Recall Evidence

This figure compares the initial Stage 1 configuration with the W1 class-and-group weighted Stage 1 configuration using TRAIN-only ROC-AUC and Normal PR-AUC. W1 improved ROC-AUC from 0.696260 to 0.758050 and Normal PR-AUC from 0.014019 to 0.016167, but precision-recall performance for the Normal class remained weak and the W1 false-Normal incident rate was 0.265188. Therefore Stage 1 was not adopted as a final hard gate and remained auxiliary. {curve_text}

## Evidence Boundary

All Section 4.5 outputs are based on existing TRAIN-only artifacts:

- `{rel(THRESHOLD_RESULTS_SOURCE)}`
- `{rel(THRESHOLD_SELECTION_SOURCE)}`
- `{rel(THRESHOLD_STABILITY_SOURCE)}`
- `{rel(W1_RESULTS_SOURCE)}`
- `{rel(W1_PROBABILITY_SOURCE)}`

No model was retrained. No threshold was reselected. Validation was not accessed or recomputed. Final Holdout was not accessed or recomputed.
"""
    CAPTIONS_OUT.write_text(text, encoding="utf-8")


def write_paper_text() -> None:
    text = f"""# Section 4.5 Paper Figure Text v1

These text blocks are separated from the high-resolution chart-only JPG figures so the dissertation document can control headings, captions, spacing, and source notes directly.

## Figure 4.x Stage 1 Threshold Stability

Title: Stage 1 Threshold Stability

Subtitle: Fold-specific TRAIN-CV optimal tau values for the initial Stage 1 Normal-vs-Incident experiment. The final proposed tau was 0.06.

Under-figure note: Wide variation across folds shows that Stage 1 threshold selection was unstable and remained auxiliary.

Image: `{rel(THRESHOLD_FIG_JPG)}`

## Figure 4.x Stage 1 ROC and Precision-Recall Evidence

Title: Stage 1 ROC and Precision-Recall Evidence

Subtitle: TRAIN-only Stage 1 comparison of initial weighting and W1 class-and-group weighting. The figure uses authoritative summary AUC metrics.

Under-figure note: W1 improved ROC-AUC, but Normal PR-AUC remained very low; Stage 1 was not used as the final K1 hard gate.

Image: `{rel(ROC_PR_FIG_JPG)}`
"""
    PAPER_TEXT_OUT.write_text(text, encoding="utf-8")


def validate_no_forbidden_sources(audit_rows: Iterable[dict[str, object]]) -> None:
    forbidden = ("validation/", "final_holdout/", "holdout/")
    for row in audit_rows:
        source = str(row["source_file"]).lower()
        if any(term in source for term in forbidden):
            raise RuntimeError(f"Forbidden source used for Section 4.5: {source}")


def main() -> None:
    DOCS.mkdir(exist_ok=True)
    FIGURES.mkdir(parents=True, exist_ok=True)
    result_rows, audit_rows, fold_taus, curves_status = load_stage1_rows()
    validate_no_forbidden_sources(audit_rows)
    write_csv(
        RESULTS_OUT,
        result_rows,
        [
            "experiment",
            "tau",
            "roc_auc",
            "pr_auc",
            "normal_precision",
            "normal_recall",
            "normal_f1",
            "false_normal_incident_rate",
            "evaluation_scope",
            "source_artifact",
        ],
    )
    write_csv(
        AUDIT_OUT,
        audit_rows,
        ["metric", "value", "experiment", "source_file", "source_field_or_row", "authoritative_status"],
    )
    write_captions(curves_status)
    write_paper_text()
    draw_threshold_stability(fold_taus)
    draw_threshold_stability_jpg(fold_taus)
    draw_auc_comparison(result_rows, curves_status)
    draw_auc_comparison_jpg(result_rows)
    for path in [RESULTS_OUT, AUDIT_OUT, CAPTIONS_OUT, PAPER_TEXT_OUT, THRESHOLD_FIG, THRESHOLD_FIG_PDF, THRESHOLD_FIG_JPG, ROC_PR_FIG, ROC_PR_FIG_PDF, ROC_PR_FIG_JPG]:
        print(path)


if __name__ == "__main__":
    main()
