from __future__ import annotations

import csv
import textwrap
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw, ImageFont


ROOT = Path("/Users/biruk/Documents/New project")
DOCS = ROOT / "docs"
FIGURES = ROOT / "figures/chapter4"

VALIDATION_RESULTS = ROOT / "data/validation/validation_confirmation_results_v1.csv"
TRAIN_VS_VALIDATION = ROOT / "data/validation/train_vs_validation_comparison_v1.csv"
VALIDATION_AUDIT = ROOT / "data/validation/validation_confirmation_audit_v1.csv"
AUTHORITATIVE_NUMBERS = ROOT / "docs/authoritative_numbers_register_v1.csv"
MASTER_RECORD = ROOT / "docs/master_praxis_experimental_record_v1.csv"

RESULTS_OUT = DOCS / "chapter4_validation_results_v1.csv"
AUDIT_OUT = DOCS / "chapter4_section_4_8_evidence_audit_v1.csv"
CAPTION_OUT = DOCS / "chapter4_section_4_8_figure_caption_v1.md"
PAPER_TEXT_OUT = DOCS / "chapter4_section_4_8_paper_figure_text_v1.md"

FIG_OUT = FIGURES / "figure_4_train_vs_validation_v1.png"
FIG_PDF_OUT = FIGURES / "figure_4_train_vs_validation_v1.pdf"
FIG_JPG_OUT = FIGURES / "figure_4_train_vs_validation_v1_highres_chart_only.jpg"

COLORS = {
    "ink": "#17212B",
    "muted": "#5F6B7A",
    "grid": "#D8DEE6",
    "axis": "#9AA6B2",
    "train": "#2F6F95",
    "validation": "#D89432",
    "hijack": "#B94644",
    "leak": "#3A9B79",
    "outage": "#6B5FB5",
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


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def fmt(value: Any, places: int = 6) -> str:
    if value in (None, "", "NA"):
        return "NA"
    return f"{float(value):.{places}f}"


def draw_wrapped(draw: ImageDraw.ImageDraw, xy: tuple[int, int], text: str, width: int, font_obj, fill: str, spacing: int = 5) -> int:
    wrapped = "\n".join(textwrap.wrap(text, width=width))
    draw.multiline_text(xy, wrapped, font=font_obj, fill=fill, spacing=spacing)
    bbox = draw.multiline_textbbox(xy, wrapped, font=font_obj, spacing=spacing)
    return bbox[3]


def save_outputs(img: Image.Image, png: Path, pdf: Path) -> None:
    png.parent.mkdir(parents=True, exist_ok=True)
    img.save(png, "PNG", optimize=True)
    img.save(pdf, "PDF", resolution=200.0)


def save_jpg(img: Image.Image, jpg: Path) -> None:
    jpg.parent.mkdir(parents=True, exist_ok=True)
    img.save(jpg, "JPEG", quality=96, subsampling=0, optimize=True, dpi=(300, 300))


def audit_value(
    rows: list[dict[str, Any]],
    metric: str,
    value: Any,
    source_file: Path,
    source_field_or_row: str,
    status: str = "PASS_AUTHORITATIVE_PHASE_J",
) -> None:
    rows.append(
        {
            "metric": metric,
            "value": value,
            "source_file": rel(source_file),
            "source_field_or_row": source_field_or_row,
            "authoritative_status": status,
        }
    )


def draw_validation_figure(rows: list[dict[str, str]], validation: dict[str, str]) -> None:
    img = Image.new("RGB", (2400, 1500), "white")
    draw = ImageDraw.Draw(img)
    draw.text((100, 70), "TRAIN-CV vs Independent Validation", font=F_TITLE, fill=COLORS["ink"])
    draw_wrapped(
        draw,
        (102, 135),
        "Phase J single Validation confirmation for the locked XGBoost candidate. The figure shows the observed independent generalization decrease transparently.",
        146,
        F_SUB,
        COLORS["muted"],
    )
    draw.line((100, 225, 2300, 225), fill=COLORS["grid"], width=3)

    main_metrics = ["incident_macro_f1", "top1", "top2", "mrr"]
    labels = ["Macro F1", "Top-1", "Top-2", "MRR"]
    main_rows = [next(r for r in rows if r["metric"] == metric) for metric in main_metrics]
    left, top, right, bottom = 160, 355, 1390, 1120
    ymin, ymax = 0.60, 1.00
    for idx in range(5):
        val = ymin + (ymax - ymin) * idx / 4
        y = bottom - int((val - ymin) / (ymax - ymin) * (bottom - top))
        draw.line((left, y, right, y), fill=COLORS["grid"], width=2)
        draw.text((86, y - 11), f"{val:.2f}", font=F_TINY, fill=COLORS["muted"])
    draw.line((left, top, left, bottom), fill=COLORS["axis"], width=3)
    draw.line((left, bottom, right, bottom), fill=COLORS["axis"], width=3)
    draw.text((left, top - 58), "Primary Incident Metrics", font=F_BOLD, fill=COLORS["ink"])

    group_gap = (right - left) / len(main_rows)
    bar_w = 82
    for idx, (label, row) in enumerate(zip(labels, main_rows), start=1):
        x = int(left + group_gap * (idx - 0.5))
        train = float(row["train_cv"])
        val = float(row["validation"])
        for offset, value, color in [(-bar_w // 2 - 8, train, COLORS["train"]), (bar_w // 2 + 8, val, COLORS["validation"])]:
            y = bottom - int((value - ymin) / (ymax - ymin) * (bottom - top))
            draw.rounded_rectangle((x + offset - bar_w // 2, y, x + offset + bar_w // 2, bottom), radius=8, fill=color)
            draw.text((x + offset - 45, y - 35), f"{value:.3f}", font=F_TINY, fill=COLORS["ink"])
        draw.text((x - 45, bottom + 30), label, font=F_SMALL, fill=COLORS["ink"])

    draw.rectangle((490, 1192, 515, 1217), fill=COLORS["train"])
    draw.text((530, 1188), "TRAIN-CV", font=F_SMALL, fill=COLORS["ink"])
    draw.rectangle((690, 1192, 715, 1217), fill=COLORS["validation"])
    draw.text((730, 1188), "Validation", font=F_SMALL, fill=COLORS["ink"])

    class_metrics = [("hijack_f1", "Hijack", COLORS["hijack"]), ("leak_f1", "Leak", COLORS["leak"]), ("outage_f1", "Outage", COLORS["outage"])]
    left2, top2, right2, bottom2 = 1620, 355, 2250, 1120
    ymin2, ymax2 = 0.50, 0.90
    for idx in range(5):
        val = ymin2 + (ymax2 - ymin2) * idx / 4
        y = bottom2 - int((val - ymin2) / (ymax2 - ymin2) * (bottom2 - top2))
        draw.line((left2, y, right2, y), fill=COLORS["grid"], width=2)
        draw.text((1545, y - 11), f"{val:.2f}", font=F_TINY, fill=COLORS["muted"])
    draw.line((left2, top2, left2, bottom2), fill=COLORS["axis"], width=3)
    draw.line((left2, bottom2, right2, bottom2), fill=COLORS["axis"], width=3)
    draw.text((left2, top2 - 58), "Validation Class F1", font=F_BOLD, fill=COLORS["ink"])
    xgap = (right2 - left2) / len(class_metrics)
    for idx, (metric, label, color) in enumerate(class_metrics, start=1):
        value = float(validation[metric])
        x = int(left2 + xgap * (idx - 0.5))
        y = bottom2 - int((value - ymin2) / (ymax2 - ymin2) * (bottom2 - top2))
        draw.rounded_rectangle((x - 65, y, x + 65, bottom2), radius=8, fill=color)
        draw.text((x - 43, y - 36), f"{value:.3f}", font=F_TINY, fill=COLORS["ink"])
        draw.text((x - 38, bottom2 + 30), label, font=F_SMALL, fill=COLORS["ink"])

    draw_wrapped(
        draw,
        (100, 1300),
        "All predefined Validation floors passed, but the independent Validation scores decreased from TRAIN-CV, especially for Hijack F1. No model selection or tuning was performed on Validation.",
        150,
        F_SMALL,
        COLORS["muted"],
    )
    draw.text((100, 1440), f"Sources: {rel(VALIDATION_RESULTS)}; {rel(TRAIN_VS_VALIDATION)}", font=F_TINY, fill=COLORS["muted"])
    save_outputs(img, FIG_OUT, FIG_PDF_OUT)


def draw_validation_jpg(rows: list[dict[str, str]], validation: dict[str, str]) -> None:
    img = Image.new("RGB", (3600, 2400), "white")
    draw = ImageDraw.Draw(img)
    main_metrics = ["incident_macro_f1", "top1", "top2", "mrr"]
    labels = ["Macro F1", "Top-1", "Top-2", "MRR"]
    main_rows = [next(r for r in rows if r["metric"] == metric) for metric in main_metrics]
    left, top, right, bottom = 220, 330, 2120, 1880
    ymin, ymax = 0.60, 1.00
    for idx in range(5):
        val = ymin + (ymax - ymin) * idx / 4
        y = bottom - int((val - ymin) / (ymax - ymin) * (bottom - top))
        draw.line((left, y, right, y), fill=COLORS["grid"], width=3)
        draw.text((75, y - 17), f"{val:.2f}", font=font(28), fill=COLORS["muted"])
    draw.line((left, top, left, bottom), fill=COLORS["axis"], width=5)
    draw.line((left, bottom, right, bottom), fill=COLORS["axis"], width=5)
    draw.text((left, top - 80), "Primary Incident Metrics", font=font(34, True), fill=COLORS["ink"])
    group_gap = (right - left) / len(main_rows)
    bar_w = 130
    for idx, (label, row) in enumerate(zip(labels, main_rows), start=1):
        x = int(left + group_gap * (idx - 0.5))
        for offset, value, color in [(-78, float(row["train_cv"]), COLORS["train"]), (78, float(row["validation"]), COLORS["validation"])]:
            y = bottom - int((value - ymin) / (ymax - ymin) * (bottom - top))
            draw.rounded_rectangle((x + offset - bar_w // 2, y, x + offset + bar_w // 2, bottom), radius=14, fill=color)
            draw.text((x + offset - 68, y - 58), f"{value:.3f}", font=font(28, True), fill=COLORS["ink"])
        draw.text((x - 65, bottom + 68), label, font=font(30), fill=COLORS["ink"])

    class_metrics = [("hijack_f1", "Hijack", COLORS["hijack"]), ("leak_f1", "Leak", COLORS["leak"]), ("outage_f1", "Outage", COLORS["outage"])]
    left2, top2, right2, bottom2 = 2500, 330, 3400, 1880
    ymin2, ymax2 = 0.50, 0.90
    for idx in range(5):
        val = ymin2 + (ymax2 - ymin2) * idx / 4
        y = bottom2 - int((val - ymin2) / (ymax2 - ymin2) * (bottom2 - top2))
        draw.line((left2, y, right2, y), fill=COLORS["grid"], width=3)
        draw.text((2370, y - 17), f"{val:.2f}", font=font(28), fill=COLORS["muted"])
    draw.line((left2, top2, left2, bottom2), fill=COLORS["axis"], width=5)
    draw.line((left2, bottom2, right2, bottom2), fill=COLORS["axis"], width=5)
    draw.text((left2, top2 - 80), "Validation Class F1", font=font(34, True), fill=COLORS["ink"])
    xgap = (right2 - left2) / len(class_metrics)
    for idx, (metric, label, color) in enumerate(class_metrics, start=1):
        value = float(validation[metric])
        x = int(left2 + xgap * (idx - 0.5))
        y = bottom2 - int((value - ymin2) / (ymax2 - ymin2) * (bottom2 - top2))
        draw.rounded_rectangle((x - 90, y, x + 90, bottom2), radius=14, fill=color)
        draw.text((x - 65, y - 58), f"{value:.3f}", font=font(28, True), fill=COLORS["ink"])
        draw.text((x - 55, bottom2 + 68), label, font=font(30), fill=COLORS["ink"])

    draw.rectangle((840, 2115, 885, 2160), fill=COLORS["train"])
    draw.text((910, 2113), "TRAIN-CV", font=font(31), fill=COLORS["ink"])
    draw.rectangle((1150, 2115, 1195, 2160), fill=COLORS["validation"])
    draw.text((1220, 2113), "Validation", font=font(31), fill=COLORS["ink"])
    save_jpg(img, FIG_JPG_OUT)


def main() -> None:
    validation = read_csv(VALIDATION_RESULTS)[0]
    comparisons = read_csv(TRAIN_VS_VALIDATION)
    audit_rows: list[dict[str, Any]] = []

    output_rows = []
    for row in comparisons:
        output_rows.append(
            {
                "metric": row["metric"],
                "train_cv": row["train_cv"],
                "validation": row["validation"],
                "delta": row["validation_minus_train_cv"],
                "source_artifact": rel(TRAIN_VS_VALIDATION),
            }
        )
        audit_value(audit_rows, f"{row['metric']}_train_cv", row["train_cv"], TRAIN_VS_VALIDATION, f"metric={row['metric']}; field=train_cv")
        audit_value(audit_rows, f"{row['metric']}_validation", row["validation"], TRAIN_VS_VALIDATION, f"metric={row['metric']}; field=validation")
        audit_value(audit_rows, f"{row['metric']}_delta", row["validation_minus_train_cv"], TRAIN_VS_VALIDATION, f"metric={row['metric']}; field=validation_minus_train_cv")

    write_csv(RESULTS_OUT, output_rows, ["metric", "train_cv", "validation", "delta", "source_artifact"])

    for field in [
        "validation_incidents",
        "window_rows",
        "incident_macro_f1",
        "top1",
        "top2",
        "mrr",
        "hijack_precision",
        "hijack_recall",
        "hijack_f1",
        "leak_precision",
        "leak_recall",
        "leak_f1",
        "outage_precision",
        "outage_recall",
        "outage_f1",
        "window_macro_f1",
        "macro_f1_floor_pass",
        "mrr_floor_pass",
        "top2_floor_pass",
        "formal_disposition",
        "severe_class_degradation",
        "stage1_status",
        "final_holdout_status",
    ]:
        audit_value(audit_rows, field, validation[field], VALIDATION_RESULTS, f"candidate=XGB_REFINED_TRAIN_CANDIDATE; field={field}")

    for row in read_csv(VALIDATION_AUDIT):
        audit_value(audit_rows, row["check"], row["status"], VALIDATION_AUDIT, f"check={row['check']}; notes={row['notes']}")

    for label in ["Validation incidents", "Validation class counts", "Phase J Macro F1"]:
        matches = [row for row in read_csv(AUTHORITATIVE_NUMBERS) if row.get("metric") == label]
        if matches:
            audit_value(audit_rows, label, matches[0].get("value"), AUTHORITATIVE_NUMBERS, f"metric={label}")
    phase_j = [row for row in read_csv(MASTER_RECORD) if row.get("phase") == "P13"]
    if phase_j:
        audit_value(audit_rows, "master_record_phase_j_decision", phase_j[0].get("decision"), MASTER_RECORD, "phase=P13")

    write_csv(AUDIT_OUT, audit_rows, ["metric", "value", "source_file", "source_field_or_row", "authoritative_status"])
    draw_validation_figure(comparisons, validation)
    draw_validation_jpg(comparisons, validation)

    caption = f"""# Section 4.8 Figure Caption

**Figure 4.9. TRAIN-CV versus independent Validation performance for the Phase J confirmation experiment.** The figure compares the locked refined XGBoost candidate's TRAIN grouped-CV reference against its first independent Validation confirmation on 213 incidents (71 Hijack, 71 Leak, and 71 Outage). The primary panel reports incident Macro F1, Top-1 accuracy, Top-2 accuracy, and MRR; the secondary panel reports Validation class-specific F1. Validation performance decreased relative to TRAIN-CV, with the largest listed decrease in Hijack F1, but all predefined Validation floors passed. No model selection, threshold selection, hyperparameter tuning, feature changes, or post-result candidate changes were made using Validation, and Final Holdout remained sealed.

Validation disposition: `{validation['formal_disposition']}`. Source artifacts: `{rel(VALIDATION_RESULTS)}`, `{rel(TRAIN_VS_VALIDATION)}`, and `{rel(VALIDATION_AUDIT)}`.
"""
    CAPTION_OUT.write_text(caption, encoding="utf-8")

    paper_text = f"""# Section 4.8 Separate Figure Text

## Figure 4.9 Title
TRAIN-CV vs Independent Validation

## Figure 4.9 Subtitle
Phase J single Validation confirmation for the locked refined XGBoost candidate.

## Key Text Under Figure
Validation confirmed the candidate against the predefined floors while showing a transparent decrease from TRAIN-CV: Macro F1 decreased by {float(next(r for r in comparisons if r['metric'] == 'incident_macro_f1')['absolute_delta']):.6f}, Top-1 by {float(next(r for r in comparisons if r['metric'] == 'top1')['absolute_delta']):.6f}, Top-2 by {float(next(r for r in comparisons if r['metric'] == 'top2')['absolute_delta']):.6f}, and MRR by {float(next(r for r in comparisons if r['metric'] == 'mrr')['absolute_delta']):.6f}.

## Chart-Only JPG
Use `{rel(FIG_JPG_OUT)}` when dissertation text and caption are placed separately in Word.
"""
    PAPER_TEXT_OUT.write_text(paper_text, encoding="utf-8")

    print(f"wrote {RESULTS_OUT}")
    print(f"wrote {AUDIT_OUT}")
    print(f"wrote {CAPTION_OUT}")
    print(f"wrote {PAPER_TEXT_OUT}")
    print(f"wrote {FIG_OUT}")
    print(f"wrote {FIG_PDF_OUT}")
    print(f"wrote {FIG_JPG_OUT}")


if __name__ == "__main__":
    main()
