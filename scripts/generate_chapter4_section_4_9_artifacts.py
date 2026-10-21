from __future__ import annotations

import csv
import math
import textwrap
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw, ImageFont


ROOT = Path("/Users/biruk/Documents/New project")
DOCS = ROOT / "docs"
FIGURES = ROOT / "figures/chapter4"

K1_RESULTS = ROOT / "data/modeling_k1/k1_model_results_v1.csv"
K1_PAIRED = ROOT / "data/modeling_k1/k1_paired_fold_comparison_v1.csv"
K1_FOLDS = ROOT / "data/modeling_k1/k1_fold_results_v1.csv"
K1_AUDIT = ROOT / "data/modeling_k1/k1_nested_cv_audit_v1.csv"
K1_CANDIDATE = ROOT / "config/post_validation_k1_candidate_v1.yaml"
K1_DECISION = ROOT / "data/modeling_k1/k1_decision_summary_v1.csv"
MASTER_SUMMARY = ROOT / "docs/master_praxis_results_summary_v1.yaml"
MASTER_RECORD = ROOT / "docs/master_praxis_experimental_record_v1.csv"
AUTHORITATIVE_NUMBERS = ROOT / "docs/authoritative_numbers_register_v1.csv"

RESULTS_OUT = DOCS / "chapter4_k1_stacking_results_v1.csv"
AUDIT_OUT = DOCS / "chapter4_section_4_9_evidence_audit_v1.csv"
CAPTIONS_OUT = DOCS / "chapter4_section_4_9_figure_captions_v1.md"
PAPER_TEXT_OUT = DOCS / "chapter4_section_4_9_paper_figure_text_v1.md"

MAIN_PNG = FIGURES / "figure_4_k1_mean_vs_stacking_v1.png"
MAIN_PDF = FIGURES / "figure_4_k1_mean_vs_stacking_v1.pdf"
MAIN_JPG = FIGURES / "figure_4_k1_mean_vs_stacking_v1_highres_chart_only.jpg"

FOLD_PNG = FIGURES / "figure_4_k1_paired_fold_improvement_v1.png"
FOLD_PDF = FIGURES / "figure_4_k1_paired_fold_improvement_v1.pdf"
FOLD_JPG = FIGURES / "figure_4_k1_paired_fold_improvement_v1_highres_chart_only.jpg"

B0_ID = "K1-B0_MEAN_PROBABILITY"
K1_ID = "K1-M2_XGB_K1-TEMPORAL"

COLORS = {
    "ink": "#17212B",
    "muted": "#5F6B7A",
    "grid": "#D8DEE6",
    "axis": "#9AA6B2",
    "b0": "#64748B",
    "k1": "#2563A8",
    "delta": "#D89432",
    "fold": "#3A9B79",
}


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    candidates = [
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/System/Library/Fonts/Supplemental/Helvetica Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Helvetica.ttf",
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


def as_float(row: dict[str, str], field: str) -> float:
    return float(row[field])


def assert_close(label: str, observed: float, expected: float, tol: float = 5e-7) -> None:
    if abs(observed - expected) > tol:
        raise ValueError(f"{label} mismatch: observed={observed}, expected={expected}")


def rounded(value: float) -> str:
    return f"{value:.6f}"


def draw_wrapped(draw: ImageDraw.ImageDraw, xy: tuple[int, int], text: str, width: int, font_obj, fill: str, spacing: int = 5) -> int:
    wrapped = "\n".join(textwrap.wrap(text, width=width))
    draw.multiline_text(xy, wrapped, font=font_obj, fill=fill, spacing=spacing)
    return draw.multiline_textbbox(xy, wrapped, font=font_obj, spacing=spacing)[3]


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
    model: str,
    source_file: Path,
    source_field_or_row: str,
    status: str = "PASS_AUTHORITATIVE_PHASE_K1",
) -> None:
    rows.append(
        {
            "metric": metric,
            "value": value,
            "model": model,
            "source_file": rel(source_file),
            "source_field_or_row": source_field_or_row,
            "authoritative_status": status,
        }
    )


def load_k1_rows() -> tuple[dict[str, str], dict[str, str]]:
    rows = read_csv(K1_RESULTS)
    b0 = next(row for row in rows if row["candidate_id"] == B0_ID)
    k1 = next(row for row in rows if row["candidate_id"] == K1_ID)
    assert_close("B0 Macro F1", as_float(b0, "incident_macro_f1"), 0.8029367898848712)
    assert_close("B0 Top-1", as_float(b0, "top1"), 0.8046324269889225)
    assert_close("B0 Top-2", as_float(b0, "top2"), 0.9355488418932527)
    assert_close("B0 MRR", as_float(b0, "mrr"), 0.8915743538100032)
    assert_close("B0 Hijack F1", as_float(b0, "hijack_f1"), 0.7508532423208191)
    assert_close("K1 Macro F1", as_float(k1, "incident_macro_f1"), 0.9346660655184286)
    assert_close("K1 Top-1", as_float(k1, "top1"), 0.9345417925478349)
    assert_close("K1 Top-2", as_float(k1, "top2"), 0.9929506545820745)
    assert_close("K1 MRR", as_float(k1, "mrr"), 0.9660960053709299)
    assert_close("K1 Hijack F1", as_float(k1, "hijack_f1"), 0.9146341463414634)
    return b0, k1


def build_results(b0: dict[str, str], k1: dict[str, str], audit_rows: list[dict[str, Any]]) -> None:
    fields = [
        "incident_macro_f1",
        "top1",
        "top2",
        "mrr",
        "hijack_f1",
        "leak_f1",
        "outage_f1",
    ]
    out_rows: list[dict[str, Any]] = []
    for model_name, row in [("K1-B0 Mean Probability", b0), ("K1 Temporal Stacker", k1)]:
        out_rows.append(
            {
                "model": model_name,
                "macro_f1": row["incident_macro_f1"],
                "top1": row["top1"],
                "top2": row["top2"],
                "mrr": row["mrr"],
                "hijack_f1": row["hijack_f1"],
                "leak_f1": row["leak_f1"],
                "outage_f1": row["outage_f1"],
                "evaluation_scope": row["methodological_status"],
                "source_artifact": rel(K1_RESULTS),
            }
        )
        for field in fields + ["train_only", "validation_used", "holdout_status", "incident_rows", "mean_fit_time_seconds", "mean_inference_time_seconds"]:
            audit_value(audit_rows, field, row[field], row["candidate_id"], K1_RESULTS, f"candidate_id={row['candidate_id']}; field={field}")

    write_csv(
        RESULTS_OUT,
        out_rows,
        ["model", "macro_f1", "top1", "top2", "mrr", "hijack_f1", "leak_f1", "outage_f1", "evaluation_scope", "source_artifact"],
    )


def add_decision_and_integrity_audit(audit_rows: list[dict[str, Any]], b0: dict[str, str], k1: dict[str, str]) -> dict[str, float]:
    aggregate_deltas = {
        "macro_f1_delta": as_float(k1, "incident_macro_f1") - as_float(b0, "incident_macro_f1"),
        "top1_delta": as_float(k1, "top1") - as_float(b0, "top1"),
        "top2_delta": as_float(k1, "top2") - as_float(b0, "top2"),
        "mrr_delta": as_float(k1, "mrr") - as_float(b0, "mrr"),
        "hijack_f1_delta": as_float(k1, "hijack_f1") - as_float(b0, "hijack_f1"),
        "leak_f1_delta": as_float(k1, "leak_f1") - as_float(b0, "leak_f1"),
        "outage_f1_delta": as_float(k1, "outage_f1") - as_float(b0, "outage_f1"),
    }
    for metric, value in aggregate_deltas.items():
        audit_value(audit_rows, metric, f"{value:.16f}", f"{K1_ID} minus {B0_ID}", K1_RESULTS, "aggregate metric difference between candidate rows")

    paired = next(row for row in read_csv(K1_PAIRED) if row["candidate_id"] == K1_ID and row["baseline_id"] == B0_ID)
    for field in paired:
        if field not in {"candidate_id", "baseline_id"}:
            audit_value(audit_rows, f"paired_fold_{field}", paired[field], K1_ID, K1_PAIRED, f"candidate_id={K1_ID}; baseline_id={B0_ID}; field={field}")

    decision = read_csv(K1_DECISION)[0]
    for field in ["outcome", "recommendation", "validation_used_for_k1", "final_holdout_status", "source_commit", "notes"]:
        audit_value(audit_rows, field, decision[field], "K1 decision", K1_DECISION, f"field={field}")

    for idx, row in enumerate(read_csv(K1_AUDIT), start=2):
        for field in ["inner_training_uses_outer_test_incidents", "meta_train_features_are_inner_oof", "meta_test_features_from_outer_train_only", "validation_rows_used", "holdout_rows_used", "status"]:
            audit_value(audit_rows, f"nested_cv_{field}_fold_{row['outer_fold']}", row[field], "K1 nested CV", K1_AUDIT, f"row={idx}; field={field}")

    candidate_text = K1_CANDIDATE.read_text(encoding="utf-8")
    for needle in ["validation_used: false", "final_holdout_status: SEALED", f"candidate_id: {K1_ID}"]:
        audit_value(audit_rows, needle, str(needle in candidate_text), K1_ID, K1_CANDIDATE, f"literal={needle}")

    for source in [MASTER_SUMMARY, AUTHORITATIVE_NUMBERS, MASTER_RECORD]:
        if source.exists():
            audit_value(audit_rows, "phase_k1_cross_reference_present", str(K1_RESULTS.relative_to(ROOT)) in source.read_text(encoding="utf-8"), "K1 cross-check", source, "contains K1 authoritative source path")

    return aggregate_deltas


def draw_grouped_comparison(b0: dict[str, str], k1: dict[str, str]) -> None:
    img = Image.new("RGB", (2400, 1500), "white")
    draw = ImageDraw.Draw(img)
    draw.text((100, 70), "Incident-Level Aggregation: Mean Probability vs Temporal Stacking", font=F_TITLE, fill=COLORS["ink"])
    draw_wrapped(
        draw,
        (102, 135),
        "Phase K1 post-Validation TRAIN-only nested-CV comparison of incident aggregation strategies. Validation was not reused, and Final Holdout remained sealed.",
        145,
        F_SUB,
        COLORS["muted"],
    )
    draw.line((100, 225, 2300, 225), fill=COLORS["grid"], width=3)

    metrics = [
        ("incident_macro_f1", "Macro F1"),
        ("top1", "Top-1"),
        ("top2", "Top-2"),
        ("mrr", "MRR"),
    ]
    left, top, right, bottom = 160, 340, 2260, 1135
    ymin, ymax = 0.0, 1.0
    for idx in range(6):
        val = ymin + (ymax - ymin) * idx / 5
        y = bottom - int((val - ymin) / (ymax - ymin) * (bottom - top))
        draw.line((left, y, right, y), fill=COLORS["grid"], width=2)
        draw.text((85, y - 11), f"{val:.1f}", font=F_TINY, fill=COLORS["muted"])
    draw.line((left, top, left, bottom), fill=COLORS["axis"], width=3)
    draw.line((left, bottom, right, bottom), fill=COLORS["axis"], width=3)

    group_gap = (right - left) / len(metrics)
    bar_w = 92
    for idx, (field, label) in enumerate(metrics, start=1):
        x = int(left + group_gap * (idx - 0.5))
        for offset, value, color in [(-58, as_float(b0, field), COLORS["b0"]), (58, as_float(k1, field), COLORS["k1"])]:
            y = bottom - int(value * (bottom - top))
            draw.rounded_rectangle((x + offset - bar_w // 2, y, x + offset + bar_w // 2, bottom), radius=8, fill=color)
            draw.text((x + offset - 48, y - 34), f"{value:.3f}", font=F_TINY, fill=COLORS["ink"])
        delta = as_float(k1, field) - as_float(b0, field)
        draw.text((x - 58, bottom + 30), label, font=F_SMALL, fill=COLORS["ink"])
        draw.text((x - 56, bottom + 64), f"+{delta:.3f}", font=F_TINY, fill=COLORS["delta"])

    draw.rectangle((800, 1215, 825, 1240), fill=COLORS["b0"])
    draw.text((840, 1211), "K1-B0 Mean Probability", font=F_SMALL, fill=COLORS["ink"])
    draw.rectangle((1165, 1215, 1190, 1240), fill=COLORS["k1"])
    draw.text((1205, 1211), "K1 Temporal Stacker", font=F_SMALL, fill=COLORS["ink"])
    draw_wrapped(draw, (100, 1310), "Temporal stacker won 5/5 grouped folds versus the mean-probability baseline. This figure compares TRAIN-only incident aggregation strategies, not Final Holdout performance.", 155, F_SMALL, COLORS["muted"])
    draw.text((100, 1440), f"Source: {rel(K1_RESULTS)}; paired-fold evidence: {rel(K1_PAIRED)}", font=F_TINY, fill=COLORS["muted"])
    save_outputs(img, MAIN_PNG, MAIN_PDF)


def draw_grouped_comparison_jpg(b0: dict[str, str], k1: dict[str, str]) -> None:
    img = Image.new("RGB", (3600, 2400), "white")
    draw = ImageDraw.Draw(img)
    metrics = [
        ("incident_macro_f1", "Macro F1"),
        ("top1", "Top-1"),
        ("top2", "Top-2"),
        ("mrr", "MRR"),
    ]
    left, top, right, bottom = 260, 260, 3380, 1930
    for idx in range(6):
        val = idx / 5
        y = bottom - int(val * (bottom - top))
        draw.line((left, y, right, y), fill=COLORS["grid"], width=3)
        draw.text((112, y - 18), f"{val:.1f}", font=font(30), fill=COLORS["muted"])
    draw.line((left, top, left, bottom), fill=COLORS["axis"], width=5)
    draw.line((left, bottom, right, bottom), fill=COLORS["axis"], width=5)
    group_gap = (right - left) / len(metrics)
    bar_w = 150
    for idx, (field, label) in enumerate(metrics, start=1):
        x = int(left + group_gap * (idx - 0.5))
        for offset, value, color in [(-95, as_float(b0, field), COLORS["b0"]), (95, as_float(k1, field), COLORS["k1"])]:
            y = bottom - int(value * (bottom - top))
            draw.rounded_rectangle((x + offset - bar_w // 2, y, x + offset + bar_w // 2, bottom), radius=14, fill=color)
            draw.text((x + offset - 78, y - 60), f"{value:.3f}", font=font(30, True), fill=COLORS["ink"])
        draw.text((x - 85, bottom + 75), label, font=font(34), fill=COLORS["ink"])
    draw.rectangle((1120, 2190, 1170, 2240), fill=COLORS["b0"])
    draw.text((1200, 2184), "K1-B0 Mean Probability", font=font(34), fill=COLORS["ink"])
    draw.rectangle((1880, 2190, 1930, 2240), fill=COLORS["k1"])
    draw.text((1960, 2184), "K1 Temporal Stacker", font=font(34), fill=COLORS["ink"])
    save_jpg(img, MAIN_JPG)


def draw_paired_fold_figure() -> bool:
    fold_rows = [row for row in read_csv(K1_FOLDS) if row["candidate_id"] in {B0_ID, K1_ID}]
    if not fold_rows:
        return False
    by_fold: dict[int, dict[str, float]] = {}
    for row in fold_rows:
        fold = int(row["fold"])
        by_fold.setdefault(fold, {})[row["candidate_id"]] = as_float(row, "incident_macro_f1")
    folds = sorted(f for f, values in by_fold.items() if B0_ID in values and K1_ID in values)
    if len(folds) != 5:
        return False

    def draw_chart(img: Image.Image, title: bool = True) -> None:
        draw = ImageDraw.Draw(img)
        scale = img.width / 2400
        if title:
            draw.text((int(100 * scale), int(70 * scale)), "Paired Fold Macro-F1 Improvement", font=font(int(43 * scale), True), fill=COLORS["ink"])
            draw_wrapped(draw, (int(102 * scale), int(135 * scale)), "Each line connects the same grouped outer fold under K1-B0 and the temporal stacker. The temporal stacker improved all five folds.", 140, font(int(22 * scale)), COLORS["muted"])
        left, top, right, bottom = int(270 * scale), int((330 if title else 190) * scale), int(2140 * scale), int((1160 if title else 1880) * scale)
        ymin, ymax = 0.70, 1.00
        for idx in range(7):
            val = ymin + (ymax - ymin) * idx / 6
            y = bottom - int((val - ymin) / (ymax - ymin) * (bottom - top))
            draw.line((left, y, right, y), fill=COLORS["grid"], width=max(2, int(2 * scale)))
            draw.text((int(145 * scale), y - int(12 * scale)), f"{val:.2f}", font=font(int(16 * scale)), fill=COLORS["muted"])
        draw.line((left, top, left, bottom), fill=COLORS["axis"], width=max(3, int(3 * scale)))
        draw.line((left, bottom, right, bottom), fill=COLORS["axis"], width=max(3, int(3 * scale)))
        x0, x1 = int(760 * scale), int(1640 * scale)
        draw.text((x0 - int(145 * scale), bottom + int(38 * scale)), "K1-B0 Mean", font=font(int(20 * scale)), fill=COLORS["ink"])
        draw.text((x1 - int(145 * scale), bottom + int(38 * scale)), "Temporal Stacker", font=font(int(20 * scale)), fill=COLORS["ink"])
        right_label_offsets = {
            fold: int(offset * scale)
            for fold, offset in zip(sorted(folds, key=lambda f: by_fold[f][K1_ID], reverse=True), [-18, 4, 26, 48, 70])
        }
        for fold in folds:
            b0 = by_fold[fold][B0_ID]
            k1 = by_fold[fold][K1_ID]
            y0 = bottom - int((b0 - ymin) / (ymax - ymin) * (bottom - top))
            y1 = bottom - int((k1 - ymin) / (ymax - ymin) * (bottom - top))
            draw.line((x0, y0, x1, y1), fill=COLORS["fold"], width=max(4, int(4 * scale)))
            r = max(8, int(9 * scale))
            draw.ellipse((x0 - r, y0 - r, x0 + r, y0 + r), fill=COLORS["b0"])
            draw.ellipse((x1 - r, y1 - r, x1 + r, y1 + r), fill=COLORS["k1"])
            draw.text((x0 - int(98 * scale), y0 - int(40 * scale)), f"F{fold}: {b0:.3f}", font=font(int(15 * scale)), fill=COLORS["ink"])
            draw.text((x1 + int(24 * scale), y1 + right_label_offsets[fold]), f"F{fold}: {k1:.3f}", font=font(int(15 * scale)), fill=COLORS["ink"])
        if title:
            draw.text((int(100 * scale), int(1440 * scale)), f"Source: {rel(K1_FOLDS)}", font=font(int(15 * scale)), fill=COLORS["muted"])

    img = Image.new("RGB", (2400, 1500), "white")
    draw_chart(img, title=True)
    save_outputs(img, FOLD_PNG, FOLD_PDF)
    jpg = Image.new("RGB", (3600, 2400), "white")
    draw_chart(jpg, title=False)
    save_jpg(jpg, FOLD_JPG)
    return True


def main() -> None:
    b0, k1 = load_k1_rows()
    audit_rows: list[dict[str, Any]] = []
    build_results(b0, k1, audit_rows)
    deltas = add_decision_and_integrity_audit(audit_rows, b0, k1)

    paired_created = draw_paired_fold_figure()
    audit_value(audit_rows, "paired_fold_supplement_created", str(paired_created), "K1 paired folds", K1_FOLDS, "exact fold-level macro_f1 available")

    write_csv(AUDIT_OUT, audit_rows, ["metric", "value", "model", "source_file", "source_field_or_row", "authoritative_status"])
    draw_grouped_comparison(b0, k1)
    draw_grouped_comparison_jpg(b0, k1)

    captions = f"""# Section 4.9 Figure Captions

**Figure 4.10. K1-B0 mean probability aggregation versus K1 temporal stacking.** This figure reports post-Validation TRAIN-only nested-CV results for the Phase K1 incident-level aggregation experiment. K1-B0 aggregates window probabilities by mean probability, whereas the K1 temporal stacker uses incident-level temporal probability summaries. Validation was not reused for K1 selection, Final Holdout remained sealed, and this comparison is not Final Holdout performance. The temporal stacker improved Macro F1 from {as_float(b0, 'incident_macro_f1'):.6f} to {as_float(k1, 'incident_macro_f1'):.6f}, Top-1 from {as_float(b0, 'top1'):.6f} to {as_float(k1, 'top1'):.6f}, Top-2 from {as_float(b0, 'top2'):.6f} to {as_float(k1, 'top2'):.6f}, and MRR from {as_float(b0, 'mrr'):.6f} to {as_float(k1, 'mrr'):.6f}. The paired grouped-fold comparison recorded a 5/5 fold win for the temporal stacker.

**Supplementary Figure 4.10a. Paired grouped-fold Macro-F1 improvement for K1 temporal stacking.** This supplementary figure uses the exact fold-level Macro-F1 records from `{rel(K1_FOLDS)}` and connects K1-B0 to the temporal stacker within each grouped outer fold. It is included only as TRAIN-only development evidence; it does not use Validation or Final Holdout.

Source artifacts: `{rel(K1_RESULTS)}`, `{rel(K1_PAIRED)}`, `{rel(K1_FOLDS)}`, `{rel(K1_AUDIT)}`, `{rel(K1_CANDIDATE)}`, and `{rel(K1_DECISION)}`.
"""
    CAPTIONS_OUT.write_text(captions, encoding="utf-8")

    paper_text = f"""# Section 4.9 Separate Figure Text

## Figure 4.10 Title
K1-B0 Mean Probability vs K1 Temporal Stacking

## Figure 4.10 Subtitle
Post-Validation TRAIN-only nested-CV comparison of incident-level aggregation strategies.

## Key Text Under Figure
Temporal stacking increased incident Macro F1 by {deltas['macro_f1_delta']:.6f}, Top-1 by {deltas['top1_delta']:.6f}, Top-2 by {deltas['top2_delta']:.6f}, MRR by {deltas['mrr_delta']:.6f}, and Hijack F1 by {deltas['hijack_f1_delta']:.6f}. The paired grouped-fold artifact reports that the temporal stacker won 5/5 folds versus K1-B0.

## Chart-Only JPGs
Use `{rel(MAIN_JPG)}` for the main chart when dissertation text and caption are placed separately in Word.

Use `{rel(FOLD_JPG)}` for the supplementary paired-fold chart when the fold-level evidence is discussed separately.
"""
    PAPER_TEXT_OUT.write_text(paper_text, encoding="utf-8")

    print(f"wrote {RESULTS_OUT}")
    print(f"wrote {AUDIT_OUT}")
    print(f"wrote {CAPTIONS_OUT}")
    print(f"wrote {PAPER_TEXT_OUT}")
    print(f"wrote {MAIN_PNG}")
    print(f"wrote {MAIN_PDF}")
    print(f"wrote {MAIN_JPG}")
    print(f"wrote {FOLD_PNG}")
    print(f"wrote {FOLD_PDF}")
    print(f"wrote {FOLD_JPG}")


if __name__ == "__main__":
    main()
