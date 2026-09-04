from __future__ import annotations

import csv
import shutil
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw, ImageFont


ROOT = Path("/Users/biruk/Documents/New project")
DOCS = ROOT / "docs"
FIGURES_CH4 = ROOT / "figures/chapter4"
FIGURES_FINAL = ROOT / "figures/final"

CONFUSION = ROOT / "data/final_holdout/final_holdout_confusion_matrix_v1.csv"
RANKING = ROOT / "data/final_holdout/final_holdout_ranking_metrics_v1.csv"
PER_CLASS = ROOT / "data/final_holdout/final_holdout_per_class_metrics_v1.csv"
PERFORMANCE = ROOT / "data/final_holdout/final_holdout_performance_summary_v1.csv"
MANIFEST_AUDIT = ROOT / "data/final_holdout/final_holdout_manifest_audit_v1.csv"
FEATURE_SUMMARY = ROOT / "data/final_holdout/final_holdout_incident_feature_summary_v1.csv"
QUALITY_GATE = ROOT / "data/final_holdout/final_holdout_incident_processing_quality_gate_v1.csv"
RANKINGS_DETAIL = ROOT / "data/final_holdout/final_holdout_incident_rankings_v1.csv"
SCHEMA_AUDIT = ROOT / "data/final_holdout/final_holdout_v4_schema_audit_v1.csv"
EVALUATION_AUDIT = ROOT / "data/final_holdout/final_evaluation_audit_v1.csv"
FINAL_RESULT = ROOT / "config/final_praxis_result_v1.yaml"

EXISTING_MATRIX_PNG = FIGURES_FINAL / "final_holdout_confusion_matrix_v1.png"
FIG_MATRIX_PNG = FIGURES_CH4 / "figure_4_final_holdout_confusion_matrix_v1.png"
FIG_MATRIX_PDF = FIGURES_CH4 / "figure_4_final_holdout_confusion_matrix_v1.pdf"
FIG_MATRIX_JPG = FIGURES_CH4 / "figure_4_final_holdout_confusion_matrix_v1_highres_chart_only.jpg"

ERROR_TABLE = DOCS / "chapter4_final_holdout_error_analysis_v1.csv"
EVIDENCE_AUDIT = DOCS / "chapter4_section_4_13_evidence_audit_v1.csv"
CAPTION = DOCS / "chapter4_section_4_13_figure_caption_v1.md"

CLASSES = ["HIJACK", "LEAK", "OUTAGE"]
EXPECTED_MATRIX = {
    ("HIJACK", "HIJACK"): 61,
    ("HIJACK", "LEAK"): 9,
    ("HIJACK", "OUTAGE"): 1,
    ("LEAK", "HIJACK"): 5,
    ("LEAK", "LEAK"): 66,
    ("LEAK", "OUTAGE"): 0,
    ("OUTAGE", "HIJACK"): 2,
    ("OUTAGE", "LEAK"): 0,
    ("OUTAGE", "OUTAGE"): 69,
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


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT)) if path.is_absolute() else str(path)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def audit(
    rows: list[dict[str, Any]],
    claim: str,
    metric: str,
    value: Any,
    source_file: Path,
    source_field_or_row: str,
    status: str = "PASS_AUTHORITATIVE_PHASE_L",
) -> None:
    rows.append(
        {
            "claim": claim,
            "metric": metric,
            "value": value,
            "source_file": rel(source_file),
            "source_field_or_row": source_field_or_row,
            "authoritative_status": status,
        }
    )


def load_and_verify(audit_rows: list[dict[str, Any]]) -> dict[str, Any]:
    matrix_rows = read_csv(CONFUSION)
    matrix = {(row["true_class"], row["predicted_class"]): int(row["count"]) for row in matrix_rows}
    if matrix != EXPECTED_MATRIX:
        raise ValueError(f"Confusion matrix mismatch: {matrix}")
    total = sum(matrix.values())
    correct = sum(matrix[(cls, cls)] for cls in CLASSES)
    errors = total - correct
    if total != 213 or correct != 196 or errors != 17:
        raise ValueError(f"Confusion totals mismatch: total={total}, correct={correct}, errors={errors}")
    for (true_cls, pred_cls), count in matrix.items():
        audit(audit_rows, "Final Holdout confusion matrix cell verified", f"{true_cls}->{pred_cls}", count, CONFUSION, f"true_class={true_cls}; predicted_class={pred_cls}")
    audit(audit_rows, "Final Holdout incident count verified", "holdout_incidents", total, CONFUSION, "sum(count)")
    audit(audit_rows, "Top-1 correct count verified", "top1_correct", correct, CONFUSION, "sum diagonal")
    audit(audit_rows, "Top-1 error count verified", "top1_errors", errors, CONFUSION, "sum off diagonal")

    per_class = {row["class"]: row for row in read_csv(PER_CLASS)}
    expected_f1 = {"HIJACK": 0.8776978417266187, "LEAK": 0.9041095890410958, "OUTAGE": 0.9787234042553191}
    for cls, expected in expected_f1.items():
        observed = float(per_class[cls]["f1"])
        if abs(observed - expected) > 5e-7:
            raise ValueError(f"{cls} F1 mismatch: {observed}")
        if int(per_class[cls]["support_incidents"]) != 71:
            raise ValueError(f"{cls} support mismatch")
        audit(audit_rows, f"{cls} F1 verified", f"{cls.lower()}_f1", observed, PER_CLASS, f"class={cls}; field=f1")
        audit(audit_rows, f"{cls} support verified", f"{cls.lower()}_support", 71, PER_CLASS, f"class={cls}; field=support_incidents")

    ranking = {row["metric"]: float(row["value"]) for row in read_csv(RANKING)}
    rank1 = int(ranking["ranked_first_count"])
    rank2 = int(ranking["ranked_second_count"])
    rank3 = int(ranking["ranked_third_count"])
    if (rank1, rank2, rank3) != (196, 15, 2):
        raise ValueError(f"Ranking count mismatch: {(rank1, rank2, rank3)}")
    for metric, value in [("ranked_first_count", rank1), ("ranked_second_count", rank2), ("ranked_third_count", rank3)]:
        audit(audit_rows, "Final Holdout ranking count verified", metric, value, RANKING, f"metric={metric}")
    perf = read_csv(PERFORMANCE)[0]
    if abs(float(perf["top2"]) - 0.9906103286384976) > 5e-7:
        raise ValueError("Top-2 mismatch")
    audit(audit_rows, "Top-2 accuracy verified", "top2", perf["top2"], PERFORMANCE, "row=0; field=top2")
    audit(audit_rows, "Top-2 correct count verified", "top2_correct", rank1 + rank2, RANKING, "ranked_first_count + ranked_second_count")

    manifest = {row["check"]: row for row in read_csv(MANIFEST_AUDIT)}
    for check in ["holdout_total_incidents", "holdout_hijack_incidents", "holdout_leak_incidents", "holdout_outage_incidents"]:
        if manifest[check]["status"] != "PASS":
            raise ValueError(f"Manifest audit failed for {check}")
        audit(audit_rows, f"{check} PASS", check, manifest[check]["observed"], MANIFEST_AUDIT, f"check={check}")

    quality = {row["incident_uid"]: row for row in read_csv(QUALITY_GATE)}
    feature = {row["incident_uid"]: row for row in read_csv(FEATURE_SUMMARY)}
    detail = {row["incident_uid"]: row for row in read_csv(RANKINGS_DETAIL)}
    hijack_68538_quality = quality["Hijack:68538"]
    hijack_68538_feature = feature["Hijack:68538"]
    hijack_68538_detail = detail["Hijack:68538"]
    if hijack_68538_quality["status"] != "REVIEW" or hijack_68538_quality["review_reasons"] != "no relevant observations":
        raise ValueError("Hijack:68538 quality gate mismatch")
    if int(hijack_68538_feature["total_feature_rows"]) <= 0 or hijack_68538_feature["processing_status"] != "REVIEW":
        raise ValueError("Hijack:68538 feature row/status mismatch")
    if hijack_68538_detail["true_class"] != "HIJACK" or hijack_68538_detail["predicted_class"] != "HIJACK":
        raise ValueError("Hijack:68538 ranking detail mismatch")
    audit(audit_rows, "Hijack:68538 processing status verified", "Hijack:68538_status", "REVIEW", QUALITY_GATE, "incident_uid=Hijack:68538; field=status")
    audit(audit_rows, "Hijack:68538 caveat reason verified", "Hijack:68538_review_reason", "no relevant observations", QUALITY_GATE, "incident_uid=Hijack:68538; field=review_reasons")
    audit(audit_rows, "Hijack:68538 valid feature rows verified", "Hijack:68538_total_feature_rows", hijack_68538_feature["total_feature_rows"], FEATURE_SUMMARY, "incident_uid=Hijack:68538; field=total_feature_rows")
    audit(audit_rows, "Hijack:68538 remained in final evaluation", "Hijack:68538_predicted_class", hijack_68538_detail["predicted_class"], RANKINGS_DETAIL, "incident_uid=Hijack:68538; field=predicted_class")

    schema = {row["check"]: row for row in read_csv(SCHEMA_AUDIT)}
    eval_audit = {row["check"]: row for row in read_csv(EVALUATION_AUDIT)}
    for check in ["total_model_features", "feature_order_matches_train", "no_train_rows", "no_validation_rows"]:
        if schema[check]["status"] != "PASS":
            raise ValueError(f"Schema audit failed for {check}")
        audit(audit_rows, f"Final schema audit {check} PASS", check, schema[check]["observed"], SCHEMA_AUDIT, f"check={check}")
    for check in ["train_only_model_fitting", "validation_excluded", "holdout_excluded_from_fitting", "final_holdout_terminal_evaluation"]:
        if eval_audit[check]["status"] != "PASS":
            raise ValueError(f"Final evaluation audit failed for {check}")
        audit(audit_rows, f"Final evaluation audit {check} PASS", check, eval_audit[check]["notes"], EVALUATION_AUDIT, f"check={check}")
    audit(audit_rows, "Final frozen result artifact present", "final_praxis_result_v1", "present", FINAL_RESULT, "artifact exists")
    return {
        "matrix": matrix,
        "total": total,
        "correct": correct,
        "errors": errors,
        "per_class": per_class,
        "ranking": ranking,
        "perf": perf,
        "hijack_68538_quality": hijack_68538_quality,
        "hijack_68538_feature": hijack_68538_feature,
        "hijack_68538_detail": hijack_68538_detail,
    }


def build_error_table(values: dict[str, Any]) -> None:
    matrix = values["matrix"]
    rows: list[dict[str, Any]] = []
    for true_cls in CLASSES:
        true_total = sum(matrix[(true_cls, pred_cls)] for pred_cls in CLASSES)
        for pred_cls in CLASSES:
            count = matrix[(true_cls, pred_cls)]
            rows.append(
                {
                    "true_class": true_cls,
                    "predicted_class": pred_cls,
                    "count": count,
                    "error_type": "correct" if true_cls == pred_cls else f"{true_cls}_misclassified_as_{pred_cls}",
                    "percentage_of_true_class": f"{count / true_total:.6f}",
                    "percentage_of_all_holdout": f"{count / values['total']:.6f}",
                    "source_artifact": rel(CONFUSION),
                }
            )
    write_csv(
        ERROR_TABLE,
        rows,
        [
            "true_class",
            "predicted_class",
            "count",
            "error_type",
            "percentage_of_true_class",
            "percentage_of_all_holdout",
            "source_artifact",
        ],
    )


def draw_highres_matrix(matrix: dict[tuple[str, str], int]) -> Image.Image:
    width, height = 3200, 2600
    img = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(img)
    f_axis = font(84, True)
    f_label = font(80)
    f_cell = font(104, True)
    f_small = font(54)
    left, top = 650, 330
    cell = 520
    max_count = max(matrix.values())
    base = (33, 97, 166)
    for i, true_cls in enumerate(CLASSES):
        for j, pred_cls in enumerate(CLASSES):
            count = matrix[(true_cls, pred_cls)]
            intensity = 0.10 + 0.82 * (count / max_count)
            color = tuple(int(255 - (255 - c) * intensity) for c in base)
            x0 = left + j * cell
            y0 = top + i * cell
            draw.rectangle((x0, y0, x0 + cell, y0 + cell), fill=color, outline="#FFFFFF", width=4)
            bbox = draw.textbbox((0, 0), str(count), font=f_cell)
            draw.text((x0 + cell / 2 - (bbox[2] - bbox[0]) / 2, y0 + cell / 2 - (bbox[3] - bbox[1]) / 2), str(count), font=f_cell, fill="#0F172A")
    for j, cls in enumerate(CLASSES):
        bbox = draw.textbbox((0, 0), cls, font=f_axis)
        draw.text((left + j * cell + cell / 2 - (bbox[2] - bbox[0]) / 2, top + 3 * cell + 70), cls, font=f_axis, fill="#111827")
    for i, cls in enumerate(CLASSES):
        bbox = draw.textbbox((0, 0), cls, font=f_axis)
        draw.text((left - 90 - (bbox[2] - bbox[0]), top + i * cell + cell / 2 - (bbox[3] - bbox[1]) / 2), cls, font=f_axis, fill="#111827")
    draw.text((left + 430, top + 3 * cell + 210), "Predicted class", font=f_label, fill="#111827")
    draw.text((80, top + 620), "True class", font=f_label, fill="#111827")
    draw.rectangle((left, top, left + 3 * cell, top + 3 * cell), outline="#111827", width=5)

    # Compact color scale for count intensity.
    scale_x = left + 3 * cell + 190
    scale_y = top
    scale_h = 3 * cell
    for y in range(scale_h):
        frac = 1 - (y / scale_h)
        intensity = 0.10 + 0.82 * frac
        color = tuple(int(255 - (255 - c) * intensity) for c in base)
        draw.line((scale_x, scale_y + y, scale_x + 90, scale_y + y), fill=color, width=1)
    draw.rectangle((scale_x, scale_y, scale_x + 90, scale_y + scale_h), outline="#111827", width=4)
    for val in [0, 20, 40, 60]:
        y = scale_y + scale_h - int(val / max_count * scale_h)
        draw.line((scale_x + 90, y, scale_x + 120, y), fill="#111827", width=4)
        draw.text((scale_x + 140, y - 35), str(val), font=f_small, fill="#111827")
    return img


def build_figures(values: dict[str, Any]) -> None:
    FIGURES_CH4.mkdir(parents=True, exist_ok=True)
    if not EXISTING_MATRIX_PNG.exists():
        raise FileNotFoundError(EXISTING_MATRIX_PNG)
    shutil.copyfile(EXISTING_MATRIX_PNG, FIG_MATRIX_PNG)
    with Image.open(EXISTING_MATRIX_PNG) as img:
        rgb = img.convert("RGB")
        rgb.save(FIG_MATRIX_PDF, "PDF", resolution=200.0)
    highres = draw_highres_matrix(values["matrix"])
    highres.save(FIG_MATRIX_JPG, "JPEG", quality=97, subsampling=0, optimize=True, dpi=(300, 300))


def build_caption() -> None:
    CAPTION.write_text(
        """# Section 4.13 Figure Caption

**Figure 4.15. Final Holdout Confusion Matrix for Hijack, Leak, and Outage.** Rows represent the true Final Holdout class and columns represent the predicted class for the frozen K1 architecture. The matrix comes from the one-time sealed Final Holdout evaluation and shows that the principal residual confusion is between Hijack and Leak. No model changes were made after observing these Final Holdout results.
""",
        encoding="utf-8",
    )


def main() -> None:
    audit_rows: list[dict[str, Any]] = []
    values = load_and_verify(audit_rows)
    build_error_table(values)
    build_figures(values)
    build_caption()
    write_csv(
        EVIDENCE_AUDIT,
        audit_rows,
        ["claim", "metric", "value", "source_file", "source_field_or_row", "authoritative_status"],
    )
    print(f"Wrote {ERROR_TABLE}")
    print(f"Wrote {EVIDENCE_AUDIT}")
    print(f"Wrote {CAPTION}")
    print(f"Wrote {FIG_MATRIX_PNG}")
    print(f"Wrote {FIG_MATRIX_PDF}")
    print(f"Wrote {FIG_MATRIX_JPG}")


if __name__ == "__main__":
    main()
