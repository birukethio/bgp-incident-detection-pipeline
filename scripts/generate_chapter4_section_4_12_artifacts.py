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

FINAL_YAML = ROOT / "config/final_praxis_result_v1.yaml"
PERFORMANCE = ROOT / "data/final_holdout/final_holdout_performance_summary_v1.csv"
PER_CLASS = ROOT / "data/final_holdout/final_holdout_per_class_metrics_v1.csv"
RANKING = ROOT / "data/final_holdout/final_holdout_ranking_metrics_v1.csv"
BOOTSTRAP = ROOT / "data/final_holdout/final_holdout_bootstrap_ci_v1.csv"
COMPARISON = ROOT / "data/final_holdout/train_vs_final_holdout_comparison_v1.csv"
MANIFEST_AUDIT = ROOT / "data/final_holdout/final_holdout_manifest_audit_v1.csv"
SCHEMA_AUDIT = ROOT / "data/final_holdout/final_holdout_v4_schema_audit_v1.csv"
EVALUATION_AUDIT = ROOT / "data/final_holdout/final_evaluation_audit_v1.csv"
CONFUSION = ROOT / "data/final_holdout/final_holdout_confusion_matrix_v1.csv"
STAT_REGISTER = ROOT / "docs/final_statistical_results_register_v1.csv"
NUMBER_REGISTER = ROOT / "docs/authoritative_numbers_register_v1.csv"

RESULTS_OUT = DOCS / "chapter4_final_holdout_results_v1.csv"
AUDIT_OUT = DOCS / "chapter4_section_4_12_evidence_audit_v1.csv"
CAPTIONS_OUT = DOCS / "chapter4_section_4_12_figure_captions_v1.md"
PAPER_TEXT_OUT = DOCS / "chapter4_section_4_12_paper_figure_text_v1.md"

FIG_PRIMARY_PNG = FIGURES / "figure_4_final_holdout_primary_performance_v1.png"
FIG_PRIMARY_PDF = FIGURES / "figure_4_final_holdout_primary_performance_v1.pdf"
FIG_PRIMARY_JPG = FIGURES / "figure_4_final_holdout_primary_performance_v1_highres_chart_only.jpg"
FIG_RANKING_PNG = FIGURES / "figure_4_final_holdout_ranking_distribution_v1.png"
FIG_RANKING_PDF = FIGURES / "figure_4_final_holdout_ranking_distribution_v1.pdf"
FIG_RANKING_JPG = FIGURES / "figure_4_final_holdout_ranking_distribution_v1_highres_chart_only.jpg"
FIG_TRAIN_PNG = FIGURES / "figure_4_train_vs_final_holdout_v1.png"
FIG_TRAIN_PDF = FIGURES / "figure_4_train_vs_final_holdout_v1.pdf"
FIG_TRAIN_JPG = FIGURES / "figure_4_train_vs_final_holdout_v1_highres_chart_only.jpg"

COLORS = {
    "ink": "#17212B",
    "muted": "#5F6B7A",
    "grid": "#D8DEE6",
    "axis": "#9AA6B2",
    "blue": "#2563A8",
    "green": "#3A9B79",
    "orange": "#D89432",
    "purple": "#6B5FB5",
    "red": "#B94E48",
    "holdout": "#2563A8",
    "train": "#8A63B8",
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


F_TITLE = font(42, True)
F_SUB = font(22)
F_AXIS = font(18)
F_SMALL = font(16)
F_TINY = font(14)
F_BOLD = font(20, True)


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


def parse_simple_yaml(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    parent = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith("  ") and parent and ":" in line:
            key, value = line.strip().split(":", 1)
            values[f"{parent}.{key.strip()}"] = value.strip().strip("'\"")
        elif ":" in line:
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip().strip("'\"")
            if value:
                values[key] = value
                parent = ""
            else:
                parent = key
    return values


def assert_close(label: str, observed: float, expected: float, tol: float = 5e-7) -> None:
    if abs(observed - expected) > tol:
        raise ValueError(f"{label} mismatch: observed={observed}, expected={expected}")


def fmt(value: float, digits: int = 6) -> str:
    return f"{value:.{digits}f}"


def audit_value(
    rows: list[dict[str, Any]],
    metric: str,
    value: Any,
    source_file: Path,
    source_field_or_row: str,
    status: str = "PASS_AUTHORITATIVE_PHASE_L",
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


def verify_audit_passes(audit_rows: list[dict[str, Any]]) -> None:
    manifest = {row["check"]: row for row in read_csv(MANIFEST_AUDIT)}
    schema = {row["check"]: row for row in read_csv(SCHEMA_AUDIT)}
    final = {row["check"]: row for row in read_csv(EVALUATION_AUDIT)}

    for check in [
        "holdout_total_incidents",
        "holdout_hijack_incidents",
        "holdout_leak_incidents",
        "holdout_outage_incidents",
        "train_holdout_overlap",
        "validation_holdout_overlap",
    ]:
        if manifest[check]["status"] != "PASS":
            raise ValueError(f"Manifest audit did not pass for {check}")
        audit_value(audit_rows, check, manifest[check]["observed"], MANIFEST_AUDIT, f"check={check}")

    for check in ["total_model_features", "feature_order_matches_train", "no_train_rows", "no_validation_rows"]:
        if schema[check]["status"] != "PASS":
            raise ValueError(f"Schema audit did not pass for {check}")
        audit_value(audit_rows, check, schema[check]["observed"], SCHEMA_AUDIT, f"check={check}")

    for check in [
        "train_only_model_fitting",
        "validation_excluded",
        "holdout_excluded_from_fitting",
        "feature_count_74",
        "final_holdout_terminal_evaluation",
    ]:
        if final[check]["status"] != "PASS":
            raise ValueError(f"Final evaluation audit did not pass for {check}")
        audit_value(audit_rows, check, final[check].get("observed", final[check]["notes"]), EVALUATION_AUDIT, f"check={check}")


def verify_inputs(audit_rows: list[dict[str, Any]]) -> dict[str, Any]:
    yaml_values = parse_simple_yaml(FINAL_YAML)
    perf = read_csv(PERFORMANCE)[0]
    per_class = {row["class"]: row for row in read_csv(PER_CLASS)}
    ranking = {row["metric"]: float(row["value"]) for row in read_csv(RANKING)}
    ci = {row["metric"]: row for row in read_csv(BOOTSTRAP)}
    comparison = {row["metric"]: row for row in read_csv(COMPARISON)}

    expected = {
        "holdout_incidents": 213,
        "holdout_window_rows": 14906,
        "incident_macro_f1": 0.9201769450076779,
        "top1": 0.92018779342723,
        "top2": 0.9906103286384976,
        "mrr": 0.9585289514866979,
        "mean_true_class_rank": 1.0892018779342723,
        "hijack_f1": 0.8776978417266187,
        "leak_f1": 0.9041095890410958,
        "outage_f1": 0.9787234042553191,
        "ci_lower": 0.8801170994295882,
        "ci_upper": 0.9544024249379308,
        "rank1": 196,
        "rank2": 15,
        "rank3": 2,
        "train_macro": 0.931653,
        "train_top1": 0.931521,
        "train_top2": 0.992346,
        "train_mrr": 0.964485,
    }

    if int(perf["holdout_incidents"]) != expected["holdout_incidents"]:
        raise ValueError("Holdout incident count mismatch")
    if int(perf["holdout_window_rows"]) != expected["holdout_window_rows"]:
        raise ValueError("Holdout row count mismatch")
    for metric in ["incident_macro_f1", "top1", "top2", "mrr", "mean_true_class_rank", "hijack_f1", "leak_f1", "outage_f1"]:
        assert_close(metric, float(perf[metric]), expected[metric])
        assert_close(f"yaml {metric}", float(yaml_values[metric]), expected[metric])
        audit_value(audit_rows, metric, perf[metric], PERFORMANCE, f"row=0; field={metric}")
        audit_value(audit_rows, f"yaml_{metric}", yaml_values[metric], FINAL_YAML, f"field={metric}")

    macro_ci = ci["incident_macro_f1"]
    assert_close("Macro F1 CI lower", float(macro_ci["ci_lower_95"]), expected["ci_lower"])
    assert_close("Macro F1 CI upper", float(macro_ci["ci_upper_95"]), expected["ci_upper"])
    audit_value(audit_rows, "incident_macro_f1_ci_lower_95", macro_ci["ci_lower_95"], BOOTSTRAP, "metric=incident_macro_f1; field=ci_lower_95")
    audit_value(audit_rows, "incident_macro_f1_ci_upper_95", macro_ci["ci_upper_95"], BOOTSTRAP, "metric=incident_macro_f1; field=ci_upper_95")

    for cls, metric in [("HIJACK", "hijack_f1"), ("LEAK", "leak_f1"), ("OUTAGE", "outage_f1")]:
        assert_close(f"{cls} F1", float(per_class[cls]["f1"]), expected[metric])
        if int(per_class[cls]["support_incidents"]) != 71:
            raise ValueError(f"{cls} support mismatch")
        audit_value(audit_rows, f"{cls.lower()}_support", 71, PER_CLASS, f"class={cls}; field=support_incidents")
        audit_value(audit_rows, f"{CLS_TO_CANON[cls]}_f1", per_class[cls]["f1"], PER_CLASS, f"class={cls}; field=f1")

    if int(ranking["ranked_first_count"]) != expected["rank1"]:
        raise ValueError("Rank 1 count mismatch")
    if int(ranking["ranked_second_count"]) != expected["rank2"]:
        raise ValueError("Rank 2 count mismatch")
    if int(ranking["ranked_third_count"]) != expected["rank3"]:
        raise ValueError("Rank 3 count mismatch")
    for metric, value in [("ranked_first_count", expected["rank1"]), ("ranked_second_count", expected["rank2"]), ("ranked_third_count", expected["rank3"])]:
        audit_value(audit_rows, metric, value, RANKING, f"metric={metric}")

    train_keys = {
        "incident_macro_f1": "train_macro",
        "top1": "train_top1",
        "top2": "train_top2",
        "mrr": "train_mrr",
    }
    for metric, key in train_keys.items():
        assert_close(f"fixed TRAIN {metric}", float(comparison[metric]["fixed_k1_train_nested_cv"]), expected[key])
        audit_value(audit_rows, f"fixed_train_{metric}", comparison[metric]["fixed_k1_train_nested_cv"], COMPARISON, f"metric={metric}; field=fixed_k1_train_nested_cv")
        audit_value(audit_rows, f"holdout_delta_{metric}", comparison[metric]["holdout_minus_train"], COMPARISON, f"metric={metric}; field=holdout_minus_train")

    verify_audit_passes(audit_rows)

    # Cross-register checks are evidence links; the CSVs use dissertation-rounded values.
    for source in [STAT_REGISTER, NUMBER_REGISTER, CONFUSION]:
        if not source.exists():
            raise FileNotFoundError(source)
        audit_value(audit_rows, f"crosscheck_{source.name}", "present", source, "artifact exists and was included in Section 4.12 source set")

    return {
        "yaml": yaml_values,
        "perf": perf,
        "per_class": per_class,
        "ranking": ranking,
        "ci": ci,
        "comparison": comparison,
        "expected": expected,
    }


CLS_TO_CANON = {"HIJACK": "hijack", "LEAK": "leak", "OUTAGE": "outage"}


def build_results_table(values: dict[str, Any]) -> None:
    perf = values["perf"]
    comparison = values["comparison"]
    ci = values["ci"]["incident_macro_f1"]
    rows = [
        {
            "section": "Final Holdout corpus",
            "metric": "incidents",
            "value": "213",
            "ci_lower_95": "NA",
            "ci_upper_95": "NA",
            "fixed_train_reference": "NA",
            "holdout_minus_train": "NA",
            "sample_unit": "incident",
            "source_artifact": rel(PERFORMANCE),
        },
        {
            "section": "Final Holdout corpus",
            "metric": "window_rows",
            "value": "14906",
            "ci_lower_95": "NA",
            "ci_upper_95": "NA",
            "fixed_train_reference": "NA",
            "holdout_minus_train": "NA",
            "sample_unit": "five_minute_window",
            "source_artifact": rel(PERFORMANCE),
        },
        {
            "section": "Primary performance",
            "metric": "incident_macro_f1",
            "value": perf["incident_macro_f1"],
            "ci_lower_95": ci["ci_lower_95"],
            "ci_upper_95": ci["ci_upper_95"],
            "fixed_train_reference": comparison["incident_macro_f1"]["fixed_k1_train_nested_cv"],
            "holdout_minus_train": comparison["incident_macro_f1"]["holdout_minus_train"],
            "sample_unit": "incident",
            "source_artifact": f"{rel(PERFORMANCE)}; {rel(BOOTSTRAP)}; {rel(COMPARISON)}",
        },
        {
            "section": "Primary performance",
            "metric": "top1",
            "value": perf["top1"],
            "ci_lower_95": "NA",
            "ci_upper_95": "NA",
            "fixed_train_reference": comparison["top1"]["fixed_k1_train_nested_cv"],
            "holdout_minus_train": comparison["top1"]["holdout_minus_train"],
            "sample_unit": "incident",
            "source_artifact": f"{rel(PERFORMANCE)}; {rel(COMPARISON)}",
        },
        {
            "section": "Primary performance",
            "metric": "top2",
            "value": perf["top2"],
            "ci_lower_95": "NA",
            "ci_upper_95": "NA",
            "fixed_train_reference": comparison["top2"]["fixed_k1_train_nested_cv"],
            "holdout_minus_train": comparison["top2"]["holdout_minus_train"],
            "sample_unit": "incident",
            "source_artifact": f"{rel(PERFORMANCE)}; {rel(COMPARISON)}",
        },
        {
            "section": "Primary performance",
            "metric": "mrr",
            "value": perf["mrr"],
            "ci_lower_95": "NA",
            "ci_upper_95": "NA",
            "fixed_train_reference": comparison["mrr"]["fixed_k1_train_nested_cv"],
            "holdout_minus_train": comparison["mrr"]["holdout_minus_train"],
            "sample_unit": "incident",
            "source_artifact": f"{rel(PERFORMANCE)}; {rel(COMPARISON)}",
        },
    ]
    for cls, canon in CLS_TO_CANON.items():
        row = values["per_class"][cls]
        rows.append(
            {
                "section": "Per-class F1",
                "metric": f"{canon}_f1",
                "value": row["f1"],
                "ci_lower_95": "NA",
                "ci_upper_95": "NA",
                "fixed_train_reference": comparison[f"{canon}_f1"]["fixed_k1_train_nested_cv"],
                "holdout_minus_train": comparison[f"{canon}_f1"]["holdout_minus_train"],
                "sample_unit": "incident",
                "source_artifact": f"{rel(PER_CLASS)}; {rel(COMPARISON)}",
            }
        )
    rank1 = int(values["ranking"]["ranked_first_count"])
    rank2 = int(values["ranking"]["ranked_second_count"])
    rank3 = int(values["ranking"]["ranked_third_count"])
    rows.extend(
        [
            {
                "section": "Ranking",
                "metric": "rank_1_count",
                "value": rank1,
                "ci_lower_95": "NA",
                "ci_upper_95": "NA",
                "fixed_train_reference": "NA",
                "holdout_minus_train": "NA",
                "sample_unit": "incident",
                "source_artifact": rel(RANKING),
            },
            {
                "section": "Ranking",
                "metric": "rank_2_count",
                "value": rank2,
                "ci_lower_95": "NA",
                "ci_upper_95": "NA",
                "fixed_train_reference": "NA",
                "holdout_minus_train": "NA",
                "sample_unit": "incident",
                "source_artifact": rel(RANKING),
            },
            {
                "section": "Ranking",
                "metric": "rank_3_count",
                "value": rank3,
                "ci_lower_95": "NA",
                "ci_upper_95": "NA",
                "fixed_train_reference": "NA",
                "holdout_minus_train": "NA",
                "sample_unit": "incident",
                "source_artifact": rel(RANKING),
            },
            {
                "section": "Ranking",
                "metric": "top2_correct_count",
                "value": rank1 + rank2,
                "ci_lower_95": "NA",
                "ci_upper_95": "NA",
                "fixed_train_reference": "NA",
                "holdout_minus_train": "NA",
                "sample_unit": "incident",
                "source_artifact": rel(RANKING),
            },
        ]
    )
    write_csv(
        RESULTS_OUT,
        rows,
        [
            "section",
            "metric",
            "value",
            "ci_lower_95",
            "ci_upper_95",
            "fixed_train_reference",
            "holdout_minus_train",
            "sample_unit",
            "source_artifact",
        ],
    )


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
    img.save(jpg, "JPEG", quality=97, subsampling=0, optimize=True, dpi=(300, 300))


def axis_chart_base(draw: ImageDraw.ImageDraw, left: int, top: int, right: int, bottom: int, min_y: float = 0.0, max_y: float = 1.0) -> None:
    draw.line((left, bottom, right, bottom), fill=COLORS["axis"], width=3)
    draw.line((left, top, left, bottom), fill=COLORS["axis"], width=3)
    for tick in [0.0, 0.25, 0.50, 0.75, 1.0]:
        y = bottom - int((tick - min_y) / (max_y - min_y) * (bottom - top))
        draw.line((left, y, right, y), fill=COLORS["grid"], width=1)
        draw.text((left - 70, y - 12), f"{tick:.2f}", font=F_TINY, fill=COLORS["muted"])


def draw_primary(values: dict[str, Any], include_text: bool, scale: int = 1) -> Image.Image:
    width, height = 2400 * scale, (1450 if include_text else 1080) * scale
    img = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(img)
    def sf(size: int, bold: bool = False):
        return font(size * scale, bold)

    margin_x = 170 * scale
    top_pad = 70 * scale if include_text else 55 * scale
    if include_text:
        draw.text((margin_x, top_pad), "Final Holdout Primary Performance", font=sf(42, True), fill=COLORS["ink"])
        draw_wrapped(
            draw,
            (margin_x, top_pad + 65 * scale),
            "One-time terminal Final Holdout evaluation of the frozen K1 architecture on 213 incidents. Macro F1 includes the authoritative 95% bootstrap confidence interval.",
            130,
            sf(22),
            COLORS["muted"],
        )
        top = 300 * scale
    else:
        top = 90 * scale
    left, right, bottom = margin_x, width - 130 * scale, height - 170 * scale
    axis_chart_base(draw, left, top, right, bottom)

    metrics = [
        ("Macro F1", float(values["perf"]["incident_macro_f1"]), COLORS["blue"]),
        ("Top-1", float(values["perf"]["top1"]), COLORS["green"]),
        ("Top-2", float(values["perf"]["top2"]), COLORS["orange"]),
        ("MRR", float(values["perf"]["mrr"]), COLORS["purple"]),
    ]
    bar_w = 245 * scale
    gap = 210 * scale
    start = left + 210 * scale
    chart_h = bottom - top
    for idx, (label, value, color) in enumerate(metrics):
        x0 = start + idx * (bar_w + gap)
        x1 = x0 + bar_w
        y = bottom - int(value * chart_h)
        draw.rounded_rectangle((x0, y, x1, bottom), radius=10 * scale, fill=color)
        draw.text((x0 + 35 * scale, y - 45 * scale), fmt(value), font=sf(22, True), fill=COLORS["ink"])
        draw.text((x0 + 45 * scale, bottom + 30 * scale), label, font=sf(22, True), fill=COLORS["ink"])
        if idx == 0:
            ci_low = float(values["ci"]["incident_macro_f1"]["ci_lower_95"])
            ci_high = float(values["ci"]["incident_macro_f1"]["ci_upper_95"])
            y_low = bottom - int(ci_low * chart_h)
            y_high = bottom - int(ci_high * chart_h)
            cx = x1 + 42 * scale
            draw.line((cx, y_high, cx, y_low), fill=COLORS["ink"], width=4 * scale)
            draw.line((cx - 20 * scale, y_high, cx + 20 * scale, y_high), fill=COLORS["ink"], width=4 * scale)
            draw.line((cx - 20 * scale, y_low, cx + 20 * scale, y_low), fill=COLORS["ink"], width=4 * scale)
            draw.text((cx + 28 * scale, y_high - 12 * scale), "95% CI", font=sf(16), fill=COLORS["muted"])
            draw.text((cx + 28 * scale, y_low - 10 * scale), f"[{fmt(ci_low)}, {fmt(ci_high)}]", font=sf(14), fill=COLORS["muted"])
    draw.text((left + 835 * scale, bottom + 90 * scale), "Metric", font=sf(18), fill=COLORS["muted"])
    draw.text((left - 115 * scale, top + chart_h // 2), "Score", font=sf(18), fill=COLORS["muted"])
    if include_text:
        footer = "Source: final_praxis_result_v1.yaml, final_holdout_performance_summary_v1.csv, and final_holdout_bootstrap_ci_v1.csv."
        draw_wrapped(draw, (margin_x, height - 95 * scale), footer, 150, sf(18), COLORS["muted"])
    return img


def draw_ranking(values: dict[str, Any], include_text: bool, scale: int = 1) -> Image.Image:
    width, height = 2200 * scale, (1350 if include_text else 1000) * scale
    img = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(img)
    def sf(size: int, bold: bool = False):
        return font(size * scale, bold)

    margin_x = 160 * scale
    if include_text:
        draw.text((margin_x, 70 * scale), "Final Holdout Ranking Distribution", font=sf(42, True), fill=COLORS["ink"])
        draw_wrapped(
            draw,
            (margin_x, 135 * scale),
            "The frozen system ranked the true incident class first for 196 of 213 holdout incidents and within the top two for 211 of 213 incidents.",
            120,
            sf(22),
            COLORS["muted"],
        )
        top = 300 * scale
    else:
        top = 85 * scale
    left, right, bottom = margin_x, width - 160 * scale, height - 160 * scale
    max_count = 213
    draw.line((left, bottom, right, bottom), fill=COLORS["axis"], width=3 * scale)
    draw.line((left, top, left, bottom), fill=COLORS["axis"], width=3 * scale)
    for tick in [0, 50, 100, 150, 200]:
        y = bottom - int(tick / max_count * (bottom - top))
        draw.line((left, y, right, y), fill=COLORS["grid"], width=1 * scale)
        draw.text((left - 60 * scale, y - 12 * scale), str(tick), font=sf(14), fill=COLORS["muted"])

    bars = [
        ("Rank 1", int(values["ranking"]["ranked_first_count"]), COLORS["blue"]),
        ("Rank 2", int(values["ranking"]["ranked_second_count"]), COLORS["green"]),
        ("Rank 3", int(values["ranking"]["ranked_third_count"]), COLORS["red"]),
    ]
    bar_w = 300 * scale
    gap = 250 * scale
    start = left + 290 * scale
    for idx, (label, count, color) in enumerate(bars):
        x0 = start + idx * (bar_w + gap)
        x1 = x0 + bar_w
        y = bottom - int(count / max_count * (bottom - top))
        draw.rounded_rectangle((x0, y, x1, bottom), radius=10 * scale, fill=color)
        draw.text((x0 + 85 * scale, y - 45 * scale), str(count), font=sf(28, True), fill=COLORS["ink"])
        draw.text((x0 + 85 * scale, bottom + 30 * scale), label, font=sf(23, True), fill=COLORS["ink"])

    top2 = int(values["ranking"]["ranked_first_count"] + values["ranking"]["ranked_second_count"])
    note = f"Top-2 correct = {top2}/213 = {float(values['perf']['top2']):.6f}"
    x_note, y_note = right - 650 * scale, top + 80 * scale
    draw.rounded_rectangle((x_note, y_note, right - 30 * scale, y_note + 105 * scale), radius=8 * scale, outline=COLORS["grid"], width=2 * scale)
    draw.text((x_note + 35 * scale, y_note + 32 * scale), note, font=sf(25, True), fill=COLORS["ink"])
    draw.text((left + 805 * scale, bottom + 88 * scale), "True-class rank", font=sf(18), fill=COLORS["muted"])
    draw.text((left - 105 * scale, top + (bottom - top) // 2), "Incidents", font=sf(18), fill=COLORS["muted"])
    if include_text:
        footer = "Source: final_holdout_ranking_metrics_v1.csv and final_holdout_performance_summary_v1.csv."
        draw_wrapped(draw, (margin_x, height - 95 * scale), footer, 130, sf(18), COLORS["muted"])
    return img


def draw_train_vs_holdout(values: dict[str, Any], include_text: bool, scale: int = 1) -> Image.Image:
    width, height = 2500 * scale, (1500 if include_text else 1120) * scale
    img = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(img)
    def sf(size: int, bold: bool = False):
        return font(size * scale, bold)

    margin_x = 170 * scale
    if include_text:
        draw.text((margin_x, 70 * scale), "Fixed TRAIN Reference vs Final Holdout", font=sf(42, True), fill=COLORS["ink"])
        draw_wrapped(
            draw,
            (margin_x, 135 * scale),
            "Comparison uses the fixed deployable K1 TRAIN nested-CV reference, not the earlier fold-selected K1 result. Deltas show Final Holdout minus TRAIN.",
            135,
            sf(22),
            COLORS["muted"],
        )
        top = 315 * scale
    else:
        top = 95 * scale
    left, right, bottom = margin_x, width - 130 * scale, height - 180 * scale
    y_max = 1.05
    axis_chart_base(draw, left, top, right, bottom, max_y=y_max)
    metrics = [
        ("Macro F1", "incident_macro_f1"),
        ("Top-1", "top1"),
        ("Top-2", "top2"),
        ("MRR", "mrr"),
    ]
    group_w = 400 * scale
    gap = 125 * scale
    bar_w = 135 * scale
    start = left + 150 * scale
    chart_h = bottom - top
    comparison = values["comparison"]
    for idx, (label, metric) in enumerate(metrics):
        row = comparison[metric]
        x = start + idx * (group_w + gap)
        train = float(row["fixed_k1_train_nested_cv"])
        holdout = float(row["final_holdout"])
        for j, (name, val, color) in enumerate([("TRAIN", train, COLORS["train"]), ("Holdout", holdout, COLORS["holdout"])]):
            x0 = x + j * (bar_w + 34 * scale)
            x1 = x0 + bar_w
            y = bottom - int(val / y_max * chart_h)
            draw.rounded_rectangle((x0, y, x1, bottom), radius=8 * scale, fill=color)
            draw.text((x0 - 8 * scale, y - 42 * scale), fmt(val), font=sf(17, True), fill=COLORS["ink"])
        delta = float(row["holdout_minus_train"])
        draw.text((x + 15 * scale, bottom - int(0.915 / y_max * chart_h)), f"Delta {delta:+.6f}", font=sf(16, True), fill=COLORS["muted"])
        draw.text((x + 60 * scale, bottom + 32 * scale), label, font=sf(21, True), fill=COLORS["ink"])
    legend_y = top + 18 * scale
    legend_x = left + 32 * scale
    draw.rectangle((legend_x, legend_y, legend_x + 30 * scale, legend_y + 18 * scale), fill=COLORS["train"])
    draw.text((legend_x + 45 * scale, legend_y - 4 * scale), "TRAIN", font=sf(17), fill=COLORS["ink"])
    draw.rectangle((legend_x, legend_y + 38 * scale, legend_x + 30 * scale, legend_y + 56 * scale), fill=COLORS["holdout"])
    draw.text((legend_x + 45 * scale, legend_y + 34 * scale), "Holdout", font=sf(17), fill=COLORS["ink"])
    draw.text((left + 900 * scale, bottom + 94 * scale), "Metric", font=sf(18), fill=COLORS["muted"])
    draw.text((left - 115 * scale, top + chart_h // 2), "Score", font=sf(18), fill=COLORS["muted"])
    if include_text:
        footer = "Source: train_vs_final_holdout_comparison_v1.csv; fixed TRAIN values are 0.931653 / 0.931521 / 0.992346 / 0.964485."
        draw_wrapped(draw, (margin_x, height - 95 * scale), footer, 150, sf(18), COLORS["muted"])
    return img


def build_captions() -> None:
    text = """# Section 4.12 Figure Captions

**Figure 4.12. Final Holdout primary performance for the frozen K1 architecture.** The figure reports the one-time terminal Final Holdout incident-level Macro F1, Top-1 accuracy, Top-2 accuracy, and MRR for 213 incidents. The Macro F1 interval is the existing 95% bootstrap confidence interval from the frozen Phase L artifact; no new bootstrap samples were generated for this documentation figure.

**Figure 4.13. Final Holdout true-class ranking distribution.** The figure shows the rank position assigned to the true incident class across the 213 Final Holdout incidents. The model ranked the true class first for 196 incidents, second for 15 incidents, and third for 2 incidents, yielding Top-2 correctness of 211/213 = 0.990610.

**Figure 4.14. Fixed TRAIN nested-CV reference versus Final Holdout.** The figure compares the fixed deployable K1 TRAIN nested-CV reference against the one-time Final Holdout evaluation for Macro F1, Top-1, Top-2, and MRR. This comparison uses the fixed deployable TRAIN values, not the earlier fold-selected K1 result, and is intended to show the observed generalization gap transparently.
"""
    CAPTIONS_OUT.write_text(text, encoding="utf-8")

    paper_text = """# Section 4.12 Figure Text

Figure 4.12: Final Holdout primary performance. Macro F1 = 0.920177 with 95% CI [0.880117, 0.954402]; Top-1 = 0.920188; Top-2 = 0.990610; MRR = 0.958529.

Figure 4.13: Final Holdout ranking distribution. Rank 1 = 196, Rank 2 = 15, Rank 3 = 2. Top-2 correct = 211/213 = 0.990610.

Figure 4.14: Fixed deployable TRAIN nested-CV reference vs Final Holdout. TRAIN = 0.931653 / 0.931521 / 0.992346 / 0.964485 for Macro F1 / Top-1 / Top-2 / MRR. Holdout deltas = -0.011476 / -0.011333 / -0.001736 / -0.005956.
"""
    PAPER_TEXT_OUT.write_text(paper_text, encoding="utf-8")


def main() -> None:
    audit_rows: list[dict[str, Any]] = []
    values = verify_inputs(audit_rows)
    build_results_table(values)
    build_captions()

    primary = draw_primary(values, include_text=True, scale=1)
    save_outputs(primary, FIG_PRIMARY_PNG, FIG_PRIMARY_PDF)
    save_jpg(draw_primary(values, include_text=False, scale=2), FIG_PRIMARY_JPG)

    ranking = draw_ranking(values, include_text=True, scale=1)
    save_outputs(ranking, FIG_RANKING_PNG, FIG_RANKING_PDF)
    save_jpg(draw_ranking(values, include_text=False, scale=2), FIG_RANKING_JPG)

    train = draw_train_vs_holdout(values, include_text=True, scale=1)
    save_outputs(train, FIG_TRAIN_PNG, FIG_TRAIN_PDF)
    save_jpg(draw_train_vs_holdout(values, include_text=False, scale=2), FIG_TRAIN_JPG)

    write_csv(
        AUDIT_OUT,
        audit_rows,
        ["metric", "value", "source_file", "source_field_or_row", "authoritative_status"],
    )
    print(f"Wrote {RESULTS_OUT}")
    print(f"Wrote {AUDIT_OUT}")
    print(f"Wrote {CAPTIONS_OUT}")
    print(f"Wrote figures under {FIGURES}")


if __name__ == "__main__":
    main()
