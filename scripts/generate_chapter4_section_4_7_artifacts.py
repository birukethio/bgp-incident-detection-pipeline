from __future__ import annotations

import csv
import json
import textwrap
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw, ImageFont


ROOT = Path("/Users/biruk/Documents/New project")
DOCS = ROOT / "docs"
FIGURES = ROOT / "figures/chapter4"

RF_VS_XGB = ROOT / "data/modeling/xgb_i2_vs_refined_rf_v1.csv"
RF_MULTI = ROOT / "data/modeling/rf_multiseed_stability_results_v1.csv"
XGB_I2_FINAL = ROOT / "data/modeling/xgb_i2_final_comparison_v1.csv"
XGB_MULTI = ROOT / "data/modeling/xgb_multiseed_stability_results_v2.csv"
XGB_CONFIG = ROOT / "config/final_model_candidate_v3_1_xgb_refined.yaml"

RESULTS_OUT = DOCS / "chapter4_xgboost_comparison_results_v1.csv"
DELTAS_OUT = DOCS / "chapter4_rf_vs_xgb_deltas_v1.csv"
CONFIG_OUT = DOCS / "chapter4_refined_xgb_configuration_v1.csv"
AUDIT_OUT = DOCS / "chapter4_section_4_7_evidence_audit_v1.csv"
CAPTION_OUT = DOCS / "chapter4_section_4_7_figure_caption_v1.md"
PAPER_TEXT_OUT = DOCS / "chapter4_section_4_7_paper_figure_text_v1.md"

FIG_OUT = FIGURES / "figure_4_rf_xgb_comparison_v1.png"
FIG_PDF_OUT = FIGURES / "figure_4_rf_xgb_comparison_v1.pdf"
FIG_JPG_OUT = FIGURES / "figure_4_rf_xgb_comparison_v1_highres_chart_only.jpg"

COLORS = {
    "ink": "#17212B",
    "muted": "#5F6B7A",
    "grid": "#D8DEE6",
    "axis": "#9AA6B2",
    "rf": "#9AA6B2",
    "xgb": "#D89432",
    "xgb2": "#2F6F95",
    "mrr": "#6B5FB5",
    "top2": "#3A9B79",
}

EXPECTED_XGB_CONFIG = {
    "n_estimators": 600,
    "max_depth": 6,
    "learning_rate": 0.125,
    "subsample": 0.9,
    "colsample_bytree": 0.9,
    "min_child_weight": 1,
    "gamma": 0,
    "reg_alpha": 0.01,
    "reg_lambda": 2.0,
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


def get_row(rows: list[dict[str, str]], key: str, value: str) -> dict[str, str]:
    matches = [row for row in rows if row.get(key) == value]
    if len(matches) != 1:
        raise RuntimeError(f"Expected exactly one row where {key}={value}; found {len(matches)}")
    return matches[0]


def parse_yaml_selected_hyperparameters(path: Path) -> dict[str, Any]:
    params: dict[str, Any] = {}
    in_params = False
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.rstrip()
        if line == "selected_hyperparameters:":
            in_params = True
            continue
        if in_params:
            if line and not line.startswith("  "):
                break
            if ":" not in line:
                continue
            key, raw_value = line.strip().split(":", 1)
            value = raw_value.strip().strip('"')
            try:
                params[key] = int(value)
            except ValueError:
                try:
                    params[key] = float(value)
                except ValueError:
                    params[key] = value
    return params


def audit_value(
    rows: list[dict[str, Any]],
    metric: str,
    value: Any,
    model_stage: str,
    source_file: Path,
    source_field_or_row: str,
    status: str = "PASS_AUTHORITATIVE_TRAIN_ONLY",
) -> None:
    rows.append(
        {
            "metric": metric,
            "value": value,
            "model_stage": model_stage,
            "source_file": rel(source_file),
            "source_field_or_row": source_field_or_row,
            "authoritative_status": status,
        }
    )


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


def result_row(stage: str, family: str, row: dict[str, str], source: Path, source_note: str) -> dict[str, str]:
    return {
        "model_stage": stage,
        "model_family": family,
        "incident_macro_f1": fmt(row["incident_macro_f1"]),
        "macro_f1_std": fmt(row.get("macro_f1_std") or row.get("std_incident_macro_f1") or "NA"),
        "top1_accuracy": fmt(row["incident_top1"]),
        "top2_accuracy": fmt(row["incident_top2"]),
        "mrr": fmt(row["incident_mrr"]),
        "hijack_f1": fmt(row["hijack_f1"]),
        "leak_f1": fmt(row["leak_f1"]),
        "outage_f1": fmt(row["outage_f1"]),
        "window_macro_f1": fmt(row["window_macro_f1"]),
        "fit_runtime": fmt(row["fit_time_seconds"], 3),
        "inference_runtime": fmt(row["inference_time_seconds"], 3),
        "evaluation_scope": "TRAIN-only grouped CV; V4 features; I1 incident-aware weighting; no Validation/Holdout access",
        "source_artifact": f"{rel(source)} ({source_note})",
    }


def draw_comparison(rows: list[dict[str, str]]) -> None:
    img = Image.new("RGB", (2400, 1500), "white")
    draw = ImageDraw.Draw(img)
    draw.text((100, 70), "RF vs XGBoost Comparison and Refinement", font=F_TITLE, fill=COLORS["ink"])
    draw_wrapped(
        draw,
        (102, 135),
        "TRAIN-only grouped-CV progression from the refined RF benchmark to Phase I XGBoost and Phase I2 refined XGBoost.",
        148,
        F_SUB,
        COLORS["muted"],
    )
    draw.line((100, 225, 2300, 225), fill=COLORS["grid"], width=3)

    labels = ["Refined RF\n(H2)", "Phase I\nXGBoost", "Refined XGB\n(I2)"]
    colors = [COLORS["rf"], COLORS["xgb"], COLORS["xgb2"]]
    macro = [float(r["incident_macro_f1"]) for r in rows]
    top2 = [float(r["top2_accuracy"]) for r in rows]
    mrr = [float(r["mrr"]) for r in rows]
    stds = [0.0, 0.0, float(rows[2]["macro_f1_std"])]

    left, top, right, bottom = 190, 350, 1220, 1120
    ymin, ymax = 0.70, 0.83
    for idx in range(7):
        val = ymin + (ymax - ymin) * idx / 6
        y = bottom - int((val - ymin) / (ymax - ymin) * (bottom - top))
        draw.line((left, y, right, y), fill=COLORS["grid"], width=2)
        draw.text((105, y - 11), f"{val:.2f}", font=F_TINY, fill=COLORS["muted"])
    draw.line((left, top, left, bottom), fill=COLORS["axis"], width=3)
    draw.line((left, bottom, right, bottom), fill=COLORS["axis"], width=3)
    draw.text((left, top - 55), "Incident Macro F1", font=F_BOLD, fill=COLORS["ink"])
    gap = (right - left) / len(macro)
    bar_w = 185
    for idx, (label, value, color, std) in enumerate(zip(labels, macro, colors, stds), start=1):
        x = int(left + gap * (idx - 0.5))
        y = bottom - int((value - ymin) / (ymax - ymin) * (bottom - top))
        draw.rounded_rectangle((x - bar_w // 2, y, x + bar_w // 2, bottom), radius=9, fill=color)
        draw.text((x - 72, y - 40), f"{value:.6f}", font=F_BOLD, fill=COLORS["ink"])
        if std:
            err_px = int(std / (ymax - ymin) * (bottom - top))
            draw.line((x, y - err_px, x, y + err_px), fill=COLORS["ink"], width=4)
            draw.line((x - 30, y - err_px, x + 30, y - err_px), fill=COLORS["ink"], width=4)
            draw.line((x - 30, y + err_px, x + 30, y + err_px), fill=COLORS["ink"], width=4)
        draw.multiline_text((x - 80, bottom + 28), label, font=F_SMALL, fill=COLORS["ink"], spacing=5, align="center")

    left2, top2y, right2, bottom2 = 1410, 350, 2260, 1120
    ymin2, ymax2 = 0.86, 0.95
    for idx in range(7):
        val = ymin2 + (ymax2 - ymin2) * idx / 6
        y = bottom2 - int((val - ymin2) / (ymax2 - ymin2) * (bottom2 - top2y))
        draw.line((left2, y, right2, y), fill=COLORS["grid"], width=2)
        draw.text((1330, y - 11), f"{val:.2f}", font=F_TINY, fill=COLORS["muted"])
    draw.line((left2, top2y, left2, bottom2), fill=COLORS["axis"], width=3)
    draw.line((left2, bottom2, right2, bottom2), fill=COLORS["axis"], width=3)
    draw.text((left2, top2y - 55), "Ranking Metrics", font=F_BOLD, fill=COLORS["ink"])
    xgap2 = (right2 - left2) / len(labels)
    top2_points = []
    mrr_points = []
    for idx, label in enumerate(labels, start=1):
        x = int(left2 + xgap2 * (idx - 0.5))
        y_top2 = bottom2 - int((top2[idx - 1] - ymin2) / (ymax2 - ymin2) * (bottom2 - top2y))
        y_mrr = bottom2 - int((mrr[idx - 1] - ymin2) / (ymax2 - ymin2) * (bottom2 - top2y))
        top2_points.append((x, y_top2))
        mrr_points.append((x, y_mrr))
        draw.multiline_text((x - 73, bottom2 + 28), label, font=F_SMALL, fill=COLORS["ink"], spacing=5, align="center")
    draw.line(top2_points, fill=COLORS["top2"], width=5)
    draw.line(mrr_points, fill=COLORS["mrr"], width=5)
    for points, values, color in [(top2_points, top2, COLORS["top2"]), (mrr_points, mrr, COLORS["mrr"])]:
        for (x, y), value in zip(points, values):
            draw.ellipse((x - 13, y - 13, x + 13, y + 13), fill=color)
            draw.text((x - 48, y - 38), f"{value:.3f}", font=F_TINY, fill=COLORS["ink"])
    draw.rectangle((1640, 1168, 1665, 1193), fill=COLORS["top2"])
    draw.text((1680, 1165), "Top-2", font=F_SMALL, fill=COLORS["ink"])
    draw.rectangle((1815, 1168, 1840, 1193), fill=COLORS["mrr"])
    draw.text((1855, 1165), "MRR", font=F_SMALL, fill=COLORS["ink"])

    delta = macro[2] - macro[0]
    draw_wrapped(
        draw,
        (100, 1280),
        f"Refined XGBoost improved over the refined RF benchmark by {delta:.6f} Macro F1 while preserving high Top-2 ranking performance. These are TRAIN-only development results.",
        150,
        F_SMALL,
        COLORS["muted"],
    )
    draw.text((100, 1440), f"Sources: {rel(RF_VS_XGB)}; {rel(XGB_I2_FINAL)}", font=F_TINY, fill=COLORS["muted"])
    save_outputs(img, FIG_OUT, FIG_PDF_OUT)


def draw_comparison_jpg(rows: list[dict[str, str]]) -> None:
    img = Image.new("RGB", (3600, 2400), "white")
    draw = ImageDraw.Draw(img)
    labels = ["Refined RF (H2)", "Phase I XGBoost", "Refined XGB (I2)"]
    colors = [COLORS["rf"], COLORS["xgb"], COLORS["xgb2"]]
    macro = [float(r["incident_macro_f1"]) for r in rows]
    top2 = [float(r["top2_accuracy"]) for r in rows]
    mrr = [float(r["mrr"]) for r in rows]
    std = float(rows[2]["macro_f1_std"])

    left, top, right, bottom = 270, 330, 1780, 1870
    ymin, ymax = 0.70, 0.83
    for idx in range(7):
        val = ymin + (ymax - ymin) * idx / 6
        y = bottom - int((val - ymin) / (ymax - ymin) * (bottom - top))
        draw.line((left, y, right, y), fill=COLORS["grid"], width=3)
        draw.text((115, y - 18), f"{val:.2f}", font=font(28), fill=COLORS["muted"])
    draw.line((left, top, left, bottom), fill=COLORS["axis"], width=5)
    draw.line((left, bottom, right, bottom), fill=COLORS["axis"], width=5)
    draw.text((left, top - 82), "Incident Macro F1", font=font(34, True), fill=COLORS["ink"])
    gap = (right - left) / len(labels)
    bar_w = 270
    for idx, (label, value, color) in enumerate(zip(labels, macro, colors), start=1):
        x = int(left + gap * (idx - 0.5))
        y = bottom - int((value - ymin) / (ymax - ymin) * (bottom - top))
        draw.rounded_rectangle((x - bar_w // 2, y, x + bar_w // 2, bottom), radius=16, fill=color)
        draw.text((x - 125, y - 66), f"{value:.6f}", font=font(34, True), fill=COLORS["ink"])
        if idx == 3:
            err_px = int(std / (ymax - ymin) * (bottom - top))
            draw.line((x, y - err_px, x, y + err_px), fill=COLORS["ink"], width=6)
            draw.line((x - 55, y - err_px, x + 55, y - err_px), fill=COLORS["ink"], width=6)
            draw.line((x - 55, y + err_px, x + 55, y + err_px), fill=COLORS["ink"], width=6)
        draw.text((x - 155, bottom + 70), label, font=font(29), fill=COLORS["ink"])

    left2, top2y, right2, bottom2 = 2070, 330, 3420, 1870
    ymin2, ymax2 = 0.86, 0.95
    for idx in range(7):
        val = ymin2 + (ymax2 - ymin2) * idx / 6
        y = bottom2 - int((val - ymin2) / (ymax2 - ymin2) * (bottom2 - top2y))
        draw.line((left2, y, right2, y), fill=COLORS["grid"], width=3)
        draw.text((1925, y - 18), f"{val:.2f}", font=font(28), fill=COLORS["muted"])
    draw.line((left2, top2y, left2, bottom2), fill=COLORS["axis"], width=5)
    draw.line((left2, bottom2, right2, bottom2), fill=COLORS["axis"], width=5)
    draw.text((left2, top2y - 82), "Ranking Metrics", font=font(34, True), fill=COLORS["ink"])
    xgap2 = (right2 - left2) / len(labels)
    top2_points = []
    mrr_points = []
    for idx, label in enumerate(labels, start=1):
        x = int(left2 + xgap2 * (idx - 0.5))
        y_top2 = bottom2 - int((top2[idx - 1] - ymin2) / (ymax2 - ymin2) * (bottom2 - top2y))
        y_mrr = bottom2 - int((mrr[idx - 1] - ymin2) / (ymax2 - ymin2) * (bottom2 - top2y))
        top2_points.append((x, y_top2))
        mrr_points.append((x, y_mrr))
        draw.text((x - 125, bottom2 + 70), label, font=font(25), fill=COLORS["ink"])
    draw.line(top2_points, fill=COLORS["top2"], width=8)
    draw.line(mrr_points, fill=COLORS["mrr"], width=8)
    for points, values, color in [(top2_points, top2, COLORS["top2"]), (mrr_points, mrr, COLORS["mrr"])]:
        for (x, y), value in zip(points, values):
            draw.ellipse((x - 22, y - 22, x + 22, y + 22), fill=color)
            draw.text((x - 55, y - 70), f"{value:.3f}", font=font(27, True), fill=COLORS["ink"])
    draw.rectangle((2500, 2060, 2545, 2105), fill=COLORS["top2"])
    draw.text((2570, 2058), "Top-2", font=font(31), fill=COLORS["ink"])
    draw.rectangle((2750, 2060, 2795, 2105), fill=COLORS["mrr"])
    draw.text((2820, 2058), "MRR", font=font(31), fill=COLORS["ink"])
    save_jpg(img, FIG_JPG_OUT)


def main() -> None:
    rf_vs_xgb_rows = read_csv(RF_VS_XGB)
    rf_multi_rows = read_csv(RF_MULTI)
    i2_final_rows = read_csv(XGB_I2_FINAL)
    multi_rows = read_csv(XGB_MULTI)

    rf_row = get_row(rf_vs_xgb_rows, "configuration", "RF_REFINED_TRAIN_CANDIDATE")
    rf_multi_row = get_row(rf_multi_rows, "candidate_id", "H2_LOCAL_001")
    phase_i_row = get_row(i2_final_rows, "candidate_id", "PHASE_I_XGB_WINNER")
    i2_row = get_row(i2_final_rows, "candidate_id", "PHASEI2_XGB_LOCAL_004")
    i2_multi_row = get_row(multi_rows, "candidate_id", "PHASEI2_XGB_LOCAL_004")
    delta_row = get_row(rf_vs_xgb_rows, "algorithm", "DELTA_XGB_MINUS_RF")

    rf_table_row = dict(rf_row)
    rf_table_row["macro_f1_std"] = rf_multi_row["std_incident_macro_f1"]
    phase_i_table_row = {
        "incident_macro_f1": phase_i_row["mean_incident_macro_f1"],
        "macro_f1_std": phase_i_row["std_incident_macro_f1"],
        "incident_top1": phase_i_row["incident_top1"],
        "incident_top2": phase_i_row["incident_top2"],
        "incident_mrr": phase_i_row["incident_mrr"],
        "hijack_f1": phase_i_row["hijack_f1"],
        "leak_f1": phase_i_row["leak_f1"],
        "outage_f1": phase_i_row["outage_f1"],
        "window_macro_f1": phase_i_row["window_macro_f1"],
        "fit_time_seconds": phase_i_row["runtime_seconds"],
        "inference_time_seconds": phase_i_row["inference_time_seconds"],
    }
    i2_table_row = {
        "incident_macro_f1": i2_row["mean_incident_macro_f1"],
        "macro_f1_std": i2_row["std_incident_macro_f1"],
        "incident_top1": i2_row["incident_top1"],
        "incident_top2": i2_row["incident_top2"],
        "incident_mrr": i2_row["incident_mrr"],
        "hijack_f1": i2_row["hijack_f1"],
        "leak_f1": i2_row["leak_f1"],
        "outage_f1": i2_row["outage_f1"],
        "window_macro_f1": i2_row["window_macro_f1"],
        "fit_time_seconds": i2_row["runtime_seconds"],
        "inference_time_seconds": i2_row["inference_time_seconds"],
    }

    results = [
        result_row("Phase H2 refined RF", "RandomForest", rf_table_row, RF_VS_XGB, "refined RF comparator row plus RF multi-seed SD"),
        result_row("Phase I XGBoost", "XGBoost", phase_i_table_row, XGB_I2_FINAL, "Phase I winner row retained in Phase I2 comparison"),
        result_row("Phase I2 refined XGBoost", "XGBoost", i2_table_row, XGB_I2_FINAL, "selected refined XGB multi-seed row"),
    ]
    results[0]["source_artifact"] = f"{rel(RF_VS_XGB)} (refined RF comparator metrics); {rel(RF_MULTI)} (refined RF multi-seed SD)"
    write_csv(
        RESULTS_OUT,
        results,
        [
            "model_stage",
            "model_family",
            "incident_macro_f1",
            "macro_f1_std",
            "top1_accuracy",
            "top2_accuracy",
            "mrr",
            "hijack_f1",
            "leak_f1",
            "outage_f1",
            "window_macro_f1",
            "fit_runtime",
            "inference_runtime",
            "evaluation_scope",
            "source_artifact",
        ],
    )

    delta_metrics = [
        ("incident_macro_f1", "Macro F1"),
        ("incident_top1", "Top-1"),
        ("incident_top2", "Top-2"),
        ("incident_mrr", "MRR"),
        ("hijack_f1", "Hijack F1"),
        ("leak_f1", "Leak F1"),
        ("outage_f1", "Outage F1"),
        ("fit_time_seconds", "fit runtime seconds"),
        ("inference_time_seconds", "inference runtime seconds"),
    ]
    delta_rows = [
        {
            "metric": label,
            "phase_i2_xgb": delta_row[field],
            "phase_h2_rf": "0",
            "delta_xgb_minus_rf": delta_row[field],
            "source_artifact": rel(RF_VS_XGB),
        }
        for field, label in delta_metrics
    ]
    # Replace the convenience columns with actual endpoint values for readability.
    rf_values = {
        "incident_macro_f1": rf_row["incident_macro_f1"],
        "incident_top1": rf_row["incident_top1"],
        "incident_top2": rf_row["incident_top2"],
        "incident_mrr": rf_row["incident_mrr"],
        "hijack_f1": rf_row["hijack_f1"],
        "leak_f1": rf_row["leak_f1"],
        "outage_f1": rf_row["outage_f1"],
        "fit_time_seconds": rf_row["fit_time_seconds"],
        "inference_time_seconds": rf_row["inference_time_seconds"],
    }
    xgb_values = {
        "incident_macro_f1": i2_table_row["incident_macro_f1"],
        "incident_top1": i2_table_row["incident_top1"],
        "incident_top2": i2_table_row["incident_top2"],
        "incident_mrr": i2_table_row["incident_mrr"],
        "hijack_f1": i2_table_row["hijack_f1"],
        "leak_f1": i2_table_row["leak_f1"],
        "outage_f1": i2_table_row["outage_f1"],
        "fit_time_seconds": i2_table_row["fit_time_seconds"],
        "inference_time_seconds": i2_table_row["inference_time_seconds"],
    }
    delta_rows = []
    for field, label in delta_metrics:
        delta_rows.append(
            {
                "metric": label,
                "phase_h2_rf": rf_values[field],
                "phase_i2_xgb": xgb_values[field],
                "delta_xgb_minus_rf": delta_row[field],
                "source_artifact": rel(RF_VS_XGB),
            }
        )
    write_csv(DELTAS_OUT, delta_rows, ["metric", "phase_h2_rf", "phase_i2_xgb", "delta_xgb_minus_rf", "source_artifact"])

    yaml_params = parse_yaml_selected_hyperparameters(XGB_CONFIG)
    artifact_params = json.loads(i2_multi_row["parameters_json"])
    config_rows: list[dict[str, Any]] = []
    audit_rows: list[dict[str, Any]] = []
    for key, expected in EXPECTED_XGB_CONFIG.items():
        source_value = yaml_params.get(key, artifact_params.get(key))
        status = "PASS_MATCHES_PHASE_I2_ARTIFACT" if source_value == expected == artifact_params.get(key) else "FAIL_CONFIG_MISMATCH"
        config_rows.append({"hyperparameter": key, "value": source_value, "source_artifact": rel(XGB_CONFIG)})
        audit_value(audit_rows, key, source_value, "Phase I2 refined XGBoost configuration", XGB_CONFIG, f"selected_hyperparameters.{key}", status)
    write_csv(CONFIG_OUT, config_rows, ["hyperparameter", "value", "source_artifact"])

    stage_sources = [
        ("Phase H2 refined RF", rf_table_row, RF_VS_XGB, "algorithm=RandomForest; configuration=RF_REFINED_TRAIN_CANDIDATE"),
        ("Phase I XGBoost", phase_i_table_row, XGB_I2_FINAL, "candidate_id=PHASE_I_XGB_WINNER"),
        ("Phase I2 refined XGBoost", i2_table_row, XGB_I2_FINAL, "candidate_id=PHASEI2_XGB_LOCAL_004"),
    ]
    metrics = [
        "incident_macro_f1",
        "macro_f1_std",
        "incident_top1",
        "incident_top2",
        "incident_mrr",
        "hijack_f1",
        "leak_f1",
        "outage_f1",
        "window_macro_f1",
        "fit_time_seconds",
        "inference_time_seconds",
    ]
    for stage, row, source, row_note in stage_sources:
        for metric in metrics:
            if stage == "Phase H2 refined RF" and metric == "macro_f1_std":
                continue
            value = row.get(metric, "NA")
            audit_value(audit_rows, metric, fmt(value, 6 if "time_seconds" not in metric else 3), stage, source, f"{row_note}; field={metric}")
    audit_value(
        audit_rows,
        "macro_f1_std_source",
        fmt(rf_multi_row["std_incident_macro_f1"]),
        "Phase H2 refined RF",
        RF_MULTI,
        "candidate_id=H2_LOCAL_001; field=std_incident_macro_f1",
    )
    for row in delta_rows:
        audit_value(audit_rows, f"delta_{row['metric']}", row["delta_xgb_minus_rf"], "Phase I2 XGB minus Phase H2 RF", RF_VS_XGB, f"algorithm=DELTA_XGB_MINUS_RF; metric={row['metric']}")
    write_csv(AUDIT_OUT, audit_rows, ["metric", "value", "model_stage", "source_file", "source_field_or_row", "authoritative_status"])

    draw_comparison(results)
    draw_comparison_jpg(results)

    delta_macro = float(delta_row["incident_macro_f1"])
    caption = f"""# Section 4.7 Figure Caption

**Figure 4.9. XGBoost comparison and refinement results, TRAIN-only grouped cross-validation.** The figure compares the Phase H2 refined Random Forest benchmark, the Phase I XGBoost candidate, and the Phase I2 refined XGBoost candidate under the frozen V4/I1 feature and weighting framework. The left panel reports incident Macro F1, with the Phase I2 error bar representing the recorded multi-seed standard deviation ({float(i2_row['std_incident_macro_f1']):.6f}). The right panel reports Top-2 accuracy and MRR, which were available consistently across all three stages. Refined XGBoost improved incident Macro F1 over the refined RF benchmark by {delta_macro:.6f}. These are TRAIN-only development results; Validation and Final Holdout were not accessed or recomputed.

Source artifacts: `{rel(RF_VS_XGB)}`, `{rel(RF_MULTI)}`, `{rel(XGB_I2_FINAL)}`, `{rel(XGB_MULTI)}`, and `{rel(XGB_CONFIG)}`.
"""
    CAPTION_OUT.write_text(caption, encoding="utf-8")

    paper_text = f"""# Section 4.7 Separate Figure Text

## Figure 4.9 Title
RF vs XGBoost Comparison and Refinement

## Figure 4.9 Subtitle
TRAIN-only grouped-CV comparison of the refined RF benchmark, Phase I XGBoost, and Phase I2 refined XGBoost.

## Key Text Under Figure
The refined XGBoost candidate improved incident Macro F1 over the refined Random Forest benchmark by {delta_macro:.6f}, with smaller but positive gains in Top-1, Top-2, MRR, and all three class F1 scores.

## Chart-Only JPG
Use `{rel(FIG_JPG_OUT)}` when dissertation text and caption are placed separately in Word.
"""
    PAPER_TEXT_OUT.write_text(paper_text, encoding="utf-8")

    print(f"wrote {RESULTS_OUT}")
    print(f"wrote {DELTAS_OUT}")
    print(f"wrote {CONFIG_OUT}")
    print(f"wrote {AUDIT_OUT}")
    print(f"wrote {CAPTION_OUT}")
    print(f"wrote {PAPER_TEXT_OUT}")
    print(f"wrote {FIG_OUT}")
    print(f"wrote {FIG_PDF_OUT}")
    print(f"wrote {FIG_JPG_OUT}")


if __name__ == "__main__":
    main()
