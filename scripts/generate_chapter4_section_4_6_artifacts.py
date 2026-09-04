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

RF_SEARCH = ROOT / "data/modeling/rf_hyperparameter_search_results_v1.csv"
RF_SHORTLIST = ROOT / "data/modeling/rf_hyperparameter_shortlist_v1.csv"
RF_H2_COMPARISON = ROOT / "data/modeling/rf_h2_final_comparison_v1.csv"
RF_MULTI_SEED = ROOT / "data/modeling/rf_multiseed_stability_results_v1.csv"
RF_CONFIG = ROOT / "config/final_model_candidate_v2_1_rf_refined.yaml"
MODEL_RUNTIME = ROOT / "docs/model_runtime_history_v1.csv"

RESULTS_OUT = DOCS / "chapter4_random_forest_optimization_results_v1.csv"
CONFIG_OUT = DOCS / "chapter4_refined_rf_configuration_v1.csv"
AUDIT_OUT = DOCS / "chapter4_section_4_6_evidence_audit_v1.csv"
CAPTION_OUT = DOCS / "chapter4_section_4_6_figure_caption_v1.md"
PAPER_TEXT_OUT = DOCS / "chapter4_section_4_6_paper_figure_text_v1.md"

FIG_OUT = FIGURES / "figure_4_rf_optimization_progression_v1.png"
FIG_PDF_OUT = FIGURES / "figure_4_rf_optimization_progression_v1.pdf"
FIG_JPG_OUT = FIGURES / "figure_4_rf_optimization_progression_v1_highres_chart_only.jpg"

COLORS = {
    "ink": "#17212B",
    "muted": "#5F6B7A",
    "grid": "#D8DEE6",
    "axis": "#9AA6B2",
    "blue": "#2F6F95",
    "green": "#3A9B79",
    "amber": "#D89432",
    "red": "#B94644",
}

EXPECTED_H2_CONFIG = {
    "n_estimators": 1200,
    "max_depth": 40,
    "max_features": 0.3,
    "min_samples_leaf": 6,
    "min_samples_split": 6,
    "bootstrap": False,
    "criterion": "log_loss",
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
            if value == "false":
                params[key] = False
            elif value == "true":
                params[key] = True
            elif value == "null":
                params[key] = None
            else:
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


def model_row(
    *,
    model_stage: str,
    configuration_name: str,
    source_row: dict[str, str],
    macro_f1_field: str,
    std_field: str | None,
    source: Path,
    fit_field: str,
    infer_field: str,
    source_note: str,
) -> dict[str, Any]:
    return {
        "model_stage": model_stage,
        "configuration_name": configuration_name,
        "incident_macro_f1": fmt(source_row[macro_f1_field]),
        "macro_f1_std": fmt(source_row[std_field]) if std_field else "NA",
        "top1_accuracy": fmt(source_row.get("incident_top1") or source_row.get("mean_top1")),
        "top2_accuracy": fmt(source_row.get("incident_top2") or source_row.get("mean_top2")),
        "mrr": fmt(source_row.get("incident_mrr") or source_row.get("mean_mrr")),
        "hijack_f1": fmt(source_row.get("incident_hijack_f1") or source_row.get("hijack_f1_mean")),
        "leak_f1": fmt(source_row.get("incident_leak_f1") or source_row.get("leak_f1_mean")),
        "outage_f1": fmt(source_row.get("incident_outage_f1") or source_row.get("outage_f1_mean")),
        "window_macro_f1": fmt(source_row.get("window_macro_f1") or source_row.get("window_macro_f1_mean")),
        "fit_runtime": fmt(source_row.get(fit_field), 3),
        "inference_runtime": fmt(source_row.get(infer_field), 3),
        "evaluation_scope": "TRAIN-only grouped CV; V4 features; I1 incident-aware weighting; no Validation/Holdout access",
        "source_artifact": f"{rel(source)} ({source_note})",
    }


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


def draw_progression(rows: list[dict[str, Any]]) -> None:
    img = Image.new("RGB", (2400, 1500), "white")
    draw = ImageDraw.Draw(img)
    draw.text((100, 70), "Random Forest Optimization Progression", font=F_TITLE, fill=COLORS["ink"])
    draw_wrapped(
        draw,
        (102, 135),
        "TRAIN-only grouped-CV Random Forest progression from baseline through Phase H tuning and Phase H2 refinement. Error bar shows H2 multi-seed SD.",
        145,
        F_SUB,
        COLORS["muted"],
    )
    draw.line((100, 225, 2300, 225), fill=COLORS["grid"], width=3)

    left, top, right, bottom = 260, 350, 2180, 1120
    ymin, ymax = 0.70, 0.82
    for idx in range(7):
        val = ymin + (ymax - ymin) * idx / 6
        y = bottom - int((val - ymin) / (ymax - ymin) * (bottom - top))
        draw.line((left, y, right, y), fill=COLORS["grid"], width=2)
        draw.text((165, y - 11), f"{val:.2f}", font=F_TINY, fill=COLORS["muted"])
    draw.line((left, top, left, bottom), fill=COLORS["axis"], width=3)
    draw.line((left, bottom, right, bottom), fill=COLORS["axis"], width=3)

    labels = ["Baseline RF", "Phase H\nTuned RF", "Phase H2\nRefined RF"]
    colors = [COLORS["axis"], COLORS["amber"], COLORS["blue"]]
    values = [float(row["incident_macro_f1"]) for row in rows]
    stds = [0.0, 0.0, 0.0 if rows[2]["macro_f1_std"] == "NA" else float(rows[2]["macro_f1_std"])]
    x_gap = (right - left) / len(values)
    bar_w = 250
    for idx, (label, value, std, color) in enumerate(zip(labels, values, stds, colors), start=1):
        x = int(left + x_gap * (idx - 0.5))
        y = bottom - int((value - ymin) / (ymax - ymin) * (bottom - top))
        draw.rounded_rectangle((x - bar_w // 2, y, x + bar_w // 2, bottom), radius=10, fill=color)
        draw.text((x - 82, y - 42), f"{value:.6f}", font=F_BOLD, fill=COLORS["ink"])
        if std:
            err_px = int(std / (ymax - ymin) * (bottom - top))
            draw.line((x, y - err_px, x, y + err_px), fill=COLORS["ink"], width=4)
            draw.line((x - 35, y - err_px, x + 35, y - err_px), fill=COLORS["ink"], width=4)
            draw.line((x - 35, y + err_px, x + 35, y + err_px), fill=COLORS["ink"], width=4)
        draw.multiline_text((x - 110, bottom + 30), label, font=F_SMALL, fill=COLORS["ink"], spacing=5, align="center")

    delta_h = values[1] - values[0]
    delta_h2 = values[2] - values[1]
    draw_wrapped(
        draw,
        (100, 1235),
        f"Phase H improved over the V4/I1 RF baseline by {delta_h:.6f} Macro F1. Phase H2 added only {delta_h2:.6f}, so it is best described as a marginal refinement and RF benchmark, not the final Praxis model.",
        150,
        F_SMALL,
        COLORS["muted"],
    )
    draw.text((100, 1440), f"Sources: {rel(RF_SEARCH)}; {rel(RF_H2_COMPARISON)}", font=F_TINY, fill=COLORS["muted"])
    save_outputs(img, FIG_OUT, FIG_PDF_OUT)


def draw_progression_jpg(rows: list[dict[str, Any]]) -> None:
    img = Image.new("RGB", (3600, 2400), "white")
    draw = ImageDraw.Draw(img)
    left, top, right, bottom = 420, 330, 3340, 1900
    ymin, ymax = 0.70, 0.82
    for idx in range(7):
        val = ymin + (ymax - ymin) * idx / 6
        y = bottom - int((val - ymin) / (ymax - ymin) * (bottom - top))
        draw.line((left, y, right, y), fill=COLORS["grid"], width=3)
        draw.text((250, y - 18), f"{val:.2f}", font=font(28), fill=COLORS["muted"])
    draw.line((left, top, left, bottom), fill=COLORS["axis"], width=5)
    draw.line((left, bottom, right, bottom), fill=COLORS["axis"], width=5)

    labels = ["Baseline RF", "Phase H Tuned RF", "Phase H2 Refined RF"]
    colors = [COLORS["axis"], COLORS["amber"], COLORS["blue"]]
    values = [float(row["incident_macro_f1"]) for row in rows]
    stds = [0.0, 0.0, 0.0 if rows[2]["macro_f1_std"] == "NA" else float(rows[2]["macro_f1_std"])]
    x_gap = (right - left) / len(values)
    bar_w = 380
    for idx, (label, value, std, color) in enumerate(zip(labels, values, stds, colors), start=1):
        x = int(left + x_gap * (idx - 0.5))
        y = bottom - int((value - ymin) / (ymax - ymin) * (bottom - top))
        draw.rounded_rectangle((x - bar_w // 2, y, x + bar_w // 2, bottom), radius=16, fill=color)
        draw.text((x - 120, y - 65), f"{value:.6f}", font=font(34, True), fill=COLORS["ink"])
        if std:
            err_px = int(std / (ymax - ymin) * (bottom - top))
            draw.line((x, y - err_px, x, y + err_px), fill=COLORS["ink"], width=6)
            draw.line((x - 55, y - err_px, x + 55, y - err_px), fill=COLORS["ink"], width=6)
            draw.line((x - 55, y + err_px, x + 55, y + err_px), fill=COLORS["ink"], width=6)
        draw.text((x - 145, bottom + 70), label, font=font(34), fill=COLORS["ink"])
    save_jpg(img, FIG_JPG_OUT)


def main() -> None:
    search_rows = read_csv(RF_SEARCH)
    h2_rows = read_csv(RF_MULTI_SEED)

    baseline = get_row(search_rows, "candidate_id", "RF_BASELINE_V4_I1")
    phase_h = get_row(search_rows, "candidate_id", "RF_SEARCH_023")
    h2 = get_row(h2_rows, "candidate_id", "H2_LOCAL_001")

    results = [
        model_row(
            model_stage="Baseline RF before Phase H",
            configuration_name="RF_BASELINE_V4_I1",
            source_row=baseline,
            macro_f1_field="incident_macro_f1",
            std_field="incident_macro_f1_fold_std",
            source=RF_SEARCH,
            fit_field="fit_time_seconds",
            infer_field="inference_time_seconds",
            source_note="baseline row included in Phase H search",
        ),
        model_row(
            model_stage="Phase H tuned RF",
            configuration_name="RF_SEARCH_023",
            source_row=phase_h,
            macro_f1_field="incident_macro_f1",
            std_field="incident_macro_f1_fold_std",
            source=RF_SEARCH,
            fit_field="fit_time_seconds",
            infer_field="inference_time_seconds",
            source_note="single-seed Phase H winner",
        ),
        model_row(
            model_stage="Phase H2 refined RF",
            configuration_name="RF_REFINED_TRAIN_CANDIDATE / H2_LOCAL_001",
            source_row=h2,
            macro_f1_field="mean_incident_macro_f1",
            std_field="std_incident_macro_f1",
            source=RF_MULTI_SEED,
            fit_field="mean_fit_time_seconds",
            infer_field="mean_inference_time_seconds",
            source_note="multi-seed stability result",
        ),
    ]

    write_csv(
        RESULTS_OUT,
        results,
        [
            "model_stage",
            "configuration_name",
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

    yaml_params = parse_yaml_selected_hyperparameters(RF_CONFIG)
    h2_params = json.loads(h2["parameters_json"])
    config_rows: list[dict[str, Any]] = []
    audit_rows: list[dict[str, Any]] = []
    for key, expected in EXPECTED_H2_CONFIG.items():
        source_value = yaml_params.get(key, h2_params.get(key))
        status = "PASS_MATCHES_PHASE_H2_ARTIFACT" if source_value == expected == h2_params.get(key) else "FAIL_CONFIG_MISMATCH"
        config_rows.append({"hyperparameter": key, "value": source_value, "source_artifact": rel(RF_CONFIG)})
        audit_value(audit_rows, key, source_value, "Phase H2 refined RF configuration", RF_CONFIG, f"selected_hyperparameters.{key}", status)
    class_weight = yaml_params.get("class_weight")
    config_rows.append({"hyperparameter": "class_weight", "value": "null" if class_weight is None else class_weight, "source_artifact": rel(RF_CONFIG)})
    audit_value(audit_rows, "class_weight", "null" if class_weight is None else class_weight, "Phase H2 refined RF configuration", RF_CONFIG, "selected_hyperparameters.class_weight", "PASS_RECORDED_IN_CONFIG")
    write_csv(CONFIG_OUT, config_rows, ["hyperparameter", "value", "source_artifact"])

    stage_sources = [
        ("Baseline RF before Phase H", baseline, RF_SEARCH, "candidate_id=RF_BASELINE_V4_I1", "incident_macro_f1", "incident_macro_f1_fold_std"),
        ("Phase H tuned RF", phase_h, RF_SEARCH, "candidate_id=RF_SEARCH_023", "incident_macro_f1", "incident_macro_f1_fold_std"),
        ("Phase H2 refined RF", h2, RF_MULTI_SEED, "candidate_id=H2_LOCAL_001", "mean_incident_macro_f1", "std_incident_macro_f1"),
    ]
    metric_map = {
        "incident_macro_f1": ("incident_macro_f1", "mean_incident_macro_f1"),
        "macro_f1_std": ("incident_macro_f1_fold_std", "std_incident_macro_f1"),
        "top1_accuracy": ("incident_top1", "mean_top1"),
        "top2_accuracy": ("incident_top2", "mean_top2"),
        "mrr": ("incident_mrr", "mean_mrr"),
        "hijack_f1": ("incident_hijack_f1", "hijack_f1_mean"),
        "leak_f1": ("incident_leak_f1", "leak_f1_mean"),
        "outage_f1": ("incident_outage_f1", "outage_f1_mean"),
        "window_macro_f1": ("window_macro_f1", "window_macro_f1_mean"),
        "fit_runtime_seconds": ("fit_time_seconds", "mean_fit_time_seconds"),
        "inference_runtime_seconds": ("inference_time_seconds", "mean_inference_time_seconds"),
    }
    for stage, row, source, row_note, _macro, _std in stage_sources:
        for metric, fields in metric_map.items():
            field = fields[1] if stage == "Phase H2 refined RF" else fields[0]
            value = row.get(field, "NA")
            audit_value(audit_rows, metric, fmt(value, 6 if "runtime" not in metric else 3), stage, source, f"{row_note}; field={field}")

    expected_user_sd = 0.002309
    h2_artifact_sd = float(h2["std_incident_macro_f1"])
    if abs(h2_artifact_sd - expected_user_sd) > 1e-9:
        audit_value(
            audit_rows,
            "user_supplied_h2_std_anchor",
            f"user={expected_user_sd:.6f}; artifact={h2_artifact_sd:.12f}",
            "Phase H2 refined RF",
            RF_MULTI_SEED,
            "candidate_id=H2_LOCAL_001; field=std_incident_macro_f1",
            "REVIEW_USER_ANCHOR_DIFFERS_FROM_AUTHORITATIVE_ARTIFACT",
        )

    write_csv(
        AUDIT_OUT,
        audit_rows,
        ["metric", "value", "model_stage", "source_file", "source_field_or_row", "authoritative_status"],
    )

    draw_progression(results)
    draw_progression_jpg(results)

    caption = f"""# Section 4.6 Figure Caption

**Figure 4.8. Random Forest optimization and stability results, TRAIN-only grouped cross-validation.** The figure compares the V4/I1 Random Forest baseline, the Phase H tuned Random Forest winner, and the Phase H2 refined Random Forest candidate. Phase H increased incident Macro F1 from {results[0]['incident_macro_f1']} to {results[1]['incident_macro_f1']}. Phase H2 produced a smaller additional increase to {results[2]['incident_macro_f1']} and includes multi-seed stability analysis (artifact SD = {results[2]['macro_f1_std']}). These are development results computed only on the TRAIN partition using grouped cross-validation; Validation and Final Holdout were not accessed or recomputed. The refined RF is the strongest Random Forest benchmark retained for later RF-vs-XGBoost comparison, not the final Praxis model.

Source artifacts: `{rel(RF_SEARCH)}`, `{rel(RF_MULTI_SEED)}`, `{rel(RF_H2_COMPARISON)}`, and `{rel(RF_CONFIG)}`.
"""
    CAPTION_OUT.write_text(caption, encoding="utf-8")

    paper_text = f"""# Section 4.6 Separate Figure Text

## Figure 4.8 Title
Random Forest Optimization Progression

## Figure 4.8 Subtitle
TRAIN-only grouped-CV comparison of the baseline RF, Phase H tuned RF, and Phase H2 refined RF.

## Key Text Under Figure
Phase H produced the main Random Forest gain over the V4/I1 baseline. Phase H2 improved Macro F1 by only {float(results[2]['incident_macro_f1']) - float(results[1]['incident_macro_f1']):.6f}, so the result should be described as a marginal refinement and the strongest RF benchmark, not as the final Praxis model.

## Chart-Only JPG
Use `{rel(FIG_JPG_OUT)}` when dissertation text and caption are placed separately in Word.
"""
    PAPER_TEXT_OUT.write_text(paper_text, encoding="utf-8")

    print(f"wrote {RESULTS_OUT}")
    print(f"wrote {CONFIG_OUT}")
    print(f"wrote {AUDIT_OUT}")
    print(f"wrote {CAPTION_OUT}")
    print(f"wrote {PAPER_TEXT_OUT}")
    print(f"wrote {FIG_OUT}")
    print(f"wrote {FIG_PDF_OUT}")
    print(f"wrote {FIG_JPG_OUT}")


if __name__ == "__main__":
    main()
