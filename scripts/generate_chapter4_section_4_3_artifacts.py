from __future__ import annotations

import csv
import math
import textwrap
from pathlib import Path
from typing import Iterable

from PIL import Image, ImageDraw, ImageFont


ROOT = Path("/Users/biruk/Documents/New project")
VARIANT_SOURCE = ROOT / "data/modeling/feature_variant_ablation_results_v1.csv"
FAMILY_SOURCE = ROOT / "data/modeling/feature_family_ablation_results_v1.csv"
DOCS = ROOT / "docs"
FIGURES = ROOT / "figures/chapter4"

VARIANT_OUT = DOCS / "chapter4_feature_variant_results_v1.csv"
FAMILY_OUT = DOCS / "chapter4_feature_family_ablation_results_v1.csv"
CAPTIONS_OUT = DOCS / "chapter4_section_4_3_figure_captions_v1.md"
AUDIT_OUT = DOCS / "chapter4_section_4_3_evidence_audit_v1.csv"

VARIANT_FIG = FIGURES / "figure_4_feature_variant_progression_v1.png"
VARIANT_FIG_PDF = FIGURES / "figure_4_feature_variant_progression_v1.pdf"
VARIANT_RANKING_FIG = FIGURES / "figure_4_feature_variant_ranking_metrics_v1.png"
VARIANT_RANKING_FIG_PDF = FIGURES / "figure_4_feature_variant_ranking_metrics_v1.pdf"
FAMILY_FIG = FIGURES / "figure_4_feature_family_ablation_v1.png"
FAMILY_FIG_PDF = FIGURES / "figure_4_feature_family_ablation_v1.pdf"
CLASS_IMPACT_FIG = FIGURES / "figure_4_feature_family_class_impact_v1.png"
CLASS_IMPACT_FIG_PDF = FIGURES / "figure_4_feature_family_class_impact_v1.pdf"
VARIANT_FIG_JPG = FIGURES / "figure_4_feature_variant_progression_v1_highres_chart_only.jpg"
FAMILY_FIG_JPG = FIGURES / "figure_4_feature_family_ablation_v1_highres_chart_only.jpg"
CLASS_IMPACT_FIG_JPG = FIGURES / "figure_4_feature_family_class_impact_v1_highres_chart_only.jpg"
PAPER_TEXT_OUT = DOCS / "chapter4_section_4_3_paper_figure_text_v1.md"

EXPECTED_VARIANTS = {
    "V1": {"behavioral_features": 44, "caida_features": 0, "rpki_features": 0, "total_features": 44},
    "V2": {"behavioral_features": 44, "caida_features": 14, "rpki_features": 0, "total_features": 58},
    "V3": {"behavioral_features": 44, "caida_features": 0, "rpki_features": 16, "total_features": 60},
    "V4": {"behavioral_features": 44, "caida_features": 14, "rpki_features": 16, "total_features": 74},
}

COLORS = {
    "ink": "#17212B",
    "muted": "#5F6B7A",
    "grid": "#D8DEE6",
    "axis": "#9AA6B2",
    "blue": "#2F6F95",
    "blue2": "#64A6BD",
    "green": "#3A9B79",
    "amber": "#E8A336",
    "orange": "#D66A3F",
    "red": "#B94644",
    "purple": "#6B5FB5",
    "pale": "#F7F9FB",
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
F_AXIS = font(20)
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


def fnum(value: str | float) -> float:
    return float(value)


def fmt(value: float | str, places: int = 6) -> str:
    if value == "NA":
        return "NA"
    return f"{float(value):.{places}f}"


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def draw_wrapped(draw: ImageDraw.ImageDraw, xy: tuple[int, int], text: str, width: int, font_obj, fill: str, spacing: int = 5) -> int:
    wrapped = "\n".join(textwrap.wrap(text, width=width))
    draw.multiline_text(xy, wrapped, font=font_obj, fill=fill, spacing=spacing)
    bbox = draw.multiline_textbbox(xy, wrapped, font=font_obj, spacing=spacing)
    return bbox[3]


def base_canvas(title: str, subtitle: str) -> tuple[Image.Image, ImageDraw.ImageDraw]:
    img = Image.new("RGB", (2400, 1500), "white")
    draw = ImageDraw.Draw(img)
    draw.text((100, 70), title, font=F_TITLE, fill=COLORS["ink"])
    draw_wrapped(draw, (102, 135), subtitle, 140, F_SUB, COLORS["muted"])
    draw.line((100, 215, 2300, 215), fill=COLORS["grid"], width=3)
    return img, draw


def save_both(img: Image.Image, png: Path, pdf: Path) -> None:
    png.parent.mkdir(parents=True, exist_ok=True)
    img.save(png, "PNG", optimize=True)
    img.save(pdf, "PDF", resolution=200.0)


def save_jpg(img: Image.Image, jpg: Path) -> None:
    jpg.parent.mkdir(parents=True, exist_ok=True)
    img.save(jpg, "JPEG", quality=96, subsampling=0, optimize=True, dpi=(300, 300))


def add_source(draw: ImageDraw.ImageDraw, source: str) -> None:
    draw.text((100, 1440), f"Source: {source}", font=F_TINY, fill=COLORS["muted"])


def bar_chart_variant(rows: list[dict[str, object]]) -> None:
    img, draw = base_canvas(
        "Feature Variant Progression",
        "Incident-level Macro F1 from TRAIN-only grouped cross-validation. V1 = Behavioral; V2 = Behavioral + CAIDA; V3 = Behavioral + RPKI/ROV; V4 = Behavioral + CAIDA + RPKI/ROV.",
    )
    left, top, right, bottom = 220, 350, 2240, 1160
    values = [float(r["incident_macro_f1"]) for r in rows]
    labels = [str(r["variant"]) for r in rows]
    ymin, ymax = 0.0, 0.62
    for step in range(0, 7):
        val = ymax * step / 6
        y = bottom - int((val - ymin) / (ymax - ymin) * (bottom - top))
        draw.line((left, y, right, y), fill=COLORS["grid"], width=2)
        draw.text((145, y - 12), f"{val:.2f}", font=F_TINY, fill=COLORS["muted"])
    draw.line((left, top, left, bottom), fill=COLORS["axis"], width=3)
    draw.line((left, bottom, right, bottom), fill=COLORS["axis"], width=3)
    bar_w = 250
    gap = (right - left - bar_w * 4) / 5
    colors = [COLORS["blue"], COLORS["green"], COLORS["amber"], COLORS["purple"]]
    descriptions = {
        "V1": "Behavioral",
        "V2": "Behavioral\n+ CAIDA",
        "V3": "Behavioral\n+ RPKI/ROV",
        "V4": "Behavioral\n+ CAIDA\n+ RPKI/ROV",
    }
    for i, (label, value) in enumerate(zip(labels, values)):
        x0 = left + gap + i * (bar_w + gap)
        x1 = x0 + bar_w
        y0 = bottom - int((value - ymin) / (ymax - ymin) * (bottom - top))
        draw.rounded_rectangle((x0, y0, x1, bottom), radius=12, fill=colors[i])
        draw.text((x0 + 50, y0 - 42), f"{value:.6f}", font=F_BOLD, fill=COLORS["ink"])
        draw.text((x0 + 100, bottom + 28), label, font=font(26, True), fill=COLORS["ink"])
        draw.multiline_text((x0 + 30, bottom + 70), descriptions[label], font=F_SMALL, fill=COLORS["muted"], spacing=4, align="center")
    draw.text((100, 1270), "Higher Macro F1 indicates better balanced incident-level classification across Hijack, Leak, and Outage.", font=F_SMALL, fill=COLORS["muted"])
    add_source(draw, rel(VARIANT_SOURCE))
    save_both(img, VARIANT_FIG, VARIANT_FIG_PDF)


def grouped_ranking_chart(rows: list[dict[str, object]]) -> None:
    img, draw = base_canvas(
        "Feature Variant Ranking Metrics",
        "TRAIN-only grouped cross-validation ranking metrics for V1-V4. Top-2 and MRR are available in the authoritative artifact; Top-1 was not measured for this experiment.",
    )
    left, top, right, bottom = 210, 350, 2240, 1150
    series = [
        ("Top-2", [float(r["top2_accuracy"]) for r in rows], COLORS["green"]),
        ("MRR", [float(r["mrr"]) for r in rows], COLORS["blue"]),
    ]
    ymax = 1.0
    for step in range(0, 6):
        val = ymax * step / 5
        y = bottom - int(val / ymax * (bottom - top))
        draw.line((left, y, right, y), fill=COLORS["grid"], width=2)
        draw.text((145, y - 12), f"{val:.2f}", font=F_TINY, fill=COLORS["muted"])
    draw.line((left, top, left, bottom), fill=COLORS["axis"], width=3)
    draw.line((left, bottom, right, bottom), fill=COLORS["axis"], width=3)
    group_w = (right - left) / 4
    bar_w = 130
    for gi, row in enumerate(rows):
        gx = left + gi * group_w + 110
        for si, (name, vals, color) in enumerate(series):
            value = vals[gi]
            x0 = gx + si * (bar_w + 30)
            y0 = bottom - int(value / ymax * (bottom - top))
            draw.rounded_rectangle((x0, y0, x0 + bar_w, bottom), radius=10, fill=color)
            draw.text((x0 - 8, y0 - 35), f"{value:.6f}", font=F_TINY, fill=COLORS["ink"])
        draw.text((gx + 60, bottom + 25), str(row["variant"]), font=font(25, True), fill=COLORS["ink"])
    x = 100
    for name, _, color in series:
        draw.rounded_rectangle((x, 1270, x + 42, 1298), radius=5, fill=color)
        draw.text((x + 55, 1266), name, font=F_SMALL, fill=COLORS["ink"])
        x += 220
    add_source(draw, rel(VARIANT_SOURCE))
    save_both(img, VARIANT_RANKING_FIG, VARIANT_RANKING_FIG_PDF)


def horizontal_delta_chart(rows: list[dict[str, object]]) -> None:
    plot_rows = [r for r in rows if r["feature_family"] != "NONE_FULL_V4"]
    plot_rows.sort(key=lambda r: float(r["delta_macro_f1_vs_full_v4"]))
    img, draw = base_canvas(
        "Feature-Family Ablation",
        "Delta Incident Macro F1 versus full V4 under TRAIN-only grouped cross-validation. Negative values mean performance decreased when that feature family was removed.",
    )
    left, top, right, bottom = 760, 300, 2240, 1260
    vals = [float(r["delta_macro_f1_vs_full_v4"]) for r in plot_rows]
    minv = min(vals + [-0.001])
    maxv = max(vals + [0.001])
    pad = max(abs(minv), abs(maxv)) * 0.2
    min_axis, max_axis = minv - pad, maxv + pad
    zero_x = left + int((0 - min_axis) / (max_axis - min_axis) * (right - left))
    draw.line((zero_x, top - 20, zero_x, bottom + 20), fill=COLORS["axis"], width=4)
    n = len(plot_rows)
    row_h = (bottom - top) / n
    for i, r in enumerate(plot_rows):
        y = top + i * row_h + row_h * 0.18
        val = float(r["delta_macro_f1_vs_full_v4"])
        x_val = left + int((val - min_axis) / (max_axis - min_axis) * (right - left))
        color = COLORS["red"] if val < -0.002 else COLORS["green"] if val > 0.002 else COLORS["gray"] if "gray" in COLORS else COLORS["muted"]
        x0, x1 = sorted((zero_x, x_val))
        draw.rounded_rectangle((x0, int(y), x1, int(y + row_h * 0.56)), radius=8, fill=color)
        label = str(r["feature_family"]).replace("_", " ").title()
        draw.text((100, int(y + 5)), label, font=F_SMALL, fill=COLORS["ink"])
        draw.text((x_val + (12 if val >= 0 else -140), int(y + 5)), f"{val:+.6f}", font=F_TINY, fill=COLORS["ink"])
    draw.text((left, 1305), "Sorted by Macro-F1 impact. Larger negative bars provide stronger evidence of useful contribution.", font=F_SMALL, fill=COLORS["muted"])
    add_source(draw, rel(FAMILY_SOURCE))
    save_both(img, FAMILY_FIG, FAMILY_FIG_PDF)


def class_impact_heatmap(rows: list[dict[str, object]]) -> None:
    full = next(r for r in rows if r["feature_family"] == "NONE_FULL_V4")
    plot_rows = [r for r in rows if r["feature_family"] != "NONE_FULL_V4"]
    classes = ["hijack_f1", "leak_f1", "outage_f1"]
    for r in plot_rows:
        r["_max_abs_class_delta"] = max(abs(float(r[c]) - float(full[c])) for c in classes)
    plot_rows.sort(key=lambda r: r["_max_abs_class_delta"], reverse=True)
    img, draw = base_canvas(
        "Class-Specific Feature-Family Impact",
        "Class F1 delta after removing each feature family from full V4. Negative cells indicate the class became harder to classify.",
    )
    left, top = 820, 310
    cell_w, cell_h = 340, 85
    headers = ["Hijack F1 Δ", "Leak F1 Δ", "Outage F1 Δ"]
    for j, header in enumerate(headers):
        draw.text((left + j * cell_w + 60, top - 55), header, font=F_BOLD, fill=COLORS["ink"])
    max_abs = max(abs(float(r[c]) - float(full[c])) for r in plot_rows for c in classes)
    for i, r in enumerate(plot_rows):
        y = top + i * cell_h
        label = str(r["feature_family"]).replace("_", " ").title()
        draw.text((100, y + 25), label, font=F_SMALL, fill=COLORS["ink"])
        for j, c in enumerate(classes):
            delta = float(r[c]) - float(full[c])
            intensity = int(min(1.0, abs(delta) / max_abs) * 105)
            if delta < 0:
                fill = f"#{255:02x}{max(130, 240-intensity):02x}{max(130, 240-intensity):02x}"
            else:
                fill = f"#{max(130, 230-intensity):02x}{255:02x}{max(130, 230-intensity):02x}"
            x = left + j * cell_w
            draw.rectangle((x, y, x + cell_w, y + cell_h), fill=fill, outline=COLORS["grid"], width=2)
            draw.text((x + 105, y + 28), f"{delta:+.6f}", font=F_TINY, fill=COLORS["ink"])
    draw.text((100, 1325), "Use as class-level evidence only; the experiment is TRAIN-only and not a causal proof of feature mechanisms.", font=F_SMALL, fill=COLORS["muted"])
    add_source(draw, rel(FAMILY_SOURCE))
    save_both(img, CLASS_IMPACT_FIG, CLASS_IMPACT_FIG_PDF)


def bar_chart_variant_jpg(rows: list[dict[str, object]]) -> None:
    img = Image.new("RGB", (3600, 2400), "white")
    draw = ImageDraw.Draw(img)
    left, top, right, bottom = 360, 260, 3400, 1900
    values = [float(r["incident_macro_f1"]) for r in rows]
    labels = [str(r["variant"]) for r in rows]
    ymin, ymax = 0.0, 0.62
    for step in range(0, 7):
        val = ymax * step / 6
        y = bottom - int((val - ymin) / (ymax - ymin) * (bottom - top))
        draw.line((left, y, right, y), fill=COLORS["grid"], width=3)
        draw.text((230, y - 16), f"{val:.2f}", font=font(24), fill=COLORS["muted"])
    draw.line((left, top, left, bottom), fill=COLORS["axis"], width=5)
    draw.line((left, bottom, right, bottom), fill=COLORS["axis"], width=5)
    bar_w = 360
    gap = (right - left - bar_w * 4) / 5
    colors = [COLORS["blue"], COLORS["green"], COLORS["amber"], COLORS["purple"]]
    descriptions = {
        "V1": "Behavioral",
        "V2": "Behavioral\n+ CAIDA",
        "V3": "Behavioral\n+ RPKI/ROV",
        "V4": "Behavioral\n+ CAIDA\n+ RPKI/ROV",
    }
    for i, (label, value) in enumerate(zip(labels, values)):
        x0 = left + gap + i * (bar_w + gap)
        x1 = x0 + bar_w
        y0 = bottom - int((value - ymin) / (ymax - ymin) * (bottom - top))
        draw.rounded_rectangle((x0, y0, x1, bottom), radius=16, fill=colors[i])
        draw.text((x0 + 82, y0 - 58), f"{value:.6f}", font=font(30, True), fill=COLORS["ink"])
        draw.text((x0 + 145, bottom + 48), label, font=font(40, True), fill=COLORS["ink"])
        draw.multiline_text((x0 + 35, bottom + 110), descriptions[label], font=font(28), fill=COLORS["muted"], spacing=8, align="center")
    save_jpg(img, VARIANT_FIG_JPG)


def horizontal_delta_chart_jpg(rows: list[dict[str, object]]) -> None:
    plot_rows = [r for r in rows if r["feature_family"] != "NONE_FULL_V4"]
    plot_rows.sort(key=lambda r: float(r["delta_macro_f1_vs_full_v4"]))
    img = Image.new("RGB", (3600, 2400), "white")
    draw = ImageDraw.Draw(img)
    left, top, right, bottom = 1180, 220, 3400, 2180
    vals = [float(r["delta_macro_f1_vs_full_v4"]) for r in plot_rows]
    minv = min(vals + [-0.001])
    maxv = max(vals + [0.001])
    pad = max(abs(minv), abs(maxv)) * 0.2
    min_axis, max_axis = minv - pad, maxv + pad
    zero_x = left + int((0 - min_axis) / (max_axis - min_axis) * (right - left))
    draw.line((zero_x, top - 40, zero_x, bottom + 40), fill=COLORS["axis"], width=6)
    n = len(plot_rows)
    row_h = (bottom - top) / n
    for i, r in enumerate(plot_rows):
        y = top + i * row_h + row_h * 0.18
        val = float(r["delta_macro_f1_vs_full_v4"])
        x_val = left + int((val - min_axis) / (max_axis - min_axis) * (right - left))
        color = COLORS["red"] if val < -0.002 else COLORS["green"] if val > 0.002 else COLORS["muted"]
        x0, x1 = sorted((zero_x, x_val))
        draw.rounded_rectangle((x0, int(y), x1, int(y + row_h * 0.56)), radius=12, fill=color)
        label = str(r["feature_family"]).replace("_", " ").title()
        draw.text((100, int(y + 10)), label, font=font(28), fill=COLORS["ink"])
        value_x = x_val + (18 if val >= 0 else -205)
        draw.text((value_x, int(y + 12)), f"{val:+.6f}", font=font(23), fill=COLORS["ink"])
    save_jpg(img, FAMILY_FIG_JPG)


def class_impact_heatmap_jpg(rows: list[dict[str, object]]) -> None:
    full = next(r for r in rows if r["feature_family"] == "NONE_FULL_V4")
    plot_rows = [r for r in rows if r["feature_family"] != "NONE_FULL_V4"]
    classes = ["hijack_f1", "leak_f1", "outage_f1"]
    for r in plot_rows:
        r["_max_abs_class_delta"] = max(abs(float(r[c]) - float(full[c])) for c in classes)
    plot_rows.sort(key=lambda r: r["_max_abs_class_delta"], reverse=True)
    img = Image.new("RGB", (3600, 2400), "white")
    draw = ImageDraw.Draw(img)
    left, top = 1250, 250
    cell_w, cell_h = 540, 180
    headers = ["Hijack F1 Delta", "Leak F1 Delta", "Outage F1 Delta"]
    for j, header in enumerate(headers):
        draw.text((left + j * cell_w + 105, top - 82), header, font=font(32, True), fill=COLORS["ink"])
    max_abs = max(abs(float(r[c]) - float(full[c])) for r in plot_rows for c in classes)
    for i, r in enumerate(plot_rows):
        y = top + i * cell_h
        label = str(r["feature_family"]).replace("_", " ").title()
        draw.text((100, y + 65), label, font=font(29), fill=COLORS["ink"])
        for j, c in enumerate(classes):
            delta = float(r[c]) - float(full[c])
            intensity = int(min(1.0, abs(delta) / max_abs) * 105)
            if delta < 0:
                fill = f"#{255:02x}{max(130, 240-intensity):02x}{max(130, 240-intensity):02x}"
            else:
                fill = f"#{max(130, 230-intensity):02x}{255:02x}{max(130, 230-intensity):02x}"
            x = left + j * cell_w
            draw.rectangle((x, y, x + cell_w, y + cell_h), fill=fill, outline=COLORS["grid"], width=3)
            draw.text((x + 185, y + 70), f"{delta:+.6f}", font=font(25), fill=COLORS["ink"])
    save_jpg(img, CLASS_IMPACT_FIG_JPG)


def build_variant_rows() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    rows = read_csv(VARIANT_SOURCE)
    selected = [r for r in rows if r["model"] == "RF_HIER" and r["imbalance_condition"] == "I1"]
    selected_by_variant = {r["feature_variant"]: r for r in selected}
    out: list[dict[str, object]] = []
    audit: list[dict[str, object]] = []
    for variant in ["V1", "V2", "V3", "V4"]:
        src = selected_by_variant[variant]
        expected = EXPECTED_VARIANTS[variant]
        if int(src["feature_count"]) != expected["total_features"]:
            raise RuntimeError(f"{variant} feature count mismatch")
        row = {
            "variant": variant,
            "behavioral_features": expected["behavioral_features"],
            "caida_features": expected["caida_features"],
            "rpki_features": expected["rpki_features"],
            "total_features": expected["total_features"],
            "incident_macro_f1": fmt(src["group_macro_f1"]),
            "top1_accuracy": "NA",
            "top2_accuracy": fmt(src["top2_accuracy"]),
            "mrr": fmt(src["mrr"]),
            "hijack_f1": fmt(src["hijack_f1"]),
            "leak_f1": fmt(src["leak_f1"]),
            "outage_f1": fmt(src["outage_f1"]),
            "evaluation_scope": "TRAIN-only incident-level grouped CV; RF_HIER; I1 imbalance condition",
            "source_artifact": rel(VARIANT_SOURCE),
        }
        out.append(row)
        for metric in ["total_features", "incident_macro_f1", "top2_accuracy", "mrr", "hijack_f1", "leak_f1", "outage_f1"]:
            source_field = "feature_count" if metric == "total_features" else {
                "incident_macro_f1": "group_macro_f1",
                "top2_accuracy": "top2_accuracy",
                "mrr": "mrr",
                "hijack_f1": "hijack_f1",
                "leak_f1": "leak_f1",
                "outage_f1": "outage_f1",
            }[metric]
            audit.append({
                "metric": metric,
                "value": row[metric],
                "experiment": f"Feature variant {variant}",
                "source_file": rel(VARIANT_SOURCE),
                "source_field_or_row": f"model=RF_HIER; feature_variant={variant}; field={source_field}",
                "authoritative_status": "PASS_AUTHORITATIVE_TRAIN_ONLY",
            })
        audit.append({
            "metric": "top1_accuracy",
            "value": "NA",
            "experiment": f"Feature variant {variant}",
            "source_file": rel(VARIANT_SOURCE),
            "source_field_or_row": "No top1_accuracy field in authoritative V1-V4 ablation artifact",
            "authoritative_status": "PASS_NOT_MEASURED_LEFT_NA",
        })
    return out, audit


def interpret_delta(delta: float) -> str:
    if delta <= -0.015:
        return "Large decrease versus full V4; strong evidence this family contributed useful predictive signal."
    if delta <= -0.005:
        return "Moderate decrease versus full V4; evidence of useful contribution."
    if delta < -0.001:
        return "Small decrease versus full V4; contribution appears limited or partly redundant."
    if delta <= 0.001:
        return "Near-zero change versus full V4; no clear incremental effect in this experiment."
    return "Positive delta versus full V4; family may be redundant under this RF_HIER/I1 setup."


def build_family_rows() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    rows = read_csv(FAMILY_SOURCE)
    selected = [r for r in rows if r["model"] == "RF_HIER" and r["imbalance_condition"] == "I1"]
    full = next(r for r in selected if r["removed_family"] == "NONE_FULL_V4")
    full_macro = fnum(full["group_macro_f1"])
    out: list[dict[str, object]] = []
    audit: list[dict[str, object]] = []
    for src in selected:
        remaining = int(src["feature_count"])
        removed = 74 - remaining
        delta = fnum(src["group_macro_f1"]) - full_macro
        row = {
            "feature_family": src["removed_family"],
            "features_removed": 0 if src["removed_family"] == "NONE_FULL_V4" else removed,
            "remaining_feature_count": remaining,
            "incident_macro_f1": fmt(src["group_macro_f1"]),
            "delta_macro_f1_vs_full_v4": fmt(delta),
            "top1_accuracy": "NA",
            "top2_accuracy": fmt(src["top2_accuracy"]),
            "mrr": fmt(src["mrr"]),
            "hijack_f1": fmt(src["hijack_f1"]),
            "leak_f1": fmt(src["leak_f1"]),
            "outage_f1": fmt(src["outage_f1"]),
            "interpretation": "Full V4 reference row." if src["removed_family"] == "NONE_FULL_V4" else interpret_delta(delta),
            "source_artifact": rel(FAMILY_SOURCE),
        }
        out.append(row)
        for metric in ["remaining_feature_count", "incident_macro_f1", "delta_macro_f1_vs_full_v4", "top2_accuracy", "mrr", "hijack_f1", "leak_f1", "outage_f1"]:
            audit.append({
                "metric": metric,
                "value": row[metric],
                "experiment": f"Feature-family ablation {src['removed_family']}",
                "source_file": rel(FAMILY_SOURCE),
                "source_field_or_row": f"model=RF_HIER; removed_family={src['removed_family']}; field={metric}",
                "authoritative_status": "PASS_AUTHORITATIVE_TRAIN_ONLY",
            })
        audit.append({
            "metric": "top1_accuracy",
            "value": "NA",
            "experiment": f"Feature-family ablation {src['removed_family']}",
            "source_file": rel(FAMILY_SOURCE),
            "source_field_or_row": "No top1_accuracy field in authoritative feature-family ablation artifact",
            "authoritative_status": "PASS_NOT_MEASURED_LEFT_NA",
        })
    out.sort(key=lambda r: (r["feature_family"] != "NONE_FULL_V4", float(r["delta_macro_f1_vs_full_v4"])))
    return out, audit


def write_captions() -> None:
    text = f"""# Section 4.3 Figure Captions v1

## Figure 4.x Feature Variant Progression

This figure reports incident-level Macro F1 for the frozen V1-V4 feature variants using the authoritative TRAIN-only grouped cross-validation artifact. V1 contains 44 Behavioral BGP features, V2 adds 14 CAIDA AS-relationship features, V3 adds 16 RPKI/ROV features, and V4 combines all three families for 74 total features. Higher Macro F1 indicates better balanced incident-level classification across Hijack, Leak, and Outage. These comparisons were used during TRAIN-only feature development; Validation and Final Holdout results were not used for feature selection.

## Figure 4.x Feature Variant Ranking Metrics

This figure reports Top-2 accuracy and mean reciprocal rank for the same frozen V1-V4 TRAIN-only grouped cross-validation comparison. Top-2 measures whether the true incident class appears among the two highest-ranked classes. MRR rewards placing the true class closer to rank 1. Top-1 was not measured in the authoritative V1-V4 ablation artifact and is therefore excluded rather than estimated.

## Figure 4.x Feature-Family Ablation

This figure reports the change in incident-level Macro F1 after removing each feature family from the full V4 representation under TRAIN-only grouped cross-validation. The delta is calculated as the ablated model Macro F1 minus the full V4 Macro F1. Negative values mean performance decreased after removing the family; larger negative values provide stronger predictive evidence that the removed feature family contributed useful information. Near-zero or positive values indicate redundancy or limited incremental contribution in this specific RF_HIER/I1 experiment.

## Figure 4.x Class-Specific Feature-Family Impact

This heatmap reports class-specific F1 deltas for Hijack, Leak, and Outage after removing each feature family from full V4. Negative cells indicate that the class became harder to classify when that feature family was removed. This figure is supported because the authoritative feature-family ablation artifact contains Hijack, Leak, and Outage F1 for every ablation row. The interpretation is predictive rather than causal: the figure shows measured classification sensitivity, not proof that a feature family caused a real-world incident.

## Evidence Boundary

All Section 4.3 figures are based on existing TRAIN-only artifacts:

- `{rel(VARIANT_SOURCE)}`
- `{rel(FAMILY_SOURCE)}`

No model was retrained. Validation was not recomputed or used. Final Holdout was not recomputed or used.
"""
    CAPTIONS_OUT.write_text(text, encoding="utf-8")


def write_paper_figure_text() -> None:
    text = f"""# Section 4.3 Paper Figure Text v1

These text blocks are separated from the high-resolution chart-only JPG figures so the dissertation document can control headings, captions, spacing, and source notes directly.

## Figure 4.x Feature Variant Progression

Title: Feature Variant Progression

Subtitle: Incident-level Macro F1 from TRAIN-only grouped cross-validation. V1 = Behavioral; V2 = Behavioral + CAIDA; V3 = Behavioral + RPKI/ROV; V4 = Behavioral + CAIDA + RPKI/ROV.

Under-figure note: Higher Macro F1 indicates better balanced incident-level classification across Hijack, Leak, and Outage.

Caption: This figure compares the frozen V1-V4 feature variants during TRAIN-only grouped cross-validation. V3 achieved the highest Macro F1 in this experiment, while V4 retained the complete 74-feature representation and strongest overall ranking/per-class balance used by the later pipeline.

Source: `{rel(VARIANT_SOURCE)}`

Image: `{rel(VARIANT_FIG_JPG)}`

## Figure 4.x Feature-Family Ablation

Title: Feature-Family Ablation

Subtitle: Delta Incident Macro F1 versus full V4 under TRAIN-only grouped cross-validation. Negative values mean performance decreased when that feature family was removed.

Under-figure note: Sorted by Macro-F1 impact. Larger negative bars provide stronger evidence of useful predictive contribution in this experiment.

Caption: This figure reports the change in incident-level Macro F1 after removing each feature family from the full V4 representation. RPKI/ROV removal produced the largest Macro-F1 decrease, indicating the strongest measured contribution among the tested feature families.

Source: `{rel(FAMILY_SOURCE)}`

Image: `{rel(FAMILY_FIG_JPG)}`

## Figure 4.x Class-Specific Feature-Family Impact

Title: Class-Specific Feature-Family Impact

Subtitle: Class F1 delta after removing each feature family from full V4. Negative cells indicate the class became harder to classify.

Under-figure note: Use as class-level evidence only; the experiment is TRAIN-only and not a causal proof of feature mechanisms.

Caption: This heatmap shows class-level sensitivity to feature-family removal. RPKI/ROV most affected Hijack F1, peer visibility most affected Leak F1, and CAIDA AS-relationship removal most affected Outage F1 in this TRAIN-only ablation.

Source: `{rel(FAMILY_SOURCE)}`

Image: `{rel(CLASS_IMPACT_FIG_JPG)}`
"""
    PAPER_TEXT_OUT.write_text(text, encoding="utf-8")


def validate_no_forbidden_sources(audit_rows: Iterable[dict[str, object]]) -> None:
    forbidden = ("validation", "final_holdout", "holdout")
    for row in audit_rows:
        source = str(row["source_file"]).lower()
        if any(term in source for term in forbidden):
            raise RuntimeError(f"Forbidden source used for Section 4.3: {source}")


def main() -> None:
    DOCS.mkdir(exist_ok=True)
    FIGURES.mkdir(parents=True, exist_ok=True)

    variant_rows, variant_audit = build_variant_rows()
    family_rows, family_audit = build_family_rows()
    audit_rows = variant_audit + family_audit
    validate_no_forbidden_sources(audit_rows)

    write_csv(
        VARIANT_OUT,
        variant_rows,
        [
            "variant",
            "behavioral_features",
            "caida_features",
            "rpki_features",
            "total_features",
            "incident_macro_f1",
            "top1_accuracy",
            "top2_accuracy",
            "mrr",
            "hijack_f1",
            "leak_f1",
            "outage_f1",
            "evaluation_scope",
            "source_artifact",
        ],
    )
    write_csv(
        FAMILY_OUT,
        family_rows,
        [
            "feature_family",
            "features_removed",
            "remaining_feature_count",
            "incident_macro_f1",
            "delta_macro_f1_vs_full_v4",
            "top1_accuracy",
            "top2_accuracy",
            "mrr",
            "hijack_f1",
            "leak_f1",
            "outage_f1",
            "interpretation",
            "source_artifact",
        ],
    )
    write_csv(
        AUDIT_OUT,
        audit_rows,
        ["metric", "value", "experiment", "source_file", "source_field_or_row", "authoritative_status"],
    )
    write_captions()
    write_paper_figure_text()
    bar_chart_variant(variant_rows)
    grouped_ranking_chart(variant_rows)
    horizontal_delta_chart(family_rows)
    class_impact_heatmap(family_rows)
    bar_chart_variant_jpg(variant_rows)
    horizontal_delta_chart_jpg(family_rows)
    class_impact_heatmap_jpg(family_rows)

    outputs = [VARIANT_OUT, FAMILY_OUT, CAPTIONS_OUT, PAPER_TEXT_OUT, AUDIT_OUT, VARIANT_FIG, VARIANT_FIG_PDF, VARIANT_RANKING_FIG, VARIANT_RANKING_FIG_PDF, FAMILY_FIG, FAMILY_FIG_PDF, CLASS_IMPACT_FIG, CLASS_IMPACT_FIG_PDF, VARIANT_FIG_JPG, FAMILY_FIG_JPG, CLASS_IMPACT_FIG_JPG]
    for path in outputs:
        print(path)


if __name__ == "__main__":
    main()
