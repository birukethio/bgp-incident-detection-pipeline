from __future__ import annotations

import csv
import math
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path("/Users/biruk/Documents/New project")
OUT_DIR = ROOT / "figures" / "chapter4"
INDEX_PATH = OUT_DIR / "chapter4_figure_pack_v1.csv"


COLORS = {
    "navy": "#133C55",
    "blue": "#2E6F95",
    "sky": "#9FD3E8",
    "teal": "#2A9D8F",
    "green": "#57A773",
    "amber": "#E9A03A",
    "orange": "#E76F51",
    "red": "#C44536",
    "purple": "#725AC1",
    "gray": "#6B7280",
    "light": "#F6F8FA",
    "line": "#D5DCE3",
    "ink": "#18212B",
}


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    candidates = [
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/System/Library/Fonts/Supplemental/Times New Roman Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Times New Roman.ttf",
        "/Library/Fonts/Arial Bold.ttf" if bold else "/Library/Fonts/Arial.ttf",
    ]
    for candidate in candidates:
        if Path(candidate).exists():
            return ImageFont.truetype(candidate, size)
    return ImageFont.load_default()


F_TITLE = font(46, True)
F_SUB = font(25)
F_AXIS = font(22)
F_SMALL = font(19)
F_TINY = font(16)
F_BOLD = font(22, True)


def read_csv(path: str) -> list[dict[str, str]]:
    with (ROOT / path).open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def canvas(title: str, subtitle: str = "", size=(2400, 1500)) -> tuple[Image.Image, ImageDraw.ImageDraw]:
    img = Image.new("RGB", size, "white")
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, size[0], 118], fill=COLORS["navy"])
    d.text((90, 35), title, font=F_TITLE, fill="white")
    if subtitle:
        d.text((92, 130), subtitle, font=F_SUB, fill=COLORS["gray"])
    return img, d


def save(img: Image.Image, name: str) -> Path:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / name
    img.save(path, "PNG", optimize=True)
    return path


def wrap(text: str, width: int = 28) -> str:
    return "\n".join(textwrap.wrap(str(text), width=width))


def draw_source(d: ImageDraw.ImageDraw, source: str, y: int = 1440) -> None:
    d.text((90, y), f"Source artifact: {source}", font=F_TINY, fill=COLORS["gray"])


def bar_chart(
    title: str,
    subtitle: str,
    labels: list[str],
    values: list[float],
    out_name: str,
    source: str,
    colors: list[str] | None = None,
    value_fmt: str = "{:.3f}",
    y_max: float | None = None,
    notes: list[str] | None = None,
) -> Path:
    img, d = canvas(title, subtitle)
    left, top, right, bottom = 170, 300, 2220, 1180
    y_max = y_max or max(values) * 1.12
    y_min = 0
    d.line([left, bottom, right, bottom], fill=COLORS["line"], width=3)
    d.line([left, top, left, bottom], fill=COLORS["line"], width=3)
    for step in range(0, 6):
        val = y_max * step / 5
        y = bottom - int((val - y_min) / (y_max - y_min) * (bottom - top))
        d.line([left, y, right, y], fill="#EDF1F5", width=2)
        d.text((85, y - 12), f"{val:.2f}", font=F_TINY, fill=COLORS["gray"])
    n = len(values)
    gap = 24
    bar_w = max(55, int((right - left - gap * (n + 1)) / n))
    colors = colors or [COLORS["blue"]] * n
    for i, (label, value) in enumerate(zip(labels, values)):
        x0 = left + gap + i * (bar_w + gap)
        x1 = x0 + bar_w
        y1 = bottom
        y0 = bottom - int((value - y_min) / (y_max - y_min) * (bottom - top))
        d.rounded_rectangle([x0, y0, x1, y1], radius=10, fill=colors[i % len(colors)])
        d.text((x0 + 4, y0 - 38), value_fmt.format(value), font=F_SMALL, fill=COLORS["ink"])
        d.multiline_text((x0, bottom + 22), wrap(label, 15), font=F_TINY, fill=COLORS["ink"], spacing=4, align="center")
    if notes:
        y = 1250
        for note in notes:
            d.text((90, y), note, font=F_SMALL, fill=COLORS["gray"])
            y += 32
    draw_source(d, source)
    return save(img, out_name)


def grouped_bar_chart(title: str, subtitle: str, groups: list[str], series: dict[str, list[float]], out_name: str, source: str) -> Path:
    img, d = canvas(title, subtitle)
    left, top, right, bottom = 160, 310, 2220, 1160
    maxv = max(max(v) for v in series.values()) * 1.12
    d.line([left, bottom, right, bottom], fill=COLORS["line"], width=3)
    d.line([left, top, left, bottom], fill=COLORS["line"], width=3)
    for step in range(6):
        val = maxv * step / 5
        y = bottom - int(val / maxv * (bottom - top))
        d.line([left, y, right, y], fill="#EDF1F5", width=2)
        d.text((80, y - 12), f"{val:.2f}", font=F_TINY, fill=COLORS["gray"])
    palette = [COLORS["blue"], COLORS["amber"], COLORS["teal"], COLORS["purple"]]
    group_w = (right - left) / len(groups)
    keys = list(series)
    bar_w = min(70, int((group_w - 45) / len(keys)))
    for gi, g in enumerate(groups):
        gx = left + gi * group_w + 24
        for si, key in enumerate(keys):
            value = series[key][gi]
            x0 = gx + si * (bar_w + 8)
            x1 = x0 + bar_w
            y0 = bottom - int(value / maxv * (bottom - top))
            d.rounded_rectangle([x0, y0, x1, bottom], radius=8, fill=palette[si])
            d.text((x0 - 4, y0 - 30), f"{value:.2f}", font=F_TINY, fill=COLORS["ink"])
        d.multiline_text((gx - 5, bottom + 20), wrap(g, 16), font=F_TINY, fill=COLORS["ink"], spacing=3)
    lx = 90
    for si, key in enumerate(keys):
        d.rounded_rectangle([lx, 1235, lx + 34, 1260], radius=4, fill=palette[si])
        d.text((lx + 45, 1232), key, font=F_SMALL, fill=COLORS["ink"])
        lx += 310
    draw_source(d, source)
    return save(img, out_name)


def line_chart(title: str, subtitle: str, labels: list[str], values: list[float], out_name: str, source: str) -> Path:
    img, d = canvas(title, subtitle)
    left, top, right, bottom = 170, 300, 2220, 1160
    ymin = min(values) - 0.04
    ymax = max(values) + 0.04
    d.line([left, bottom, right, bottom], fill=COLORS["line"], width=3)
    d.line([left, top, left, bottom], fill=COLORS["line"], width=3)
    for step in range(6):
        val = ymin + (ymax - ymin) * step / 5
        y = bottom - int((val - ymin) / (ymax - ymin) * (bottom - top))
        d.line([left, y, right, y], fill="#EDF1F5", width=2)
        d.text((80, y - 12), f"{val:.2f}", font=F_TINY, fill=COLORS["gray"])
    pts = []
    for i, value in enumerate(values):
        x = left + int(i / (len(values) - 1) * (right - left))
        y = bottom - int((value - ymin) / (ymax - ymin) * (bottom - top))
        pts.append((x, y))
    d.line(pts, fill=COLORS["orange"], width=7)
    for (x, y), label, value in zip(pts, labels, values):
        d.ellipse([x - 12, y - 12, x + 12, y + 12], fill=COLORS["navy"])
        d.text((x - 48, y - 48), f"{value:.3f}", font=F_TINY, fill=COLORS["ink"])
        d.multiline_text((x - 72, bottom + 24), wrap(label, 15), font=F_TINY, fill=COLORS["ink"], spacing=3, align="center")
    draw_source(d, source)
    return save(img, out_name)


def confusion_matrix() -> Path:
    rows = read_csv("data/final_holdout/final_holdout_confusion_matrix_v1.csv")
    classes = ["HIJACK", "LEAK", "OUTAGE"]
    m = {(r["true_class"], r["predicted_class"]): int(r["count"]) for r in rows}
    img, d = canvas(
        "Final Holdout Confusion Matrix",
        "Terminal K1 evaluation on 213 untouched incidents; diagonal cells are correct classifications.",
    )
    left, top, cell = 520, 330, 310
    maxv = max(m.values())
    d.text((left + cell, 255), "Predicted class", font=F_BOLD, fill=COLORS["ink"])
    d.text((180, top + cell), "True class", font=F_BOLD, fill=COLORS["ink"])
    for i, c in enumerate(classes):
        d.text((left + (i + 1) * cell + 70, top - 55), c.title(), font=F_BOLD, fill=COLORS["ink"])
        d.text((left - 175, top + i * cell + 120), c.title(), font=F_BOLD, fill=COLORS["ink"])
    for i, t in enumerate(classes):
        for j, pred in enumerate(classes):
            val = m.get((t, pred), 0)
            intensity = int(245 - (val / maxv) * 150)
            if i == j:
                fill = f"#{intensity:02x}{min(255, intensity+20):02x}{255:02x}"
            else:
                off = max(230, 255 - val * 8)
                fill = f"#{255:02x}{off:02x}{off:02x}"
            x0, y0 = left + (j + 1) * cell, top + i * cell
            d.rectangle([x0, y0, x0 + cell, y0 + cell], fill=fill, outline=COLORS["line"], width=4)
            d.text((x0 + 120, y0 + 105), str(val), font=font(56, True), fill=COLORS["ink"])
    d.text((90, 1280), "Main residual confusion: Hijack vs Leak. Outage has the strongest separation.", font=F_SUB, fill=COLORS["gray"])
    draw_source(d, "data/final_holdout/final_holdout_confusion_matrix_v1.csv")
    return save(img, "figure_ch4_final_holdout_confusion_matrix_v1.png")


def feature_composition() -> Path:
    img, d = canvas("Frozen V4 Feature Composition", "The final model-ready representation contains 74 features.")
    vals = [44, 14, 16]
    labels = ["Behavioral BGP", "CAIDA AS relationship", "RPKI/ROV"]
    colors = [COLORS["blue"], COLORS["teal"], COLORS["amber"]]
    total = sum(vals)
    cx, cy, r = 720, 760, 360
    start = -90
    for val, color in zip(vals, colors):
        extent = val / total * 360
        d.pieslice([cx - r, cy - r, cx + r, cy + r], start, start + extent, fill=color, outline="white", width=5)
        start += extent
    d.ellipse([cx - 170, cy - 170, cx + 170, cy + 170], fill="white", outline="white")
    d.text((cx - 65, cy - 50), "74", font=font(72, True), fill=COLORS["navy"])
    d.text((cx - 110, cy + 28), "V4 features", font=F_SMALL, fill=COLORS["gray"])
    y = 470
    for label, val, color in zip(labels, vals, colors):
        d.rounded_rectangle([1280, y, 1330, y + 36], radius=6, fill=color)
        d.text((1360, y - 2), f"{label}: {val}", font=F_SUB, fill=COLORS["ink"])
        y += 110
    d.text((1280, y + 40), "V4 = Behavioral + CAIDA + RPKI/ROV", font=F_BOLD, fill=COLORS["navy"])
    d.text((1280, y + 90), "This feature count replaces the older 49-feature narrative.", font=F_SMALL, fill=COLORS["gray"])
    draw_source(d, "config/feature_variants_v1.yaml; docs/authoritative_numbers_register_v1.csv")
    return save(img, "figure_ch4_v4_feature_composition_v1.png")


def ranking_distribution() -> Path:
    rows = read_csv("data/final_holdout/final_holdout_ranking_metrics_v1.csv")
    vals = {r["metric"]: float(r["value"]) for r in rows}
    labels = ["Rank 1", "Rank 2", "Rank 3"]
    values = [vals["ranked_first_count"], vals["ranked_second_count"], vals["ranked_third_count"]]
    return bar_chart(
        "Final Holdout Ranking Distribution",
        "The true class was ranked in the Top-2 for 211 of 213 untouched holdout incidents.",
        labels,
        values,
        "figure_ch4_final_holdout_ranking_distribution_v1.png",
        "data/final_holdout/final_holdout_ranking_metrics_v1.csv",
        [COLORS["green"], COLORS["amber"], COLORS["red"]],
        "{:.0f}",
        y_max=213,
    )


def generate_all() -> list[dict[str, str]]:
    outputs: list[dict[str, str]] = []

    perf = read_csv("docs/model_performance_progression_v1.csv")
    outputs.append({
        "figure_file": str(bar_chart(
            "Model Performance Progression",
            "Incident Macro F1 across the final experimental path, from RF baseline to terminal Final Holdout.",
            [r["stage"] for r in perf],
            [float(str(r["incident_macro_f1"]).split()[0]) for r in perf],
            "figure_ch4_model_performance_progression_v1.png",
            "docs/model_performance_progression_v1.csv",
            [COLORS["gray"], COLORS["blue"], COLORS["blue"], COLORS["purple"], COLORS["teal"], COLORS["teal"], COLORS["teal"], COLORS["green"]],
            "{:.3f}",
            y_max=1.0,
        )),
        "chapter4_use": "Overview / model progression",
        "caption": "Incident Macro F1 improved from the behavioral Random Forest baseline through XGBoost and K1 stacking, with the final sealed Holdout result remaining close to the fixed TRAIN reference.",
    })

    fv = [r for r in read_csv("data/modeling/feature_variant_ablation_results_v1.csv") if r["model"] == "RF_HIER"]
    outputs.append({
        "figure_file": str(grouped_bar_chart(
            "V1-V4 Feature Variant Ablation",
            "Grouped TRAIN evidence showing how feature variants changed class-level F1 under the RF hierarchy baseline.",
            [r["feature_variant"] for r in fv],
            {
                "Hijack F1": [float(r["hijack_f1"]) for r in fv],
                "Leak F1": [float(r["leak_f1"]) for r in fv],
                "Outage F1": [float(r["outage_f1"]) for r in fv],
            },
            "figure_ch4_feature_variant_ablation_v1.png",
            "data/modeling/feature_variant_ablation_results_v1.csv",
        )),
        "chapter4_use": "Feature variant ablation",
        "caption": "Feature variant ablation separates behavioral-only evidence from CAIDA and RPKI/ROV enrichment effects before the later XGBoost and K1 phases.",
    })

    fam = read_csv("data/modeling/feature_family_ablation_results_v1.csv")
    full = next(r for r in fam if r["removed_family"] == "NONE_FULL_V4")
    families = [r for r in fam if r["removed_family"] not in {"NONE_FULL_V4"}]
    families = sorted(families, key=lambda r: float(full["group_macro_f1"]) - float(r["group_macro_f1"]), reverse=True)[:8]
    drops = [float(full["group_macro_f1"]) - float(r["group_macro_f1"]) for r in families]
    outputs.append({
        "figure_file": str(bar_chart(
            "Feature-Family Removal Sensitivity",
            "Drop in grouped incident Macro F1 after removing one feature family from V4; larger bars indicate greater sensitivity.",
            [r["removed_family"].replace("_", " ").title() for r in families],
            drops,
            "figure_ch4_feature_family_removal_sensitivity_v1.png",
            "data/modeling/feature_family_ablation_results_v1.csv",
            [COLORS["orange"]] * len(drops),
            "{:.3f}",
            y_max=max(drops) * 1.25 if drops else 0.05,
        )),
        "chapter4_use": "Feature-family ablation",
        "caption": "Feature-family removal highlights which groups most affected grouped Macro F1 in the controlled TRAIN-only ablation.",
    })

    rf_xgb = read_csv("data/modeling/rf_vs_xgboost_comparison_v1.csv")
    outputs.append({
        "figure_file": str(grouped_bar_chart(
            "Refined Random Forest vs XGBoost",
            "TRAIN grouped-CV comparator used before Phase J; XGBoost became the stronger candidate.",
            [r["algorithm"] for r in rf_xgb],
            {
                "Macro F1": [float(r["incident_macro_f1"]) for r in rf_xgb],
                "Top-1": [float(r["top1"]) for r in rf_xgb],
                "Top-2": [float(r["top2"]) for r in rf_xgb],
                "MRR": [float(r["mrr"]) for r in rf_xgb],
            },
            "figure_ch4_refined_rf_vs_xgboost_v1.png",
            "data/modeling/rf_vs_xgboost_comparison_v1.csv",
        )),
        "chapter4_use": "RF vs XGBoost",
        "caption": "Refined XGBoost improved Macro F1, Top-1, Top-2, and MRR relative to the refined Random Forest benchmark under the selected TRAIN-only comparison.",
    })

    k1 = read_csv("data/modeling_k1/k1_model_results_v1.csv")
    chosen = [r for r in k1 if r["candidate_id"] in {"K1-B0_MEAN_PROBABILITY", "K1-M2_XGB_K1-TEMPORAL", "K1-M2_XGB_K1-SIMPLE", "K1-M1_LOGISTIC_K1-TEMPORAL"}]
    outputs.append({
        "figure_file": str(bar_chart(
            "K1 Incident-Level Stacking Gain",
            "Incident Macro F1 for mean probability aggregation and K1 meta-model variants.",
            [r["candidate_id"].replace("K1-", "").replace("_", "\n") for r in chosen],
            [float(r["incident_macro_f1"]) for r in chosen],
            "figure_ch4_k1_stacking_gain_v1.png",
            "data/modeling_k1/k1_model_results_v1.csv",
            [COLORS["gray"], COLORS["teal"], COLORS["blue"], COLORS["purple"]],
            "{:.3f}",
            y_max=1.0,
            notes=["K1 was developed after Phase J using TRAIN only; it was not evaluated on Validation."],
        )),
        "chapter4_use": "K1 mean aggregation vs stacker",
        "caption": "K1 temporal stacking materially improved incident-level classification over simple mean probability aggregation in the TRAIN-only K1 experiment.",
    })

    k2 = read_csv("data/modeling_k2/k2_multiseed_performance_v1.csv")
    metrics = ["incident_macro_f1", "top1", "top2", "mrr"]
    vals = [float(next(r for r in k2 if r["metric"] == m)["mean"]) for m in metrics]
    stds = [float(next(r for r in k2 if r["metric"] == m)["std"]) for m in metrics]
    outputs.append({
        "figure_file": str(bar_chart(
            "K2 Multi-Seed Stability",
            "Mean metric values across K1 seed checks; labels show standard deviation.",
            ["Macro F1", "Top-1", "Top-2", "MRR"],
            vals,
            "figure_ch4_k2_multiseed_stability_v1.png",
            "data/modeling_k2/k2_multiseed_performance_v1.csv",
            [COLORS["teal"], COLORS["teal"], COLORS["green"], COLORS["green"]],
            "{:.3f}",
            y_max=1.0,
            notes=[f"Std: Macro F1={stds[0]:.4f}, Top-1={stds[1]:.4f}, Top-2={stds[2]:.4f}, MRR={stds[3]:.4f}"],
        )),
        "chapter4_use": "K2 stability",
        "caption": "K2 showed low seed sensitivity for the selected K1 architecture before the final deployable freeze.",
    })

    k25 = read_csv("data/modeling_k25/k25_architecture_multiseed_results_v1.csv")
    arch_rows = [r for r in k25 if r["metric"] == "incident_macro_f1"]
    outputs.append({
        "figure_file": str(bar_chart(
            "K2.5 Architecture Comparator",
            "Incident Macro F1 across second-level architecture alternatives; A0 XGB-to-XGB remained selected.",
            [r["architecture_id"] for r in arch_rows],
            [float(r["mean"]) for r in arch_rows],
            "figure_ch4_k25_architecture_comparator_v1.png",
            "data/modeling_k25/k25_architecture_multiseed_results_v1.csv",
            [COLORS["green"] if r["architecture_id"] == "A0_XGB_TO_XGB" else COLORS["gray"] for r in arch_rows],
            "{:.3f}",
            y_max=1.0,
        )),
        "chapter4_use": "K2.5 architecture comparison",
        "caption": "The K2.5 architecture comparator supported keeping the XGBoost-to-XGBoost K1 design.",
    })

    holdout = read_csv("data/final_holdout/final_holdout_performance_summary_v1.csv")[0]
    outputs.append({
        "figure_file": str(bar_chart(
            "Final Holdout Headline Metrics",
            "One-time terminal evaluation on 213 untouched incidents using the frozen K1 model.",
            ["Macro F1", "Top-1", "Top-2", "MRR"],
            [float(holdout["incident_macro_f1"]), float(holdout["top1"]), float(holdout["top2"]), float(holdout["mrr"])],
            "figure_ch4_final_holdout_headline_metrics_v1.png",
            "data/final_holdout/final_holdout_performance_summary_v1.csv",
            [COLORS["green"], COLORS["green"], COLORS["teal"], COLORS["teal"]],
            "{:.3f}",
            y_max=1.0,
            notes=["Macro F1 95% CI: [0.880117, 0.954402]."],
        )),
        "chapter4_use": "Final Holdout headline results",
        "caption": "The frozen K1 model generalized strongly on the sealed Final Holdout, with high classification and ranking metrics.",
    })

    per_class = read_csv("data/final_holdout/final_holdout_per_class_metrics_v1.csv")
    outputs.append({
        "figure_file": str(grouped_bar_chart(
            "Final Holdout Per-Class Metrics",
            "Precision, recall, and F1 by incident class; Outage was strongest and Hijack remained hardest.",
            [r["class"].title() for r in per_class],
            {
                "Precision": [float(r["precision"]) for r in per_class],
                "Recall": [float(r["recall"]) for r in per_class],
                "F1": [float(r["f1"]) for r in per_class],
            },
            "figure_ch4_final_holdout_per_class_metrics_v1.png",
            "data/final_holdout/final_holdout_per_class_metrics_v1.csv",
        )),
        "chapter4_use": "Final per-class results",
        "caption": "Per-class Final Holdout metrics show strongest performance for Outage and the lowest F1 for Hijack.",
    })

    outputs.append({
        "figure_file": str(ranking_distribution()),
        "chapter4_use": "Final ranking metrics",
        "caption": "The system ranked the true class first for 196 incidents and second for 15 incidents, yielding Top-2 coverage for 211 of 213 Final Holdout incidents.",
    })
    outputs.append({
        "figure_file": str(confusion_matrix()),
        "chapter4_use": "Final error/confusion analysis",
        "caption": "The final confusion matrix shows most residual errors occur between Hijack and Leak, while Outage is sharply separated.",
    })

    tvh = read_csv("data/final_holdout/train_vs_final_holdout_comparison_v1.csv")
    selected = [r for r in tvh if r["metric"] in {"incident_macro_f1", "top1", "top2", "mrr", "hijack_f1", "leak_f1", "outage_f1"}]
    outputs.append({
        "figure_file": str(bar_chart(
            "TRAIN Reference vs Final Holdout Delta",
            "Absolute metric deltas between fixed TRAIN nested-CV reference and terminal Final Holdout.",
            [r["metric"].replace("_", " ").title() for r in selected],
            [float(r["absolute_delta"]) for r in selected],
            "figure_ch4_train_vs_final_holdout_delta_v1.png",
            "data/final_holdout/train_vs_final_holdout_comparison_v1.csv",
            [COLORS["amber"] if float(r["absolute_delta"]) > 0.02 else COLORS["teal"] for r in selected],
            "{:.3f}",
            y_max=max(float(r["absolute_delta"]) for r in selected) * 1.25,
            notes=["Small deltas support generalization; Hijack shows the largest class-specific drop."],
        )),
        "chapter4_use": "TRAIN vs Holdout comparison",
        "caption": "TRAIN-to-Holdout deltas are small for aggregate ranking metrics, with the largest class-specific difference in Hijack F1.",
    })

    feature_composition_path = feature_composition()
    outputs.append({
        "figure_file": str(feature_composition_path),
        "chapter4_use": "Feature engineering summary",
        "caption": "The final V4 feature corpus combines 44 behavioral, 14 CAIDA, and 16 RPKI/ROV features for 74 total model inputs.",
    })

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with INDEX_PATH.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["figure_file", "chapter4_use", "caption"])
        writer.writeheader()
        writer.writerows(outputs)
    return outputs


if __name__ == "__main__":
    for record in generate_all():
        print(record["figure_file"])
    print(INDEX_PATH)
