from __future__ import annotations

import csv
import textwrap
from pathlib import Path
from typing import Iterable

from PIL import Image, ImageDraw, ImageFont


ROOT = Path("/Users/biruk/Documents/New project")
DOCS = ROOT / "docs"
FIGURES = ROOT / "figures/chapter4"

IMBALANCE_SOURCE = ROOT / "data/modeling/imbalance_strategy_model_comparison_v1.csv"
P95_SOURCE = ROOT / "data/modeling/p95_temporal_sampling_audit_v1.csv"
DECISION_SOURCE = ROOT / "data/modeling/experiment_decision_ledger_v1.csv"

RESULTS_OUT = DOCS / "chapter4_incident_imbalance_results_v1.csv"
CAPTION_OUT = DOCS / "chapter4_section_4_4_figure_caption_v1.md"
AUDIT_OUT = DOCS / "chapter4_section_4_4_evidence_audit_v1.csv"

FIG_OUT = FIGURES / "figure_4_incident_imbalance_comparison_v1.png"
FIG_PDF_OUT = FIGURES / "figure_4_incident_imbalance_comparison_v1.pdf"
FIG_JPG_OUT = FIGURES / "figure_4_incident_imbalance_comparison_v1_highres_chart_only.jpg"
PAPER_TEXT_OUT = DOCS / "chapter4_section_4_4_paper_figure_text_v1.md"

STRATEGY_DETAILS = {
    "I0": {
        "window_treatment": "Natural five-minute window representation",
        "incident_weighting": "No",
        "temporal_cap": "None",
    },
    "I1": {
        "window_treatment": "All available windows retained",
        "incident_weighting": "Yes; incident-aware weighting",
        "temporal_cap": "None",
    },
    "I2": {
        "window_treatment": "Incident-aware weighting plus p95 temporal cap",
        "incident_weighting": "Yes; incident-aware weighting",
        "temporal_cap": "164 five-minute windows per incident",
    },
}

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


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def fmt(value: float | str, places: int = 6) -> str:
    if value == "NA":
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


def summarize_p95_rows() -> dict[str, object]:
    if not P95_SOURCE.exists():
        return {
            "windows_removed": "NA",
            "window_removal_percent": "NA",
            "affected_source": "NA",
        }
    rows = read_csv(P95_SOURCE)
    selected = [r for r in rows if r["model_task"] == "RF_HIER_STAGE2" and r["imbalance_condition"] == "I2"]
    if not selected:
        return {
            "windows_removed": "NA",
            "window_removal_percent": "NA",
            "affected_source": rel(P95_SOURCE),
        }
    original = sum(int(r["original_rows"]) for r in selected)
    retained = sum(int(r["retained_rows"]) for r in selected)
    discarded = sum(int(r["discarded_rows"]) for r in selected)
    pct = discarded / original * 100 if original else 0.0
    return {
        "windows_removed": discarded,
        "window_removal_percent": pct,
        "p95_original_rows_in_capped_groups": original,
        "p95_retained_rows_in_capped_groups": retained,
        "affected_source": rel(P95_SOURCE),
    }


def load_decision() -> dict[str, str]:
    rows = read_csv(DECISION_SOURCE)
    matches = [r for r in rows if r["decision"] == "I1 selected"]
    if len(matches) != 1:
        raise RuntimeError("Could not uniquely identify the I1 selection decision.")
    return matches[0]


def build_result_rows() -> tuple[list[dict[str, object]], list[dict[str, object]], dict[str, str], dict[str, object]]:
    rows = read_csv(IMBALANCE_SOURCE)
    selected = [r for r in rows if r["model"] == "RF_HIER" and r["imbalance_condition"] in {"I0", "I1", "I2"}]
    if len(selected) != 3:
        raise RuntimeError("Could not uniquely identify RF_HIER I0/I1/I2 imbalance rows.")
    by_strategy = {r["imbalance_condition"]: r for r in selected}
    p95_summary = summarize_p95_rows()
    decision = load_decision()
    out: list[dict[str, object]] = []
    audit: list[dict[str, object]] = []

    for strategy in ["I0", "I1", "I2"]:
        src = by_strategy[strategy]
        train_rows = float(src["train_rows_used"])
        windows_removed = "NA"
        if strategy in {"I0", "I1"}:
            windows_removed = fmt(0)
        elif strategy == "I2":
            windows_removed = fmt(float(by_strategy["I1"]["train_rows_used"]) - train_rows)
        details = STRATEGY_DETAILS[strategy]
        row = {
            "strategy": strategy,
            "window_treatment": details["window_treatment"],
            "incident_weighting": details["incident_weighting"],
            "temporal_cap": details["temporal_cap"],
            "incident_macro_f1": fmt(src["group_macro_f1_mean"]),
            "top1_accuracy": "NA",
            "top2_accuracy": fmt(src["top2"]),
            "mrr": fmt(src["mrr"]),
            "hijack_f1": fmt(src["hijack_f1"]),
            "leak_f1": fmt(src["leak_f1"]),
            "outage_f1": fmt(src["outage_f1"]),
            "window_macro_f1": fmt(src["window_macro_f1_mean"]),
            "windows_retained": fmt(train_rows, 1),
            "windows_removed": windows_removed,
            "evaluation_scope": "TRAIN-only grouped CV; Phase B imbalance treatment comparison; RF_HIER; V1 behavioral schema",
            "source_artifact": rel(IMBALANCE_SOURCE),
        }
        out.append(row)
        source_map = {
            "incident_macro_f1": "group_macro_f1_mean",
            "top2_accuracy": "top2",
            "mrr": "mrr",
            "hijack_f1": "hijack_f1",
            "leak_f1": "leak_f1",
            "outage_f1": "outage_f1",
            "window_macro_f1": "window_macro_f1_mean",
            "windows_retained": "train_rows_used",
        }
        for metric, field in source_map.items():
            audit.append({
                "metric": metric,
                "value": row[metric],
                "strategy": strategy,
                "source_file": rel(IMBALANCE_SOURCE),
                "source_field_or_row": f"model=RF_HIER; imbalance_condition={strategy}; field={field}",
                "authoritative_status": "PASS_AUTHORITATIVE_TRAIN_ONLY",
            })
        audit.append({
            "metric": "top1_accuracy",
            "value": "NA",
            "strategy": strategy,
            "source_file": rel(IMBALANCE_SOURCE),
            "source_field_or_row": "No top1_accuracy field in authoritative imbalance comparison artifact",
            "authoritative_status": "PASS_NOT_MEASURED_LEFT_NA",
        })
        audit.append({
            "metric": "windows_removed",
            "value": row["windows_removed"],
            "strategy": strategy,
            "source_file": rel(IMBALANCE_SOURCE),
            "source_field_or_row": "Derived from RF_HIER I1 train_rows_used minus strategy train_rows_used; I0/I1 remove no windows",
            "authoritative_status": "PASS_DERIVED_FROM_AUTHORITATIVE_TRAIN_ONLY" if strategy == "I2" else "PASS_NOT_APPLICABLE_NO_CAP",
        })

    audit.append({
        "metric": "p95_capped_group_windows_removed",
        "value": p95_summary["windows_removed"],
        "strategy": "I2",
        "source_file": p95_summary["affected_source"],
        "source_field_or_row": "Rows with model_task=RF_HIER_STAGE2; sum(discarded_rows) across capped groups/folds",
        "authoritative_status": "PASS_CONTEXT_ONLY_CAP_AUDIT",
    })
    audit.append({
        "metric": "p95_capped_group_window_removal_percent",
        "value": fmt(p95_summary["window_removal_percent"]) if p95_summary["window_removal_percent"] != "NA" else "NA",
        "strategy": "I2",
        "source_file": p95_summary["affected_source"],
        "source_field_or_row": "sum(discarded_rows) / sum(original_rows) for RF_HIER_STAGE2 capped groups/folds",
        "authoritative_status": "PASS_CONTEXT_ONLY_CAP_AUDIT",
    })
    audit.append({
        "metric": "selection_decision",
        "value": decision["decision"],
        "strategy": "I1",
        "source_file": rel(DECISION_SOURCE),
        "source_field_or_row": "decision=I1 selected",
        "authoritative_status": "PASS_AUTHORITATIVE_DECISION",
    })
    audit.append({
        "metric": "selection_reason",
        "value": decision["reason"],
        "strategy": "I1",
        "source_file": rel(DECISION_SOURCE),
        "source_field_or_row": "decision=I1 selected; field=reason",
        "authoritative_status": "PASS_AUTHORITATIVE_DECISION",
    })
    return out, audit, decision, p95_summary


def chart(rows: list[dict[str, object]]) -> None:
    img, draw = base_canvas(
        "Incident Imbalance and Weighting Results",
        "TRAIN-only grouped cross-validation comparison of I0, I1, and I2. I1 was retained because it equalized incident influence while preserving all available windows.",
    )
    strategies = ["I0", "I1", "I2"]
    by = {r["strategy"]: r for r in rows}
    colors = {"I0": COLORS["blue"], "I1": COLORS["green"], "I2": COLORS["amber"]}

    left, top, right, bottom = 170, 360, 1120, 1160
    ymax = 0.60
    for step in range(0, 7):
        val = ymax * step / 6
        y = bottom - int(val / ymax * (bottom - top))
        draw.line((left, y, right, y), fill=COLORS["grid"], width=2)
        draw.text((105, y - 11), f"{val:.2f}", font=F_TINY, fill=COLORS["muted"])
    draw.line((left, top, left, bottom), fill=COLORS["axis"], width=3)
    draw.line((left, bottom, right, bottom), fill=COLORS["axis"], width=3)
    draw.text((left, 310), "Incident Macro F1", font=font(25, True), fill=COLORS["ink"])
    bar_w = 190
    gap = (right - left - bar_w * 3) / 4
    descriptions = {
        "I0": "Natural\nwindows",
        "I1": "Weighted\nall windows",
        "I2": "Weighted\np95 cap",
    }
    for i, strategy in enumerate(strategies):
        value = float(by[strategy]["incident_macro_f1"])
        x0 = left + gap + i * (bar_w + gap)
        y0 = bottom - int(value / ymax * (bottom - top))
        draw.rounded_rectangle((x0, y0, x0 + bar_w, bottom), radius=11, fill=colors[strategy])
        if strategy == "I1":
            draw.rounded_rectangle((x0 - 10, y0 - 10, x0 + bar_w + 10, bottom + 10), radius=14, outline=COLORS["ink"], width=5)
            draw.text((x0 + 25, y0 - 72), "SELECTED", font=font(19, True), fill=COLORS["ink"])
        draw.text((x0 + 35, y0 - 38), f"{value:.6f}", font=F_BOLD, fill=COLORS["ink"])
        draw.text((x0 + 70, bottom + 30), strategy, font=font(28, True), fill=COLORS["ink"])
        draw.multiline_text((x0 + 15, bottom + 75), descriptions[strategy], font=F_SMALL, fill=COLORS["muted"], spacing=4, align="center")

    left2, top2, right2, bottom2 = 1340, 360, 2260, 1160
    draw.text((left2, 310), "Ranking Metrics", font=font(25, True), fill=COLORS["ink"])
    ymax2 = 1.0
    for step in range(0, 6):
        val = ymax2 * step / 5
        y = bottom2 - int(val / ymax2 * (bottom2 - top2))
        draw.line((left2, y, right2, y), fill=COLORS["grid"], width=2)
        draw.text((1280, y - 11), f"{val:.2f}", font=F_TINY, fill=COLORS["muted"])
    draw.line((left2, top2, left2, bottom2), fill=COLORS["axis"], width=3)
    draw.line((left2, bottom2, right2, bottom2), fill=COLORS["axis"], width=3)
    series = [("Top-2", "top2_accuracy", COLORS["purple"]), ("MRR", "mrr", COLORS["blue"])]
    group_w = (right2 - left2) / 3
    bw = 92
    for i, strategy in enumerate(strategies):
        gx = left2 + i * group_w + 70
        for j, (_, field, color) in enumerate(series):
            value = float(by[strategy][field])
            x0 = gx + j * (bw + 22)
            y0 = bottom2 - int(value / ymax2 * (bottom2 - top2))
            draw.rounded_rectangle((x0, y0, x0 + bw, bottom2), radius=9, fill=color)
            draw.text((x0 - 14, y0 - 32), f"{value:.6f}", font=F_TINY, fill=COLORS["ink"])
        draw.text((gx + 75, bottom2 + 30), strategy, font=font(25, True), fill=COLORS["ink"])
    legend_x = left2
    for name, _, color in series:
        draw.rounded_rectangle((legend_x, 1265, legend_x + 42, 1292), radius=5, fill=color)
        draw.text((legend_x + 54, 1260), name, font=F_SMALL, fill=COLORS["ink"])
        legend_x += 190
    draw.text((100, 1350), "I1 is marked as the selected strategy because it preserved all observations while reducing long-incident dominance through incident-aware weights.", font=F_SMALL, fill=COLORS["muted"])
    draw.text((100, 1440), f"Source: {rel(IMBALANCE_SOURCE)}; decision source: {rel(DECISION_SOURCE)}", font=F_TINY, fill=COLORS["muted"])
    save_outputs(img, FIG_OUT, FIG_PDF_OUT)


def chart_only_jpg(rows: list[dict[str, object]]) -> None:
    img = Image.new("RGB", (3600, 2400), "white")
    draw = ImageDraw.Draw(img)
    strategies = ["I0", "I1", "I2"]
    by = {r["strategy"]: r for r in rows}
    colors = {"I0": COLORS["blue"], "I1": COLORS["green"], "I2": COLORS["amber"]}

    left, top, right, bottom = 260, 280, 1700, 1900
    ymax = 0.60
    for step in range(0, 7):
        val = ymax * step / 6
        y = bottom - int(val / ymax * (bottom - top))
        draw.line((left, y, right, y), fill=COLORS["grid"], width=3)
        draw.text((145, y - 16), f"{val:.2f}", font=font(24), fill=COLORS["muted"])
    draw.line((left, top, left, bottom), fill=COLORS["axis"], width=5)
    draw.line((left, bottom, right, bottom), fill=COLORS["axis"], width=5)
    draw.text((left, 205), "Incident Macro F1", font=font(38, True), fill=COLORS["ink"])
    bar_w = 290
    gap = (right - left - bar_w * 3) / 4
    for i, strategy in enumerate(strategies):
        value = float(by[strategy]["incident_macro_f1"])
        x0 = left + gap + i * (bar_w + gap)
        y0 = bottom - int(value / ymax * (bottom - top))
        draw.rounded_rectangle((x0, y0, x0 + bar_w, bottom), radius=16, fill=colors[strategy])
        if strategy == "I1":
            draw.rounded_rectangle((x0 - 14, y0 - 14, x0 + bar_w + 14, bottom + 14), radius=18, outline=COLORS["ink"], width=7)
        draw.text((x0 + 55, y0 - 58), f"{value:.6f}", font=font(30, True), fill=COLORS["ink"])
        draw.text((x0 + 112, bottom + 52), strategy, font=font(42, True), fill=COLORS["ink"])

    left2, top2, right2, bottom2 = 2050, 280, 3450, 1900
    draw.text((left2, 205), "Ranking Metrics", font=font(38, True), fill=COLORS["ink"])
    ymax2 = 1.0
    for step in range(0, 6):
        val = ymax2 * step / 5
        y = bottom2 - int(val / ymax2 * (bottom2 - top2))
        draw.line((left2, y, right2, y), fill=COLORS["grid"], width=3)
        draw.text((1945, y - 16), f"{val:.2f}", font=font(24), fill=COLORS["muted"])
    draw.line((left2, top2, left2, bottom2), fill=COLORS["axis"], width=5)
    draw.line((left2, bottom2, right2, bottom2), fill=COLORS["axis"], width=5)
    series = [("Top-2", "top2_accuracy", COLORS["purple"]), ("MRR", "mrr", COLORS["blue"])]
    group_w = (right2 - left2) / 3
    bw = 145
    for i, strategy in enumerate(strategies):
        gx = left2 + i * group_w + 100
        for j, (_, field, color) in enumerate(series):
            value = float(by[strategy][field])
            x0 = gx + j * (bw + 34)
            y0 = bottom2 - int(value / ymax2 * (bottom2 - top2))
            draw.rounded_rectangle((x0, y0, x0 + bw, bottom2), radius=13, fill=color)
            draw.text((x0 - 21, y0 - 50), f"{value:.6f}", font=font(23), fill=COLORS["ink"])
        draw.text((gx + 120, bottom2 + 52), strategy, font=font(42, True), fill=COLORS["ink"])
    legend_x = left2
    for name, _, color in series:
        draw.rounded_rectangle((legend_x, 2130, legend_x + 70, 2173), radius=8, fill=color)
        draw.text((legend_x + 90, 2124), name, font=font(30), fill=COLORS["ink"])
        legend_x += 300
    save_jpg(img, FIG_JPG_OUT)


def write_caption(decision: dict[str, str], p95_summary: dict[str, object]) -> None:
    removal_note = "NA"
    if p95_summary["windows_removed"] != "NA":
        removal_note = f"{p95_summary['windows_removed']} windows removed from capped RF_HIER_STAGE2 over-cap groups across folds ({float(p95_summary['window_removal_percent']):.6f}% of those groups' original rows)"
    text = f"""# Section 4.4 Figure Caption v1

## Figure 4.x Incident Imbalance and Weighting Results

This figure compares the three predeclared TRAIN-only imbalance strategies: I0, I1, and I2. I0 used the natural five-minute window representation without incident-aware weighting or temporal capping. I1 retained all available windows but applied incident-aware weighting so that each incident contributed approximately equal aggregate training influence. I2 added the same incident-aware weighting but capped long incidents at 164 five-minute windows. The primary comparison metric is incident-level Macro F1 from grouped cross-validation; Top-2 and MRR are shown because they were consistently recorded for all three strategies.

I1 is highlighted as the selected strategy, not because it maximized every metric, but because the recorded decision states: "{decision['reason']}" The recorded supporting evidence was: "{decision['evidence']}" The p95 cap audit context is: {removal_note}.

Evidence boundary: this figure uses existing TRAIN-only artifacts only. No model was retrained. Validation was not accessed or recomputed. Final Holdout was not accessed or recomputed.

Sources:

- `{rel(IMBALANCE_SOURCE)}`
- `{rel(P95_SOURCE)}`
- `{rel(DECISION_SOURCE)}`
"""
    CAPTION_OUT.write_text(text, encoding="utf-8")


def write_paper_text(decision: dict[str, str]) -> None:
    text = f"""# Section 4.4 Paper Figure Text v1

These text blocks are separated from the high-resolution chart-only JPG so the dissertation document can control headings, captions, spacing, and source notes directly.

## Figure 4.x Incident Imbalance and Weighting Results

Title: Incident Imbalance and Weighting Results

Subtitle: TRAIN-only grouped cross-validation comparison of I0, I1, and I2. I1 was retained because it equalized incident influence while preserving all available windows.

Under-figure note: I1 is marked as the selected strategy because it preserved all observations while reducing long-incident dominance through incident-aware weights.

Caption: This figure compares the three predeclared imbalance strategies. I0 used the natural five-minute window representation, I1 retained all windows with incident-aware weighting, and I2 applied incident-aware weighting plus a 164-window p95 temporal cap. Although I2 produced the highest incident Macro F1 among these three rows, the recorded decision retained I1 because: "{decision['reason']}"

Source: `{rel(IMBALANCE_SOURCE)}`

Decision source: `{rel(DECISION_SOURCE)}`

Image: `{rel(FIG_JPG_OUT)}`
"""
    PAPER_TEXT_OUT.write_text(text, encoding="utf-8")


def validate_no_forbidden_sources(audit_rows: Iterable[dict[str, object]]) -> None:
    forbidden = ("validation", "final_holdout", "holdout")
    for row in audit_rows:
        source = str(row["source_file"]).lower()
        if any(term in source for term in forbidden):
            raise RuntimeError(f"Forbidden source used for Section 4.4: {source}")


def main() -> None:
    DOCS.mkdir(exist_ok=True)
    FIGURES.mkdir(parents=True, exist_ok=True)
    rows, audit, decision, p95_summary = build_result_rows()
    validate_no_forbidden_sources(audit)
    write_csv(
        RESULTS_OUT,
        rows,
        [
            "strategy",
            "window_treatment",
            "incident_weighting",
            "temporal_cap",
            "incident_macro_f1",
            "top1_accuracy",
            "top2_accuracy",
            "mrr",
            "hijack_f1",
            "leak_f1",
            "outage_f1",
            "window_macro_f1",
            "windows_retained",
            "windows_removed",
            "evaluation_scope",
            "source_artifact",
        ],
    )
    write_csv(
        AUDIT_OUT,
        audit,
        ["metric", "value", "strategy", "source_file", "source_field_or_row", "authoritative_status"],
    )
    write_caption(decision, p95_summary)
    write_paper_text(decision)
    chart(rows)
    chart_only_jpg(rows)
    for path in [RESULTS_OUT, CAPTION_OUT, PAPER_TEXT_OUT, AUDIT_OUT, FIG_OUT, FIG_PDF_OUT, FIG_JPG_OUT]:
        print(path)


if __name__ == "__main__":
    main()
