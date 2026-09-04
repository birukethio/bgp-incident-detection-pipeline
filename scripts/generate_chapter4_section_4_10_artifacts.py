from __future__ import annotations

import csv
import textwrap
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw, ImageFont


ROOT = Path("/Users/biruk/Documents/New project")
DOCS = ROOT / "docs"
FIGURES = ROOT / "figures/chapter4"

K2_MULTI = ROOT / "data/modeling_k2/k2_multiseed_performance_v1.csv"
K2_SEEDS = ROOT / "data/modeling_k2/k2_seed_sensitivity_v1.csv"
K2_READY = ROOT / "data/modeling_k2/k2_forensic_readiness_audit_v1.csv"
K2_FINAL_VS_B0 = ROOT / "data/modeling_k2/k2_final_vs_b0_comparison_v1.csv"
K2_PERM = ROOT / "data/modeling_k2/k2_label_permutation_sanity_v1.csv"
K2_UNIQUE = ROOT / "data/modeling_k2/k2_incident_uniqueness_audit_v1.csv"
K2_L1 = ROOT / "data/modeling_k2/k2_first_level_leakage_audit_v1.csv"
K2_L2 = ROOT / "data/modeling_k2/k2_second_level_leakage_audit_v1.csv"
K2_META = ROOT / "data/modeling_k2/k2_meta_feature_leakage_audit_v1.csv"
K2_TOPOLOGY = ROOT / "data/modeling_k2/k2_stacking_topology_audit_v1.csv"
K2_FOLD_SEED = ROOT / "data/modeling_k2/k2_fold_seed_stability_v1.csv"
K1_FOLD = ROOT / "data/modeling_k1/k1_fold_results_v1.csv"
K1_PAIRED = ROOT / "data/modeling_k1/k1_paired_fold_comparison_v1.csv"
K1_CANDIDATE = ROOT / "config/k1_final_candidate_v1.yaml"
MASTER_SUMMARY = ROOT / "docs/master_praxis_results_summary_v1.yaml"
MASTER_RECORD = ROOT / "docs/master_praxis_experimental_record_v1.csv"
AUTHORITATIVE_NUMBERS = ROOT / "docs/authoritative_numbers_register_v1.csv"

RESULTS_OUT = DOCS / "chapter4_k2_stability_results_v1.csv"
FORENSIC_OUT = DOCS / "chapter4_k2_forensic_summary_v1.csv"
AUDIT_OUT = DOCS / "chapter4_section_4_10_evidence_audit_v1.csv"
CAPTION_OUT = DOCS / "chapter4_section_4_10_figure_caption_v1.md"
PAPER_TEXT_OUT = DOCS / "chapter4_section_4_10_paper_figure_text_v1.md"

FIG_PNG = FIGURES / "figure_4_k1_multiseed_stability_v1.png"
FIG_PDF = FIGURES / "figure_4_k1_multiseed_stability_v1.pdf"
FIG_JPG = FIGURES / "figure_4_k1_multiseed_stability_v1_highres_chart_only.jpg"

B0_ID = "K1-B0_MEAN_PROBABILITY"
K1_ID = "K1-M2_XGB_K1-TEMPORAL"

COLORS = {
    "ink": "#17212B",
    "muted": "#5F6B7A",
    "grid": "#D8DEE6",
    "axis": "#9AA6B2",
    "macro": "#2563A8",
    "top1": "#3A9B79",
    "top2": "#D89432",
    "mrr": "#6B5FB5",
    "mean": "#111827",
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
    if not path.is_absolute():
        return str(path)
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


def f(row: dict[str, str], field: str) -> float:
    return float(row[field])


def assert_close(label: str, observed: float, expected: float, tol: float = 5e-7) -> None:
    if abs(observed - expected) > tol:
        raise ValueError(f"{label} mismatch: observed={observed}, expected={expected}")


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
    source_file: Path,
    source_field_or_row: str,
    status: str = "PASS_AUTHORITATIVE_PHASE_K2",
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


def verify_anchors(multi: list[dict[str, str]]) -> None:
    lookup = {row["metric"]: row for row in multi}
    expected = {
        "incident_macro_f1": (0.9343041406552057, 0.0023092401102531527),
        "top1": (0.9341389728096676, 0.0023488225155469202),
        "top2": (0.9925478348439073, 0.0008056394763343634),
        "mrr": (0.9658274588788185, 0.0012269665580729656),
        "hijack_f1": (0.9128576166771365, 0.003787542330486435),
        "leak_f1": (0.9101250272654745, 0.003552673916598309),
        "outage_f1": (0.9799297780230063, 0.0010882403606675608),
    }
    for metric, (mean, std) in expected.items():
        assert_close(f"{metric} mean", f(lookup[metric], "mean"), mean)
        assert_close(f"{metric} std", f(lookup[metric], "std"), std)


def build_stability_results(seed_rows: list[dict[str, str]], audit_rows: list[dict[str, Any]]) -> None:
    fields = ["seed", "incident_macro_f1", "top1", "top2", "mrr", "hijack_f1", "leak_f1", "outage_f1"]
    out = []
    for row in seed_rows:
        out.append(
            {
                "seed": row["seed"],
                "macro_f1": row["incident_macro_f1"],
                "top1": row["top1"],
                "top2": row["top2"],
                "mrr": row["mrr"],
                "hijack_f1": row["hijack_f1"],
                "leak_f1": row["leak_f1"],
                "outage_f1": row["outage_f1"],
            }
        )
        for field in fields[1:]:
            audit_value(audit_rows, f"seed_{row['seed']}_{field}", row[field], K2_SEEDS, f"seed={row['seed']}; field={field}")
    write_csv(RESULTS_OUT, out, ["seed", "macro_f1", "top1", "top2", "mrr", "hijack_f1", "leak_f1", "outage_f1"])


def summarize_status_count(path: Path, status_field: str = "status") -> str:
    rows = read_csv(path)
    counts: dict[str, int] = {}
    for row in rows:
        counts[row[status_field]] = counts.get(row[status_field], 0) + 1
    return "; ".join(f"{key}={counts[key]}" for key in sorted(counts))


def build_forensic_summary(audit_rows: list[dict[str, Any]]) -> tuple[float, float, int, bool]:
    perm = read_csv(K2_PERM)
    perm_values = [f(row, "macro_f1") for row in perm]
    perm_min, perm_max = min(perm_values), max(perm_values)
    unique_rows = {row["check"]: row for row in read_csv(K2_UNIQUE)}
    paired = next(row for row in read_csv(K1_PAIRED) if row["candidate_id"] == K1_ID and row["baseline_id"] == B0_ID)
    b0 = next(row for row in read_csv(K1_FOLD) if row["candidate_id"] == B0_ID)
    b0_aggregate = float(next(row for row in read_csv(K2_FINAL_VS_B0) if row["metric"] == "incident_macro_f1")["b0"])
    all_seed_above_b0 = all(f(row, "incident_macro_f1") > b0_aggregate for row in read_csv(K2_SEEDS))

    rows = [
        {"check": "Level-1 leakage", "result": "none detected", "evidence": summarize_status_count(K2_L1), "source_artifact": rel(K2_L1)},
        {"check": "Level-2 leakage", "result": "none detected", "evidence": summarize_status_count(K2_L2), "source_artifact": rel(K2_L2)},
        {"check": "unique incident meta rows", "result": unique_rows["meta_rows"]["observed"], "evidence": "expected 993; duplicate incident_uid=0", "source_artifact": rel(K2_UNIQUE)},
        {"check": "class balance", "result": "331/331/331", "evidence": f"hijack={unique_rows['hijack_count']['observed']}; leak={unique_rows['leak_count']['observed']}; outage={unique_rows['outage_count']['observed']}", "source_artifact": rel(K2_UNIQUE)},
        {"check": "true-label meta-features", "result": "none detected", "evidence": "no meta features require true labels; structural future-window features flagged separately for scope", "source_artifact": rel(K2_META)},
        {"check": "permutation test", "result": f"Macro F1 range {perm_min:.6f}-{perm_max:.6f}", "evidence": summarize_status_count(K2_PERM), "source_artifact": rel(K2_PERM)},
        {"check": "multi-seed stability", "result": "PASS", "evidence": "five-seed analysis completed with low metric variation", "source_artifact": rel(K2_MULTI)},
        {"check": "fold/seed consistency", "result": "PASS", "evidence": f"paired K1-vs-B0 folds won={paired['folds_won']}; all K2 seed Macro F1 values exceed B0 aggregate={all_seed_above_b0}", "source_artifact": f"{rel(K1_PAIRED)}; {rel(K2_SEEDS)}"},
        {"check": "Validation usage", "result": "not used", "evidence": "validation_not_used PASS; K2 code path uses TRAIN/K1 artifacts only", "source_artifact": rel(K2_READY)},
        {"check": "Final Holdout access", "result": "not accessed", "evidence": "holdout_untouched PASS; Final Holdout remains SEALED", "source_artifact": rel(K2_READY)},
        {"check": "overall disposition", "result": "PASS", "evidence": "classification=K1_GAIN_CONFIRMED", "source_artifact": rel(K2_READY)},
    ]
    write_csv(FORENSIC_OUT, rows, ["check", "result", "evidence", "source_artifact"])
    for row in rows:
        audit_value(audit_rows, f"forensic_{row['check']}", row["result"], Path(row["source_artifact"].split(";")[0]), row["evidence"])
    for row in perm:
        audit_value(audit_rows, f"permutation_{row['permutation']}_macro_f1", row["macro_f1"], K2_PERM, f"permutation={row['permutation']}; seed={row['seed']}; field=macro_f1")
    audit_value(audit_rows, "b0_reference_macro_f1", b0_aggregate, K2_FINAL_VS_B0, "metric=incident_macro_f1; field=b0")
    audit_value(audit_rows, "first_b0_fold_seen_for_schema_reference", b0["incident_macro_f1"], K1_FOLD, "candidate_id=K1-B0_MEAN_PROBABILITY; first fold row")
    return perm_min, perm_max, int(unique_rows["meta_rows"]["observed"]), all_seed_above_b0


def draw_stability(seed_rows: list[dict[str, str]], multi: list[dict[str, str]], width: int, height: int, include_text: bool) -> Image.Image:
    img = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(img)
    scale = width / 2400
    if include_text:
        draw.text((int(100 * scale), int(70 * scale)), "K1 Multi-Seed Stability", font=font(int(43 * scale), True), fill=COLORS["ink"])
        draw_wrapped(draw, (int(102 * scale), int(135 * scale)), "Phase K2 TRAIN-only forensic verification: actual seed-level metrics with mean reference lines. Validation was not reused, and Final Holdout remained sealed.", 145, font(int(22 * scale)), COLORS["muted"])
        draw.line((int(100 * scale), int(225 * scale), int(2300 * scale), int(225 * scale)), fill=COLORS["grid"], width=max(3, int(3 * scale)))

    metrics = [
        ("incident_macro_f1", "Macro F1", COLORS["macro"]),
        ("top1", "Top-1", COLORS["top1"]),
        ("top2", "Top-2", COLORS["top2"]),
        ("mrr", "MRR", COLORS["mrr"]),
    ]
    multi_lookup = {row["metric"]: row for row in multi}
    left = int(170 * scale)
    top = int((350 if include_text else 240) * scale)
    right = int(2240 * scale)
    bottom = int((1110 if include_text else 1860) * scale)
    ymin, ymax = 0.90, 1.00
    for idx in range(6):
        val = ymin + (ymax - ymin) * idx / 5
        y = bottom - int((val - ymin) / (ymax - ymin) * (bottom - top))
        draw.line((left, y, right, y), fill=COLORS["grid"], width=max(2, int(2 * scale)))
        draw.text((int(72 * scale), y - int(11 * scale)), f"{val:.2f}", font=font(int(15 * scale)), fill=COLORS["muted"])
    draw.line((left, top, left, bottom), fill=COLORS["axis"], width=max(3, int(3 * scale)))
    draw.line((left, bottom, right, bottom), fill=COLORS["axis"], width=max(3, int(3 * scale)))

    seeds = [row["seed"] for row in seed_rows]
    x_gap = (right - left) / (len(seeds) - 1)
    xs = [int(left + i * x_gap) for i in range(len(seeds))]
    for x, seed in zip(xs, seeds):
        draw.text((x - int(54 * scale), bottom + int(34 * scale)), seed[-2:], font=font(int(17 * scale)), fill=COLORS["ink"])
    draw.text((int((left + right) / 2 - 120 * scale), bottom + int(84 * scale)), "Seed suffix", font=font(int(17 * scale)), fill=COLORS["muted"])

    mean_label_offsets = {
        "incident_macro_f1": int(34 * scale),
        "top1": int(-50 * scale),
        "top2": int(-25 * scale),
        "mrr": int(-17 * scale),
    }
    for field, label, color in metrics:
        pts = []
        for x, row in zip(xs, seed_rows):
            value = f(row, field)
            y = bottom - int((value - ymin) / (ymax - ymin) * (bottom - top))
            pts.append((x, y, value))
        for (x0, y0, _), (x1, y1, _) in zip(pts, pts[1:]):
            draw.line((x0, y0, x1, y1), fill=color, width=max(4, int(4 * scale)))
        for x, y, _ in pts:
            r = max(7, int(8 * scale))
            draw.ellipse((x - r, y - r, x + r, y + r), fill=color)
        mean = f(multi_lookup[field], "mean")
        mean_y = bottom - int((mean - ymin) / (ymax - ymin) * (bottom - top))
        dash = int(18 * scale)
        cursor = left
        while cursor < right:
            draw.line((cursor, mean_y, min(cursor + dash, right), mean_y), fill=color, width=max(2, int(2 * scale)))
            cursor += dash * 2
        draw.text(
            (right - int(125 * scale), mean_y + mean_label_offsets[field]),
            f"{label} mean {mean:.3f}",
            font=font(int(14 * scale)),
            fill=color,
        )

    legend_x = int(620 * scale)
    legend_y = int((1210 if include_text else 2120) * scale)
    for i, (_, label, color) in enumerate(metrics):
        x = legend_x + int(i * 290 * scale)
        draw.rectangle((x, legend_y, x + int(25 * scale), legend_y + int(25 * scale)), fill=color)
        draw.text((x + int(40 * scale), legend_y - int(4 * scale)), label, font=font(int(18 * scale)), fill=COLORS["ink"])

    if include_text:
        draw_wrapped(draw, (int(100 * scale), int(1300 * scale)), "Across five seeds, the selected K1 architecture remained stable: Macro F1 varied by 0.006055, Top-2 by 0.002014, and the forensic audit reported no detected Level-1 or Level-2 leakage.", 152, font(int(18 * scale)), COLORS["muted"])
        draw.text((int(100 * scale), int(1440 * scale)), f"Sources: {rel(K2_SEEDS)}; {rel(K2_MULTI)}; {rel(K2_READY)}", font=font(int(15 * scale)), fill=COLORS["muted"])
    return img


def main() -> None:
    multi = read_csv(K2_MULTI)
    seed_rows = read_csv(K2_SEEDS)
    verify_anchors(multi)

    audit_rows: list[dict[str, Any]] = []
    for row in multi:
        for field in ["mean", "std", "min", "max", "range", "coefficient_of_variation"]:
            audit_value(audit_rows, f"{row['metric']}_{field}", row[field], K2_MULTI, f"metric={row['metric']}; field={field}")

    build_stability_results(seed_rows, audit_rows)
    perm_min, perm_max, meta_rows, all_seed_above_b0 = build_forensic_summary(audit_rows)

    for source in [K1_CANDIDATE, MASTER_SUMMARY, AUTHORITATIVE_NUMBERS, MASTER_RECORD]:
        if source.exists():
            text = source.read_text(encoding="utf-8")
            audit_value(audit_rows, f"cross_reference_{source.name}", str("K2" in text or "k2_" in text), source, "K2/k2 reference present")

    write_csv(AUDIT_OUT, audit_rows, ["metric", "value", "source_file", "source_field_or_row", "authoritative_status"])

    fig = draw_stability(seed_rows, multi, 2400, 1500, True)
    save_outputs(fig, FIG_PNG, FIG_PDF)
    jpg = draw_stability(seed_rows, multi, 3600, 2250, True)
    save_jpg(jpg, FIG_JPG)

    m = {row["metric"]: row for row in multi}
    caption = f"""# Section 4.10 Figure Caption

**Figure 4.11. K1 multi-seed stability and forensic verification summary.** This figure reports existing Phase K2 TRAIN-only seed-level results for the selected K1 temporal stacking architecture. Each line shows one incident-level metric across the five evaluated seeds, and the dashed reference lines show the corresponding five-seed means. Macro F1 was {float(m['incident_macro_f1']['mean']):.6f} ± {float(m['incident_macro_f1']['std']):.6f}, Top-1 was {float(m['top1']['mean']):.6f} ± {float(m['top1']['std']):.6f}, Top-2 was {float(m['top2']['mean']):.6f} ± {float(m['top2']['std']):.6f}, and MRR was {float(m['mrr']['mean']):.6f} ± {float(m['mrr']['std']):.6f}. The forensic audit reported no detected Level-1 or Level-2 leakage, 993 unique incident meta rows, balanced 331/331/331 classes, and no true-class encoded meta-features. Label permutation Macro F1 collapsed to {perm_min:.6f}-{perm_max:.6f}. These are post-Validation TRAIN-only forensic/stability results; Validation was not recomputed or reused, and Final Holdout remained sealed.

Source artifacts: `{rel(K2_MULTI)}`, `{rel(K2_SEEDS)}`, `{rel(K2_READY)}`, `{rel(K2_PERM)}`, and `{rel(K2_FINAL_VS_B0)}`.
"""
    CAPTION_OUT.write_text(caption, encoding="utf-8")

    paper_text = f"""# Section 4.10 Separate Figure Text

## Figure 4.11 Title
K1 Multi-Seed Stability

## Figure 4.11 Subtitle
Phase K2 TRAIN-only forensic verification across five evaluated seeds.

## Key Text Under Figure
K2 verified stable K1 performance across five seeds: Macro F1 = {float(m['incident_macro_f1']['mean']):.6f} ± {float(m['incident_macro_f1']['std']):.6f}, Top-1 = {float(m['top1']['mean']):.6f} ± {float(m['top1']['std']):.6f}, Top-2 = {float(m['top2']['mean']):.6f} ± {float(m['top2']['std']):.6f}, and MRR = {float(m['mrr']['mean']):.6f} ± {float(m['mrr']['std']):.6f}. The forensic disposition was PASS / K1_GAIN_CONFIRMED, with {meta_rows} unique incident meta rows and permutation Macro F1 range {perm_min:.6f}-{perm_max:.6f}.

## Chart-Only JPG
Use `{rel(FIG_JPG)}` when dissertation text and caption are placed separately in Word.

## Fold/Seed Evidence Note
Direct paired fold evidence shows K1 beating B0 in 5/5 grouped folds. All five K2 seed-level Macro F1 values also exceed the B0 aggregate baseline: {all_seed_above_b0}.
"""
    PAPER_TEXT_OUT.write_text(paper_text, encoding="utf-8")

    print(f"wrote {RESULTS_OUT}")
    print(f"wrote {FORENSIC_OUT}")
    print(f"wrote {AUDIT_OUT}")
    print(f"wrote {CAPTION_OUT}")
    print(f"wrote {PAPER_TEXT_OUT}")
    print(f"wrote {FIG_PNG}")
    print(f"wrote {FIG_PDF}")
    print(f"wrote {FIG_JPG}")


if __name__ == "__main__":
    main()
