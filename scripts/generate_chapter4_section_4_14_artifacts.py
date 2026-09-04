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

LATENCY = ROOT / "data/performance/final_k1_inference_latency_v1.csv"
SUMMARY_MD = ROOT / "docs/final_k1_latency_summary_v1.md"
MODEL_TABLE = ROOT / "docs/model_latency_table_v1.csv"
PROFESSOR_MD = ROOT / "docs/professor_tau_and_latency_answers_v1.md"
NOTEBOOK = ROOT / "notebooks/57_tau_threshold_and_final_model_latency.ipynb"
AUTHORITATIVE_NUMBERS = ROOT / "docs/authoritative_numbers_register_v1.csv"
STAT_REGISTER = ROOT / "docs/final_statistical_results_register_v1.csv"
MASTER_SUMMARY = ROOT / "docs/master_praxis_results_summary_v1.yaml"

RESULTS_OUT = DOCS / "chapter4_latency_results_v1.csv"
ENV_OUT = DOCS / "chapter4_latency_environment_v1.csv"
AUDIT_OUT = DOCS / "chapter4_section_4_14_evidence_audit_v1.csv"
CAPTION_OUT = DOCS / "chapter4_section_4_14_figure_caption_v1.md"
PAPER_TEXT_OUT = DOCS / "chapter4_section_4_14_paper_figure_text_v1.md"

FIG_PNG = FIGURES / "figure_4_k1_latency_breakdown_v1.png"
FIG_PDF = FIGURES / "figure_4_k1_latency_breakdown_v1.pdf"
FIG_JPG = FIGURES / "figure_4_k1_latency_breakdown_v1_highres_chart_only.jpg"

COMPONENTS = [
    "Level-1 XGBoost ensemble probability averaging",
    "K1 meta-feature construction",
    "Level-2 XGBoost output ranking",
    "Complete measured K1 computational path from probabilities to ranking",
]

EXPECTED = {
    "Level-1 XGBoost ensemble probability averaging": {
        "mean": 9.600850950671453e-06,
        "median": 8.37654567211807e-06,
        "p95": 1.198121260470682e-05,
        "p99": 1.2301627443159154e-05,
        "unit": "milliseconds/window",
    },
    "K1 meta-feature construction": {
        "mean": 25.47103125,
        "median": 24.6709895,
        "p95": 27.520333474999997,
        "p99": 27.773608494999998,
        "unit": "milliseconds/incident",
    },
    "Level-2 XGBoost output ranking": {
        "mean": 0.10239925,
        "median": 0.100427,
        "p95": 0.10726137499999999,
        "p99": 0.107868875,
        "unit": "milliseconds/incident",
    },
    "Complete measured K1 computational path from probabilities to ranking": {
        "mean": 25.579447833333333,
        "median": 24.7749895,
        "p95": 27.634936375,
        "p99": 27.889153875,
        "unit": "milliseconds/incident",
    },
}

EXCLUDED = (
    "live BGP UPDATE collection; MRT parsing; five-minute observation-window accumulation; "
    "Behavioral feature generation; CAIDA enrichment; RPKI/ROV enrichment; model startup/loading; "
    "complete live data-pipeline overhead"
)

COLORS = {
    "ink": "#17212B",
    "muted": "#5F6B7A",
    "grid": "#D8DEE6",
    "axis": "#9AA6B2",
    "blue": "#2563A8",
    "green": "#3A9B79",
    "orange": "#D89432",
    "purple": "#6B5FB5",
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


def assert_close(label: str, observed: float, expected: float, tol: float = 1e-12) -> None:
    if abs(observed - expected) > tol:
        raise ValueError(f"{label} mismatch: observed={observed}, expected={expected}")


def audit(
    rows: list[dict[str, Any]],
    claim: str,
    metric: str,
    value: Any,
    source_file: Path,
    source_field_or_row: str,
    status: str = "PASS_AUTHORITATIVE_PHASE_N",
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


def load_and_verify(audit_rows: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    rows = {row["component"]: row for row in read_csv(LATENCY)}
    table_rows = {row["component"]: row for row in read_csv(MODEL_TABLE)}
    for component, expected in EXPECTED.items():
        if component not in rows:
            raise ValueError(f"Missing latency component: {component}")
        row = rows[component]
        table_row = table_rows[component]
        for metric in ["mean", "median", "p95", "p99"]:
            assert_close(f"{component} {metric}", float(row[metric]), float(expected[metric]))
            assert_close(f"model table {component} {metric}", float(table_row[metric]), float(expected[metric]))
            audit(audit_rows, f"{component} {metric} verified", metric, row[metric], LATENCY, f"component={component}; field={metric}")
        if row["unit"] != expected["unit"]:
            raise ValueError(f"{component} unit mismatch")
        audit(audit_rows, f"{component} unit verified", "unit", row["unit"], LATENCY, f"component={component}; field=unit")
    complete = rows["Complete measured K1 computational path from probabilities to ranking"]
    throughput = float(complete["incidents_per_second_approx"])
    derived = 1000.0 / float(complete["mean"])
    assert_close("throughput derived from mean", throughput, derived, tol=1e-9)
    audit(audit_rows, "Approximate downstream throughput verified", "incidents_per_second_approx", throughput, LATENCY, "complete path row; formula 1000 / mean_ms")

    env_fields = {
        "Python version": "python_version",
        "XGBoost version": "xgboost_version",
        "OS/platform": "platform",
        "Recorded CPU field": "cpu",
        "Thread count": "thread_count",
        "Model loaded state": "model_loaded_state",
    }
    for label, field in env_fields.items():
        audit(audit_rows, f"{label} recovered", field, complete[field], LATENCY, f"complete path row; field={field}")
    audit(audit_rows, "CPU model not recorded", "cpu_model", "NA", LATENCY, "artifact records cpu=i386 but no CPU model string")
    audit(audit_rows, "RAM not recorded", "ram", "NA", LATENCY, "no RAM field in Phase N artifacts")

    summary = SUMMARY_MD.read_text(encoding="utf-8")
    professor = PROFESSOR_MD.read_text(encoding="utf-8")
    if "POST_WINDOW_INCIDENT_CLASSIFICATION" not in summary:
        raise ValueError("Summary does not contain POST_WINDOW_INCIDENT_CLASSIFICATION")
    if "Operational diagnosis time should be described as post-window incident classification" not in professor:
        raise ValueError("Professor answer does not contain the post-window caveat")
    audit(audit_rows, "Post-window characterization verified", "classification", "POST_WINDOW_INCIDENT_CLASSIFICATION", SUMMARY_MD, "classification line")
    audit(audit_rows, "Excluded pipeline stages documented", "excluded_processing", EXCLUDED, SUMMARY_MD, "warm computational path caveat")
    for artifact in [NOTEBOOK, AUTHORITATIVE_NUMBERS, STAT_REGISTER, MASTER_SUMMARY]:
        if not artifact.exists():
            raise FileNotFoundError(artifact)
        audit(audit_rows, f"{artifact.name} present for cross-reference", "artifact_present", "present", artifact, "exists")
    return rows


def build_results(rows: dict[str, dict[str, str]]) -> None:
    out: list[dict[str, Any]] = []
    for component in COMPONENTS:
        row = rows[component]
        out.append(
            {
                "measurement": component,
                "mean_ms": row["mean"],
                "median_ms": row["median"],
                "p95_ms": row["p95"],
                "p99_ms": row["p99"],
                "unit": row["unit"],
                "scope": "POST-WINDOW INCIDENT CLASSIFICATION; warm downstream K1 path after feature/probability availability",
                "included_processing": row["notes"],
                "excluded_processing": EXCLUDED,
                "source_artifact": rel(LATENCY),
            }
        )
    complete = rows["Complete measured K1 computational path from probabilities to ranking"]
    out.append(
        {
            "measurement": "Approximate downstream throughput",
            "mean_ms": complete["incidents_per_second_approx"],
            "median_ms": "NA",
            "p95_ms": "NA",
            "p99_ms": "NA",
            "unit": "incidents/second",
            "scope": "presentation derivative, not measured live network throughput",
            "included_processing": "Calculated from authoritative mean latency as 1000 ms / mean_ms_per_incident.",
            "excluded_processing": EXCLUDED,
            "source_artifact": rel(LATENCY),
        }
    )
    write_csv(
        RESULTS_OUT,
        out,
        [
            "measurement",
            "mean_ms",
            "median_ms",
            "p95_ms",
            "p99_ms",
            "unit",
            "scope",
            "included_processing",
            "excluded_processing",
            "source_artifact",
        ],
    )


def build_environment(rows: dict[str, dict[str, str]]) -> None:
    complete = rows["Complete measured K1 computational path from probabilities to ranking"]
    env = [
        {"parameter": "Python version", "value": complete["python_version"], "source_artifact": rel(LATENCY)},
        {"parameter": "XGBoost version", "value": complete["xgboost_version"], "source_artifact": rel(LATENCY)},
        {"parameter": "OS/platform", "value": complete["platform"], "source_artifact": rel(LATENCY)},
        {"parameter": "thread count", "value": complete["thread_count"], "source_artifact": rel(LATENCY)},
        {"parameter": "recorded CPU field", "value": complete["cpu"], "source_artifact": rel(LATENCY)},
        {"parameter": "CPU model", "value": "NA", "source_artifact": rel(LATENCY)},
        {"parameter": "RAM", "value": "NA", "source_artifact": rel(LATENCY)},
        {"parameter": "model loaded state", "value": complete["model_loaded_state"], "source_artifact": rel(LATENCY)},
    ]
    write_csv(ENV_OUT, env, ["parameter", "value", "source_artifact"])


def draw_wrapped(draw: ImageDraw.ImageDraw, xy: tuple[int, int], text: str, width: int, font_obj, fill: str, spacing: int = 5) -> int:
    wrapped = "\n".join(textwrap.wrap(text, width=width))
    draw.multiline_text(xy, wrapped, font=font_obj, fill=fill, spacing=spacing)
    return draw.multiline_textbbox(xy, wrapped, font=font_obj, spacing=spacing)[3]


def draw_latency(rows: dict[str, dict[str, str]], include_text: bool, scale: int = 1) -> Image.Image:
    width, height = 2500 * scale, (1500 if include_text else 1120) * scale
    img = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(img)

    def sf(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
        return font(size * scale, bold)

    margin_x = 180 * scale
    if include_text:
        draw.text((margin_x, 70 * scale), "Warm Downstream K1 Computational Latency", font=sf(42, True), fill=COLORS["ink"])
        draw_wrapped(
            draw,
            (margin_x, 135 * scale),
            "Phase N benchmark after feature/probability availability. This is post-window incident classification, not end-to-end live BGP detection latency.",
            138,
            sf(22),
            COLORS["muted"],
        )
        top = 320 * scale
    else:
        top = 90 * scale
    left, right, bottom = margin_x + 620 * scale, width - 220 * scale, height - 170 * scale
    row_gap = 190 * scale
    bar_h = 82 * scale
    components = [
        ("Level-1 avg", "Level-1 XGBoost ensemble probability averaging", COLORS["green"]),
        ("Meta features", "K1 meta-feature construction", COLORS["blue"]),
        ("Level-2 ranking", "Level-2 XGBoost output ranking", COLORS["orange"]),
    ]
    means = [float(rows[component]["mean"]) for _, component, _ in components]
    min_log = math.log10(1e-6)
    max_log = math.log10(30.0)

    draw.line((left, bottom, right, bottom), fill=COLORS["axis"], width=3 * scale)
    for tick in [1e-6, 1e-4, 1e-2, 1, 10, 30]:
        x = left + int((math.log10(tick) - min_log) / (max_log - min_log) * (right - left))
        draw.line((x, top - 25 * scale, x, bottom), fill=COLORS["grid"], width=1 * scale)
        label = f"{tick:g}"
        draw.text((x - 22 * scale, bottom + 26 * scale), label, font=sf(14), fill=COLORS["muted"])
    draw.text((left + 390 * scale, bottom + 80 * scale), "Mean latency, milliseconds (log scale)", font=sf(19), fill=COLORS["muted"])

    for idx, (short, component, color) in enumerate(components):
        mean = float(rows[component]["mean"])
        y = top + idx * row_gap
        x0 = left
        x1 = left + int((math.log10(max(mean, 1e-6)) - min_log) / (max_log - min_log) * (right - left))
        draw.rounded_rectangle((x0, y, max(x1, x0 + 4 * scale), y + bar_h), radius=8 * scale, fill=color)
        draw.text((margin_x, y + 16 * scale), short, font=sf(25, True), fill=COLORS["ink"])
        value = f"{mean:.6f} ms"
        if mean < 0.0001:
            value = f"{mean:.9f} ms"
        draw.text((min(x1 + 24 * scale, right - 380 * scale), y + 20 * scale), value, font=sf(22, True), fill=COLORS["ink"])
        if component == "K1 meta-feature construction":
            draw.text((min(x1 + 24 * scale, right - 500 * scale), y + 58 * scale), "dominant measured component", font=sf(16), fill="white")

    complete = rows["Complete measured K1 computational path from probabilities to ranking"]
    if include_text:
        note_y = top + 3 * row_gap + 60 * scale
        draw.rounded_rectangle((margin_x, note_y, right, note_y + 150 * scale), radius=8 * scale, outline=COLORS["grid"], width=2 * scale)
        complete_text = (
            f"Complete downstream path: mean {float(complete['mean']):.6f} ms/incident, "
            f"median {float(complete['median']):.6f}, p95 {float(complete['p95']):.6f}, p99 {float(complete['p99']):.6f}; "
            f"throughput derivative {float(complete['incidents_per_second_approx']):.2f} incidents/s."
        )
        draw_wrapped(draw, (margin_x + 35 * scale, note_y + 32 * scale), complete_text, 120, sf(22), COLORS["ink"])
    if include_text:
        footer = "Excluded: live collection, MRT parsing, window accumulation, Behavioral, CAIDA, RPKI/ROV enrichment, startup/loading, and complete live pipeline overhead."
        draw_wrapped(draw, (margin_x, height - 105 * scale), footer, 145, sf(17), COLORS["muted"])
    return img


def save_figures(rows: dict[str, dict[str, str]]) -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    fig = draw_latency(rows, include_text=True, scale=1)
    fig.save(FIG_PNG, "PNG", optimize=True)
    fig.save(FIG_PDF, "PDF", resolution=200.0)
    jpg = draw_latency(rows, include_text=False, scale=2)
    jpg.save(FIG_JPG, "JPEG", quality=97, subsampling=0, optimize=True, dpi=(300, 300))


def build_caption_and_text(rows: dict[str, dict[str, str]]) -> None:
    CAPTION_OUT.write_text(
        """# Section 4.14 Figure Caption

**Figure 4.16. Breakdown of Warm Downstream K1 Computational Latency.** The figure reports the Phase N post-feature computation benchmark for the frozen K1 architecture. The measurement begins after first-level probability information is available and summarizes Level-1 probability averaging, incident-level meta-feature construction, and Level-2 output ranking. It is therefore a POST-WINDOW INCIDENT CLASSIFICATION benchmark, not an end-to-end live BGP anomaly-detection latency measurement. The excluded stages include live BGP UPDATE collection, MRT parsing, five-minute observation-window accumulation, Behavioral feature generation, CAIDA enrichment, RPKI/ROV enrichment, model startup/loading, and complete live data-pipeline overhead.
""",
        encoding="utf-8",
    )
    complete = rows["Complete measured K1 computational path from probabilities to ranking"]
    PAPER_TEXT_OUT.write_text(
        f"""# Section 4.14 Figure Text

Figure 4.16: Warm downstream K1 computational latency. Complete measured path = {float(complete['mean']):.6f} ms/incident mean, {float(complete['median']):.6f} median, {float(complete['p95']):.6f} p95, {float(complete['p99']):.6f} p99. Approximate downstream throughput derivative = {float(complete['incidents_per_second_approx']):.2f} incidents/second. This is post-window incident classification and not end-to-end live detection latency.
""",
        encoding="utf-8",
    )


def main() -> None:
    audit_rows: list[dict[str, Any]] = []
    rows = load_and_verify(audit_rows)
    build_results(rows)
    build_environment(rows)
    save_figures(rows)
    build_caption_and_text(rows)
    write_csv(
        AUDIT_OUT,
        audit_rows,
        ["claim", "metric", "value", "source_file", "source_field_or_row", "authoritative_status"],
    )
    print(f"Wrote {RESULTS_OUT}")
    print(f"Wrote {ENV_OUT}")
    print(f"Wrote {AUDIT_OUT}")
    print(f"Wrote {CAPTION_OUT}")
    print(f"Wrote {FIG_PNG}")
    print(f"Wrote {FIG_PDF}")
    print(f"Wrote {FIG_JPG}")


if __name__ == "__main__":
    main()
