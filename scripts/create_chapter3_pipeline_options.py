from __future__ import annotations

from pathlib import Path
import textwrap

from PIL import Image, ImageDraw, ImageFont
from reportlab.lib.pagesizes import landscape, letter
from reportlab.pdfgen import canvas


ROOT = Path("/Users/biruk/Documents/New project")
OUT = ROOT / "figures/chapter3"
DOCS = ROOT / "docs/chapter3_figure_options"

W, H = 4200, 2400
NAVY = "#0B2545"
INK = "#1F2933"
LINE = "#243447"
MUTED = "#657786"
DATA = "#E8F1FA"
PROCESS = "#F4F7F2"
MODEL = "#F9F0E6"
EVAL = "#F3EAF8"
GUARD = "#FFF5CC"
WHITE = "#FFFFFF"


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    candidates = [
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/System/Library/Fonts/Supplemental/Times New Roman Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Times New Roman.ttf",
        "/Library/Fonts/Arial Bold.ttf" if bold else "/Library/Fonts/Arial.ttf",
    ]
    for path in candidates:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


TITLE_FONT = font(72, True)
BOX_TITLE = font(42, True)
BODY_FONT = font(33)
SMALL_FONT = font(30)


def wrapped(text: str, width: int) -> list[str]:
    lines: list[str] = []
    for part in text.split("\n"):
        lines.extend(textwrap.wrap(part, width=width) or [""])
    return lines


def text_center(draw: ImageDraw.ImageDraw, xy: tuple[int, int], lines: list[str], fnt, fill=INK, spacing=8):
    x, y = xy
    heights = []
    widths = []
    for line in lines:
        box = draw.textbbox((0, 0), line, font=fnt)
        widths.append(box[2] - box[0])
        heights.append(box[3] - box[1])
    total_h = sum(heights) + spacing * (len(lines) - 1)
    cy = y - total_h // 2
    for line, tw, th in zip(lines, widths, heights):
        draw.text((x - tw // 2, cy), line, font=fnt, fill=fill)
        cy += th + spacing


def box(draw: ImageDraw.ImageDraw, x: int, y: int, w: int, h: int, title: str, body: str, fill: str):
    draw.rounded_rectangle((x, y, x + w, y + h), radius=28, fill=fill, outline=LINE, width=5)
    title_lines = wrapped(title, 22)
    body_lines = wrapped(body, max(18, min(35, w // 24)))
    text_center(draw, (x + w // 2, y + 72), title_lines, BOX_TITLE, fill=NAVY, spacing=6)
    text_center(draw, (x + w // 2, y + int(h * 0.62)), body_lines, BODY_FONT, fill=INK, spacing=8)


def arrow(draw: ImageDraw.ImageDraw, start: tuple[int, int], end: tuple[int, int]):
    draw.line((start, end), fill=LINE, width=6)
    x1, y1 = start
    x2, y2 = end
    if x2 >= x1:
        pts = [(x2, y2), (x2 - 28, y2 - 18), (x2 - 28, y2 + 18)]
    else:
        pts = [(x2, y2), (x2 + 28, y2 - 18), (x2 + 28, y2 + 18)]
    draw.polygon(pts, fill=LINE)


def save(img: Image.Image, stem: str):
    OUT.mkdir(parents=True, exist_ok=True)
    png = OUT / f"{stem}.png"
    jpg = OUT / f"{stem}_highres.jpg"
    pdf = OUT / f"{stem}.pdf"
    img.save(png)
    img.save(jpg, quality=96, dpi=(450, 450))
    c = canvas.Canvas(str(pdf), pagesize=landscape(letter))
    page_w, page_h = landscape(letter)
    temp = OUT / f"{stem}.__tmp__.jpg"
    img.save(temp, quality=96)
    c.drawImage(str(temp), 0, 0, width=page_w, height=page_h, preserveAspectRatio=True, anchor="c")
    c.showPage()
    c.save()
    temp.unlink(missing_ok=True)


def base(title: str) -> tuple[Image.Image, ImageDraw.ImageDraw]:
    img = Image.new("RGB", (W, H), WHITE)
    draw = ImageDraw.Draw(img)
    text_center(draw, (W // 2, 115), [title], TITLE_FONT, fill=NAVY)
    draw.line((250, 185, W - 250, 185), fill="#C7D3E0", width=4)
    return img, draw


def option_a():
    img, draw = base("End-to-End Methodological Pipeline for BGP Incident Classification and Ranking")
    bw, bh = 620, 340
    xs = [180, 900, 1620, 2340, 3060]
    y1, y2 = 360, 1180
    top = [
        ("Frozen Incident Corpus", "1,419 incidents\n473 per class\nTRAIN / Validation / Holdout", DATA),
        ("RouteViews MRT Acquisition", "Incident-scoped UPDATE data\nUTC collection windows", DATA),
        ("Five-Minute BGP Windows", "Behavioral observations\nPartition inherited from incident", PROCESS),
        ("Context Enrichment", "CAIDA AS relationships\nHistorical RPKI/ROV", PROCESS),
        ("Frozen V4 Matrix", "74 features\n44 Behavioral + 14 CAIDA + 16 RPKI/ROV", PROCESS),
    ]
    bottom = [
        ("TRAIN-Only Development", "Grouped CV\nAblation, weighting,\nRF/XGB comparison", MODEL),
        ("K1 Temporal Stacking", "Level 1 XGBoost probabilities\nIncident-level temporal summaries\nLevel 2 XGBoost", MODEL),
        ("Independent Evaluation", "Validation confirmation\nFinal Holdout sealed until model freeze", EVAL),
        ("Ranked Incident Output", "Hijack / Leak / Outage\nTop-1, Top-2, MRR\nMacro F1", EVAL),
    ]
    for x, (t, b, color) in zip(xs, top):
        box(draw, x, y1, bw, bh, t, b, color)
    for i in range(len(xs) - 1):
        arrow(draw, (xs[i] + bw, y1 + bh // 2), (xs[i + 1], y1 + bh // 2))
    for x, (t, b, color) in zip(xs[1:], bottom):
        box(draw, x, y2, bw, bh, t, b, color)
    arrow(draw, (xs[-1] + bw // 2, y1 + bh), (xs[1] + bw // 2, y2))
    for i in range(1, 4):
        arrow(draw, (xs[i] + bw, y2 + bh // 2), (xs[i + 1], y2 + bh // 2))
    box(draw, 220, 1810, 1600, 340, "Leakage Controls", "Incident-level split. Windows inherit partition. Validation and Final Holdout protected.", GUARD)
    box(draw, 2100, 1810, 1700, 340, "Auxiliary Normal Branch", "Stage 1 was explored, but remained unresolved and outside final K1.", "#F5F5F5")
    save(img, "figure_3_1_option_a_end_to_end_pipeline_v1")


def option_b():
    img, draw = base("Compact Methodological Workflow")
    bw, bh = 500, 330
    xs = [140, 790, 1440, 2090, 2740, 3390]
    y = 650
    items = [
        ("Labels", "Cloudflare and external\nincident evidence", DATA),
        ("MRT Windows", "RouteViews UPDATEs\n5-minute UTC windows", DATA),
        ("V4 Features", "Behavioral + CAIDA\n+ RPKI/ROV", PROCESS),
        ("TRAIN CV", "Grouped by incident\nNo window leakage", MODEL),
        ("K1 Stacker", "Temporal incident\nrepresentation", MODEL),
        ("Final Output", "Ranked BGP incident\nclass", EVAL),
    ]
    for x, (t, b, color) in zip(xs, items):
        box(draw, x, y, bw, bh, t, b, color)
    for i in range(len(xs) - 1):
        arrow(draw, (xs[i] + bw, y + bh // 2), (xs[i + 1], y + bh // 2))
    box(draw, 650, 1400, 1250, 350, "Partition Discipline", "TRAIN 993\nValidation 213\nFinal Holdout 213\nIncident-level splits", GUARD)
    box(draw, 2300, 1400, 1250, 350, "Evaluation Discipline", "Validation once\nFinal Holdout once after freeze\nNo post-Holdout tuning", EVAL)
    save(img, "figure_3_1_option_b_compact_workflow_v1")


def option_c():
    img, draw = base("Final K1 Classification and Ranking Architecture")
    box(draw, 200, 480, 800, 360, "Five-Minute V4 Windows", "74 frozen features\n44 Behavioral + 14 CAIDA + 16 RPKI/ROV", DATA)
    box(draw, 1400, 480, 800, 360, "Level 1 XGBoost", "Window-level probabilities\nHijack / Leak / Outage", MODEL)
    box(draw, 2600, 480, 1000, 360, "Incident Temporal Summary", "Probability distribution, confidence,\ndisagreement, and early/middle/late dynamics", PROCESS)
    box(draw, 1400, 1280, 800, 360, "Level 2 XGBoost", "Incident-level K1 stacker\nFixed deployable model", MODEL)
    box(draw, 2600, 1280, 1000, 360, "Ranked Diagnosis", "Top-1 class\nTop-2 support\nMRR-ready ranking", EVAL)
    arrow(draw, (1000, 660), (1400, 660))
    arrow(draw, (2200, 660), (2600, 660))
    arrow(draw, (3100, 840), (1800, 1280))
    arrow(draw, (2200, 1460), (2600, 1460))
    box(draw, 200, 1400, 800, 340, "Protection Rules", "Grouped/nested CV.\nValidation not reused for K1.\nFinal Holdout sealed until final freeze.", GUARD)
    save(img, "figure_3_1_option_c_k1_architecture_v1")


def write_title_options():
    DOCS.mkdir(parents=True, exist_ok=True)
    (DOCS / "figure_3_1_title_caption_options_v1.md").write_text(
        """# Figure 3.1 Title and Caption Options

## Recommended

**Figure 3.1. End-to-End Methodological Pipeline for BGP Incident Classification and Ranking**

Caption: This figure summarizes the final Praxis methodology from incident-label curation through RouteViews MRT acquisition, five-minute BGP window construction, Behavioral/CAIDA/RPKI feature engineering, TRAIN-only model development, K1 incident-level temporal stacking, and final ranked classification of Hijack, Leak, and Outage incidents. The figure also highlights the incident-level leakage controls that separate TRAIN, Validation, and Final Holdout evidence.

Best use: Chapter 3 opening methodology figure.

## Option A

**Figure 3.1. End-to-End Research Pipeline for Leakage-Safe BGP Incident Classification**

Caption: The pipeline treats each incident as the independent experimental unit while five-minute windows serve as lower-level feature observations. All windows inherit the frozen incident partition, preventing cross-partition leakage during model development and evaluation.

Best use: If you want the figure title to emphasize experimental rigor.

## Option B

**Figure 3.1. From RouteViews Observations to Ranked BGP Incident Diagnosis**

Caption: Historical RouteViews UPDATE observations are transformed into five-minute V4 feature windows, enriched with AS-relationship and RPKI/ROV context, and aggregated through the K1 temporal stacking architecture to rank likely incident classes.

Best use: If you want the title to emphasize the data-processing story.

## Option C

**Figure 3.1. Final Praxis Methodology for Hijack, Route Leak, and Outage Classification**

Caption: The final methodology integrates labeled BGP incident evidence, RouteViews-derived behavioral features, CAIDA relationship context, and historical RPKI/ROV validation into a leakage-safe incident-level classification and ranking workflow.

Best use: If you want the title to be concrete and class-specific.
""",
        encoding="utf-8",
    )


def main():
    option_a()
    option_b()
    option_c()
    write_title_options()


if __name__ == "__main__":
    main()
