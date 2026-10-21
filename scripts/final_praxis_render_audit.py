from __future__ import annotations

import csv
import re
from pathlib import Path

import pdfplumber
from PIL import Image, ImageDraw
from docx import Document


ROOT = Path("/Users/biruk/Documents/New project")
WORK = ROOT / "deliverables/praxis_final_cleanup"
DOCX = WORK / "Final_Praxis_Submission.docx"
PDF = WORK / "Final_Praxis_Submission.pdf"
RENDER_DIR = WORK / "render_final_verified"
PAGE_COMPLIANCE = WORK / "Final_Praxis_Page_Compliance.csv"
CONSISTENCY_AUDIT = WORK / "Final_Praxis_Consistency_Audit.md"


def extract_pdf_page_text() -> list[str]:
    with pdfplumber.open(PDF) as pdf:
        return [page.extract_text() or "" for page in pdf.pages]


def first_page_containing(pages: list[str], phrase: str, start_at: int = 1) -> int | None:
    for i, text in enumerate(pages, start=1):
        if i < start_at:
            continue
        if phrase in text:
            return i
    return None


def last_page_containing(pages: list[str], phrase: str, start_at: int = 1) -> int | None:
    found = None
    for i, text in enumerate(pages, start=1):
        if i >= start_at and phrase in text:
            found = i
    return found


def update_page_compliance() -> None:
    pages = extract_pdf_page_text()
    starts = {
        "Chapter 1": last_page_containing(pages, "Chapter 1 - Introduction", 1),
        "Chapter 2": last_page_containing(pages, "Chapter 2 - Literature Review", 1),
        "Chapter 3": last_page_containing(pages, "Chapter 3 - Methodology", 1),
        "Chapter 4": last_page_containing(pages, "Chapter 4 - Results", 1),
        "Chapter 5": last_page_containing(pages, "Chapter 5 - Conclusions", 1),
        "References": last_page_containing(pages, "References", 1),
    }
    original = {"Chapter 1": 12, "Chapter 2": 52, "Chapter 3": 73, "Chapter 4": 52, "Chapter 5": 22}
    preferred = {
        "Chapter 1": "5-8",
        "Chapter 2": "30-35",
        "Chapter 3": "22-28",
        "Chapter 4": "20-25",
        "Chapter 5": "3-5",
    }
    maxes = {"Chapter 1": 8, "Chapter 2": 35, "Chapter 3": 28, "Chapter 4": 25, "Chapter 5": 5}
    lowers = {"Chapter 1": 5, "Chapter 2": 30, "Chapter 3": 22, "Chapter 4": 20, "Chapter 5": 3}
    ordered = ["Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5", "References"]
    rows = []
    for idx, chapter in enumerate(ordered[:-1]):
        start = starts[chapter]
        next_start = starts[ordered[idx + 1]]
        final_pages = None if start is None or next_start is None else next_start - start
        if final_pages is None:
            status = "FAIL"
        elif final_pages > maxes[chapter]:
            status = "FAIL"
        elif final_pages < lowers[chapter]:
            status = "REVIEW"
        else:
            status = "PASS"
        rows.append(
            {
                "chapter": chapter,
                "original_pages": original[chapter],
                "final_pages": final_pages if final_pages is not None else "UNKNOWN",
                "preferred_range": preferred[chapter],
                "maximum_allowed": maxes[chapter],
                "status": status,
            }
        )
    rows.append(
        {
            "chapter": "Full rendered document",
            "original_pages": 263,
            "final_pages": len(pages),
            "preferred_range": "82-101 overall target",
            "maximum_allowed": 101,
            "status": "PASS" if len(pages) <= 101 else "FAIL",
        }
    )
    with PAGE_COMPLIANCE.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["chapter", "original_pages", "final_pages", "preferred_range", "maximum_allowed", "status"],
        )
        writer.writeheader()
        writer.writerows(rows)


def update_consistency_audit() -> None:
    text = "\n".join(p.text for p in Document(DOCX).paragraphs)
    checks = {
        "final_corpus_1419": r"1,419",
        "balanced_473": r"473 Hijack, 473 Leak, and 473 Outage|473 Hijack / 473 Leak / 473 Outage",
        "train_993": r"993",
        "validation_holdout_213": r"213 Validation|213 Final Holdout|213 incidents",
        "v4_74": r"74",
        "final_macro_f1": r"0\.920177",
        "final_ci": r"0\.880117.*0\.954402",
        "top2_211": r"211 of 213|211/213",
        "latency_25_58": r"25\.58",
    }
    stale = {
        "old_34_event": r"\b34[- ]event\b",
        "old_75_event": r"\b75[- ]event\b",
        "old_84_event": r"\b84[- ]event\b",
        "old_seven_event_holdout": r"\bseven[- ]event\b|\b7[- ]event\b",
        "old_40_46_49_feature": r"\b40[- ]feature\b|\b46[- ]feature\b|\b49[- ]feature\b",
        "old_three_rpki": r"\bthree[- ]RPKI\b|\b3 RPKI\b",
        "old_09769": r"\b0\.9769\b",
        "old_tau_070": r"\btau\s*=\s*0\.70\b|τ\s*=\s*0\.70",
        "old_410_latency": r"\b4\.10\s*(microsecond|us|µs)",
        "old_rf_final": r"hierarchical Random Forest",
    }
    lines = [
        "# Final Praxis Consistency Audit",
        "",
        "## Authoritative final values",
    ]
    for name, pattern in checks.items():
        status = "PASS" if re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL) else "REVIEW"
        lines.append(f"- {name}: {status}")
    lines.extend(["", "## Stale-claim scan"])
    for name, pattern in stale.items():
        found = bool(re.search(pattern, text, flags=re.IGNORECASE))
        lines.append(f"- {name}: {'REVIEW_FOUND' if found else 'PASS_NOT_FOUND'}")
    lines.extend(
        [
            "",
            "## Notes",
            "- Stage 1 is described as experimental/auxiliary, not the final system.",
            "- Final latency is described as warm downstream K1 computation after feature/probability availability, not end-to-end live detection.",
            "- References were structurally normalized from the manuscript's existing bibliography. External DOI/URL verification was not performed in this local editorial pass.",
        ]
    )
    CONSISTENCY_AUDIT.write_text("\n".join(lines) + "\n", encoding="utf-8")


def make_contact_sheets() -> None:
    page_paths = sorted(RENDER_DIR.glob("page-*.png"), key=lambda p: int(p.stem.split("-")[1]))
    sheet_dir = RENDER_DIR / "contact_sheets"
    sheet_dir.mkdir(exist_ok=True)
    thumb_w = 360
    label_h = 24
    cols = 5
    rows = 4
    per_sheet = cols * rows
    for sheet_index in range(0, len(page_paths), per_sheet):
        subset = page_paths[sheet_index : sheet_index + per_sheet]
        thumbs = []
        for path in subset:
            image = Image.open(path).convert("RGB")
            ratio = thumb_w / image.width
            thumb_h = int(image.height * ratio)
            image = image.resize((thumb_w, thumb_h), Image.Resampling.LANCZOS)
            tile = Image.new("RGB", (thumb_w, thumb_h + label_h), "white")
            tile.paste(image, (0, label_h))
            draw = ImageDraw.Draw(tile)
            draw.text((8, 5), path.stem.replace("-", " "), fill=(0, 0, 0))
            thumbs.append(tile)
        max_h = max(t.height for t in thumbs)
        sheet = Image.new("RGB", (cols * thumb_w, rows * max_h), "white")
        for j, tile in enumerate(thumbs):
            x = (j % cols) * thumb_w
            y = (j // cols) * max_h
            sheet.paste(tile, (x, y))
        out = sheet_dir / f"contact_sheet_{sheet_index // per_sheet + 1:02d}.jpg"
        sheet.save(out, quality=92)


def main() -> None:
    update_page_compliance()
    update_consistency_audit()
    make_contact_sheets()
    print(PAGE_COMPLIANCE)
    print(CONSISTENCY_AUDIT)


if __name__ == "__main__":
    main()
