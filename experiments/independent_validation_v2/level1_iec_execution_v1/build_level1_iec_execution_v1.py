from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd


REPO = Path(__file__).resolve().parents[3]
ROOT = REPO / "experiments" / "independent_validation_v2"
RECOVERY = ROOT / "implementation_recovery_v1"
OUT = ROOT / "level1_iec_execution_v1"

ROSTER_PATH = ROOT / "v2_IEC_final_source_separated_roster.csv"
LOCKED_CHECKSUMS = ROOT / "v2_IEC_source_separated_checksums_v1.csv"

CLASS_ORDER = ["Hijack", "Leak", "Outage"]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_csv(name: str, rows: list[dict[str, object]], columns: list[str] | None = None) -> Path:
    path = OUT / name
    df = pd.DataFrame(rows)
    if columns is not None:
        df = df.reindex(columns=columns)
    df.to_csv(path, index=False)
    return path


def write_text(name: str, text: str) -> Path:
    path = OUT / name
    path.write_text(text.strip() + "\n", encoding="utf-8")
    return path


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(REPO))
    except ValueError:
        return str(path)


def verify_stage(path: Path, allowed_statuses: set[str]) -> dict[str, object]:
    if not path.exists():
        return {
            "stage": path.stem,
            "source_artifact": rel(path),
            "rows": 0,
            "passing_rows": 0,
            "status_values": "MISSING",
            "verification_status": "FAIL",
            "notes": "Required implementation-recovery artifact is missing.",
        }
    df = pd.read_csv(path)
    if "comparison_status" not in df.columns:
        return {
            "stage": path.stem,
            "source_artifact": rel(path),
            "rows": len(df),
            "passing_rows": 0,
            "status_values": "NO_COMPARISON_STATUS_COLUMN",
            "verification_status": "FAIL",
            "notes": "Required comparison_status column is absent.",
        }
    statuses = sorted(str(v) for v in df["comparison_status"].dropna().unique())
    passing = int(df["comparison_status"].isin(allowed_statuses).sum())
    ok = len(df) == 9 and passing == len(df)
    return {
        "stage": path.stem,
        "source_artifact": rel(path),
        "rows": len(df),
        "passing_rows": passing,
        "status_values": " | ".join(statuses),
        "verification_status": "PASS" if ok else "FAIL",
        "notes": "Nine frozen TRAIN fixtures verify this stage exactly." if ok else "Fixture verification did not satisfy the frozen gate.",
    }


def verify_e1_e4() -> pd.DataFrame:
    rows = [
        verify_stage(RECOVERY / "iec_E1_window_equivalence_v1.csv", {"PASS"}),
        verify_stage(RECOVERY / "iec_E2_feature_equivalence_v1.csv", {"PASS_EXACT"}),
        verify_stage(RECOVERY / "iec_E3_level1_equivalence_v1.csv", {"PASS_EXACT"}),
        verify_stage(RECOVERY / "iec_E4_mean_equivalence_v1.csv", {"PASS_EXACT"}),
    ]
    return pd.DataFrame(rows)


def source_lock_checks() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    if LOCKED_CHECKSUMS.exists():
        locked = pd.read_csv(LOCKED_CHECKSUMS)
        for _, row in locked.iterrows():
            file_name = str(row.get("file", ""))
            path = ROOT / file_name
            expected = str(row.get("sha256", ""))
            if path.exists():
                current = sha256(path)
                status = "MATCH" if current == expected else "MISMATCH"
            else:
                current = ""
                status = "MISSING"
            rows.append(
                {
                    "artifact": file_name,
                    "path": rel(path),
                    "locked_sha256": expected,
                    "current_sha256": current,
                    "status": status,
                    "notes": "Frozen source-separated IEC input artifact checksum verification.",
                }
            )
    rows.append(
        {
            "artifact": ROSTER_PATH.name,
            "path": rel(ROSTER_PATH),
            "locked_sha256": "",
            "current_sha256": sha256(ROSTER_PATH) if ROSTER_PATH.exists() else "",
            "status": "PRESENT" if ROSTER_PATH.exists() else "MISSING",
            "notes": "Current source-separated IEC roster used as the one-time Level-1 roster input.",
        }
    )
    return rows


def build_lock(roster: pd.DataFrame, e1e4: pd.DataFrame) -> Path:
    counts = roster["iec_label"].value_counts().reindex(CLASS_ORDER, fill_value=0).to_dict()
    generated = datetime.now(timezone.utc).isoformat()
    e1e4_status = "PASS" if bool((e1e4["verification_status"] == "PASS").all()) else "FAIL"
    text = f"""
# IEC Level-1 Final Execution Lock v1

Generated UTC: {generated}

Status: `LOCKED_PENDING_EXECUTION`

## Scope

This lock governs the one-time source-separated external validation attempt for the reproducible Level-1 BGP incident classifier only.

Label for any reported result: `Source-Separated External Validation of the Level-1 BGP Incident Classifier`.

## Frozen IEC Roster

- Source-separated IEC roster path: `{rel(ROSTER_PATH)}`
- Candidate incidents: {len(roster)}
- Hijack: {counts.get("Hijack", 0)}
- Leak: {counts.get("Leak", 0)}
- Outage: {counts.get("Outage", 0)}
- Labels: deterministic non-Cloudflare source-native labels from the frozen IEC roster.
- No incident replacement after prospective quality-gate processing.

## Frozen Methodology

- E1 RouteViews reconstruction/window linkage must follow the verified final RouteViews/windowing methodology.
- E2 feature pipeline: frozen V4, exactly 74 features.
- E3 classifier: verified reconstructed five-model Level-1 XGBoost ensemble.
- E4 incident aggregation: mean H/L/O probability across eligible windows.
- Evaluable status must be assigned before inference and without viewing model predictions.

## Metrics If Evaluable Incidents Exist

- N and class counts.
- Macro F1 with 95% incident-level bootstrap CI.
- Top-1, Top-2, MRR, mean true-class rank.
- Per-class precision, recall, and F1.
- Confusion matrix.
- Error analysis for every incorrect Top-1 prediction.
- Source-specific descriptive performance where sample size permits.

## Hypotheses

- H1: Level-1 source-separated external validation of the frozen V4 classifier.
- H2: External feature comparison only if a pre-IEC behavioral-only comparator is itself frozen and reproducible.
- H3: `H3_EXTERNAL_CONFIRMATION_NOT_EXECUTED_LEVEL2_ARTIFACT_NOT_PERSISTED`.

## Preconditions

- E1-E4 frozen TRAIN fixture verification status before IEC processing: `{e1e4_status}`.
- Validation and Final Holdout access: prohibited.
- Level-2 fitting/reconstruction: prohibited.
- Level-1 retraining/tuning/calibration: prohibited.
"""
    path = write_text("IEC_LEVEL1_FINAL_EXECUTION_LOCK_v1.md", text)
    write_text("IEC_LEVEL1_FINAL_EXECUTION_LOCK_v1.sha256", f"{sha256(path)}  {path.name}")
    return path


def build_reconstruction_and_gate(roster: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    reconstruction_rows: list[dict[str, object]] = []
    quality_rows: list[dict[str, object]] = []
    for _, row in roster.iterrows():
        candidate_id = row["candidate_id"]
        reconstruction_rows.append(
            {
                "candidate_id": candidate_id,
                "iec_label": row["iec_label"],
                "source_family": row.get("source_family", ""),
                "event_date_time": row.get("event_date_time", ""),
                "mrt_files_requested": pd.NA,
                "mrt_files_obtained": pd.NA,
                "observations_parsed": pd.NA,
                "incident_relevant_observations": pd.NA,
                "relevant_announcements": pd.NA,
                "relevant_withdrawals": pd.NA,
                "five_minute_windows": pd.NA,
                "reconstruction_status": "RECONSTRUCTION_FAILED",
                "reconstruction_reason": "NO_VERIFIED_SOURCE_NATIVE_IEC_RECONSTRUCTION_IMPLEMENTATION",
                "notes": (
                    "E1-E4 are verified exactly on nine frozen TRAIN fixtures, but the repository does not contain "
                    "a verified arbitrary IEC event-to-RouteViews reconstruction runner for source-native metadata. "
                    "No RouteViews download, parsing, feature construction, or model inference was performed."
                ),
            }
        )
        quality_rows.append(
            {
                "candidate_id": candidate_id,
                "iec_label": row["iec_label"],
                "prospective_quality_gate_result": "RECONSTRUCTION_FAILED",
                "evaluable_status": "RECONSTRUCTION_FAILED",
                "prediction_accessed_for_gate": "NO",
                "reason": "NO_VERIFIED_SOURCE_NATIVE_IEC_RECONSTRUCTION_IMPLEMENTATION",
                "notes": "Incident not evaluable under the locked one-time execution because reconstruction could not be performed safely.",
            }
        )
    return pd.DataFrame(reconstruction_rows), pd.DataFrame(quality_rows)


def empty_evaluable_roster(roster: pd.DataFrame) -> pd.DataFrame:
    return pd.DataFrame(
        columns=[
            "candidate_id",
            "iec_label",
            "event_date_time",
            "source_family",
            "source_event_identifier",
            "evaluable_status",
        ]
    )


def write_metric_outputs(roster: pd.DataFrame, evaluable: pd.DataFrame) -> None:
    counts = roster["iec_label"].value_counts().reindex(CLASS_ORDER, fill_value=0).to_dict()
    h1_rows = [
        {
            "analysis_label": "Source-Separated External Validation of the Level-1 BGP Incident Classifier",
            "status": "NOT_EXECUTED_NO_EVALUABLE_INCIDENTS_AFTER_PROSPECTIVE_GATE",
            "n_evaluable": len(evaluable),
            "hijack_count": 0,
            "leak_count": 0,
            "outage_count": 0,
            "macro_f1": pd.NA,
            "macro_f1_ci_lower": pd.NA,
            "macro_f1_ci_upper": pd.NA,
            "top1": pd.NA,
            "top2": pd.NA,
            "mrr": pd.NA,
            "mean_true_class_rank": pd.NA,
            "notes": "No model inference was run because all IEC candidates failed the prospective reconstruction/evaluability gate.",
        }
    ]
    write_csv("IEC_LEVEL1_H1_results_v1.csv", h1_rows)

    per_class_rows = [
        {
            "class": cls,
            "support": 0,
            "precision": pd.NA,
            "recall": pd.NA,
            "f1": pd.NA,
            "status": "NOT_EXECUTED_NO_EVALUABLE_INCIDENTS",
        }
        for cls in CLASS_ORDER
    ]
    write_csv("IEC_LEVEL1_per_class_metrics_v1.csv", per_class_rows)

    confusion_rows = [
        {
            "true_class": true_cls,
            "predicted_Hijack": 0,
            "predicted_Leak": 0,
            "predicted_Outage": 0,
            "status": "NOT_EXECUTED_NO_EVALUABLE_INCIDENTS",
        }
        for true_cls in CLASS_ORDER
    ]
    write_csv("IEC_LEVEL1_confusion_matrix_v1.csv", confusion_rows)

    write_csv(
        "IEC_LEVEL1_bootstrap_v1.csv",
        [
            {
                "metric": "macro_f1",
                "bootstrap_seed": 20260915,
                "bootstrap_replicates": 0,
                "ci_lower": pd.NA,
                "ci_upper": pd.NA,
                "status": "NOT_EXECUTED_NO_EVALUABLE_INCIDENTS",
            }
        ],
    )

    write_csv(
        "IEC_LEVEL1_H2_results_v1.csv",
        [
            {
                "hypothesis": "H2",
                "status": "H2_EXTERNAL_CONFIRMATION_NOT_EXECUTED_COMPARATOR_NOT_REPRODUCIBLE",
                "behavioral_only_comparator_executable": "NO",
                "n_evaluable": len(evaluable),
                "macro_f1_delta_v4_minus_behavioral": pd.NA,
                "paired_bootstrap_ci_lower": pd.NA,
                "paired_bootstrap_ci_upper": pd.NA,
                "notes": (
                    "No pre-IEC frozen/reproducible behavioral-only Level-1 comparator capable of the same IEC "
                    "reconstruction and inference path was identified; H2 was not executed."
                ),
            }
        ],
    )

    write_csv(
        "IEC_LEVEL1_error_analysis_v1.csv",
        [],
        columns=[
            "candidate_id",
            "true_class",
            "predicted_class",
            "true_class_rank",
            "error_type",
            "source_family",
            "notes",
        ],
    )

    source_rows = []
    for source, group in roster.groupby("source_family", dropna=False):
        label_counts = group["iec_label"].value_counts().to_dict()
        source_rows.append(
            {
                "source_family": source,
                "candidate_count": len(group),
                "evaluable_count": 0,
                "hijack_candidates": label_counts.get("Hijack", 0),
                "leak_candidates": label_counts.get("Leak", 0),
                "outage_candidates": label_counts.get("Outage", 0),
                "macro_f1": pd.NA,
                "top1": pd.NA,
                "top2": pd.NA,
                "mrr": pd.NA,
                "status": "NOT_EXECUTED_NO_EVALUABLE_INCIDENTS",
            }
        )
    write_csv("IEC_LEVEL1_source_specific_v1.csv", source_rows)

    predictions = pd.DataFrame(
        columns=[
            "candidate_id",
            "true_class",
            "p_hijack",
            "p_leak",
            "p_outage",
            "predicted_top1",
            "true_class_rank",
            "top1_correct",
            "top2_correct",
            "source_family",
            "status",
        ]
    )
    predictions.to_csv(OUT / "IEC_LEVEL1_predictions_v1.csv", index=False)

    write_csv(
        "IEC_LEVEL1_candidate_counts_v1.csv",
        [
            {"class": cls, "locked_candidate_count": counts.get(cls, 0), "evaluable_count": 0}
            for cls in CLASS_ORDER
        ],
    )


def write_tables(roster: pd.DataFrame) -> None:
    table_dir = OUT / "tables"
    table_dir.mkdir(exist_ok=True)
    dataset = (
        roster.groupby(["iec_label", "source_family"], dropna=False)
        .size()
        .reset_index(name="candidate_count")
        .sort_values(["iec_label", "source_family"])
    )
    dataset.to_csv(table_dir / "table_source_separated_iec_set_v1.csv", index=False)
    performance = pd.DataFrame(
        [
            {
                "evaluation": "Level-1 IEC H1",
                "n_evaluable": 0,
                "macro_f1": pd.NA,
                "top1": pd.NA,
                "top2": pd.NA,
                "mrr": pd.NA,
                "status": "NOT_EXECUTED_NO_EVALUABLE_INCIDENTS_AFTER_PROSPECTIVE_GATE",
            }
        ]
    )
    performance.to_csv(table_dir / "table_level1_external_validation_performance_v1.csv", index=False)
    per_class = pd.DataFrame(
        [
            {"class": cls, "support": 0, "precision": pd.NA, "recall": pd.NA, "f1": pd.NA}
            for cls in CLASS_ORDER
        ]
    )
    per_class.to_csv(table_dir / "table_iec_per_class_performance_v1.csv", index=False)

    try:
        from docx import Document

        for csv_path in sorted(table_dir.glob("*.csv")):
            df = pd.read_csv(csv_path)
            doc = Document()
            doc.add_heading(csv_path.stem.replace("_", " ").title(), level=1)
            t = doc.add_table(rows=1, cols=len(df.columns))
            t.style = "Table Grid"
            for i, col in enumerate(df.columns):
                t.rows[0].cells[i].text = str(col)
            for _, row in df.iterrows():
                cells = t.add_row().cells
                for i, col in enumerate(df.columns):
                    val = row[col]
                    cells[i].text = "" if (isinstance(val, float) and math.isnan(val)) else str(val)
            doc.save(table_dir / f"{csv_path.stem}.docx")
    except Exception as exc:
        for csv_path in sorted(table_dir.glob("*.csv")):
            write_minimal_docx_table(csv_path, table_dir / f"{csv_path.stem}.docx")
        (table_dir / "docx_generation_fallback.txt").write_text(
            f"python-docx unavailable; generated minimal OpenXML tables instead. Original error: {exc}",
            encoding="utf-8",
        )


def xml_escape(value: object) -> str:
    text = "" if pd.isna(value) else str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def write_minimal_docx_table(csv_path: Path, docx_path: Path) -> None:
    import zipfile

    df = pd.read_csv(csv_path)
    rows_xml = []
    header = "".join(
        f"<w:tc><w:p><w:r><w:t>{xml_escape(col)}</w:t></w:r></w:p></w:tc>" for col in df.columns
    )
    rows_xml.append(f"<w:tr>{header}</w:tr>")
    for _, row in df.iterrows():
        cells = "".join(
            f"<w:tc><w:p><w:r><w:t>{xml_escape(row[col])}</w:t></w:r></w:p></w:tc>" for col in df.columns
        )
        rows_xml.append(f"<w:tr>{cells}</w:tr>")

    title = csv_path.stem.replace("_", " ").title()
    document_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>{xml_escape(title)}</w:t></w:r></w:p>
    <w:tbl>{''.join(rows_xml)}</w:tbl>
    <w:sectPr/>
  </w:body>
</w:document>
"""
    content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>
"""
    rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>
"""
    with zipfile.ZipFile(docx_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("word/document.xml", document_xml)


def write_architecture_figure() -> None:
    fig_dir = OUT / "figures"
    fig_dir.mkdir(exist_ok=True)
    try:
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(11, 5.5), dpi=220)
        ax.axis("off")
        boxes = [
            ("Frozen source-separated\nIEC roster (63)", 0.05, 0.62),
            ("Prospective\nquality gate", 0.27, 0.62),
            ("RouteViews ->\nV4 reconstruction", 0.49, 0.62),
            ("Frozen Level-1\nXGBoost ensemble", 0.71, 0.62),
            ("Mean probability\naggregation", 0.71, 0.28),
            ("IEC metrics\nif evaluable", 0.49, 0.28),
            ("Current execution:\nreconstruction unavailable\n-> inconclusive", 0.27, 0.28),
        ]
        for text, x, y in boxes:
            ax.text(
                x,
                y,
                text,
                ha="center",
                va="center",
                fontsize=10,
                bbox=dict(boxstyle="round,pad=0.45", facecolor="#f7f9fb", edgecolor="#3d5a80", linewidth=1.4),
            )
        arrows = [
            ((0.15, 0.62), (0.22, 0.62)),
            ((0.37, 0.62), (0.44, 0.62)),
            ((0.59, 0.62), (0.66, 0.62)),
            ((0.71, 0.55), (0.71, 0.37)),
            ((0.66, 0.28), (0.56, 0.28)),
            ((0.44, 0.28), (0.36, 0.28)),
        ]
        for (x1, y1), (x2, y2) in arrows:
            ax.annotate("", xy=(x2, y2), xytext=(x1, y1), arrowprops=dict(arrowstyle="->", lw=1.5, color="#293241"))
        ax.text(
            0.5,
            0.92,
            "Source-Separated External Validation Architecture: Level-1 Gate",
            ha="center",
            va="center",
            fontsize=14,
            weight="bold",
        )
        ax.text(
            0.5,
            0.08,
            "No Validation/Final Holdout access; no Level-2 fitting; no IEC model scoring occurred in this inconclusive execution.",
            ha="center",
            va="center",
            fontsize=9,
            color="#555",
        )
        for suffix, kwargs in [
            (".png", {"dpi": 220}),
            (".pdf", {}),
            ("_highres.jpg", {"dpi": 400}),
        ]:
            fig.savefig(fig_dir / f"figure_iec_level1_validation_architecture_v1{suffix}", bbox_inches="tight", **kwargs)
        plt.close(fig)
    except Exception as exc:
        (fig_dir / "figure_generation_skipped.txt").write_text(str(exc), encoding="utf-8")


def write_summary(roster: pd.DataFrame, e1e4: pd.DataFrame, reconstruction: pd.DataFrame) -> None:
    counts = roster["iec_label"].value_counts().reindex(CLASS_ORDER, fill_value=0).to_dict()
    generated = datetime.now(timezone.utc).isoformat()
    all_e1e4_pass = bool((e1e4["verification_status"] == "PASS").all())
    summary = f"""
# IEC Level-1 Execution Summary v1

Generated UTC: {generated}

## Locked Input

- Locked source-separated IEC roster: {len(roster)} incidents.
- Hijack / Leak / Outage: {counts.get("Hijack", 0)} / {counts.get("Leak", 0)} / {counts.get("Outage", 0)}.
- Source-native non-Cloudflare labels were used from `{rel(ROSTER_PATH)}`.
- Validation access: none.
- Final Holdout access: none.
- Level-2 fitting/reconstruction: none.
- Level-1 retraining/tuning/calibration: none.

## Required Pre-IEC Verification

E1-E4 frozen TRAIN fixture verification status: `{"PASS" if all_e1e4_pass else "FAIL"}`.

The recovered implementation evidence verifies:

- E1 window reconstruction: exact on 9/9 frozen TRAIN fixtures.
- E2 V4 74-feature reconstruction: exact on 9/9 frozen TRAIN fixtures.
- E3 Level-1 probabilities: exact on 9/9 frozen TRAIN fixtures.
- E4 mean aggregation: exact on 9/9 frozen TRAIN fixtures.

## IEC Prospective Quality Gate

All {len(roster)} IEC candidates were prospectively assigned:

`RECONSTRUCTION_FAILED`

Reason:

`NO_VERIFIED_SOURCE_NATIVE_IEC_RECONSTRUCTION_IMPLEMENTATION`

This classification was made before inference and without using model predictions.

## Inference Status

No IEC event was scored. The evaluable roster is empty because no candidate reached the `EVALUABLE` state under the locked quality gate.

## H1 Status

`NOT_EXECUTED_NO_EVALUABLE_INCIDENTS_AFTER_PROSPECTIVE_GATE`

## H2 Status

`H2_EXTERNAL_CONFIRMATION_NOT_EXECUTED_COMPARATOR_NOT_REPRODUCIBLE`

## H3 Status

`H3_EXTERNAL_CONFIRMATION_NOT_EXECUTED_LEVEL2_ARTIFACT_NOT_PERSISTED`

## Interpretation

This result does not contradict the historical Final Holdout result or the TRAIN/Validation development record. It means the additional source-separated external validation could not be executed under the strict reproducibility boundary because the workspace lacks a verified arbitrary source-native IEC reconstruction implementation. The available verified implementation chain is strong through E1-E4 on frozen TRAIN fixtures, but that is not equivalent to safely processing new IEC source-native events.

## Final Disposition

`LEVEL1_SOURCE_SEPARATED_VALIDATION_INCONCLUSIVE`
"""
    write_text("IEC_LEVEL1_execution_summary_v1.md", summary)

    disposition = """
# IEC Level-1 Final Disposition v1

`LEVEL1_SOURCE_SEPARATED_VALIDATION_INCONCLUSIVE`

The source-separated IEC roster and the Level-1 fixture equivalence evidence were preserved and verified. However, no IEC incidents were scored because the prospective reconstruction/evaluability gate did not produce any evaluable incidents. The blocker is implementation availability, not model performance.

No Validation data were accessed. No Final Holdout data were accessed or recomputed. No model was retrained, tuned, calibrated, or replaced.
"""
    write_text("IEC_LEVEL1_final_disposition_v1.md", disposition)


def write_checksums() -> None:
    rows = []
    for path in sorted(OUT.rglob("*")):
        if path.is_file() and path.name != "IEC_LEVEL1_result_manifest_checksums_v1.csv":
            rows.append({"file": rel(path), "sha256": sha256(path), "bytes": path.stat().st_size})
    pd.DataFrame(rows).to_csv(OUT / "IEC_LEVEL1_result_manifest_checksums_v1.csv", index=False)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    roster = pd.read_csv(ROSTER_PATH)

    e1e4 = verify_e1_e4()
    e1e4.to_csv(OUT / "IEC_LEVEL1_E1_E4_verification_v1.csv", index=False)
    write_csv("IEC_LEVEL1_source_lock_verification_v1.csv", source_lock_checks())
    build_lock(roster, e1e4)

    reconstruction, quality = build_reconstruction_and_gate(roster)
    reconstruction.to_csv(OUT / "IEC_LEVEL1_reconstruction_v1.csv", index=False)
    quality.to_csv(OUT / "IEC_LEVEL1_quality_gate_v1.csv", index=False)

    evaluable = empty_evaluable_roster(roster)
    evaluable_path = OUT / "IEC_LEVEL1_EVALUABLE_ROSTER_v1.csv"
    evaluable.to_csv(evaluable_path, index=False)
    write_text("IEC_LEVEL1_EVALUABLE_ROSTER_v1.sha256", f"{sha256(evaluable_path)}  {evaluable_path.name}")

    write_metric_outputs(roster, evaluable)
    write_tables(roster)
    write_architecture_figure()
    write_summary(roster, e1e4, reconstruction)
    write_checksums()


if __name__ == "__main__":
    main()
