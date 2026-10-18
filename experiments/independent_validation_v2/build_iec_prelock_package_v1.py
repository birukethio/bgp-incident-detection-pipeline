from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
SOURCE_DIR = ROOT / "experiments" / "independent_validation_audit_v2"
OUT_DIR = ROOT / "experiments" / "independent_validation_v2"


def _clean(value: object) -> str:
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except TypeError:
        pass
    return str(value).strip()


def _pick(row: pd.Series, names: Iterable[str], default: str = "") -> str:
    for name in names:
        if name in row.index:
            value = _clean(row[name])
            if value:
                return value
    return default


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _boolish_yes(value: str) -> str:
    v = value.strip().upper()
    if v in {"YES", "TRUE", "ROUTEVIEWS_AVAILABLE", "AVAILABLE"}:
        return "YES"
    if v in {"NO", "FALSE", "NOT_AVAILABLE", "UNAVAILABLE"}:
        return "NO"
    return value or "NOT_RECORDED"


def load_candidates() -> pd.DataFrame:
    form_path = SOURCE_DIR / "v2_expert_adjudication_form.csv"
    roster_path = SOURCE_DIR / "v2_prelock_candidate_roster.csv"
    if form_path.exists():
        return pd.read_csv(form_path)
    if roster_path.exists():
        return pd.read_csv(roster_path)
    raise FileNotFoundError("No prior V2 candidate form or prelock roster was found.")


def source_native_label(row: pd.Series) -> str:
    explicit = _pick(
        row,
        [
            "source_native_label",
            "source_native_incident_terminology",
            "source_label",
            "source_event_type",
            "source_classification",
        ],
    )
    if explicit:
        return explicit

    source = _pick(row, ["primary_evidence_source", "primary_source", "source"])
    evidence = _pick(
        row,
        [
            "source_derived_evidence_summary",
            "evidence_summary",
            "exact_source_evidence_available_to_reviewer",
            "exact_evidence",
        ],
    )
    mapped = _pick(row, ["proposed_class", "category", "class"])
    if source or evidence:
        return f"NOT_SEPARATELY_RECORDED_IN_PRIOR_ARTIFACT; mapped class={mapped}; verify source terminology from cited evidence"
    return "NOT_RECORDED_REQUIRES_HUMAN_SOURCE_VERIFICATION"


def make_source_native_matrix(candidates: pd.DataFrame) -> pd.DataFrame:
    records: list[dict[str, str]] = []
    for _, row in candidates.iterrows():
        candidate_id = _pick(row, ["candidate_id", "incident_id", "incident_uid"])
        primary_url = _pick(row, ["primary_source_url_or_reference", "source_url", "url"])
        source = _pick(row, ["primary_evidence_source", "primary_source", "source"])
        proposed_class = _pick(row, ["proposed_class", "category", "class"])
        cloudflare_secondary = "NO"
        corroborating = _pick(row, ["corroborating_sources", "secondary_evidence_sources"])
        if "cloudflare" in corroborating.lower() and "cloudflare" not in source.lower():
            cloudflare_secondary = "YES_SECONDARY_ONLY"
        records.append(
            {
                "iec_candidate_id": candidate_id,
                "source_native_event_id": _pick(row, ["source_event_identifier", "source_record_id"], "NOT_RECORDED"),
                "source_organization": source or "NOT_RECORDED",
                "source_type": _pick(row, ["source_type"], "NOT_RECORDED"),
                "source_url_reference": primary_url or "NOT_RECORDED",
                "publication_date": _pick(row, ["source_publication_date", "publication_date"], "NOT_RECORDED"),
                "retrieval_date": _pick(row, ["source_retrieval_date", "retrieval_date"], "NOT_RECORDED"),
                "source_native_incident_terminology": source_native_label(row),
                "SOURCE_NATIVE_LABEL": source_native_label(row),
                "MAPPED_STUDY_CLASS": proposed_class,
                "event_datetime": _pick(row, ["event_date_time", "start_utc", "event_time"], "NOT_RECORDED"),
                "event_end_time": _pick(row, ["event_end_time", "end_time", "end_utc"], "NOT_RECORDED"),
                "affected_asn": _pick(row, ["affected_asn", "asn", "affected_asns"], "NOT_RECORDED"),
                "origin_asn": _pick(row, ["origin_asn_where_applicable", "origin_asn", "origin_asns"], "NOT_RECORDED"),
                "affected_prefixes": _pick(row, ["prefixes_available_from_source", "prefix", "affected_prefixes"], "NOT_RECORDED"),
                "affected_prefix_count": _pick(row, ["affected_prefix_count_reported", "prefix_count"], "NOT_RECORDED"),
                "complete_prefix_metadata_available": _pick(row, ["full_prefix_list_available"], "NOT_RECORDED"),
                "partial_prefix_metadata": _pick(row, ["partial_prefix_metadata"], "NOT_RECORDED"),
                "source_evidence_supporting_label": _pick(
                    row,
                    [
                        "source_derived_evidence_summary",
                        "evidence_summary",
                        "exact_source_evidence_available_to_reviewer",
                        "exact_evidence",
                    ],
                    "NOT_RECORDED",
                ),
                "corroborating_sources": corroborating or "NOT_RECORDED",
                "routeviews_archive_available": _boolish_yes(
                    _pick(row, ["routeviews_archive_availability_confirmed", "routeviews_availability"])
                ),
                "overlap_status_original_1419": _pick(
                    row,
                    ["overlap_status_with_original_1419_corpus", "overlap_status"],
                    "NOT_RECORDED",
                ),
                "primary_label_source_is_non_cloudflare": "NO" if "cloudflare" in source.lower() else "YES",
                "cloudflare_secondary_only_if_present": cloudflare_secondary,
                "source_artifact": str(SOURCE_DIR / "v2_expert_adjudication_form.csv"),
                "verification_status": "PENDING_HUMAN_SOURCE_VERIFICATION",
            }
        )
    return pd.DataFrame(records)


def make_human_qc_form(matrix: pd.DataFrame) -> pd.DataFrame:
    df = matrix.copy()
    df["source_label_verification_allowed"] = (
        "SOURCE_NATIVE_LABEL_VERIFIED | SOURCE_NATIVE_LABEL_NOT_VERIFIED | AMBIGUOUS | INSUFFICIENT_EVIDENCE"
    )
    df["event_identity_verification_allowed"] = (
        "EVENT_IDENTITY_VERIFIED | EVENT_IDENTITY_AMBIGUOUS | EVENT_IDENTITY_NOT_VERIFIED"
    )
    df["routing_reconstruction_adequacy_allowed"] = (
        "SUFFICIENT | SUFFICIENT_WITH_DOCUMENTED_LIMITATION | INSUFFICIENT"
    )
    df["independence_assessment_allowed"] = "NEW_INDEPENDENT_EVENT | POSSIBLE_EXISTING_EVENT | NOT_INDEPENDENT | REVIEW_REQUIRED"
    df["human_qc_decision_allowed"] = (
        "ACCEPT_FOR_IEC | ACCEPT_WITH_LIMITATION | REJECT | AMBIGUOUS | INSUFFICIENT_EVIDENCE"
    )
    for reviewer in ("a", "b"):
        df[f"reviewer_{reviewer}_id"] = ""
        df[f"reviewer_{reviewer}_source_label_verification"] = ""
        df[f"reviewer_{reviewer}_event_identity_verification"] = ""
        df[f"reviewer_{reviewer}_routing_reconstruction_adequacy"] = ""
        df[f"reviewer_{reviewer}_independence_assessment"] = ""
        df[f"reviewer_{reviewer}_human_qc_decision"] = ""
        df[f"reviewer_{reviewer}_comment"] = ""
        df[f"reviewer_{reviewer}_review_date"] = ""
    return df


def reviewer_complete(form: pd.DataFrame) -> bool:
    required = [
        "reviewer_a_human_qc_decision",
        "reviewer_a_source_label_verification",
        "reviewer_a_event_identity_verification",
        "reviewer_a_routing_reconstruction_adequacy",
        "reviewer_a_independence_assessment",
    ]
    return all(col in form.columns and form[col].astype(str).str.strip().replace("nan", "").ne("").any() for col in required)


def make_exclusion_ledger(matrix: pd.DataFrame, human_complete: bool) -> pd.DataFrame:
    rows = []
    for _, row in matrix.iterrows():
        rows.append(
            {
                "iec_candidate_id": row["iec_candidate_id"],
                "mapped_study_class": row["MAPPED_STUDY_CLASS"],
                "prelock_status": "PENDING_HUMAN_SOURCE_VERIFICATION" if not human_complete else "READY_FOR_ACCEPTANCE_RULE_APPLICATION",
                "exclusion_category": "NOT_YET_ADJUDICATED" if not human_complete else "",
                "exclusion_reason": (
                    "Human QC fields are blank; final IEC roster and evaluation lock must not be created."
                    if not human_complete
                    else ""
                ),
                "primary_label_source_is_non_cloudflare": row["primary_label_source_is_non_cloudflare"],
                "routeviews_archive_available": row["routeviews_archive_available"],
                "overlap_status_original_1419": row["overlap_status_original_1419"],
            }
        )
    return pd.DataFrame(rows)


def write_summary(matrix: pd.DataFrame, human_complete: bool, checksums: pd.DataFrame) -> None:
    counts = matrix["MAPPED_STUDY_CLASS"].value_counts().to_dict()
    status = "WAITING_FOR_HUMAN_SOURCE_VERIFICATION" if not human_complete else "HUMAN_QC_PRESENT_REQUIRES_LOCK_STEP"
    lines = [
        "# V2 IEC Pre-Lock Package Summary",
        "",
        f"Generated UTC: {datetime.now(timezone.utc).isoformat()}",
        "",
        "Scope: source-native non-Cloudflare independent external confirmation package.",
        "",
        "## Candidate Counts",
        f"- Hijack: {counts.get('Hijack', 0)}",
        f"- Leak: {counts.get('Leak', 0)}",
        f"- Outage: {counts.get('Outage', 0)}",
        f"- Total: {len(matrix)}",
        "",
        "## Human QC Status",
        (
            "- Completed human QC fields were not found. The final IEC roster, evaluation lock, and model scoring were not created."
            if not human_complete
            else "- Human QC fields appear present; apply the locked acceptance rule in a separate explicit lock step."
        ),
        "",
        "## Non-Destructive Controls",
        "- No model scoring was performed.",
        "- Validation and Final Holdout were not accessed.",
        "- Prior V1/V2 audit artifacts were read only.",
        "- Cloudflare is not used as a primary label source in the IEC source-native matrix.",
        "",
        "## Created Artifacts",
    ]
    for _, row in checksums.iterrows():
        lines.append(f"- `{row['file']}` SHA-256 `{row['sha256']}`")
    lines.extend(["", f"Final status: `{status}`", ""])
    (OUT_DIR / "v2_IEC_prelock_status_v1.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    candidates = load_candidates()
    matrix = make_source_native_matrix(candidates)
    human_form = make_human_qc_form(matrix)
    human_complete = reviewer_complete(human_form)
    ledger = make_exclusion_ledger(matrix, human_complete)

    outputs = {
        "v2_IEC_source_native_event_matrix.csv": matrix,
        "v2_IEC_human_QC_form.csv": human_form,
        "v2_IEC_exclusion_ledger.csv": ledger,
    }
    for name, df in outputs.items():
        df.to_csv(OUT_DIR / name, index=False)

    if not human_complete:
        (OUT_DIR / "v2_IEC_final_roster_NOT_CREATED.md").write_text(
            "# V2 IEC Final Roster Not Created\n\n"
            "Human QC fields are blank in the available review package. Per the locked V2 IEC instructions, "
            "the final roster, evaluation lock, and any model scoring must wait until human source verification is complete.\n\n"
            "Status: `WAITING_FOR_HUMAN_SOURCE_VERIFICATION`\n",
            encoding="utf-8",
        )

    manifest = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "source_candidate_artifact": str(SOURCE_DIR / "v2_expert_adjudication_form.csv"),
        "candidate_count": int(len(matrix)),
        "class_counts": matrix["MAPPED_STUDY_CLASS"].value_counts().to_dict(),
        "human_qc_complete": bool(human_complete),
        "final_roster_created": False,
        "evaluation_lock_created": False,
        "model_scoring_performed": False,
        "validation_accessed": False,
        "final_holdout_accessed": False,
        "status": "WAITING_FOR_HUMAN_SOURCE_VERIFICATION" if not human_complete else "HUMAN_QC_PRESENT_REQUIRES_LOCK_STEP",
    }
    manifest_path = OUT_DIR / "v2_IEC_manifest_v1.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    checksum_rows = []
    for path in sorted(OUT_DIR.glob("v2_IEC_*")):
        if path.is_file() and path.name != "v2_IEC_result_checksums_v1.csv":
            checksum_rows.append({"file": path.name, "sha256": _sha256(path)})
    checksums = pd.DataFrame(checksum_rows)
    checksum_path = OUT_DIR / "v2_IEC_result_checksums_v1.csv"
    checksums.to_csv(checksum_path, index=False)

    # Recompute checksums after adding the checksum file itself only for the summary view.
    summary_checksums = pd.concat(
        [
            checksums,
            pd.DataFrame([{"file": checksum_path.name, "sha256": _sha256(checksum_path)}]),
        ],
        ignore_index=True,
    )
    write_summary(matrix, human_complete, summary_checksums)

    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
