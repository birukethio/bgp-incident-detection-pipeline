from __future__ import annotations

import csv
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "experiments" / "independent_validation_audit_v2"
FORM = OUT / "v2_expert_adjudication_form.csv"

CONFIRM_MAP = {
    "Hijack": "CONFIRM_HIJACK",
    "Leak": "CONFIRM_LEAK",
    "Outage": "CONFIRM_OUTAGE",
}
ACCEPTABLE_METADATA = {
    "SUFFICIENT_FOR_ROUTING_RECONSTRUCTION",
    "SUFFICIENT_WITH_DOCUMENTED_LIMITATION",
}


def clean(value: object) -> str:
    if pd.isna(value):
        return ""
    return str(value).strip()


def write_csv(path: Path, rows: list[dict], fieldnames: list[str] | None = None) -> None:
    if fieldnames is None:
        fieldnames = []
        for row in rows:
            for key in row:
                if key not in fieldnames:
                    fieldnames.append(key)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def reviewer_decision(row: pd.Series, prefix: str) -> dict:
    return {
        "class": clean(row.get(f"{prefix}_expert_class_assessment")),
        "metadata": clean(row.get(f"{prefix}_metadata_adequacy")),
        "independence": clean(row.get(f"{prefix}_independence_assessment")),
        "comment": clean(row.get(f"{prefix}_expert_comment")),
        "reviewer": clean(row.get(f"{prefix}_expert_name_or_id")),
        "date": clean(row.get(f"{prefix}_review_date")),
    }


def is_complete(decision: dict) -> bool:
    return bool(decision["class"] and decision["metadata"] and decision["independence"])


def is_accept(row: pd.Series, decision: dict) -> bool:
    return (
        decision["class"] == CONFIRM_MAP.get(clean(row["proposed_class"]))
        and decision["metadata"] in ACCEPTABLE_METADATA
        and decision["independence"] == "INDEPENDENT"
    )


def main() -> None:
    df = pd.read_csv(FORM, dtype=str)
    rows = []
    accepted_rows = []
    class_pairs = []
    any_completed = False

    for _, row in df.iterrows():
        a = reviewer_decision(row, "reviewer_a")
        b = reviewer_decision(row, "reviewer_b")
        a_complete = is_complete(a)
        b_complete = is_complete(b)
        any_completed = any_completed or a_complete or b_complete
        class_agree = ""
        full_agree = ""
        final_status = "PENDING_HUMAN_REVIEW"
        resolution = "NOT_RESOLVED_NO_COMPLETED_REVIEW"
        final_class = ""
        final_metadata = ""
        final_independence = ""
        include = "NO"

        if a_complete and b_complete:
            class_pairs.append((a["class"], b["class"]))
            class_agree = "YES" if a["class"] == b["class"] else "NO"
            full_agree = "YES" if (a["class"], a["metadata"], a["independence"]) == (b["class"], b["metadata"], b["independence"]) else "NO"
            if full_agree == "YES":
                final_class, final_metadata, final_independence = a["class"], a["metadata"], a["independence"]
                if is_accept(row, a):
                    final_status = "ACCEPT"
                    include = "YES"
                else:
                    final_status = "EXCLUDE"
                resolution = "TWO_REVIEWER_AGREEMENT"
            else:
                final_status = "REVIEW_REQUIRED"
                resolution = "REVIEWER_DISAGREEMENT_REQUIRES_ADJUDICATION"
        elif a_complete or b_complete:
            d = a if a_complete else b
            final_class, final_metadata, final_independence = d["class"], d["metadata"], d["independence"]
            final_status = "PROVISIONAL_SINGLE_REVIEWER_ONLY"
            resolution = "SECOND_REVIEWER_OR_ADJUDICATOR_REQUIRED"

        rec = {
            "candidate_id": clean(row["candidate_id"]),
            "proposed_class": clean(row["proposed_class"]),
            "reviewer_a_class": a["class"],
            "reviewer_a_metadata": a["metadata"],
            "reviewer_a_independence": a["independence"],
            "reviewer_b_class": b["class"],
            "reviewer_b_metadata": b["metadata"],
            "reviewer_b_independence": b["independence"],
            "reviewer_class_agreement": class_agree,
            "reviewer_full_agreement": full_agree,
            "final_class_assessment": final_class,
            "final_metadata_adequacy": final_metadata,
            "final_independence_assessment": final_independence,
            "final_adjudication_status": final_status,
            "include_in_v2_final_adjudicated_roster": include,
            "resolution_basis": resolution,
            "expert_comment_combined": " | ".join(x for x in [a["comment"], b["comment"]] if x),
        }
        rows.append(rec)
        if include == "YES":
            accepted = row.to_dict()
            accepted.update(rec)
            accepted_rows.append(accepted)

    roster_fields = [
        "candidate_id", "proposed_class", "event_date_time", "event_end_time",
        "affected_asn", "origin_asn_where_applicable", "prefixes_available_from_source",
        "affected_prefix_count_reported", "full_prefix_list_available", "partial_prefix_metadata",
        "primary_evidence_source", "primary_source_url_or_reference", "source_type",
        "source_event_identifier", "routeviews_archive_availability_confirmed",
        "overlap_status_with_original_1419_corpus", "final_class_assessment",
        "final_metadata_adequacy", "final_independence_assessment", "resolution_basis",
    ]
    write_csv(OUT / "v2_final_adjudicated_roster.csv", accepted_rows, roster_fields)
    write_csv(OUT / "v2_expert_disagreement_resolution.csv", rows)

    total = len(df)
    completed_a = sum(is_complete(reviewer_decision(r, "reviewer_a")) for _, r in df.iterrows())
    completed_b = sum(is_complete(reviewer_decision(r, "reviewer_b")) for _, r in df.iterrows())
    both_complete = sum(
        is_complete(reviewer_decision(r, "reviewer_a")) and is_complete(reviewer_decision(r, "reviewer_b"))
        for _, r in df.iterrows()
    )
    disagreement = sum(r["reviewer_full_agreement"] == "NO" for r in rows)
    raw_agreement = ""
    kappa = ""
    if class_pairs:
        raw = sum(a == b for a, b in class_pairs) / len(class_pairs)
        raw_agreement = f"{raw:.6f}"
        labels = sorted(set([x for pair in class_pairs for x in pair]))
        n = len(class_pairs)
        p_a = Counter(a for a, _ in class_pairs)
        p_b = Counter(b for _, b in class_pairs)
        pe = sum((p_a[l] / n) * (p_b[l] / n) for l in labels)
        kappa = "NA" if pe == 1 else f"{(raw - pe) / (1 - pe):.6f}"
    else:
        raw_agreement = "NA_NO_COMPLETED_REVIEW_PAIRS"
        kappa = "NA_NO_COMPLETED_REVIEW_PAIRS"

    final_counts = Counter(r.get("proposed_class", "") for r in accepted_rows)
    metadata_limited = sum(r.get("final_metadata_adequacy") == "SUFFICIENT_WITH_DOCUMENTED_LIMITATION" for r in accepted_rows)
    routeviews_available = sum(clean(r.get("routeviews_archive_availability_confirmed")) == "YES" for r in accepted_rows)
    source_dist = Counter(clean(r.get("source_type")) for r in accepted_rows)
    insufficient = sum(
        "INSUFFICIENT" in clean(r["reviewer_a_class"]) or "INSUFFICIENT" in clean(r["reviewer_b_class"])
        or clean(r["reviewer_a_metadata"]) == "INSUFFICIENT" or clean(r["reviewer_b_metadata"]) == "INSUFFICIENT"
        for r in rows
    )
    ambiguous = sum(clean(r["reviewer_a_class"]) == "AMBIGUOUS" or clean(r["reviewer_b_class"]) == "AMBIGUOUS" for r in rows)
    excluded = total - len(accepted_rows)

    agreement_md = [
        "# V2 Expert Agreement Summary",
        "",
        f"Generated UTC: {datetime.now(timezone.utc).isoformat()}",
        "",
        f"- Review records: {total}",
        f"- Reviewer A complete records: {completed_a}",
        f"- Reviewer B complete records: {completed_b}",
        f"- Records with both reviewers complete: {both_complete}",
        f"- Disagreement count between reviewers: {disagreement}",
        f"- Raw inter-rater agreement: {raw_agreement}",
        f"- Cohen's kappa: {kappa}",
        "",
        "No automatic class adjudication was performed beyond applying the locked acceptance rule to completed matching human decisions.",
    ]
    if not any_completed:
        agreement_md.append("")
        agreement_md.append("Status: `BLOCKED_NO_COMPLETED_EXPERT_REVIEW`")
    (OUT / "v2_expert_agreement_summary.md").write_text("\n".join(agreement_md) + "\n", encoding="utf-8")

    summary = [
        "# V2 Final Adjudication Summary",
        "",
        f"Generated UTC: {datetime.now(timezone.utc).isoformat()}",
        "",
        "Locked acceptance rule: confirmed class + sufficient or sufficient-with-documented-limitation metadata + independent status.",
        "",
        f"- Final Hijack count: {final_counts.get('Hijack', 0)}",
        f"- Final Leak count: {final_counts.get('Leak', 0)}",
        f"- Final Outage count: {final_counts.get('Outage', 0)}",
        f"- Excluded count: {excluded}",
        f"- Ambiguous count: {ambiguous}",
        f"- Insufficient-evidence count: {insufficient}",
        f"- Metadata-limited count: {metadata_limited}",
        f"- Disagreement count between reviewers: {disagreement}",
        f"- Raw inter-rater agreement: {raw_agreement}",
        f"- Cohen's kappa: {kappa}",
        f"- Final RouteViews-available count: {routeviews_available}",
        "",
        "## Final Source Distribution",
    ]
    if source_dist:
        for src, n in sorted(source_dist.items()):
            summary.append(f"- {src}: {n}")
    else:
        summary.append("- None: no incident met the final acceptance rule because no completed expert-review decisions are present.")
    summary.extend([
        "",
        "## Disposition",
        "`FINAL_ADJUDICATED_ROSTER_NOT_BUILT_NO_COMPLETED_EXPERT_REVIEW`",
        "",
        "No model scoring was performed. Validation and Final Holdout were not accessed. The V2 evaluation lock was not created.",
    ])
    (OUT / "v2_final_adjudication_summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
