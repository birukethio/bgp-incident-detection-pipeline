from __future__ import annotations

import csv
import hashlib
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "experiments" / "independent_validation_audit_v2"
HL = OUT / "v2_hijack_leak_expansion_candidates.csv"
BASE = OUT / "v2_candidate_independent_events.csv"

CLASS_CHOICES = "CONFIRM_HIJACK | CONFIRM_LEAK | CONFIRM_OUTAGE | AMBIGUOUS | INSUFFICIENT_EVIDENCE | REJECT"
METADATA_CHOICES = "SUFFICIENT_FOR_ROUTING_RECONSTRUCTION | SUFFICIENT_WITH_DOCUMENTED_LIMITATION | INSUFFICIENT"
INDEPENDENCE_CHOICES = "INDEPENDENT | POSSIBLE_EXISTING_EVENT | REVIEW_REQUIRED"


def source_type(source: str) -> str:
    s = str(source).lower()
    if "ioda" in s:
        return "IODA"
    if "manrs" in s or "internet society" in s:
        return "MANRS"
    if "qrator" in s:
        return "Qrator"
    if "kentik" in s:
        return "Kentik"
    if "bgphorizon" in s:
        return "BGPHorizon"
    if "routecause" in s:
        return "RouteCause"
    if "nanog" in s or "nog" in s:
        return "NOG/NANOG"
    if "operator" in s or "affected-network" in s:
        return "operator/affected-network statement"
    return "other"


def prefix_count(prefix: str, evidence: str) -> str:
    text = f"{prefix} {evidence}"
    patterns = [
        r"(\d[\d,]*)\s+(?:hijacked|leaked|affected|announced)?\s*prefixes",
        r"prefix(?:\s+count)?\s*[:=]\s*(\d[\d,]*)",
        r"(\d[\d,]*)\s+conflicts",
    ]
    for pat in patterns:
        m = re.search(pat, text, flags=re.IGNORECASE)
        if m:
            return m.group(1).replace(",", "")
    cidrs = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b|\b[0-9a-fA-F:]+::/[0-9]{1,3}\b", text)
    if cidrs:
        return str(len(set(cidrs)))
    return ""


def full_prefix_list_available(prefix: str, limitation: str) -> tuple[str, str]:
    text = f"{prefix} {limitation}".lower()
    if "exact list not recovered" in text or "full prefix list" in text or "prefix count only" in text:
        return "NO", "PARTIAL_PREFIX_METADATA"
    if "prefix list not source-native" in text:
        return "NO", "PARTIAL_PREFIX_METADATA"
    if "exact prefix list not recovered" in text:
        return "NO", "PARTIAL_PREFIX_METADATA"
    if "prefixes" in text and ("multiple" in text or "exact" not in text):
        return "PARTIAL", "PARTIAL_PREFIX_METADATA"
    if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b|\b[0-9a-fA-F:]+::/[0-9]{1,3}\b", prefix):
        return "YES_OR_EXAMPLES_AVAILABLE", "NO"
    return "NO", "PARTIAL_PREFIX_METADATA"


def origin_asn_where_applicable(row: dict) -> str:
    cls = row["proposed_class"]
    asn = str(row.get("asn", ""))
    if cls == "Hijack":
        if "victim" in asn.lower():
            return asn
        return "See affected/hijacker ASN text"
    if cls == "Leak":
        return "Origin ASNs embedded in leaked prefixes/AS paths where source provides them; see evidence summary"
    return "Not applicable / outage AS scope"


def affected_asn(row: dict) -> str:
    return str(row.get("asn", ""))


def load_accepted() -> pd.DataFrame:
    hl = pd.read_csv(HL, dtype=str).fillna("")
    hl = hl[(hl["proposed_class"].isin(["Hijack", "Leak"])) & (hl["adjudication_status"] == "ACCEPT") & (hl["overlap_status"] == "NEW_INDEPENDENT_EVENT")].copy()
    hl_norm = pd.DataFrame({
        "candidate_id": hl["candidate_id"],
        "proposed_class": hl["proposed_class"],
        "event_date_time": hl["event_date_time"],
        "end_time": hl["end_time"],
        "asn": hl["asn"],
        "prefix": hl["prefix"],
        "primary_source": hl["primary_source"],
        "primary_source_url": hl["source_url"],
        "source_publication_date": hl["source_publication_date"],
        "source_event_identifier": hl["source_event_identifier"],
        "evidence_summary": hl["evidence_summary"],
        "exact_evidence": hl["exact_evidence"],
        "corroborating_sources": hl["corroborating_sources"],
        "routeviews_availability": hl["routeviews_availability"],
        "overlap_status": hl["overlap_status"],
        "metadata_limitations": hl["metadata_limitations"],
    })

    base = pd.read_csv(BASE, dtype=str).fillna("")
    out = base[(base["proposed_class"] == "Outage") & (base["adjudication_status"] == "ACCEPT") & (base["overlap_status"] == "NEW_INDEPENDENT_EVENT")].copy()
    out_norm = pd.DataFrame({
        "candidate_id": out["candidate_id"],
        "proposed_class": out["proposed_class"],
        "event_date_time": out["event_date_time"],
        "end_time": out["end_time"],
        "asn": out["asn"],
        "prefix": out["prefix"],
        "primary_source": out["primary_evidence_source"],
        "primary_source_url": out["primary_source_url"],
        "source_publication_date": "source dataset",
        "source_event_identifier": out["candidate_id"],
        "evidence_summary": out["evidence_summary"],
        "exact_evidence": out["adjudication_rationale"],
        "corroborating_sources": out["secondary_evidence_sources"],
        "routeviews_availability": out["routeviews_availability"],
        "overlap_status": out["overlap_status"],
        "metadata_limitations": "AS-scoped outage; prefix list not source-native.",
    })
    df = pd.concat([hl_norm, out_norm], ignore_index=True)
    return df.sort_values(["proposed_class", "candidate_id"]).reset_index(drop=True)


def build_records(df: pd.DataFrame) -> list[dict]:
    records = []
    for _, r in df.iterrows():
        d = r.to_dict()
        full_prefix, partial_flag = full_prefix_list_available(d["prefix"], d["metadata_limitations"])
        count = prefix_count(d["prefix"], f"{d['evidence_summary']} {d['exact_evidence']}")
        prefix_summary = d["prefix"]
        if partial_flag == "PARTIAL_PREFIX_METADATA":
            prefix_summary = f"{d['prefix']} | limitation: {d['metadata_limitations']}"
        rec = {
            "candidate_id": d["candidate_id"],
            "proposed_class": d["proposed_class"],
            "event_date_time": d["event_date_time"],
            "event_end_time": d["end_time"],
            "affected_asn": affected_asn(d),
            "origin_asn_where_applicable": origin_asn_where_applicable(d),
            "prefixes_available_from_source": d["prefix"],
            "affected_prefix_count_reported": count,
            "full_prefix_list_available": full_prefix,
            "partial_prefix_metadata": "YES" if partial_flag == "PARTIAL_PREFIX_METADATA" else "NO",
            "partial_prefix_metadata_summary": prefix_summary if partial_flag == "PARTIAL_PREFIX_METADATA" else "Full or example prefix metadata available from source row.",
            "primary_evidence_source": d["primary_source"],
            "primary_source_url_or_reference": d["primary_source_url"],
            "source_type": source_type(d["primary_source"]),
            "source_publication_date": d["source_publication_date"],
            "source_event_identifier": d["source_event_identifier"],
            "source_derived_evidence_summary": d["evidence_summary"],
            "exact_source_evidence_available_to_reviewer": d["exact_evidence"],
            "corroborating_sources": d["corroborating_sources"],
            "routeviews_archive_availability_confirmed": "YES" if "ROUTEVIEWS" in d["routeviews_availability"] else "NO",
            "routeviews_availability_notes": d["routeviews_availability"],
            "overlap_status_with_original_1419_corpus": d["overlap_status"],
            "reviewer_class_assessment_choices": CLASS_CHOICES,
            "reviewer_metadata_adequacy_choices": METADATA_CHOICES,
            "reviewer_independence_assessment_choices": INDEPENDENCE_CHOICES,
            "reviewer_a_expert_name_or_id": "",
            "reviewer_a_expert_class_assessment": "",
            "reviewer_a_metadata_adequacy": "",
            "reviewer_a_independence_assessment": "",
            "reviewer_a_expert_comment": "",
            "reviewer_a_review_date": "",
            "reviewer_b_expert_name_or_id": "",
            "reviewer_b_expert_class_assessment": "",
            "reviewer_b_metadata_adequacy": "",
            "reviewer_b_independence_assessment": "",
            "reviewer_b_expert_comment": "",
            "reviewer_b_review_date": "",
        }
        records.append(rec)
    return records


def write_csv(path: Path, rows: list[dict]) -> None:
    keys = []
    for row in rows:
        for k in row:
            if k not in keys:
                keys.append(k)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)


def write_packets(records: list[dict]) -> None:
    lines = [
        "# V2 Independent Validation Pre-Lock Expert Adjudication Packets\n\n",
        "Purpose: human expert review of proposed independent confirmation incidents before any V2 evaluation lock.\n\n",
        "Blinding: this packet contains only source-derived incident evidence and reviewer fields. It intentionally omits all downstream experimental artifacts.\n\n",
        "Reviewer choices:\n",
        f"- Class assessment: `{CLASS_CHOICES}`\n",
        f"- Metadata adequacy: `{METADATA_CHOICES}`\n",
        f"- Independence assessment: `{INDEPENDENCE_CHOICES}`\n\n",
    ]
    for r in records:
        lines.extend([
            f"## {r['candidate_id']}\n",
            f"- Proposed class: {r['proposed_class']}\n",
            f"- Event time: {r['event_date_time']} to {r['event_end_time']}\n",
            f"- Affected ASN(s): {r['affected_asn']}\n",
            f"- Origin ASN where applicable: {r['origin_asn_where_applicable']}\n",
            f"- Prefix metadata from source: {r['prefixes_available_from_source']}\n",
            f"- Affected prefix count reported: {r['affected_prefix_count_reported'] or 'Not explicitly reported'}\n",
            f"- Full prefix list available: {r['full_prefix_list_available']}\n",
            f"- Partial prefix metadata: {r['partial_prefix_metadata']}\n",
            f"- Partial-prefix note: {r['partial_prefix_metadata_summary']}\n",
            f"- Primary source: {r['primary_evidence_source']}\n",
            f"- Source type: {r['source_type']}\n",
            f"- Source URL/reference: {r['primary_source_url_or_reference']}\n",
            f"- Source event identifier: {r['source_event_identifier']}\n",
            f"- Source-derived evidence summary: {r['source_derived_evidence_summary']}\n",
            f"- Exact evidence provided to reviewer: {r['exact_source_evidence_available_to_reviewer']}\n",
            f"- Corroborating source(s): {r['corroborating_sources']}\n",
            f"- RouteViews archive availability confirmed: {r['routeviews_archive_availability_confirmed']} ({r['routeviews_availability_notes']})\n",
            f"- Overlap status with original 1,419-event corpus: {r['overlap_status_with_original_1419_corpus']}\n",
            "\nReviewer A decision: ____________________\n\n",
            "Reviewer B decision: ____________________\n\n",
        ])
    (OUT / "v2_expert_adjudication_packets.md").write_text("".join(lines), encoding="utf-8")


def sha(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def main() -> None:
    df = load_accepted()
    records = build_records(df)

    write_csv(OUT / "v2_expert_adjudication_form.csv", records)
    write_packets(records)

    source_rows = []
    by_source = defaultdict(list)
    for r in records:
        by_source[(r["source_type"], r["primary_evidence_source"], r["primary_source_url_or_reference"])].append(r["candidate_id"])
    for (stype, source, url), ids in sorted(by_source.items()):
        classes = sorted({next(r["proposed_class"] for r in records if r["candidate_id"] == cid) for cid in ids})
        source_rows.append({
            "source_type": stype,
            "primary_evidence_source": source,
            "source_url_or_reference": url,
            "candidate_count": len(ids),
            "classes": "; ".join(classes),
            "candidate_ids": "; ".join(ids),
        })
    write_csv(OUT / "v2_expert_adjudication_source_index.csv", source_rows)

    partial = [r for r in records if r["partial_prefix_metadata"] == "YES"]
    write_csv(OUT / "v2_partial_prefix_metadata_cases.csv", partial)

    roster_cols = [
        "candidate_id", "proposed_class", "event_date_time", "event_end_time",
        "affected_asn", "prefixes_available_from_source", "affected_prefix_count_reported",
        "partial_prefix_metadata", "primary_evidence_source", "source_type",
        "routeviews_archive_availability_confirmed", "overlap_status_with_original_1419_corpus",
    ]
    write_csv(OUT / "v2_prelock_candidate_roster.csv", [{k: r[k] for k in roster_cols} for r in records])

    outputs = [
        "v2_expert_adjudication_form.csv",
        "v2_expert_adjudication_packets.md",
        "v2_expert_adjudication_source_index.csv",
        "v2_partial_prefix_metadata_cases.csv",
        "v2_prelock_candidate_roster.csv",
    ]
    checksum_rows = [{"file": f, "sha256": sha(OUT / f)} for f in outputs]
    write_csv(OUT / "v2_expert_adjudication_package_checksums.csv", checksum_rows)

    counts = Counter(r["proposed_class"] for r in records)
    partial_counts = Counter(r["proposed_class"] for r in partial)
    (OUT / "v2_expert_adjudication_package_summary.md").write_text(
        "\n".join([
            "# V2 Expert Adjudication Package Summary",
            "",
            f"Generated UTC: {datetime.now(timezone.utc).isoformat()}",
            "",
            "This is a human-review package only. It contains source-derived incident evidence and blank expert-review fields; no downstream experimental artifacts were included.",
            "",
            "## Candidate Counts",
            f"- Hijack: {counts.get('Hijack', 0)}",
            f"- Leak: {counts.get('Leak', 0)}",
            f"- Outage: {counts.get('Outage', 0)}",
            f"- Total: {sum(counts.values())}",
            "",
            "## Partial Prefix Metadata Cases",
            f"- Hijack: {partial_counts.get('Hijack', 0)}",
            f"- Leak: {partial_counts.get('Leak', 0)}",
            f"- Outage: {partial_counts.get('Outage', 0)}",
            f"- Total: {len(partial)}",
            "",
            "## Review Status",
            "No automatic adjudication was performed. The V2 evaluation lock was not created.",
            "",
        ]),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
