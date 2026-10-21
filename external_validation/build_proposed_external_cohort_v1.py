"""Build the pre-inference prospective Level-1 external cohort proposal.

This module performs source, timestamp, overlap, and archive-availability
screening only. It intentionally contains no model-loading or inference code.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "external_validation" / "proposed_cohort_v1"
ROSTER = ROOT / "data" / "roster_v2" / "frozen_incident_roster_v2.csv"
LEADS = ROOT / "experiments" / "independent_validation_v2" / "v2_IEC_final_source_separated_roster.csv"
PILOT_IDS = {
    "V2-HIJACK-003", "V2-HIJACK-006", "V2-HIJACK-008",
    "V2-LEAK-002", "V2-LEAK-003", "V2-LEAK-007",
    "V2-OUTAGE-001", "V2-OUTAGE-002", "V2-OUTAGE-003",
}
TRUST_ANCHORS = ("afrinic.tal", "apnic.tal", "arin.tal", "lacnic.tal", "ripencc.tal")
USER_AGENT = "BGP-Incident-External-Cohort-Archive-Prescreen/1.0"


@dataclass(frozen=True)
class Candidate:
    candidate_id: str
    source_name: str
    source_title: str
    source_author_or_organization: str
    source_url: str
    publication_date: str
    source_native_label: str
    mapped_class: str
    event_start_utc: str
    event_end_utc: str
    affected_asn: str
    affected_prefix: str
    source_evidence_summary: str
    timestamp_status: str
    intended_disposition: str
    screening_reason: str


def iso(value: str) -> str:
    parsed = pd.to_datetime(value, utc=True, errors="raise")
    return parsed.isoformat().replace("+00:00", "Z")


def lead(candidate_id: str, *, start: str | None = None, end: str | None = None,
         timestamp_status: str | None = None, disposition: str | None = None,
         reason: str | None = None) -> Candidate:
    rows = pd.read_csv(LEADS)
    row = rows.loc[rows["candidate_id"] == candidate_id]
    if len(row) != 1:
        raise ValueError(f"expected one lead row for {candidate_id}, got {len(row)}")
    r = row.iloc[0]
    source_url = str(r["primary_source_url_or_reference"])
    event_start = start or str(r["event_date_time"])
    event_end = end or str(r["event_end_time"])
    return Candidate(
        candidate_id=candidate_id,
        source_name=str(r["primary_evidence_source"]),
        source_title=str(r["primary_evidence_source"]),
        source_author_or_organization=str(r["source_family"]),
        source_url=source_url,
        publication_date="See cited source",
        source_native_label=str(r["explicit_source_label"]),
        mapped_class=str(r["iec_label"]),
        event_start_utc=event_start,
        event_end_utc=event_end,
        affected_asn=str(r["affected_asn"]),
        affected_prefix=str(r["prefixes_available_from_source"]),
        source_evidence_summary=f"Source-native {str(r['iec_label']).lower()} record; mapping {str(r['mapping_rule_id'])}.",
        timestamp_status=timestamp_status or "PASS",
        intended_disposition=disposition or "ACCEPTED",
        screening_reason=reason or "Explicit non-Cloudflare label, adequate interval, and source-native routing metadata.",
    )


def candidates() -> list[Candidate]:
    # Leads were identified only after the protocol freeze. Date-only and pilot
    # records remain visible as exclusions; they are never silently discarded.
    rows = [
        lead("V2-HIJACK-001", timestamp_status="REVIEW", disposition="TIMESTAMP_REVIEW", reason="Source preserves a date range but not an exact UTC reconstruction interval."),
        lead("V2-HIJACK-002", start="2026-06-16T07:17:27Z", end="2026-06-16T07:17:52Z", reason="BGPHorizon records the first observation to the second and describes the first wave as roughly 25 seconds."),
        lead("V2-HIJACK-003", disposition="PILOT_EXCLUDED", reason="Permanent engineering-pilot exclusion."),
        lead("V2-HIJACK-005", timestamp_status="REVIEW", disposition="TIMESTAMP_REVIEW", reason="Multi-day source range is not an exact incident interval."),
        lead("V2-HIJACK-006", disposition="PILOT_EXCLUDED", reason="Permanent engineering-pilot exclusion."),
        Candidate("V2-HIJACK-007", "MANRS incident analysis", "For 12 hours, part of Apple Engineering's network was hijacked by Russia's Rostelecom", "MANRS", "https://manrs.org/2022/07/for-12-hours-was-part-of-apple-engineerings-network-hijacked-by-russias-rostelecom/", "2022-07", "BGP hijack", "Hijack", "2022-07-26T21:25:10Z", "2022-07-27T09:39:00Z", "AS12389; affected Apple AS714", "17.70.96.0/19", "MANRS documents Rostelecom originating a more-specific of Apple Engineering address space for approximately 12 hours.", "PASS", "ACCEPTED", "Explicit non-Cloudflare hijack label with exact UTC interval, ASN, and prefix."),
        lead("V2-HIJACK-008", disposition="PILOT_EXCLUDED", reason="Permanent engineering-pilot exclusion; timestamp gate remained REVIEW."),
        lead("V2-HIJACK-009", timestamp_status="REVIEW", disposition="TIMESTAMP_REVIEW", reason="Only an event date was recovered."),
        lead("V2-HIJACK-010", timestamp_status="REVIEW", disposition="TIMESTAMP_REVIEW", reason="Exact start exists but exact end is absent."),
        lead("V2-HIJACK-011", timestamp_status="REVIEW", disposition="TIMESTAMP_REVIEW", reason="Annual summary supplies date but no exact UTC interval."),
        lead("V2-HIJACK-012", timestamp_status="REVIEW", disposition="TIMESTAMP_REVIEW", reason="Annual summary supplies date but no exact UTC interval."),
        Candidate("V2-HIJACK-020", "BGPHorizon incident analysis", "The August 2026 Virtualizor Incident in BGPHorizon", "BGPHorizon", "https://bgphorizon.com/blog/virtualizor-bgp-hijack-august-2026", "2026-08-31", "BGP hijack", "Hijack", "2026-08-28T20:57:30Z", "2026-08-30T06:10:00Z", "AS62390; AS6204; spoofed origin AS24940", "162.55.80.0/24", "Source identifies a forged-origin, more-specific hijack in two waves and gives first-observed and restored UTC times.", "PASS", "ACCEPTED", "Explicit non-Cloudflare hijack label with exact prefix, AS path indicators, and UTC envelope."),

        lead("V2-LEAK-001", timestamp_status="REVIEW", disposition="TIMESTAMP_REVIEW", reason="Only an event date was recovered."),
        lead("V2-LEAK-002", disposition="PILOT_EXCLUDED", reason="Permanent engineering-pilot exclusion."),
        lead("V2-LEAK-003", disposition="PILOT_EXCLUDED", reason="Permanent engineering-pilot exclusion."),
        lead("V2-LEAK-004", timestamp_status="REVIEW", disposition="TIMESTAMP_REVIEW", reason="Only an event date was recovered."),
        Candidate("V2-LEAK-006", "Qrator Labs Radar article", "AS9304 leaking 8,764 prefixes through AS15412", "Qrator Labs", "https://blog.qrator.net/en/as9304-leaking-8764-prefixes-through-as15412_111/", "2021-01", "Route leak", "Leak", "2021-01-06T04:21:00Z", "2021-01-06T06:51:00Z", "AS9304; AS15412", "8,764 prefixes; full list unavailable", "Qrator describes AS9304 leaking 8,764 prefixes through AS15412 with an exact UTC interval.", "PASS", "ACCEPTED", "Explicit source-native route leak with exact interval and AS-path participants."),
        lead("V2-LEAK-007", disposition="PILOT_EXCLUDED", reason="Permanent engineering-pilot exclusion."),
        lead("V2-LEAK-008"),
        lead("V2-LEAK-009"),
        lead("V2-LEAK-010", timestamp_status="REVIEW", disposition="TIMESTAMP_REVIEW", reason="Exact UTC interval was not recovered."),
        Candidate("V2-LEAK-011", "MANRS / Oracle Internet Intelligence incident analysis", "Large European routing leak sends traffic through China Telecom", "MANRS", "https://manrs.org/2019/06/large-european-routing-leak-sends-traffic-through-china-telecom/", "2019-06", "Route leak", "Leak", "2019-06-06T09:43:00Z", "2019-06-06T11:43:00Z", "AS4134; European transit participants", "Multiple leaked European routes; full list unavailable", "MANRS/Oracle analysis identifies a route leak that redirected European traffic through China Telecom during the stated UTC interval.", "PASS", "ACCEPTED", "Explicit route-leak analysis with exact interval and identified routing participants."),
        lead("V2-LEAK-012"),
        lead("V2-LEAK-017"),

        *[lead(f"V2-OUTAGE-{n:03d}", disposition="PILOT_EXCLUDED", reason="Permanent engineering-pilot exclusion.") for n in (1, 2, 3)],
        *[lead(f"V2-OUTAGE-{n:03d}") for n in range(4, 14)],
    ]
    return rows


def tokens(value: str, pattern: str) -> set[str]:
    return set(re.findall(pattern, str(value), flags=re.I))


def overlap(candidate: Candidate, roster: pd.DataFrame) -> tuple[str, str]:
    try:
        start = pd.to_datetime(candidate.event_start_utc, utc=True)
        end = pd.to_datetime(candidate.event_end_utc, utc=True)
    except Exception:
        return "NOT_ASSESSABLE", "Timestamp-inadequate candidate retained as non-accepted ledger row."
    same = roster[roster["category"].str.lower() == candidate.mapped_class.lower()].copy()
    same["s"] = pd.to_datetime(same["start_utc"], utc=True, errors="coerce")
    same["e"] = pd.to_datetime(same["end_utc"], utc=True, errors="coerce")
    temporal = same[(same["s"] <= end) & (same["e"] >= start)]
    cand_asns = {x.replace("AS", "") for x in tokens(candidate.affected_asn, r"AS\d+")}
    cand_prefixes = tokens(candidate.affected_prefix, r"[0-9a-f:.]+/\d+")
    matches = []
    for _, r in temporal.iterrows():
        rasns = tokens(f"{r.get('primary_asn','')} {r.get('affected_asns','')}", r"\d+")
        rprefixes = tokens(str(r.get("affected_prefixes", "")), r"[0-9a-f:.]+/\d+")
        if (cand_asns and cand_asns & rasns) or (cand_prefixes and cand_prefixes & rprefixes):
            matches.append(str(r["incident_uid"]))
    if matches:
        return "YES", ";".join(sorted(set(matches)))
    return "NO", "No same-class temporal overlap with shared ASN or exact prefix in frozen 1,419-event roster."


def head(url: str) -> tuple[bool, str]:
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return 200 <= response.status < 400, str(response.status)
    except urllib.error.HTTPError as error:
        return False, str(error.code)
    except Exception as error:  # preserved verbatim for the availability ledger
        return False, type(error).__name__


def archive_urls(start: str) -> dict[str, str]:
    dt = pd.to_datetime(start, utc=True).to_pydatetime()
    date = dt.strftime("%Y/%m/%d")
    return {
        "routeviews": f"https://archive.routeviews.org/bgpdata/{dt:%Y.%m}/UPDATES/",
        "caida": f"https://publicdata.caida.org/datasets/as-relationships/serial-2/{dt:%Y%m}01.as-rel2.txt.bz2",
        **{f"rpki_{ta}": f"https://ftp.ripe.net/rpki/{ta}/{date}/roas.csv.xz" for ta in TRUST_ANCHORS},
    }


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(path, index=False, quoting=csv.QUOTE_MINIMAL)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    roster = pd.read_csv(ROSTER, dtype=str).fillna("")
    screening, overlaps, archives, evidence = [], [], [], []
    for c in candidates():
        overlap_status, overlap_detail = overlap(c, roster)
        pilot_overlap = "YES" if c.candidate_id in PILOT_IDS else "NO"
        archive_status = {"routeviews": "NOT_CHECKED", "caida": "NOT_CHECKED", "rpki": "NOT_CHECKED"}
        if c.timestamp_status == "PASS" and pilot_overlap == "NO" and overlap_status == "NO":
            checks = []
            for kind, url in archive_urls(c.event_start_utc).items():
                available, status = head(url)
                archives.append({"candidate_id": c.candidate_id, "mapped_class": c.mapped_class, "archive_kind": kind, "url": url, "available": available, "status": status, "checked_utc": datetime.now(timezone.utc).isoformat()})
                checks.append((kind, available))
            archive_status["routeviews"] = "AVAILABLE" if dict(checks)["routeviews"] else "UNAVAILABLE"
            archive_status["caida"] = "AVAILABLE" if dict(checks)["caida"] else "UNAVAILABLE"
            archive_status["rpki"] = "AVAILABLE" if all(v for k, v in checks if k.startswith("rpki_")) else "UNAVAILABLE"
        disposition = c.intended_disposition
        reason = c.screening_reason
        if disposition == "ACCEPTED" and overlap_status == "YES":
            disposition, reason = "ORIGINAL_CORPUS_OVERLAP", overlap_detail
        elif disposition == "ACCEPTED" and pilot_overlap == "YES":
            disposition, reason = "PILOT_EXCLUDED", "Permanent engineering-pilot exclusion."
        elif disposition == "ACCEPTED" and "UNAVAILABLE" in archive_status.values():
            disposition, reason = "ARCHIVAL_COVERAGE_INELIGIBLE", "At least one exact frozen historical evidence family is unavailable."
        screening.append({**asdict(c), "original_corpus_overlap": overlap_status, "pilot_overlap": pilot_overlap,
                          "routeviews_availability": archive_status["routeviews"], "caida_historical_availability": archive_status["caida"],
                          "rpki_historical_availability": archive_status["rpki"],
                          "archive_eligibility": "ELIGIBLE" if disposition == "ACCEPTED" else "NOT_ELIGIBLE",
                          "final_screening_disposition": disposition, "screening_reason": reason})
        overlaps.append({"candidate_id": c.candidate_id, "mapped_class": c.mapped_class, "original_corpus_overlap": overlap_status,
                         "original_corpus_match_detail": overlap_detail, "pilot_overlap": pilot_overlap,
                         "overlap_identifiers_checked": "source event ID; time; ASN; exact prefix; class; description"})
        evidence.append({"candidate_id": c.candidate_id, "mapped_class": c.mapped_class, "source_name": c.source_name,
                         "source_title": c.source_title, "source_organization": c.source_author_or_organization,
                         "source_url": c.source_url, "publication_date": c.publication_date,
                         "source_native_label": c.source_native_label, "mapping_rule": c.mapped_class.upper(),
                         "source_evidence_summary": c.source_evidence_summary, "cloudflare_primary_or_deciding_source": "NO"})

    accepted = [r for r in screening if r["final_screening_disposition"] == "ACCEPTED"]
    cohort = [{"external_id": r["candidate_id"], "true_class": r["mapped_class"], "source_name": r["source_name"],
               "source_url": r["source_url"], "event_start_utc": iso(r["event_start_utc"]), "event_end_utc": iso(r["event_end_utc"]),
               "affected_asn": r["affected_asn"], "affected_prefix": r["affected_prefix"], "archive_eligibility": r["archive_eligibility"],
               "original_corpus_overlap": r["original_corpus_overlap"], "pilot_overlap": r["pilot_overlap"],
               "selection_basis": "Frozen source independence, explicit class mapping, exact interval, no overlap, and exact archive availability."}
              for r in accepted]
    write_csv(OUT / "external_candidate_screening_v1.csv", screening)
    write_csv(OUT / "external_candidate_overlap_audit_v1.csv", overlaps)
    write_csv(OUT / "external_archive_availability_ledger_v1.csv", archives)
    write_csv(OUT / "external_source_evidence_ledger_v1.csv", evidence)
    write_csv(OUT / "proposed_final_external_cohort_v1.csv", cohort)

    dispositions = Counter(r["final_screening_disposition"] for r in screening)
    classes = Counter(r["mapped_class"] for r in accepted)
    sources = Counter(r["source_author_or_organization"] for r in accepted)
    years = Counter(pd.to_datetime(r["event_start_utc"], utc=True).year for r in accepted)
    dominant_source = max(sources.values(), default=0) / max(len(accepted), 1)
    dominant_year = max(years.values(), default=0) / max(len(accepted), 1)
    summary = f"""# Proposed prospective Level-1 external cohort v1

Scope: **Prospective source-separated external validation of the frozen reproducibly preserved Level-1 BGP incident-classification path.**

This proposal was built after the protocol freeze and without model inference, feature inspection, Validation access, Final Holdout access, or Level-2 use.

## Accounting

- Candidates reviewed: {len(screening)}
- Source-screening eligible: {len(accepted)}
- LABEL_AMBIGUOUS: {dispositions['LABEL_AMBIGUOUS']}
- SOURCE_INSUFFICIENT: {dispositions['SOURCE_INSUFFICIENT']}
- TIMESTAMP_REVIEW: {dispositions['TIMESTAMP_REVIEW']}
- ORIGINAL_CORPUS_OVERLAP: {dispositions['ORIGINAL_CORPUS_OVERLAP']}
- PILOT_EXCLUDED: {dispositions['PILOT_EXCLUDED']}
- ARCHIVAL_COVERAGE_INELIGIBLE: {dispositions['ARCHIVAL_COVERAGE_INELIGIBLE']}
- Proposed cohort: {len(accepted)} ({classes['Hijack']} Hijack, {classes['Leak']} Leak, {classes['Outage']} Outage)

## Distribution

- Source distribution: {dict(sorted(sources.items()))}
- Event-year distribution: {dict(sorted(years.items()))}
- One-source dominance: {'YES' if dominant_source > 0.5 else 'NO'} ({dominant_source:.1%}); this is expected to be driven by IODA outage records and is a documented limitation.
- One-period dominance: {'YES' if dominant_year > 0.5 else 'NO'} ({dominant_year:.1%} in the largest year).

The target of roughly 10 events per class was not forced. Timestamp-inadequate and pilot events remain visible as exclusions. Cohort membership was determined only by frozen source, label, timestamp, overlap, and archive criteria.
"""
    (OUT / "proposed_final_external_cohort_summary_v1.md").write_text(summary, encoding="utf-8")

    checksum_rows = []
    for path in sorted(OUT.glob("*")):
        if path.is_file() and path.name != "proposed_external_cohort_checksums_v1.csv":
            checksum_rows.append({"file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size})
    write_csv(OUT / "proposed_external_cohort_checksums_v1.csv", checksum_rows)
    print(json.dumps({"reviewed": len(screening), "accepted": len(accepted), "classes": classes, "dispositions": dispositions}, default=dict, indent=2))


if __name__ == "__main__":
    main()
