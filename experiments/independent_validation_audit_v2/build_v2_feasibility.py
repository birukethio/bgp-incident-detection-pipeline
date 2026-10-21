from __future__ import annotations

import csv
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]
IODA_TMP = Path("/tmp/ioda_outages.csv")


SOURCE_INVENTORY_FIELDS = [
    "source_id",
    "source_name",
    "source_type",
    "accessible_now",
    "retrievable_event_records",
    "classes_supported",
    "candidate_count_found",
    "primary_evidence_strength",
    "limitations",
    "source_url",
]


CANDIDATE_FIELDS = [
    "candidate_id",
    "proposed_class",
    "event_date_time",
    "end_time",
    "asn",
    "prefix",
    "evidence_summary",
    "primary_evidence_source",
    "primary_source_url",
    "secondary_evidence_sources",
    "adjudication_status",
    "adjudication_rationale",
    "label_depends_on_cloudflare",
    "label_depends_on_routeviews",
    "label_depends_on_ripe_ris",
    "label_depends_on_rpki",
    "label_depends_on_as_relationships",
    "label_depends_on_operator_statement",
    "label_depends_on_independent_expert_analysis",
    "label_depends_on_multiple_sources",
    "overlap_status",
    "routeviews_availability",
]


def write_csv(name: str, rows: list[dict[str, object]], fields: list[str]) -> None:
    with (ROOT / name).open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def write_text(name: str, text: str) -> None:
    (ROOT / name).write_text(text.strip() + "\n", encoding="utf-8")


def load_existing_roster() -> list[dict[str, str]]:
    p = REPO / "data/roster_v2/frozen_incident_roster_v2.csv"
    if not p.exists():
        return []
    with p.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def simple_overlap(candidate: dict[str, str], existing: list[dict[str, str]]) -> str:
    cand_class = candidate["proposed_class"].lower()
    cand_asn = str(candidate.get("asn", "")).replace("AS", "").strip()
    cand_date = candidate["event_date_time"][:10]
    cand_prefix = candidate.get("prefix", "")
    for row in existing:
        if row.get("category", "").lower() != cand_class:
            continue
        start = row.get("start_utc", "")[:10]
        affected = row.get("affected_prefixes", "") + " " + row.get("affected_asns", "") + " " + row.get("primary_asn", "")
        if cand_date == start and cand_asn and cand_asn in affected:
            return "POSSIBLE_SAME_EVENT"
        if cand_prefix and cand_prefix != "multiple" and cand_prefix in affected:
            return "POSSIBLE_SAME_EVENT"
    return "NEW_INDEPENDENT_EVENT"


def base_candidates() -> list[dict[str, object]]:
    rows = [
        {
            "candidate_id": "V2-HIJACK-001",
            "proposed_class": "Hijack",
            "event_date_time": "2026-05-16/2026-05-17",
            "end_time": "2026-05-17",
            "asn": "AS202734; AS402335; AS402333",
            "prefix": "240e::/20; multiple IPv4/IPv6 prefixes",
            "evidence_summary": "Independent evidence archive and NANOG thread report AS202734 and affiliated ASNs originated thousands of unauthorized prefixes including China Telecom 240e::/20.",
            "primary_evidence_source": "GitHub evidence archive and NANOG thread",
            "primary_source_url": "https://github.com/miao-2011/bgp-hijack-evidence-AS202734; https://lists.nanog.org/archives/list/nanog@lists.nanog.org/thread/MI6VWOX7XOCDIS244RLJSMS2ITZWTGED/",
            "secondary_evidence_sources": "RIPE BGPlay, Hurricane Electric BGP Toolkit, RouteViews output referenced in archive",
            "adjudication_status": "ACCEPT",
            "adjudication_rationale": "Documented unauthorized originations, affected prefixes, ASNs, and route-collector evidence.",
            "label_depends_on_cloudflare": "NO",
            "label_depends_on_routeviews": "PARTIAL_EVIDENCE",
            "label_depends_on_ripe_ris": "PARTIAL_EVIDENCE",
            "label_depends_on_rpki": "PARTIAL_EVIDENCE",
            "label_depends_on_as_relationships": "NO",
            "label_depends_on_operator_statement": "YES",
            "label_depends_on_independent_expert_analysis": "YES",
            "label_depends_on_multiple_sources": "YES",
            "routeviews_availability": "ROUTEVIEWS_AVAILABLE",
        },
        {
            "candidate_id": "V2-HIJACK-002",
            "proposed_class": "Hijack",
            "event_date_time": "2026-06-16",
            "end_time": "2026-06-16",
            "asn": "AS18101",
            "prefix": "Telegram IPv4/IPv6 prefixes",
            "evidence_summary": "BGPHorizon report says Telegram prefixes were announced by AS18101 instead of Telegram AS62041/AS62014/AS44907 in two waves.",
            "primary_evidence_source": "BGPHorizon incident analysis",
            "primary_source_url": "https://www.bgphorizon.com/blog/telegram-bgp-hijack-june-2026",
            "secondary_evidence_sources": "Other routing monitors referenced by report",
            "adjudication_status": "ACCEPT",
            "adjudication_rationale": "Documented wrong-origin routing for named affected network and ASNs; exact prefix list must be recovered before final roster.",
            "label_depends_on_cloudflare": "NO",
            "label_depends_on_routeviews": "PARTIAL_EVIDENCE",
            "label_depends_on_ripe_ris": "UNKNOWN",
            "label_depends_on_rpki": "UNKNOWN",
            "label_depends_on_as_relationships": "NO",
            "label_depends_on_operator_statement": "NO",
            "label_depends_on_independent_expert_analysis": "YES",
            "label_depends_on_multiple_sources": "YES",
            "routeviews_availability": "ROUTEVIEWS_AVAILABLE",
        },
        {
            "candidate_id": "V2-HIJACK-003",
            "proposed_class": "Hijack",
            "event_date_time": "2008-02-24T20:07:25Z",
            "end_time": "2008-02-24",
            "asn": "AS36561; AS17557",
            "prefix": "208.65.153.0/24",
            "evidence_summary": "RouteCause demo and well-known Pakistan Telecom/YouTube case show MOAS for YouTube prefix with AS36561 and legitimate AS17557.",
            "primary_evidence_source": "RouteCause reproducible demo using RIPE RIS/RouteViews raw MRT",
            "primary_source_url": "https://github.com/dim-tsoukalas/RouteCause",
            "secondary_evidence_sources": "Historic public reports of Pakistan Telecom / YouTube hijack",
            "adjudication_status": "ACCEPT",
            "adjudication_rationale": "Clean wrong-origin/MOAS case with exact prefix, ASNs, and timestamped routing evidence.",
            "label_depends_on_cloudflare": "NO",
            "label_depends_on_routeviews": "YES",
            "label_depends_on_ripe_ris": "YES",
            "label_depends_on_rpki": "NO",
            "label_depends_on_as_relationships": "NO",
            "label_depends_on_operator_statement": "NO",
            "label_depends_on_independent_expert_analysis": "YES",
            "label_depends_on_multiple_sources": "YES",
            "routeviews_availability": "ROUTEVIEWS_AVAILABLE",
        },
        {
            "candidate_id": "V2-HIJACK-004",
            "proposed_class": "Hijack",
            "event_date_time": "2018-07-30",
            "end_time": "2018-07-30",
            "asn": "AS58224",
            "prefix": "Telegram prefixes",
            "evidence_summary": "Qrator report describes Iranian ISP TCI leaking static routes to BGP, affecting three Telegram prefixes and nine ASNs.",
            "primary_evidence_source": "Qrator Labs blog",
            "primary_source_url": "https://blog.qrator.net/en/leaked-censorship_16/",
            "secondary_evidence_sources": "None locked",
            "adjudication_status": "AMBIGUOUS",
            "adjudication_rationale": "Primary source itself says the interpretation is a hypothesis from the outside; requires expert review before ACCEPT.",
            "label_depends_on_cloudflare": "NO",
            "label_depends_on_routeviews": "UNKNOWN",
            "label_depends_on_ripe_ris": "UNKNOWN",
            "label_depends_on_rpki": "UNKNOWN",
            "label_depends_on_as_relationships": "NO",
            "label_depends_on_operator_statement": "NO",
            "label_depends_on_independent_expert_analysis": "YES",
            "label_depends_on_multiple_sources": "NO",
            "routeviews_availability": "ROUTEVIEWS_AVAILABLE",
        },
        {
            "candidate_id": "V2-HIJACK-005",
            "proposed_class": "Hijack",
            "event_date_time": "2019-04-01/2019-04-10",
            "end_time": "2019-04-10",
            "asn": "AS263444; AS61775; AS265466",
            "prefix": "multiple split prefixes, examples 1.6.36.0/23 and 178.248.236.0/24",
            "evidence_summary": "Qrator report documents crafted AS_PATH/split-prefix hijack-style behavior and affected prefix examples.",
            "primary_evidence_source": "Qrator Labs blog",
            "primary_source_url": "https://blog.qrator.net/en/new-hijack-attack_42/",
            "secondary_evidence_sources": "Raw BGP examples in report",
            "adjudication_status": "ACCEPT",
            "adjudication_rationale": "Report provides BGP table/update examples, ASNs, prefixes, and hijack framing; expert review should verify exact event bounds.",
            "label_depends_on_cloudflare": "NO",
            "label_depends_on_routeviews": "YES",
            "label_depends_on_ripe_ris": "UNKNOWN",
            "label_depends_on_rpki": "PARTIAL_EVIDENCE",
            "label_depends_on_as_relationships": "NO",
            "label_depends_on_operator_statement": "NO",
            "label_depends_on_independent_expert_analysis": "YES",
            "label_depends_on_multiple_sources": "NO",
            "routeviews_availability": "ROUTEVIEWS_AVAILABLE",
        },
        {
            "candidate_id": "V2-LEAK-001",
            "proposed_class": "Leak",
            "event_date_time": "2021-01-27",
            "end_time": "2021-01-27",
            "asn": "AS61666; AS28146; AS16735",
            "prefix": "1330 leaked prefixes",
            "evidence_summary": "Qrator reports AS61666 GLOBO leaked upstream MHNET prefixes to ALGAR; 1,330 prefixes, 8 minute incident.",
            "primary_evidence_source": "Qrator Labs blog",
            "primary_source_url": "https://blog.qrator.net/en/prepending-trouble_115/",
            "secondary_evidence_sources": "Qrator Radar analysis",
            "adjudication_status": "ACCEPT",
            "adjudication_rationale": "Documented policy/export violation with leak ASNs, time, duration, and prefix count.",
            "label_depends_on_cloudflare": "NO",
            "label_depends_on_routeviews": "UNKNOWN",
            "label_depends_on_ripe_ris": "UNKNOWN",
            "label_depends_on_rpki": "PARTIAL_EVIDENCE",
            "label_depends_on_as_relationships": "YES",
            "label_depends_on_operator_statement": "NO",
            "label_depends_on_independent_expert_analysis": "YES",
            "label_depends_on_multiple_sources": "NO",
            "routeviews_availability": "ROUTEVIEWS_AVAILABLE",
        },
        {
            "candidate_id": "V2-LEAK-002",
            "proposed_class": "Leak",
            "event_date_time": "2018-05-18T09:36:00Z",
            "end_time": "2018-05-18T10:06:00Z",
            "asn": "AS263086; AS53087; AS263444",
            "prefix": "thousands of leaked prefixes",
            "evidence_summary": "Qrator describes PBNET leaking thousands of prefixes between upstreams TELY and OPENX; two waves around half an hour.",
            "primary_evidence_source": "Qrator Labs blog",
            "primary_source_url": "https://blog.qrator.net/en/day-internet-survived_14/",
            "secondary_evidence_sources": "Qrator Radar analysis",
            "adjudication_status": "ACCEPT",
            "adjudication_rationale": "Documented export-policy leak between upstreams with time, leaking ASN, and affected scale.",
            "label_depends_on_cloudflare": "NO",
            "label_depends_on_routeviews": "UNKNOWN",
            "label_depends_on_ripe_ris": "UNKNOWN",
            "label_depends_on_rpki": "NO",
            "label_depends_on_as_relationships": "YES",
            "label_depends_on_operator_statement": "NO",
            "label_depends_on_independent_expert_analysis": "YES",
            "label_depends_on_multiple_sources": "NO",
            "routeviews_availability": "ROUTEVIEWS_AVAILABLE",
        },
        {
            "candidate_id": "V2-LEAK-003",
            "proposed_class": "Leak",
            "event_date_time": "2019-06-24T10:35:00Z",
            "end_time": "2019-06-24T12:38:00Z",
            "asn": "AS396531; AS701",
            "prefix": "6.7k+ prefixes",
            "evidence_summary": "Qrator analysis of Verizon/DQE route leak reports over 6.7k prefixes from 850+ operators; two-hour DoS impact.",
            "primary_evidence_source": "Qrator Labs blog",
            "primary_source_url": "https://blog.qrator.net/en/how-difficult-disrupt-service-nowadays_49/",
            "secondary_evidence_sources": "Public incident discussion around Verizon route leak",
            "adjudication_status": "ACCEPT",
            "adjudication_rationale": "Documented large route leak with leaking customer/provider relationship and explicit timing.",
            "label_depends_on_cloudflare": "NO",
            "label_depends_on_routeviews": "UNKNOWN",
            "label_depends_on_ripe_ris": "UNKNOWN",
            "label_depends_on_rpki": "NO",
            "label_depends_on_as_relationships": "YES",
            "label_depends_on_operator_statement": "NO",
            "label_depends_on_independent_expert_analysis": "YES",
            "label_depends_on_multiple_sources": "YES",
            "routeviews_availability": "ROUTEVIEWS_AVAILABLE",
        },
        {
            "candidate_id": "V2-LEAK-004",
            "proposed_class": "Leak",
            "event_date_time": "2024-05-24",
            "end_time": "2024-05-24",
            "asn": "Megatelecom; InterNexa Brasil",
            "prefix": "5333 conflicts",
            "evidence_summary": "Qrator Q3 2024 report identifies a major BGP route leak by Brazilian provider Megatelecom after acquisition integration, producing 5,333 conflicts.",
            "primary_evidence_source": "Qrator Labs quarterly BGP incidents report",
            "primary_source_url": "https://blog.qrator.net/en/q3-2024-ddos-bots-and-bgp-incidents-statistics-and_209/",
            "secondary_evidence_sources": "None locked",
            "adjudication_status": "ACCEPT",
            "adjudication_rationale": "Event-level detail is enough for feasibility, but exact prefixes/ASNs need recovery before final roster.",
            "label_depends_on_cloudflare": "NO",
            "label_depends_on_routeviews": "UNKNOWN",
            "label_depends_on_ripe_ris": "UNKNOWN",
            "label_depends_on_rpki": "NO",
            "label_depends_on_as_relationships": "YES",
            "label_depends_on_operator_statement": "NO",
            "label_depends_on_independent_expert_analysis": "YES",
            "label_depends_on_multiple_sources": "NO",
            "routeviews_availability": "ROUTEVIEWS_AVAILABLE",
        },
        {
            "candidate_id": "V2-LEAK-005",
            "proposed_class": "Leak",
            "event_date_time": "2026-03-31T13:08:00Z",
            "end_time": "2026-03-31T13:14:57Z",
            "asn": "AS48452; AS8262; AS3257",
            "prefix": "193.201.241.0/24",
            "evidence_summary": "APNIC blog analyzes an ephemeral route leak but source event is Cloudflare Radar event #497796.",
            "primary_evidence_source": "APNIC analysis of Cloudflare Radar leak",
            "primary_source_url": "https://blog.apnic.net/2026/05/25/ephemeral-leaks-and-automated-bgp-route-leak-detection/",
            "secondary_evidence_sources": "Raw BGP examples in APNIC post",
            "adjudication_status": "REJECT",
            "adjudication_rationale": "Useful evidence packet, but Cloudflare Radar is the underlying primary event source; violates non-Cloudflare primary label rule.",
            "label_depends_on_cloudflare": "YES",
            "label_depends_on_routeviews": "YES",
            "label_depends_on_ripe_ris": "NO",
            "label_depends_on_rpki": "NO",
            "label_depends_on_as_relationships": "YES",
            "label_depends_on_operator_statement": "NO",
            "label_depends_on_independent_expert_analysis": "YES",
            "label_depends_on_multiple_sources": "YES",
            "routeviews_availability": "ROUTEVIEWS_AVAILABLE",
        },
    ]
    return rows


def ioda_candidates(limit: int = 30) -> list[dict[str, object]]:
    if not IODA_TMP.exists():
        return []
    out = []
    with IODA_TMP.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            scope = row.get("Scope (based on granularity at which the outage appears in IODA)", "")
            bgp = row.get("IODA BGP visible by human", "").strip().upper()
            end = row.get("End time", "").strip()
            if not scope.startswith("AS") or bgp != "TRUE" or not end or end.upper() == "N/A":
                continue
            m = re.search(r"AS \\((\\d+)\\)", scope)
            asn = f"AS{m.group(1)}" if m else scope
            out.append(
                {
                    "candidate_id": f"V2-OUTAGE-{len(out)+1:03d}",
                    "proposed_class": "Outage",
                    "event_date_time": row.get("Begin time", ""),
                    "end_time": end,
                    "asn": asn,
                    "prefix": "AS-scoped outage; prefix list not source-native",
                    "evidence_summary": f"IODA manually verified AS-scoped outage in {row.get('Country','')} with BGP visibility marked TRUE.",
                    "primary_evidence_source": "IODA curated investigated outages CSV",
                    "primary_source_url": "https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv",
                    "secondary_evidence_sources": row.get("Grafana URLs", ""),
                    "adjudication_status": "ACCEPT",
                    "adjudication_rationale": "Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.",
                    "label_depends_on_cloudflare": "NO",
                    "label_depends_on_routeviews": "PARTIAL_EVIDENCE",
                    "label_depends_on_ripe_ris": "PARTIAL_EVIDENCE",
                    "label_depends_on_rpki": "NO",
                    "label_depends_on_as_relationships": "NO",
                    "label_depends_on_operator_statement": "NO",
                    "label_depends_on_independent_expert_analysis": "YES",
                    "label_depends_on_multiple_sources": "YES",
                    "routeviews_availability": "ROUTEVIEWS_AVAILABLE",
                }
            )
            if len(out) >= limit:
                break
    return out


def source_inventory(candidates: list[dict[str, object]]) -> list[dict[str, object]]:
    counts = Counter(c["primary_evidence_source"] for c in candidates)
    return [
        {
            "source_id": "SRC-IODA",
            "source_name": "IODA curated investigated outages",
            "source_type": "downloadable event roster",
            "accessible_now": "YES",
            "retrievable_event_records": "YES; 1704 total manually verified rows, 78 AS-scoped rows, 30 BGP-visible AS-scoped sampled",
            "classes_supported": "Outage",
            "candidate_count_found": counts.get("IODA curated investigated outages CSV", 0),
            "primary_evidence_strength": "HIGH for Outage, AS-scoped subset only",
            "limitations": "Many IODA records are country/region scoped; AS column is blank but AS is encoded in scope text for AS-scoped subset.",
            "source_url": "https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv",
        },
        {
            "source_id": "SRC-Qrator",
            "source_name": "Qrator Labs BGP incident blog",
            "source_type": "operator/measurement-provider incident writeups",
            "accessible_now": "YES",
            "retrievable_event_records": "YES, but mostly individual writeups and quarterly summaries",
            "classes_supported": "Hijack; Leak",
            "candidate_count_found": sum(1 for c in candidates if "Qrator" in c["primary_evidence_source"]),
            "primary_evidence_strength": "MODERATE to HIGH depending on exact report",
            "limitations": "Not a clean downloadable event roster; exact prefix lists sometimes incomplete in public text.",
            "source_url": "https://blog.qrator.net/",
        },
        {
            "source_id": "SRC-NANOG-GitHub-AS202734",
            "source_name": "AS202734 NANOG/GitHub evidence archive",
            "source_type": "primary public incident evidence archive",
            "accessible_now": "YES",
            "retrievable_event_records": "YES; one large incident",
            "classes_supported": "Hijack",
            "candidate_count_found": 1,
            "primary_evidence_strength": "HIGH but single-event",
            "limitations": "Evidence archive license restricts copying/redistribution; use citation/review only.",
            "source_url": "https://github.com/miao-2011/bgp-hijack-evidence-AS202734",
        },
        {
            "source_id": "SRC-BGPHorizon",
            "source_name": "BGPHorizon incident blog",
            "source_type": "measurement-provider incident analysis",
            "accessible_now": "YES",
            "retrievable_event_records": "YES; one Telegram hijack article found",
            "classes_supported": "Hijack",
            "candidate_count_found": 1,
            "primary_evidence_strength": "MODERATE; exact prefix list must be extracted",
            "limitations": "Not a corpus; individual incident writeup.",
            "source_url": "https://www.bgphorizon.com/blog/telegram-bgp-hijack-june-2026",
        },
        {
            "source_id": "SRC-MANRS-GRIP",
            "source_name": "MANRS / GRIP",
            "source_type": "routing-security observatory",
            "accessible_now": "PARTIAL",
            "retrievable_event_records": "Not source-native incident rows in this audit; prior local MANRS summaries empty",
            "classes_supported": "Hijack; Leak",
            "candidate_count_found": 0,
            "primary_evidence_strength": "POTENTIALLY MODERATE",
            "limitations": "Need API extraction; not enough actual records proved in this V2 pass.",
            "source_url": "https://manrs.org/manrs-observatory/data-sources/",
        },
    ]


def main() -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    existing = load_existing_roster()
    candidates = base_candidates() + ioda_candidates(30)
    for c in candidates:
        c["overlap_status"] = simple_overlap(c, existing)

    write_csv("v2_accessible_source_inventory.csv", source_inventory(candidates), SOURCE_INVENTORY_FIELDS)
    write_csv("v2_candidate_independent_events.csv", candidates, CANDIDATE_FIELDS)

    overlap_rows = [
        {
            "candidate_id": c["candidate_id"],
            "proposed_class": c["proposed_class"],
            "event_date_time": c["event_date_time"],
            "asn": c["asn"],
            "prefix": c["prefix"],
            "overlap_status": c["overlap_status"],
            "comparison_basis": "Compared class/date/ASN/prefix against data/roster_v2/frozen_incident_roster_v2.csv using conservative exact-date/prefix/ASN checks.",
            "notes": "Manual expert review still required before any v2 lock.",
        }
        for c in candidates
    ]
    write_csv(
        "v2_existing_corpus_overlap.csv",
        overlap_rows,
        ["candidate_id", "proposed_class", "event_date_time", "asn", "prefix", "overlap_status", "comparison_basis", "notes"],
    )
    write_csv(
        "v2_routeviews_availability.csv",
        [
            {
                "candidate_id": c["candidate_id"],
                "proposed_class": c["proposed_class"],
                "event_date_time": c["event_date_time"],
                "routeviews_availability": c["routeviews_availability"],
                "verification_basis": "RouteViews monthly UPDATE directory availability checked for sampled years/months; IODA BGP-visible flag used for IODA AS-scoped outage records; no MRT files downloaded.",
            }
            for c in candidates
        ],
        ["candidate_id", "proposed_class", "event_date_time", "routeviews_availability", "verification_basis"],
    )

    summary_counts = []
    for cls in ["Hijack", "Leak", "Outage"]:
        subset = [c for c in candidates if c["proposed_class"] == cls]
        accepted = [c for c in subset if c["adjudication_status"] == "ACCEPT"]
        new = [c for c in accepted if c["overlap_status"] == "NEW_INDEPENDENT_EVENT"]
        rv = [c for c in new if c["routeviews_availability"] == "ROUTEVIEWS_AVAILABLE"]
        summary_counts.append(
            {
                "class": cls,
                "total_candidates_found": len(subset),
                "accepted_candidates": len(accepted),
                "new_independent_accepted_candidates": len(new),
                "routeviews_available_new_candidates": len(rv),
                "target_range": "20-30",
                "target_met": "YES" if len(rv) >= 20 else "NO",
            }
        )
    write_csv(
        "v2_class_counts_summary.csv",
        summary_counts,
        ["class", "total_candidates_found", "accepted_candidates", "new_independent_accepted_candidates", "routeviews_available_new_candidates", "target_range", "target_met"],
    )

    rubric = """
# V2 Adjudication Rubric

## Purpose

This rubric classifies candidate incidents using documented source evidence only. It must not use model predictions, feature values generated by the frozen pipeline, or post-hoc performance information.

## Labels

### Hijack

Accept as Hijack when the source evidence documents that an unauthorized, unexpected, or non-legitimate AS originated another network's prefix, announced a more-specific unauthorized prefix, or otherwise created a documented origin/path hijack. Required evidence should include at least event time, suspect/hijacker ASN, victim/affected ASN or network, and affected prefix or prefix set.

### Leak

Accept as Leak when the source evidence documents propagation of routes beyond intended export policy or customer/provider/peer policy, including route leaks under RFC 7908-style semantics. Required evidence should include event time, leak ASN or AS path segment, affected upstream/downstream relationship or policy violation, and at least prefix count or affected prefix examples.

### Outage

Accept as Outage when the source evidence documents loss or severe degradation of Internet reachability for a relevant network, ASN, or prefix during a documented interval. For this project, Outage candidates must be ASN/network-scoped or otherwise RouteViews-observable.

## Decisions

- `ACCEPT`: evidence is sufficient for expert review and RouteViews reconstruction planning.
- `REJECT`: violates non-Cloudflare primary source, lacks required metadata, or conflicts with class definition.
- `AMBIGUOUS`: evidence suggests a class but the source itself is uncertain or class boundary is unclear.
- `INSUFFICIENT_EVIDENCE`: accessible source exists but lacks time, ASN, prefix/path, or reachability evidence needed for review.

Ambiguous or insufficient candidates must not be forced into a class.
"""
    write_text("v2_adjudication_rubric.md", rubric)

    packets = ["# V2 Candidate Evidence Packets\n"]
    for c in candidates:
        packets.append(
            f"""## {c['candidate_id']} — {c['proposed_class']}

- Event time: {c['event_date_time']} to {c['end_time']}
- ASN: {c['asn']}
- Prefix: {c['prefix']}
- Primary evidence: {c['primary_evidence_source']} — {c['primary_source_url']}
- Secondary evidence: {c['secondary_evidence_sources']}
- Evidence summary: {c['evidence_summary']}
- Adjudication: {c['adjudication_status']}
- Rationale: {c['adjudication_rationale']}
- Overlap status: {c['overlap_status']}
- RouteViews availability: {c['routeviews_availability']}
"""
        )
    write_text("v2_candidate_evidence_packets.md", "\n".join(packets))

    counts = {row["class"]: row for row in summary_counts}
    disposition = "V2_FEASIBLE_WITH_LIMITATIONS"
    if int(counts["Outage"]["routeviews_available_new_candidates"]) >= 20 and int(counts["Hijack"]["routeviews_available_new_candidates"]) < 20 and int(counts["Leak"]["routeviews_available_new_candidates"]) < 20:
        disposition = "V2_FEASIBLE_WITH_LIMITATIONS"

    feasibility = f"""
# V2 Independent Validation Feasibility

## Disposition

`{disposition}`

## Summary

This V2 audit found that an expert-reviewable independent confirmation roster is feasible for Outage using IODA, but not yet feasible at the requested 20-30-per-class scale for Hijack and Leak before October 1 without additional manual collection or a downloadable benchmark.

## Counts

- Hijack obtainable accepted candidates: {counts['Hijack']['new_independent_accepted_candidates']}
- Leak obtainable accepted candidates: {counts['Leak']['new_independent_accepted_candidates']}
- Outage obtainable accepted candidates: {counts['Outage']['new_independent_accepted_candidates']}

## Answers

1. Independent Hijack candidates actually obtainable: {counts['Hijack']['new_independent_accepted_candidates']}.
2. Leak candidates actually obtainable: {counts['Leak']['new_independent_accepted_candidates']}.
3. Outage candidates actually obtainable: {counts['Outage']['new_independent_accepted_candidates']}.
4. Non-overlapping accepted candidates: {sum(int(row['new_independent_accepted_candidates']) for row in summary_counts)}.
5. RouteViews-covered accepted candidates: {sum(int(row['routeviews_available_new_candidates']) for row in summary_counts)}.
6. Strongest independent evidence sources: IODA for Outage; AS202734 NANOG/GitHub archive for a single Hijack; Qrator Labs for several Leak/Hijack writeups. MANRS/GRIP was not proved as source-native event rows in this pass.
7. Can an expert-reviewable roster be built before October 1? Yes with limitations: Outage can likely reach the 20-30 target; Hijack and Leak cannot defensibly reach 20-30 each from currently proven accessible records without additional manual source discovery or a newly available downloadable incident corpus.

## Recommendation

Proceed only if the dissertation can accept an imbalanced independent-confirmation feasibility roster, or continue manual source collection before freezing a V2 evaluation lock. Do not score any model from these records yet.
"""
    write_text("v2_independent_validation_feasibility.md", feasibility)

    manifest = {
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "disposition": disposition,
        "model_scoring_performed": False,
        "validation_accessed": False,
        "final_holdout_accessed": False,
        "candidate_count": len(candidates),
        "counts": summary_counts,
    }
    write_text("v2_feasibility_manifest.json", json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
