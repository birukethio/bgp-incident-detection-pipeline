from __future__ import annotations

import hashlib
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parents[2]
V1 = PROJECT / "experiments/cross_source_label_validation_v1"
ROSTER = PROJECT / "data/roster_v2/frozen_incident_roster_v2.csv"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    roster = pd.read_csv(ROSTER)
    target_roster = roster[roster["category"].isin(["Hijack", "Leak"])].copy()
    prior_matched = pd.read_csv(V1 / "cross_source_matched_incidents_v1.csv")
    prior_metrics = pd.read_csv(V1 / "cross_source_agreement_metrics_v1.csv")

    # Search ledger records the targeted local and web checks performed for the expansion.
    search_rows = [
        {
            "search_scope": "Local frozen roster",
            "query_or_artifact": "473 Hijack + 473 Leak incidents from frozen_incident_roster_v2.csv",
            "source_type": "corpus",
            "result": "SEARCHED",
            "accepted_new_match_count": 0,
            "notes": "Target search population only; Outages intentionally excluded.",
        },
        {
            "search_scope": "Local exact event artifacts",
            "query_or_artifact": "cloudflare_incidents/cloudflare_kentik_route_leak_validation_2024-2025.csv",
            "source_type": "Kentik",
            "result": "DUPLICATE_ALREADY_IN_V1",
            "accepted_new_match_count": 0,
            "notes": "Confirmed existing Leak:291677 match for AS3223/AS3356 on 2025-04-01; not a new incident.",
        },
        {
            "search_scope": "Local exact event artifacts",
            "query_or_artifact": "cloudflare_incidents/timed_external_bgp_route_leak_label_candidates.csv",
            "source_type": "BGPmon/ThousandEyes/APNIC/etc.",
            "result": "NO_TARGET_ROSTER_EXACT_MATCH",
            "accepted_new_match_count": 0,
            "notes": "Timed independent leak events are mostly pre-2024 or did not exact-match the Cloudflare v2 Leak roster by date/time plus ASN/path.",
        },
        {
            "search_scope": "Local exact event artifacts",
            "query_or_artifact": "cloudflare_incidents/external_route_leak_writeup_candidates_non_kentik.csv",
            "source_type": "BGPmon/operator writeups",
            "result": "NO_TARGET_ROSTER_EXACT_MATCH",
            "accepted_new_match_count": 0,
            "notes": "No additional Cloudflare Leak roster event matched under frozen exact ASN/date-time rules.",
        },
        {
            "search_scope": "Local matching artifacts",
            "query_or_artifact": "cloudflare_incidents/cloudflare_manrs_ioda_matched_incidents_2021-2025.csv",
            "source_type": "MANRS/IODA",
            "result": "EXCLUDED_AGGREGATE_CONTEXT_ONLY",
            "accepted_new_match_count": 0,
            "notes": "Matches use month + country/economy aggregate routeMisoriginations; frozen rules exclude these from same-event label agreement.",
        },
        {
            "search_scope": "Local matching artifacts",
            "query_or_artifact": "cloudflare_incidents/exhaustive_daily_cloudflare_ripestat_strong_matches_2024-2025.csv",
            "source_type": "RIPEstat raw BGP observation",
            "result": "EXCLUDED_ROUTING_EVIDENCE_ONLY",
            "accepted_new_match_count": 0,
            "notes": "Raw BGP update observations can support visibility but do not provide independent source-native incident classification.",
        },
        {
            "search_scope": "Web targeted query",
            "query_or_artifact": "\"AS3223\" \"AS3356\" \"route leak\" Kentik / MANRS / Qrator",
            "source_type": "Kentik/MANRS/Qrator web",
            "result": "DUPLICATE_OR_REPRINT",
            "accepted_new_match_count": 0,
            "notes": "Search found Kentik source and MANRS republication/guest post for the existing Leak:291677 event; Qrator mention lacked an accessible source-native same-event event page in searched results.",
        },
        {
            "search_scope": "Web targeted query",
            "query_or_artifact": "\"AS45117\" \"AS55410\" \"AS4755\" route leak; \"AS133073\" \"AS133115\" \"AS6453\" route leak; other high-volume Cloudflare leak paths",
            "source_type": "Kentik/Qrator/operator/web",
            "result": "NO_QUALIFYING_MATCH_FOUND",
            "accepted_new_match_count": 0,
            "notes": "Search results did not yield independent source-native same-event classifications for sampled high-volume Cloudflare Leak records.",
        },
        {
            "search_scope": "Web targeted query",
            "query_or_artifact": "\"AS24429\" \"AS59504\" hijack; \"185.156.177.1/32\" hijack; \"AS18002\" \"AS58898\" hijack; \"45.116.112.0/24\" hijack",
            "source_type": "operator/BGPHorizon/RouteCause/BGPStream/web",
            "result": "NO_QUALIFYING_MATCH_FOUND",
            "accepted_new_match_count": 0,
            "notes": "Search returned registry/AS-set/current routing pages, not source-native same-event Hijack classifications.",
        },
    ]
    search_log = pd.DataFrame(search_rows)
    search_log.to_csv(ROOT / "hijack_leak_targeted_search_log_v1.csv", index=False)

    candidates = pd.DataFrame(
        [
            {
                "candidate_source": "Kentik",
                "source_url": "https://www.kentik.com/blog/beyond-their-intended-scope-ddos-mitigation-leak/",
                "candidate_class": "Leak",
                "candidate_event": "Voxility/Lumen DDoS mitigation path leak",
                "candidate_time": "2025-04-01T07:35:00Z",
                "candidate_asn_path_or_prefix": "AS3356 AS3223; examples include 220.240.123.0/24 and 27.123.34.0/23",
                "cloudflare_incident_uid": "Leak:291677",
                "decision": "DUPLICATE_ALREADY_COUNTED_IN_V1",
                "reason": "Already counted as the sole v1 Leak same-event independent match.",
            },
            {
                "candidate_source": "MANRS",
                "source_url": "https://manrs.org/2025/04/ddos-mitigation-leak-kentik/",
                "candidate_class": "Leak",
                "candidate_event": "Voxility/Lumen DDoS mitigation path leak",
                "candidate_time": "2025-04-01T07:35:00Z",
                "candidate_asn_path_or_prefix": "AS3356 AS3223; Kentik examples reused",
                "cloudflare_incident_uid": "Leak:291677",
                "decision": "NOT_COUNTED_REPRINT_OF_KENTIK",
                "reason": "MANRS page is explicitly a Doug Madory/Kentik guest post/republication, so it is not an independent second label source under the frozen rules.",
            },
            {
                "candidate_source": "RIPEstat",
                "source_url": "local:cloudflare_incidents/exhaustive_daily_cloudflare_ripestat_strong_matches_2024-2025.csv",
                "candidate_class": "Hijack/Leak",
                "candidate_event": "Multiple Cloudflare Hijack/Leak raw BGP update matches",
                "candidate_time": "2024-2025",
                "candidate_asn_path_or_prefix": "various ASN/prefix update observations",
                "cloudflare_incident_uid": "",
                "decision": "EXCLUDED_ROUTING_EVIDENCE_ONLY",
                "reason": "Raw BGP observations do not independently classify the event as Hijack or Leak.",
            },
            {
                "candidate_source": "MANRS Observatory monthly summaries",
                "source_url": "local:cloudflare_incidents/cloudflare_manrs_ioda_matched_incidents_2021-2025.csv",
                "candidate_class": "Hijack",
                "candidate_event": "Multiple month/country route-misorigination aggregate matches",
                "candidate_time": "2021-2025 monthly",
                "candidate_asn_path_or_prefix": "country/month aggregate counts; no same-event ID",
                "cloudflare_incident_uid": "",
                "decision": "EXCLUDED_AGGREGATE_CONTEXT_ONLY",
                "reason": "Frozen rules require same real-world event evidence, not aggregate month/country references.",
            },
        ]
    )
    candidates.to_csv(ROOT / "hijack_leak_targeted_candidate_evidence_v1.csv", index=False)

    # No new accepted rows were found beyond v1.
    additional = pd.DataFrame(
        columns=[
            "incident_uid",
            "original_incident_id",
            "cloudflare_label",
            "event_date_time",
            "asn",
            "prefix",
            "independent_source",
            "source_url_reference",
            "source_native_terminology",
            "deterministic_mapped_label",
            "match_evidence",
            "match_strength",
            "agreement",
        ]
    )
    additional.to_csv(ROOT / "hijack_leak_additional_matches_v1.csv", index=False)

    prior_hl = prior_matched[prior_matched["cloudflare_label"].isin(["Hijack", "Leak"])].copy()
    revised_rows = [
        {
            "metric": "target_original_hijack_incidents",
            "value": int((target_roster["category"] == "Hijack").sum()),
            "notes": "Frozen Cloudflare v2 corpus; Outages excluded from targeted expansion.",
        },
        {
            "metric": "target_original_leak_incidents",
            "value": int((target_roster["category"] == "Leak").sum()),
            "notes": "Frozen Cloudflare v2 corpus; Outages excluded from targeted expansion.",
        },
        {
            "metric": "prior_v1_hijack_matches",
            "value": int((prior_hl["cloudflare_label"] == "Hijack").sum()),
            "notes": "From frozen v1 cross-source result.",
        },
        {
            "metric": "prior_v1_leak_matches",
            "value": int((prior_hl["cloudflare_label"] == "Leak").sum()),
            "notes": "From frozen v1 cross-source result.",
        },
        {"metric": "additional_hijack_matches", "value": 0, "notes": "No qualifying new exact same-event source-native Hijack matches found."},
        {"metric": "additional_leak_matches", "value": 0, "notes": "No qualifying new exact same-event source-native Leak matches found beyond existing Leak:291677."},
        {"metric": "revised_hijack_matches", "value": int((prior_hl["cloudflare_label"] == "Hijack").sum()), "notes": "Unchanged from v1."},
        {"metric": "revised_leak_matches", "value": int((prior_hl["cloudflare_label"] == "Leak").sum()), "notes": "Unchanged from v1."},
        {
            "metric": "revised_hijack_leak_exact_agreement",
            "value": float(prior_hl["agreement"].mean()) if len(prior_hl) else float("nan"),
            "notes": "Among corroborated Hijack/Leak incidents only. Hijack denominator is zero; only one Leak match exists.",
        },
        {
            "metric": "revised_overall_v1_agreement",
            "value": float(prior_matched["agreement"].mean()) if len(prior_matched) else float("nan"),
            "notes": "Overall v1 agreement remains unchanged because no new matches were appended to v1.",
        },
    ]
    pd.DataFrame(revised_rows).to_csv(ROOT / "hijack_leak_revised_counts_metrics_v1.csv", index=False)

    source_dist = pd.DataFrame(
        [
            {"source": "Kentik", "prior_v1_hijack_matches": 0, "prior_v1_leak_matches": 1, "additional_hijack_matches": 0, "additional_leak_matches": 0},
            {"source": "MANRS", "prior_v1_hijack_matches": 0, "prior_v1_leak_matches": 0, "additional_hijack_matches": 0, "additional_leak_matches": 0},
            {"source": "Qrator", "prior_v1_hijack_matches": 0, "prior_v1_leak_matches": 0, "additional_hijack_matches": 0, "additional_leak_matches": 0},
            {"source": "RIPEstat/RIPE RIS raw observations", "prior_v1_hijack_matches": 0, "prior_v1_leak_matches": 0, "additional_hijack_matches": 0, "additional_leak_matches": 0},
            {"source": "Operator/BGPHorizon/RouteCause/BGPStream/peer-reviewed datasets", "prior_v1_hijack_matches": 0, "prior_v1_leak_matches": 0, "additional_hijack_matches": 0, "additional_leak_matches": 0},
        ]
    )
    source_dist.to_csv(ROOT / "hijack_leak_source_distribution_v1.csv", index=False)

    summary = f"""# Hijack/Leak Targeted Cross-Source Expansion v1

This additive search targeted only the 473 Cloudflare Hijack and 473 Cloudflare Leak incidents in the frozen corpus. Outages were not searched. The original v1 cross-source result was not altered.

## Frozen matching rule retained

The expansion used the existing event-matching and deterministic label-mapping rules:

- exact or strong same-event evidence required;
- non-Cloudflare primary source required;
- source-native Hijack/Leak terminology required;
- exact ASN plus prefix/path plus date/time evidence prioritized;
- aggregate month/country references excluded;
- raw BGP observations excluded as independent classification;
- Cloudflare excluded as corroboration.

## Result

- Additional Hijack matches: 0
- Additional Leak matches: 0
- Agreement/disagreement among additional matches: not applicable; no additional accepted matches
- Revised Hijack corroboration count: {int((prior_hl['cloudflare_label'] == 'Hijack').sum())}
- Revised Leak corroboration count: {int((prior_hl['cloudflare_label'] == 'Leak').sum())}
- Revised overall v1 agreement: {float(prior_matched['agreement'].mean()):.6f}

## Notes on searched evidence

The targeted local and web search recovered the already-counted Kentik Voxility/Lumen AS3223/AS3356 route-leak match (`Leak:291677`). MANRS republishes the Kentik analysis as a guest post, so it was reviewed but not counted as an independent new label source. RIPEstat and RouteViews/RIPE RIS style raw observations were excluded because they are routing evidence rather than source-native event classifications. MANRS monthly-country summaries were excluded because they are aggregate context rather than deterministic same-event matches.

## Disposition

No additional high-quality same-event Hijack or Leak matches were found under the frozen rules.
"""
    (ROOT / "hijack_leak_targeted_expansion_summary_v1.md").write_text(summary, encoding="utf-8")

    artifacts = []
    for path in sorted(ROOT.glob("*")):
        if path.is_file() and path.name != "hijack_leak_targeted_expansion_checksums_v1.csv":
            artifacts.append({"artifact": str(path.relative_to(PROJECT)), "sha256": sha256(path), "size_bytes": path.stat().st_size})
    pd.DataFrame(artifacts).to_csv(ROOT / "hijack_leak_targeted_expansion_checksums_v1.csv", index=False)

    print(summary)


if __name__ == "__main__":
    main()
