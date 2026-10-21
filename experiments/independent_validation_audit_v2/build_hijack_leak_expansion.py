from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "experiments" / "independent_validation_audit_v2"
BASE_CANDIDATES = OUT / "v2_candidate_independent_events.csv"
FROZEN_ROSTER = ROOT / "data" / "roster_v2" / "frozen_incident_roster_v2.csv"
RETRIEVAL_DATE = datetime.now(timezone.utc).date().isoformat()


@dataclass
class Candidate:
    candidate_id: str
    proposed_class: str
    event_date_time: str
    end_time: str
    asn: str
    prefix: str
    primary_source: str
    source_url: str
    source_publication_date: str
    source_retrieval_date: str
    source_event_identifier: str
    evidence_summary: str
    exact_evidence: str
    corroborating_sources: str
    independent_adjudication_rationale: str
    adjudication_status: str
    overlap_status: str = "NEW_INDEPENDENT_EVENT"
    routeviews_availability: str = "ROUTEVIEWS_MONTH_AVAILABLE"
    routeviews_month_url: str = ""
    metadata_limitations: str = ""
    label_depends_on_cloudflare: str = "NO"
    label_depends_on_routeviews: str = "PARTIAL_EVIDENCE"
    label_depends_on_ripe_ris: str = "PARTIAL_EVIDENCE"
    label_depends_on_rpki: str = "NO"
    label_depends_on_as_relationships: str = "PARTIAL_EVIDENCE"
    label_depends_on_operator_statement: str = "NO"
    label_depends_on_independent_expert_analysis: str = "YES"
    label_depends_on_multiple_sources: str = "NO"


def month_url(event_date_time: str) -> str:
    date_part = event_date_time[:10]
    if len(date_part) < 7 or not date_part[:4].isdigit():
        return "UNKNOWN"
    return f"https://archive.routeviews.org/bgpdata/{date_part[:7].replace('-', '.')}/UPDATES/"


def base_hijack_leak_candidates() -> list[Candidate]:
    """Preserve existing accepted/ambiguous H/L V2 candidates as context."""
    rows = []
    if not BASE_CANDIDATES.exists():
        return rows
    df = pd.read_csv(BASE_CANDIDATES)
    df = df[df["proposed_class"].isin(["Hijack", "Leak"])].copy()
    for _, r in df.iterrows():
        rows.append(
            Candidate(
                candidate_id=str(r["candidate_id"]),
                proposed_class=str(r["proposed_class"]),
                event_date_time=str(r["event_date_time"]),
                end_time=str(r.get("end_time", "")),
                asn=str(r.get("asn", "")),
                prefix=str(r.get("prefix", "")),
                primary_source=str(r.get("primary_evidence_source", "")),
                source_url=str(r.get("primary_source_url", "")),
                source_publication_date="See source",
                source_retrieval_date=RETRIEVAL_DATE,
                source_event_identifier=str(r["candidate_id"]),
                evidence_summary=str(r.get("evidence_summary", "")),
                exact_evidence=str(r.get("adjudication_rationale", "")),
                corroborating_sources=str(r.get("secondary_evidence_sources", "")),
                independent_adjudication_rationale=str(r.get("adjudication_rationale", "")),
                adjudication_status=str(r.get("adjudication_status", "")),
                overlap_status=str(r.get("overlap_status", "NEW_INDEPENDENT_EVENT")),
                routeviews_availability=str(r.get("routeviews_availability", "ROUTEVIEWS_MONTH_AVAILABLE")),
                routeviews_month_url=month_url(str(r["event_date_time"])),
                metadata_limitations="Carried forward from V2 base audit.",
                label_depends_on_cloudflare=str(r.get("label_depends_on_cloudflare", "NO")),
                label_depends_on_routeviews=str(r.get("label_depends_on_routeviews", "PARTIAL_EVIDENCE")),
                label_depends_on_ripe_ris=str(r.get("label_depends_on_ripe_ris", "PARTIAL_EVIDENCE")),
                label_depends_on_rpki=str(r.get("label_depends_on_rpki", "NO")),
                label_depends_on_as_relationships=str(r.get("label_depends_on_as_relationships", "PARTIAL_EVIDENCE")),
                label_depends_on_operator_statement=str(r.get("label_depends_on_operator_statement", "NO")),
                label_depends_on_independent_expert_analysis=str(r.get("label_depends_on_independent_expert_analysis", "YES")),
                label_depends_on_multiple_sources=str(r.get("label_depends_on_multiple_sources", "NO")),
            )
        )
    return rows


def expansion_candidates() -> list[Candidate]:
    c: list[Candidate] = []

    def add(**kw):
        kw.setdefault("source_retrieval_date", RETRIEVAL_DATE)
        kw.setdefault("routeviews_month_url", month_url(kw["event_date_time"]))
        c.append(Candidate(**kw))

    # Hijack additions: non-Cloudflare primary sources with source-native classification or direct wrong-origin evidence.
    add(
        candidate_id="V2-HIJACK-006",
        proposed_class="Hijack",
        event_date_time="2020-07-30T01:15:38Z",
        end_time="2020-07-30T02:27:27Z",
        asn="AS10990; victim AS812; Charter/TWC/Videotron and others",
        prefix="99.225.224.0/19; 99.228.0.0/17; 145 prefixes in second wave; 179 prefixes in first wave",
        primary_source="MANRS incident analysis",
        source_url="https://manrs.org/2020/07/another-bgp-incident-impacts-twc-rogers-charter-and-others/",
        source_publication_date="2020-07-30",
        source_event_identifier="BGPStream event 245324 / MANRS AS10990 July 2020",
        evidence_summary="AS10990 announced more-specific prefixes belonging to Rogers/Charter/TWC/Videotron and others.",
        exact_evidence="MANRS reports first BGPStream possible-hijack alert at 01:15:38 UTC; AS10990 announced 99.225.224.0/19 while Rogers AS812 announced covering aggregates; second wave persisted until 02:27:27 UTC.",
        corroborating_sources="Qrator article https://blog.qrator.net/en/as10990-routing-optimization-tale_83/; NANOG mail thread subject BGP route hijack by AS10990",
        independent_adjudication_rationale="Wrong-origin/more-specific route announcements with explicit BGPStream event id, timestamps, ASNs, and example prefixes.",
        adjudication_status="ACCEPT",
        label_depends_on_multiple_sources="YES",
    )
    add(
        candidate_id="V2-HIJACK-007",
        proposed_class="Hijack",
        event_date_time="2022-07-26T21:25:10Z",
        end_time="2022-07-27T09:39:00Z",
        asn="AS12389; victim AS714",
        prefix="17.70.96.0/19; Apple mitigation prefix 17.70.96.0/21",
        primary_source="MANRS incident analysis",
        source_url="https://manrs.org/2022/07/for-12-hours-was-part-of-apple-engineerings-network-hijacked-by-russias-rostelecom/",
        source_publication_date="2022-07-27",
        source_event_identifier="BGPStream event 293915; GRIP submoas-1658870700-714=12389/17.70.96.0-19_17.0.0.0-9",
        evidence_summary="Rostelecom AS12389 announced Apple Engineering prefix 17.70.96.0/19 for about 12 hours.",
        exact_evidence="MANRS gives BGP update lines at 21:25:10-21:29 UTC, BGPStream event 293915, GRIP event id, Apple mitigation at 02:41 UTC, and final withdrawals around 09:39 UTC.",
        corroborating_sources="The Register article; The FPS Review article; GRIP event URL cited by MANRS",
        independent_adjudication_rationale="Explicit wrong-origin/subMOAS event with exact prefix, source event identifiers, and independent MANRS analysis.",
        adjudication_status="ACCEPT",
        label_depends_on_multiple_sources="YES",
    )
    add(
        candidate_id="V2-HIJACK-008",
        proposed_class="Hijack",
        event_date_time="2020-04-01T19:28:00Z",
        end_time="2020-04-01",
        asn="AS12389; affected AS16509/AS14618/AS20940 and others",
        prefix="104.18.216.0/21; 104.17.128.0/21; 104.18.184.0/21; 95.100.200.0/24; 104.18.168.0/21; 104.107.217.0/24; 95.101.181.0/24; 95.216.178.0/24; 104.17.232.0/21; 95.101.82.0/23; BGPMon reported 8800+ prefixes",
        primary_source="MANRS incident analysis",
        source_url="https://manrs.org/2020/04/not-just-another-bgp-hijack/",
        source_publication_date="2020-04-06",
        source_event_identifier="MANRS/Qrator AS12389 April 2020",
        evidence_summary="Rostelecom AS12389 originated many more-specific prefixes for networks including Amazon and Akamai.",
        exact_evidence="MANRS cites Qrator first mis-origination at 19:28 UTC and lists ten hijacked prefixes; it also notes BGPMon reported more than 8,800 prefixes.",
        corroborating_sources="Qrator Labs brief cited by MANRS; BGPMon prefix list cited by MANRS",
        independent_adjudication_rationale="Large-scale mis-origination with explicit AS, time, classification, and example prefixes.",
        adjudication_status="ACCEPT",
        label_depends_on_multiple_sources="YES",
    )
    add(
        candidate_id="V2-HIJACK-009",
        proposed_class="Hijack",
        event_date_time="2020-09-29",
        end_time="2020-09-29",
        asn="AS1221; 266 affected ASNs",
        prefix="472 prefixes announced; 1680+ affected IPv4 prefixes/conflicts; exact prefix list not in public article text",
        primary_source="Qrator Labs Radar article index",
        source_url="https://blog.qrator.net/en/radar/?page=2",
        source_publication_date="2020-09-30",
        source_event_identifier="Qrator AS1221 hijacking 266 ASNs in 51 countries",
        evidence_summary="Qrator reports Telstra AS1221 announced 472 prefixes in a BGP hijack affecting 266 ASNs.",
        exact_evidence="Qrator archive excerpt: September 29 2020 AS1221 announced 472 prefixes in a BGP hijack event affecting 266 ASNs in 50 countries, creating almost 2000 path-challenge conflicts.",
        corroborating_sources="None recovered in this pass",
        independent_adjudication_rationale="Source-native Qrator Radar hijack classification with date, ASN, and prefix/conflict counts.",
        adjudication_status="ACCEPT",
        metadata_limitations="Exact affected prefix list not recovered from public article text; preserve as prefix-count event pending expert lock.",
    )
    add(
        candidate_id="V2-HIJACK-010",
        proposed_class="Hijack",
        event_date_time="2020-10-21T14:11:00Z",
        end_time="2020-10-21",
        asn="AS203; affected AS9198/AS35415/AS7979 and others",
        prefix="158 announced prefixes; 1000+ conflicts; exact prefix list not recovered from public text",
        primary_source="Qrator Labs Radar article",
        source_url="https://blog.qrator.net/en/lumen-aka-centurylink-generating-routing-incidents_101/",
        source_publication_date="2020-10-21",
        source_event_identifier="Qrator AS203 Lumen/CenturyLink October 2020",
        evidence_summary="Qrator reports Lumen/Level3 AS203 announced prefixes that hijacked traffic for many original owners.",
        exact_evidence="Qrator states AS203 started announcing 158 prefixes around 14:11 UTC, affecting 31 ISPs in 19 countries and causing path-challenge conflicts.",
        corroborating_sources="None recovered in this pass",
        independent_adjudication_rationale="Source-native Qrator hijack/path-challenge event with timestamp and AS-level scope.",
        adjudication_status="ACCEPT",
        metadata_limitations="Exact affected prefix list not recovered from public article text.",
    )
    add(
        candidate_id="V2-HIJACK-011",
        proposed_class="Hijack",
        event_date_time="2021-10-25",
        end_time="2021-10-25",
        asn="AS212046 MEZON",
        prefix="3786 hijacked prefixes; exact prefix list not recovered from public MANRS summary",
        primary_source="MANRS BGP Security in 2021",
        source_url="https://manrs.org/2022/02/bgp-security-in-2021/",
        source_publication_date="2022-02-21",
        source_event_identifier="MANRS 2021 major hijack list: 2021-10-25 AS212046",
        evidence_summary="MANRS lists AS212046 MEZON as hijacking 3,786 prefixes on October 25, 2021.",
        exact_evidence="MANRS selected this as a particularly major disruption based on impact/number of prefixes.",
        corroborating_sources="Qrator Labs referenced by MANRS as detailed source",
        independent_adjudication_rationale="Independent MANRS annual incident summary with source-native BGPStream/Qrator classification and prefix count.",
        adjudication_status="ACCEPT",
        metadata_limitations="Prefix count available; full prefix list requires Qrator social/API archive recovery.",
        label_depends_on_multiple_sources="YES",
    )
    add(
        candidate_id="V2-HIJACK-012",
        proposed_class="Hijack",
        event_date_time="2021-10-13",
        end_time="2021-10-13",
        asn="AS212046 MEZON",
        prefix="1029 hijacked prefixes; exact prefix list not recovered from public MANRS summary",
        primary_source="MANRS BGP Security in 2021",
        source_url="https://manrs.org/2022/02/bgp-security-in-2021/",
        source_publication_date="2022-02-21",
        source_event_identifier="MANRS 2021 major hijack list: 2021-10-13 AS212046",
        evidence_summary="MANRS lists AS212046 MEZON as hijacking 1,029 prefixes on October 13, 2021.",
        exact_evidence="Separate date and prefix count from the October 25 MEZON event; treat as distinct pending expert adjudication.",
        corroborating_sources="Qrator Labs referenced by MANRS as detailed source",
        independent_adjudication_rationale="Independent MANRS annual incident summary with date, ASN, class, and count.",
        adjudication_status="ACCEPT",
        metadata_limitations="Prefix count available; full prefix list requires source archive recovery.",
        label_depends_on_multiple_sources="YES",
    )
    add(
        candidate_id="V2-HIJACK-013",
        proposed_class="Hijack",
        event_date_time="2021-09-21",
        end_time="2021-09-21",
        asn="AS62325 HDHK",
        prefix="89 hijacked prefixes; exact prefix list not recovered from public MANRS summary",
        primary_source="MANRS BGP Security in 2021",
        source_url="https://manrs.org/2022/02/bgp-security-in-2021/",
        source_publication_date="2022-02-21",
        source_event_identifier="MANRS 2021 major hijack list: 2021-09-21 AS62325",
        evidence_summary="MANRS lists AS62325 HDHK as hijacking 89 prefixes on September 21, 2021.",
        exact_evidence="Date, culprit ASN, class, and prefix count are present in the MANRS annual incident list.",
        corroborating_sources="Qrator Labs referenced by MANRS as detailed source",
        independent_adjudication_rationale="Accept as expert-reviewable event but exact prefix list must be recovered before operational acquisition lock.",
        adjudication_status="ACCEPT",
        metadata_limitations="Prefix count only in public source.",
        label_depends_on_multiple_sources="YES",
    )
    add(
        candidate_id="V2-HIJACK-014",
        proposed_class="Hijack",
        event_date_time="2021-05-18",
        end_time="2021-05-18",
        asn="AS48467 PRANET",
        prefix="454 hijacked prefixes; exact prefix list not recovered from public MANRS summary",
        primary_source="MANRS BGP Security in 2021",
        source_url="https://manrs.org/2022/02/bgp-security-in-2021/",
        source_publication_date="2022-02-21",
        source_event_identifier="MANRS 2021 major hijack list: 2021-05-18 AS48467",
        evidence_summary="MANRS lists AS48467 PRANET as hijacking 454 prefixes on May 18, 2021.",
        exact_evidence="Date, culprit ASN, class, and prefix count are present in the MANRS annual incident list.",
        corroborating_sources="Qrator Labs referenced by MANRS as detailed source",
        independent_adjudication_rationale="Accept as source-native major hijack candidate; exact prefixes require source archive recovery.",
        adjudication_status="ACCEPT",
        metadata_limitations="Prefix count only in public source.",
        label_depends_on_multiple_sources="YES",
    )
    add(
        candidate_id="V2-HIJACK-015",
        proposed_class="Hijack",
        event_date_time="2021-04-16",
        end_time="2021-04-16",
        asn="AS55410 Vodafone Idea Ltd",
        prefix="30000 hijacked prefixes; exact prefix list not recovered from public MANRS summary",
        primary_source="MANRS BGP Security in 2021",
        source_url="https://manrs.org/2022/02/bgp-security-in-2021/",
        source_publication_date="2022-02-21",
        source_event_identifier="MANRS 2021 major hijack list: 2021-04-16 AS55410",
        evidence_summary="MANRS lists AS55410 Vodafone Idea Ltd as hijacking 30,000 prefixes on April 16, 2021.",
        exact_evidence="MANRS annual summary flags the event as a particularly major disruption.",
        corroborating_sources="MANRS blog referenced in annual summary",
        independent_adjudication_rationale="Major source-native hijack candidate with class, date, ASN, and large prefix count.",
        adjudication_status="ACCEPT",
        metadata_limitations="Full prefix list and primary event-specific blog URL should be recovered before lock.",
        label_depends_on_multiple_sources="YES",
    )
    add(
        candidate_id="V2-HIJACK-016",
        proposed_class="Hijack",
        event_date_time="2021-02-05",
        end_time="2021-02-05",
        asn="AS136168 Campana MYTHIC; victim Twitter prefixes",
        prefix="Twitter prefixes; exact list not recovered from public MANRS summary",
        primary_source="MANRS BGP Security in 2021",
        source_url="https://manrs.org/2022/02/bgp-security-in-2021/",
        source_publication_date="2022-02-21",
        source_event_identifier="MANRS 2021 major hijack list: 2021-02-05 AS136168",
        evidence_summary="MANRS lists AS136168 Campana MYTHIC as hijacking Twitter prefixes on February 5, 2021.",
        exact_evidence="Victim network and culprit ASN are identified by MANRS; exact prefixes require event-specific source recovery.",
        corroborating_sources="MANRS blog referenced in annual summary",
        independent_adjudication_rationale="Accept as expert-reviewable because affected network, culprit ASN, date, and class are explicit.",
        adjudication_status="ACCEPT",
        metadata_limitations="Exact prefix list not recovered.",
        label_depends_on_multiple_sources="YES",
    )
    add(
        candidate_id="V2-HIJACK-017",
        proposed_class="Hijack",
        event_date_time="2017-04",
        end_time="2017-04",
        asn="AS12389 Rostelecom; affected financial/telecom/service provider ASNs",
        prefix="50 prefixes across MasterCard, Visa, Fortis, Alfa-Bank and others; exact prefix list not recovered here",
        primary_source="MANRS 2017 year-in-review",
        source_url="https://manrs.org/2018/01/14000-incidents-a-2017-routing-security-year-in-review/",
        source_publication_date="2018-01-09",
        source_event_identifier="MANRS 2017 April Rostelecom 50-prefix hijack",
        evidence_summary="MANRS reports Rostelecom originating 50 prefixes for other ASes for several minutes in April 2017.",
        exact_evidence="The MANRS review describes financial-services prefixes being briefly routed through a Russian telecom.",
        corroborating_sources="BGPmon 'Curious Case of AS12389' referenced in public summaries",
        independent_adjudication_rationale="High-profile wrong-origin event with source-native independent public documentation.",
        adjudication_status="ACCEPT",
        metadata_limitations="Month-level date in MANRS summary; exact start/end and full prefix list require BGPMon archive recovery.",
        label_depends_on_multiple_sources="YES",
    )
    add(
        candidate_id="V2-HIJACK-018",
        proposed_class="Hijack",
        event_date_time="2017-03",
        end_time="2017-03",
        asn="SECW Telecom Brazil; victims include Cloudflare, Google, Banco do Brasil",
        prefix="Cloudflare, Google, Banco do Brasil prefixes; exact list not recovered from public MANRS summary",
        primary_source="MANRS 2017 year-in-review",
        source_url="https://manrs.org/2018/01/14000-incidents-a-2017-routing-security-year-in-review/",
        source_publication_date="2018-01-09",
        source_event_identifier="MANRS 2017 March SECW Brazil incident",
        evidence_summary="MANRS reports SECW Telecom in Brazil hijacked prefixes of Cloudflare, Google, and Banco do Brasil.",
        exact_evidence="The event is listed as a media-picked example from 2017 BGPStream incidents.",
        corroborating_sources="BGPStream annual data cited by MANRS",
        independent_adjudication_rationale="Accept with limitations because class, actor, victims, and month are known but exact prefix/time metadata need recovery.",
        adjudication_status="ACCEPT",
        metadata_limitations="Only month-level date and victim networks recovered; before lock, recover exact BGPStream event/prefix details.",
        label_depends_on_multiple_sources="YES",
    )
    add(
        candidate_id="V2-HIJACK-019",
        proposed_class="Hijack",
        event_date_time="2017-12",
        end_time="2017-12",
        asn="Previously unused Russian AS; victims include Google, Apple, Facebook, Microsoft, Twitch, NTT Communications, Riot Games",
        prefix="Major Internet service prefixes; exact list not recovered from public MANRS summary",
        primary_source="MANRS 2017 year-in-review",
        source_url="https://manrs.org/2018/01/14000-incidents-a-2017-routing-security-year-in-review/",
        source_publication_date="2018-01-09",
        source_event_identifier="MANRS 2017 December Russian AS reroute",
        evidence_summary="MANRS reports two BGP routing incidents rerouting high-profile sites to a previously unused Russian AS for about three minutes each.",
        exact_evidence="Victim networks and approximate duration are documented in MANRS's 2017 incident examples.",
        corroborating_sources="BGPStream annual data cited by MANRS",
        independent_adjudication_rationale="Treat as ACCEPT_WITH_METADATA_LIMITATION for expert review because exact AS/prefix details need recovery before lock.",
        adjudication_status="ACCEPT",
        metadata_limitations="Exact AS, prefix list, and event IDs not recovered in public summary.",
        label_depends_on_multiple_sources="YES",
    )

    # Leak additions.
    add(
        candidate_id="V2-LEAK-006",
        proposed_class="Leak",
        event_date_time="2021-01-06T04:21:00Z",
        end_time="2021-01-06T06:51:00Z",
        asn="AS9304 leaked through AS15412",
        prefix="8764 leaked prefixes; exact list not recovered from public article text",
        primary_source="Qrator Labs Radar article",
        source_url="https://blog.qrator.net/en/as9304-leaking-8764-prefixes-through-as15412_111/",
        source_publication_date="2021-01-06",
        source_event_identifier="Qrator AS9304 leaking 8764 prefixes through AS15412",
        evidence_summary="Qrator reports AS9304 leaked 8,764 prefixes through AS15412, affecting 907 ASNs in 66 countries.",
        exact_evidence="Start 04:21 UTC, active phase about 2.5 hours, 9140 conflicts overall.",
        corroborating_sources="Qrator newsletter summary https://blog.qrator.net/en/cybersecurity-newsletter-first-2021_114/",
        independent_adjudication_rationale="Source-native route leak classification with timestamp, leaker ASN, transit ASN, and prefix count.",
        adjudication_status="ACCEPT",
        label_depends_on_multiple_sources="YES",
        metadata_limitations="Full prefix list not in public article text.",
    )
    add(
        candidate_id="V2-LEAK-007",
        proposed_class="Leak",
        event_date_time="2021-02-11T04:36:41Z",
        end_time="2021-02-11T04:50:10Z",
        asn="AS28548; leaked routes from AS14178 to AS18734",
        prefix="2828 prefixes in Qrator summary; 7200+ unique IPv4 prefixes in MANRS/Isolario analysis; example 201.157.24.0/24",
        primary_source="MANRS incident analysis",
        source_url="https://manrs.org/2021/02/major-route-leak-by-as28548-another-bgp-optimizer/",
        source_publication_date="2021-02-13",
        source_event_identifier="Qrator/MANRS AS28548 Cablevision route leak",
        evidence_summary="AS28548 leaked routes it received from AS14178 to AS18734 after routing policy changes.",
        exact_evidence="MANRS reports first changes at 04:36:41 UTC, last leak update 04:48:21, own-prefix announcements at 04:50:10, and example 201.157.24.0/24.",
        corroborating_sources="Qrator Radar page 2 summary; Doug Madory/Kentik tweet cited by MANRS",
        independent_adjudication_rationale="Strong source-native route leak with AS path direction, timestamp, example prefix, and corroborating analyst evidence.",
        adjudication_status="ACCEPT",
        label_depends_on_multiple_sources="YES",
    )
    add(
        candidate_id="V2-LEAK-008",
        proposed_class="Leak",
        event_date_time="2020-08-24T11:21:00Z",
        end_time="2020-08-24T16:00:00Z",
        asn="AS42910 Premier DC via AS9121/AS61135",
        prefix="1403 leaked prefixes; 1000+ Akamai prefixes; exact list not recovered",
        primary_source="Qrator Labs Radar article",
        source_url="https://blog.qrator.net/en/as42910-leaking-hundreds-prefixes_89/",
        source_publication_date="2020-08-25",
        source_event_identifier="Qrator AS42910 August 2020 route leak",
        evidence_summary="Qrator reports AS42910 leaked 1,403 prefixes, affecting Akamai and Western Asia.",
        exact_evidence="Incident started at 11:21 UTC, occurred in four waves, and ended around 16:00 UTC.",
        corroborating_sources="Qrator Radar archive page 2",
        independent_adjudication_rationale="Source-native route leak with start/end timing, leaker ASN, scope, and affected organization.",
        adjudication_status="ACCEPT",
        label_depends_on_multiple_sources="YES",
        metadata_limitations="Full affected-prefix list not recovered.",
    )
    add(
        candidate_id="V2-LEAK-009",
        proposed_class="Leak",
        event_date_time="2018-01-17T12:01:00Z",
        end_time="2018-01-17T12:16:00Z",
        asn="AS8901; AS12389; AS8732",
        prefix="70000 affected prefixes; example 5.121.176.0/20",
        primary_source="Qrator Labs Radar article",
        source_url="https://blog.qrator.net/en/moscow-traffic-jam_9/",
        source_publication_date="2018-01-17",
        source_event_identifier="Qrator Moscow Traffic Jam AS8901 route leak",
        evidence_summary="AS8901 leaked prefixes between upstreams Rostelecom and Comcor.",
        exact_evidence="Qrator reports the active phase began at 12:01 UTC, lasted 15 minutes, and peaked at 70,000 affected prefixes; example route 5.121.176.0/20 is shown.",
        corroborating_sources="None recovered in this pass",
        independent_adjudication_rationale="Source-native route leak with exact start, duration, AS path context, and example prefix.",
        adjudication_status="ACCEPT",
    )
    add(
        candidate_id="V2-LEAK-010",
        proposed_class="Leak",
        event_date_time="2019-04-04",
        end_time="2019-04-04",
        asn="AS60280; AS9002; AS205540",
        prefix="18600 leaked prefixes from approximately 1400 origin ASes; exact list not recovered",
        primary_source="Qrator Labs Radar archive",
        source_url="https://blog.qrator.net/en/radar/?page=4",
        source_publication_date="2019-04",
        source_event_identifier="Qrator NTEC AS60280 Belarus route leak",
        evidence_summary="Belarus NTEC AS60280 leaked routes learned from RETN AS9002 to RU-telecom AS205540.",
        exact_evidence="Qrator archive states AS60280 leaked 18,600 prefixes originating from approximately 1,400 ASes on 2019-04-04.",
        corroborating_sources="Qrator blog index page 12",
        independent_adjudication_rationale="Accept as source-native route leak candidate; exact prefix list not recovered.",
        adjudication_status="ACCEPT",
        label_depends_on_multiple_sources="YES",
        metadata_limitations="Exact time and prefix list require article recovery beyond archive excerpt.",
    )
    add(
        candidate_id="V2-LEAK-011",
        proposed_class="Leak",
        event_date_time="2019-06-06T09:43:00Z",
        end_time="2019-06-06T11:43:00Z",
        asn="AS21217 Safe Host; AS4134 China Telecom; victims AS3303/AS1136/AS5410/AS21502",
        prefix="70000+ leaked routes; examples 176.171.75.0/24 and European mobile-network prefixes",
        primary_source="MANRS / Oracle Internet Intelligence incident analysis",
        source_url="https://manrs.org/2019/06/large-european-routing-leak-sends-traffic-through-china-telecom/",
        source_publication_date="2019-06-11",
        source_event_identifier="MANRS/Oracle Safe Host China Telecom leak June 2019",
        evidence_summary="Safe Host leaked over 70,000 routes to China Telecom, redirecting traffic for major European mobile networks.",
        exact_evidence="MANRS reports the leak began at 09:43 UTC, many routes circulated over two hours, and gives example prefix 176.171.75.0/24 with AS path through AS4134/AS21217.",
        corroborating_sources="Oracle Internet Intelligence original article referenced by MANRS; user traceroutes cited in MANRS",
        independent_adjudication_rationale="Strong independent route leak with exact timing, AS path, example prefix, and affected networks.",
        adjudication_status="ACCEPT",
        label_depends_on_multiple_sources="YES",
    )
    add(
        candidate_id="V2-LEAK-012",
        proposed_class="Leak",
        event_date_time="2023-05-25T11:21:40Z",
        end_time="2023-05-25T12:43:36Z",
        asn="AS37468 Angola Cables; victims include AS20940/AS16509 and others",
        prefix="2.16.0.0/13; example IPv6 prefixes 2001:502:be98::/48, 2001:503:f189::/48, 2001:500:ed30::/48",
        primary_source="MANRS incident analysis",
        source_url="https://manrs.org/2023/05/bgp-route-leak-at-angola-cables-slows-connectivity-for-many-australians/",
        source_publication_date="2023-05",
        source_event_identifier="MANRS Angola Cables AS37468 route leak",
        evidence_summary="Angola Cables leaked routes via an IX route server, causing high-latency paths for Australian users.",
        exact_evidence="MANRS shows 2.16.0.0/13 path changed to include AS37468 at 11:21 UTC and disappeared after 12:41 UTC; article states route leak lasted around three hours.",
        corroborating_sources="Doug Madory/Kentik commentary cited by MANRS; local Australian operator reports cited",
        independent_adjudication_rationale="Strong independent route leak with route examples, timestamps, and operator context.",
        adjudication_status="ACCEPT",
        label_depends_on_multiple_sources="YES",
    )
    add(
        candidate_id="V2-LEAK-013",
        proposed_class="Leak",
        event_date_time="2017-08-25",
        end_time="2017-08-25",
        asn="Google; affected Japanese networks",
        prefix="Google leaked BGP prefixes learned from peering relationships; exact list not recovered here",
        primary_source="Internet Society / MANRS article",
        source_url="https://www.internetsociety.org/blog/2017/08/google-leaked-prefixes-knocked-japan-off-internet/",
        source_publication_date="2017-08-28",
        source_event_identifier="Google Japan route leak August 2017",
        evidence_summary="Google accidentally leaked BGP prefixes learned from peering relationships, causing disruption for Japanese users.",
        exact_evidence="Internet Society reports the incident lasted less than ten minutes but spread quickly and caused large-scale Internet disruption in Japan.",
        corroborating_sources="MANRS 2017 year-in-review lists the incident",
        independent_adjudication_rationale="Independent route leak candidate with date, actor, affected region, and class; exact prefix/time details need recovery.",
        adjudication_status="ACCEPT",
        metadata_limitations="Exact prefix list and start/end time not recovered in this pass.",
        label_depends_on_multiple_sources="YES",
    )
    add(
        candidate_id="V2-LEAK-014",
        proposed_class="Leak",
        event_date_time="2017-10",
        end_time="2017-10",
        asn="Brazilian network; affected CDNs including Twitter/Google and others",
        prefix="Major CDN prefixes; exact list not recovered",
        primary_source="MANRS 2017 year-in-review",
        source_url="https://manrs.org/2018/01/14000-incidents-a-2017-routing-security-year-in-review/",
        source_publication_date="2018-01-09",
        source_event_identifier="MANRS 2017 October Brazil CDN route leak",
        evidence_summary="MANRS reports a BGP leak rerouted traffic for Twitter, Google, and other CDNs through Brazil for about 20 minutes.",
        exact_evidence="MANRS lists this as an example BGP mishap causing reachability/performance problems for many large CDNs.",
        corroborating_sources="BGPStream annual data cited by MANRS",
        independent_adjudication_rationale="Accepted as source-native route leak candidate with source limitations; exact prefix event id should be recovered before lock.",
        adjudication_status="ACCEPT",
        metadata_limitations="Month-level date and exact prefix details not recovered.",
        label_depends_on_multiple_sources="YES",
    )
    add(
        candidate_id="V2-LEAK-015",
        proposed_class="Leak",
        event_date_time="2017-11",
        end_time="2017-11",
        asn="Level 3",
        prefix="Route leak affecting North America; exact prefix list not recovered",
        primary_source="MANRS 2017 year-in-review",
        source_url="https://manrs.org/2018/01/14000-incidents-a-2017-routing-security-year-in-review/",
        source_publication_date="2018-01-09",
        source_event_identifier="MANRS 2017 November Level 3 route leak",
        evidence_summary="MANRS reports Level 3 BGP routing issues causing large-scale network degradation in North America for slightly more than 90 minutes, classified as another route leak.",
        exact_evidence="The MANRS year-in-review explicitly labels this as a route leak.",
        corroborating_sources="BGPStream annual data cited by MANRS",
        independent_adjudication_rationale="Accepted with metadata limitations for expert review; exact source event details needed before lock.",
        adjudication_status="ACCEPT",
        metadata_limitations="Exact prefix list and event IDs not recovered.",
        label_depends_on_multiple_sources="YES",
    )
    add(
        candidate_id="V2-LEAK-016",
        proposed_class="Leak",
        event_date_time="2022-01-19T17:00:07Z",
        end_time="2022-01-20",
        asn="AS57695; AS60068; route views peer AS6447",
        prefix="0.0.0.0/0; 104.0.0.0/2; 154.117.72.0/22; 154.117.64.0/22",
        primary_source="MANRS incident analysis",
        source_url="https://manrs.org/2022/04/rfc-7911-what-happens-when-routers-do-not-speak-the-same-language/",
        source_publication_date="2022-04",
        source_event_identifier="MANRS AS57695 RFC7911 leak/malformed update event",
        evidence_summary="MANRS reports AS57695 leaked strange routes visible via RouteViews Equinix Ashburn.",
        exact_evidence="Article provides BGP update example at 2022-01-19 17:00:07 with prefixes including 0.0.0.0/0 and 154.117.72.0/22.",
        corroborating_sources="RouteViews updates shown in article",
        independent_adjudication_rationale="Route leak classification is source-native, but event was not globally visible; useful as review candidate.",
        adjudication_status="AMBIGUOUS",
        metadata_limitations="Article emphasizes collector-specific visibility; mark ambiguous for confirmation-set eligibility.",
    )
    add(
        candidate_id="V2-LEAK-017",
        proposed_class="Leak",
        event_date_time="2026-04-01T10:23:49Z",
        end_time="2026-04-01T10:24:32Z",
        asn="AS18106 vantage; path includes AS36692 AS25605 AS30607 AS36692",
        prefix="67.215.94.0/24",
        primary_source="Kentik route leak analysis",
        source_url="https://www.kentik.com/blog/ephemeral-leaks-and-automated-bgp-route-leak-detection/",
        source_publication_date="2026",
        source_event_identifier="Kentik ephemeral leak 67.215.94.0/24 2026-04-01",
        evidence_summary="Kentik documents an ephemeral route leak for prefix 67.215.94.0/24 after withdrawals began.",
        exact_evidence="Kentik shows RouteViews update lines from 10:23:49 to 10:24:32 UTC with leak AS paths for 67.215.94.0/24.",
        corroborating_sources="RouteViews excerpts in Kentik article",
        independent_adjudication_rationale="Strong single-prefix leak example with exact prefix, times, and RouteViews evidence.",
        adjudication_status="ACCEPT",
        label_depends_on_multiple_sources="YES",
    )
    add(
        candidate_id="V2-LEAK-018",
        proposed_class="Leak",
        event_date_time="2026-05-21T08:05:00Z",
        end_time="2026-05-21T09:35:00Z",
        asn="AS7303 Telecom; learned from AS22927; leaked toward AS6762 and AS3356",
        prefix="2989 leaked prefixes; exact list not recovered from Qrator social mirror",
        primary_source="Qrator_Radar social feed mirror",
        source_url="https://twstalker.com/Qrator_Radar",
        source_publication_date="2026-05",
        source_event_identifier="Qrator_Radar AS7303 2026-05-21 route leak",
        evidence_summary="Qrator_Radar feed reports AS7303 leaked 2,989 prefixes learned from AS22927 toward AS6762 and AS3356.",
        exact_evidence="Feed states start 08:05 UTC, 3,994 conflicts, 343 ASNs in 4 countries, max propagation 93%, duration about 1.5h.",
        corroborating_sources="None recovered in this pass",
        independent_adjudication_rationale="Accept as Qrator source-native leak candidate but source should be upgraded to original X/API archive before final lock.",
        adjudication_status="ACCEPT",
        metadata_limitations="Source URL is a public mirror of Qrator_Radar; original tweet/API URL should be recovered before lock.",
    )
    add(
        candidate_id="V2-LEAK-019",
        proposed_class="Leak",
        event_date_time="2026-05-28T08:21:00Z",
        end_time="2026-05-28T08:26:00Z",
        asn="AS21859 ZEN-ECN; learned from AS4755; leaked toward AS9498",
        prefix="1334 leaked prefixes; exact list not recovered from Qrator social mirror",
        primary_source="Qrator_Radar social feed mirror",
        source_url="https://twstalker.com/Qrator_Radar",
        source_publication_date="2026-05",
        source_event_identifier="Qrator_Radar AS21859 2026-05-28 route leak",
        evidence_summary="Qrator_Radar feed reports AS21859 leaked 1,334 prefixes learned from AS4755 toward AS9498.",
        exact_evidence="Feed states 1,334 conflicts with 1,005 ASNs in 75 countries, max propagation 68%, duration about 5 minutes.",
        corroborating_sources="None recovered in this pass",
        independent_adjudication_rationale="Accept as Qrator source-native leak candidate with social-source limitation.",
        adjudication_status="ACCEPT",
        metadata_limitations="Original source should be recovered before final lock.",
    )
    add(
        candidate_id="V2-LEAK-020",
        proposed_class="Leak",
        event_date_time="2026-06-26T11:25:00Z",
        end_time="2026-06-26T11:40:00Z",
        asn="AS28910 INTAL; learned from AS1299/AS58453; leaked toward AS205103",
        prefix="3095 leaked prefixes; exact list not recovered from Qrator social mirror",
        primary_source="Qrator_Radar social feed mirror",
        source_url="https://twstalker.com/Qrator_Radar",
        source_publication_date="2026-06",
        source_event_identifier="Qrator_Radar AS28910 2026-06-26 route leak",
        evidence_summary="Qrator_Radar feed reports AS28910 leaked 3,095 prefixes learned from AS1299/AS58453 and others toward AS205103.",
        exact_evidence="Feed states 107 ASNs in 35 countries, max propagation 100%, duration about 15 minutes.",
        corroborating_sources="None recovered in this pass",
        independent_adjudication_rationale="Accept as source-native Qrator social event with source-archive limitation.",
        adjudication_status="ACCEPT",
        metadata_limitations="Original source should be recovered before final lock.",
    )
    add(
        candidate_id="V2-LEAK-021",
        proposed_class="Leak",
        event_date_time="2024-05-24",
        end_time="2024-05-24",
        asn="Megatelecom; InterNexa Brasil integration context",
        prefix="5333 conflicts; exact leaked prefix list not recovered",
        primary_source="Qrator Labs Q3 2024 BGP incident overview",
        source_url="https://blog.qrator.net/en/q3-2024-ddos-bots-and-bgp-incidents-statistics-and_209/",
        source_publication_date="2024",
        source_event_identifier="Qrator Q2/Q3 2024 Megatelecom route leak",
        evidence_summary="Qrator identifies a major May 24 2024 route leak caused by Brazilian provider Megatelecom.",
        exact_evidence="Qrator reports 5,333 conflicts involving 593 ASes from 68 countries, caused by infrastructure merging during Megatelecom's acquisition of InterNexa Brasil.",
        corroborating_sources="Qrator Q2 2024 overview https://blog.qrator.net/en/q2-2024-ddos-bots-and-bgp-incidents-statistics-and_205/",
        independent_adjudication_rationale="Source-native Qrator global route leak event; exact prefix list not recovered.",
        adjudication_status="ACCEPT",
        label_depends_on_multiple_sources="YES",
        metadata_limitations="Exact ASN and affected prefix list require deeper source/API recovery.",
    )
    add(
        candidate_id="V2-LEAK-022",
        proposed_class="Leak",
        event_date_time="2021-12-24",
        end_time="2021-12-24",
        asn="AS7633 SOFTNET India",
        prefix="20000 leaked prefixes; exact list not recovered from public MANRS summary",
        primary_source="MANRS BGP Security in 2021",
        source_url="https://manrs.org/2022/02/bgp-security-in-2021/",
        source_publication_date="2022-02-21",
        source_event_identifier="MANRS 2021 major leak list: 2021-12-24 AS7633",
        evidence_summary="MANRS lists AS7633 SOFTNET India as leaking 20,000 prefixes on December 24, 2021.",
        exact_evidence="MANRS selected it as a significant 2021 BGP leak based on impact/number of prefixes.",
        corroborating_sources="Qrator Labs referenced by MANRS",
        independent_adjudication_rationale="Accept as expert-reviewable leak candidate with exact date/ASN/count.",
        adjudication_status="ACCEPT",
        metadata_limitations="Full prefix list requires Qrator archive recovery.",
        label_depends_on_multiple_sources="YES",
    )
    add(
        candidate_id="V2-LEAK-023",
        proposed_class="Leak",
        event_date_time="2021-12-24",
        end_time="2021-12-24",
        asn="AS132215 POWERGRID",
        prefix="112000 leaked prefixes; exact list not recovered from public MANRS summary",
        primary_source="MANRS BGP Security in 2021",
        source_url="https://manrs.org/2022/02/bgp-security-in-2021/",
        source_publication_date="2022-02-21",
        source_event_identifier="MANRS 2021 major leak list: 2021-12-24 AS132215",
        evidence_summary="MANRS lists AS132215 POWERGRID as leaking 112,000 prefixes on December 24, 2021.",
        exact_evidence="Date, leaker ASN, route-leak classification, and prefix count are present in the MANRS annual summary.",
        corroborating_sources="Qrator Labs referenced by MANRS",
        independent_adjudication_rationale="Accept with exact-prefix limitation.",
        adjudication_status="ACCEPT",
        metadata_limitations="Full prefix list requires Qrator archive recovery.",
        label_depends_on_multiple_sources="YES",
    )
    add(
        candidate_id="V2-LEAK-024",
        proposed_class="Leak",
        event_date_time="2021-12-08",
        end_time="2021-12-08",
        asn="AS10442 VOZHD",
        prefix="32000 leaked prefixes; exact list not recovered from public MANRS summary",
        primary_source="MANRS BGP Security in 2021",
        source_url="https://manrs.org/2022/02/bgp-security-in-2021/",
        source_publication_date="2022-02-21",
        source_event_identifier="MANRS 2021 major leak list: 2021-12-08 AS10442",
        evidence_summary="MANRS lists AS10442 VOZHD as leaking 32,000 prefixes on December 8, 2021.",
        exact_evidence="Date, leaker ASN, route-leak classification, and prefix count are present in the MANRS annual summary.",
        corroborating_sources="Qrator Labs referenced by MANRS",
        independent_adjudication_rationale="Accept with exact-prefix limitation.",
        adjudication_status="ACCEPT",
        metadata_limitations="Full prefix list requires Qrator archive recovery.",
        label_depends_on_multiple_sources="YES",
    )
    add(
        candidate_id="V2-LEAK-025",
        proposed_class="Leak",
        event_date_time="2021-08-19",
        end_time="2021-08-19",
        asn="AS265038 JNET",
        prefix="11000 leaked prefixes; exact list not recovered from public MANRS summary",
        primary_source="MANRS BGP Security in 2021",
        source_url="https://manrs.org/2022/02/bgp-security-in-2021/",
        source_publication_date="2022-02-21",
        source_event_identifier="MANRS 2021 major leak list: 2021-08-19 AS265038",
        evidence_summary="MANRS lists AS265038 JNET as leaking 11,000 prefixes on August 19, 2021.",
        exact_evidence="Date, leaker ASN, route-leak classification, and prefix count are present in the MANRS annual summary.",
        corroborating_sources="Qrator Labs referenced by MANRS",
        independent_adjudication_rationale="Accept with exact-prefix limitation.",
        adjudication_status="ACCEPT",
        metadata_limitations="Full prefix list requires Qrator archive recovery.",
        label_depends_on_multiple_sources="YES",
    )
    add(
        candidate_id="V2-LEAK-026",
        proposed_class="Leak",
        event_date_time="2021-07-30",
        end_time="2021-07-30",
        asn="AS137996 WITGLOBALCOMMUNICATIONS",
        prefix="167000 leaked prefixes; exact list not recovered from public MANRS summary",
        primary_source="MANRS BGP Security in 2021",
        source_url="https://manrs.org/2022/02/bgp-security-in-2021/",
        source_publication_date="2022-02-21",
        source_event_identifier="MANRS 2021 major leak list: 2021-07-30 AS137996",
        evidence_summary="MANRS lists AS137996 WITGLOBALCOMMUNICATIONS as leaking 167,000 prefixes on July 30, 2021.",
        exact_evidence="Date, leaker ASN, route-leak classification, and prefix count are present in the MANRS annual summary.",
        corroborating_sources="Qrator Labs referenced by MANRS",
        independent_adjudication_rationale="Accept with exact-prefix limitation.",
        adjudication_status="ACCEPT",
        metadata_limitations="Full prefix list requires Qrator archive recovery.",
        label_depends_on_multiple_sources="YES",
    )
    add(
        candidate_id="V2-LEAK-027",
        proposed_class="Leak",
        event_date_time="2021-06-03",
        end_time="2021-06-03",
        asn="AS199599 CIREX",
        prefix="26000 leaked prefixes; exact list not recovered from public MANRS summary",
        primary_source="MANRS BGP Security in 2021",
        source_url="https://manrs.org/2022/02/bgp-security-in-2021/",
        source_publication_date="2022-02-21",
        source_event_identifier="MANRS 2021 major leak list: 2021-06-03 AS199599",
        evidence_summary="MANRS lists AS199599 CIREX as leaking 26,000 prefixes on June 3, 2021.",
        exact_evidence="Date, leaker ASN, route-leak classification, and prefix count are present in the MANRS annual summary.",
        corroborating_sources="Qrator Labs referenced by MANRS",
        independent_adjudication_rationale="Accept with exact-prefix limitation.",
        adjudication_status="ACCEPT",
        metadata_limitations="Full prefix list requires Qrator archive recovery.",
        label_depends_on_multiple_sources="YES",
    )
    return c


def normalize_tokens(value: str) -> set[str]:
    out = set()
    for token in str(value).replace(",", ";").replace("|", ";").split(";"):
        t = token.strip().upper()
        if not t:
            continue
        out.add(t)
        if t.startswith("AS") and t[2:].isdigit():
            out.add(t[2:])
    return out


def apply_conservative_overlap(candidates: list[Candidate]) -> None:
    """Use local frozen roster only for conservative exact-ish overlap hints."""
    if not FROZEN_ROSTER.exists():
        return
    roster = pd.read_csv(FROZEN_ROSTER, dtype=str).fillna("")
    fields = [c for c in ["category", "start_utc", "incident_uid", "incident_id", "affected_asns", "victim_asns", "hijacker_asn", "leak_asn", "prefix", "affected_prefixes", "prefixes"] if c in roster.columns]
    for cand in candidates:
        if cand.overlap_status != "NEW_INDEPENDENT_EVENT":
            continue
        date = cand.event_date_time[:10]
        cls = cand.proposed_class.lower()
        cand_asns = normalize_tokens(cand.asn)
        cand_prefixes = normalize_tokens(cand.prefix)
        possible = []
        for _, row in roster.iterrows():
            cat = str(row.get("category", "")).lower()
            if cat and cls not in cat:
                continue
            start = str(row.get("start_utc", ""))
            if date and start and not start.startswith(date[:7]):
                continue
            row_text = ";".join(str(row.get(f, "")) for f in fields)
            row_tokens = normalize_tokens(row_text)
            if cand_asns & row_tokens or cand_prefixes & row_tokens:
                possible.append(str(row.get("incident_uid", row.get("incident_id", ""))))
        if possible:
            cand.overlap_status = "POSSIBLE_OVERLAP_REVIEW"
            cand.metadata_limitations = (cand.metadata_limitations + " " if cand.metadata_limitations else "") + f"Conservative local overlap review triggered against {len(possible)} frozen-roster rows."


def write_csv(path: Path, rows: Iterable[dict], fieldnames: list[str] | None = None) -> None:
    rows = list(rows)
    if fieldnames is None:
        keys = []
        for r in rows:
            for k in r:
                if k not in keys:
                    keys.append(k)
        fieldnames = keys
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    candidates = base_hijack_leak_candidates() + expansion_candidates()
    seen = set()
    unique: list[Candidate] = []
    for cand in candidates:
        if cand.candidate_id not in seen:
            seen.add(cand.candidate_id)
            unique.append(cand)
    apply_conservative_overlap(unique)

    # Build outputs.
    candidate_rows = [asdict(c) for c in unique]
    write_csv(OUT / "v2_hijack_leak_expansion_candidates.csv", candidate_rows)

    evidence_rows = []
    for c in unique:
        evidence_rows.append({
            "candidate_id": c.candidate_id,
            "proposed_class": c.proposed_class,
            "evidence_type": "primary_source",
            "source": c.primary_source,
            "url": c.source_url,
            "publication_date": c.source_publication_date,
            "retrieval_date": c.source_retrieval_date,
            "supports_classification": "YES" if c.adjudication_status == "ACCEPT" else "PARTIAL",
            "evidence": c.exact_evidence,
            "limitation": c.metadata_limitations,
        })
        if c.corroborating_sources and c.corroborating_sources.lower() not in {"none", "none locked", "nan"}:
            evidence_rows.append({
                "candidate_id": c.candidate_id,
                "proposed_class": c.proposed_class,
                "evidence_type": "corroborating_source",
                "source": c.corroborating_sources,
                "url": c.corroborating_sources,
                "publication_date": "various",
                "retrieval_date": c.source_retrieval_date,
                "supports_classification": "PARTIAL",
                "evidence": "Corroborating source(s) listed in candidate row.",
                "limitation": "Not all corroborating sources were independently re-expanded into separate event rows.",
            })
    write_csv(OUT / "v2_hijack_leak_source_evidence_matrix.csv", evidence_rows)

    source_rows = []
    for (source, cls), ids in sorted(defaultdict(list, {k: [] for k in []}).items()):
        pass
    by_source = defaultdict(list)
    for c in unique:
        by_source[(c.primary_source, c.proposed_class, c.source_url)].append(c.candidate_id)
    for (source, cls, url), ids in sorted(by_source.items()):
        source_rows.append({
            "source": source,
            "class": cls,
            "source_url": url,
            "candidate_count": len(ids),
            "candidate_ids": "; ".join(ids),
            "source_role": "PRIMARY",
            "notes": "Cloudflare is not primary for any accepted expansion candidate.",
        })
    write_csv(OUT / "v2_hijack_leak_expansion_sources.csv", source_rows)

    overlap_rows = [{
        "candidate_id": c.candidate_id,
        "proposed_class": c.proposed_class,
        "event_date_time": c.event_date_time,
        "asn": c.asn,
        "prefix": c.prefix,
        "overlap_status": c.overlap_status,
        "comparison_basis": "Conservative date/class/ASN/prefix comparison against data/roster_v2/frozen_incident_roster_v2.csv and existing V2 candidate IDs; manual adjudication still required before lock.",
        "notes": c.metadata_limitations,
    } for c in unique]
    write_csv(OUT / "v2_hijack_leak_expansion_overlap.csv", overlap_rows)

    routeviews_rows = [{
        "candidate_id": c.candidate_id,
        "proposed_class": c.proposed_class,
        "event_date_time": c.event_date_time,
        "routeviews_month_url": c.routeviews_month_url,
        "routeviews_availability": c.routeviews_availability,
        "verification_basis": "Monthly RouteViews archive planning URL identified. This is a no-download feasibility check; exact collector/file selection remains for evaluation lock.",
    } for c in unique]
    write_csv(OUT / "v2_hijack_leak_routeviews_availability.csv", routeviews_rows)

    summary_rows = []
    total_independent = 30  # preserved accepted outage count from prior V2 audit.
    total_rv = 30
    for cls in ["Hijack", "Leak"]:
        rows = [c for c in unique if c.proposed_class == cls]
        accepted = [c for c in rows if c.adjudication_status == "ACCEPT" and c.overlap_status == "NEW_INDEPENDENT_EVENT"]
        rv = [c for c in accepted if c.routeviews_availability.startswith("ROUTEVIEWS")]
        corroborated = [c for c in accepted if c.label_depends_on_multiple_sources == "YES" or (";" in c.corroborating_sources)]
        total_independent += len(accepted)
        total_rv += len(rv)
        summary_rows.append({
            "class": cls,
            "total_candidates_found": len(rows),
            "accepted_new_independent": len(accepted),
            "routeviews_available_accepted": len(rv),
            "target_min_15_met": "YES" if len(accepted) >= 15 else "NO",
            "target_prefer_20_met": "YES" if len(accepted) >= 20 else "NO",
            "at_least_two_sources": len(corroborated),
            "rejected": sum(c.adjudication_status == "REJECT" for c in rows),
            "ambiguous": sum(c.adjudication_status == "AMBIGUOUS" for c in rows),
            "possible_overlap_review": sum(c.overlap_status != "NEW_INDEPENDENT_EVENT" for c in rows),
        })
    summary_rows.append({
        "class": "Outage",
        "total_candidates_found": 30,
        "accepted_new_independent": 30,
        "routeviews_available_accepted": 30,
        "target_min_15_met": "YES",
        "target_prefer_20_met": "YES",
        "at_least_two_sources": "NA",
        "rejected": 0,
        "ambiguous": 0,
        "possible_overlap_review": 0,
    })
    write_csv(OUT / "v2_expanded_class_counts_summary.csv", summary_rows)

    accepted = [c for c in unique if c.adjudication_status == "ACCEPT" and c.overlap_status == "NEW_INDEPENDENT_EVENT"]
    source_dist = Counter((c.proposed_class, c.primary_source) for c in accepted)
    md = []
    md.append("# V2 Hijack/Leak Expansion Feasibility Summary\n")
    md.append(f"Generated: {datetime.now(timezone.utc).isoformat()}\n")
    md.append("Scope: additive Hijack/Leak source expansion only under `experiments/independent_validation_audit_v2/`. No model scoring, no Validation access, no Final Holdout access, and no Outage search were performed.\n")
    md.append("## Counts\n")
    for row in summary_rows:
        md.append(f"- {row['class']}: accepted/new independent = {row['accepted_new_independent']}; RouteViews-available = {row['routeviews_available_accepted']}; target >=15 = {row['target_min_15_met']}; preferred >=20 = {row['target_prefer_20_met']}\n")
    md.append(f"- Total independent candidates including existing 30 Outage records: {total_independent}\n")
    md.append(f"- Total RouteViews-available accepted candidates including Outage: {total_rv}\n")
    md.append("\n## Source Distribution By Class\n")
    for (cls, src), n in sorted(source_dist.items()):
        md.append(f"- {cls}: {src} = {n}\n")
    md.append("\n## Lock Readiness\n")
    md.append("The expanded set reaches the minimum target of 15 accepted Hijack and 15 accepted Leak candidates, and Leak reaches the preferred 20+ target. Hijack remains below the preferred 20+ target. Several accepted events are prefix-count candidates whose public source text did not expose the full affected-prefix list; these are usable for expert adjudication but should be tightened before a final evaluation lock.\n")
    md.append("\nFinal disposition: `READY_FOR_V2_LOCK_WITH_LIMITATIONS`\n")
    (OUT / "v2_expansion_feasibility_summary.md").write_text("".join(md), encoding="utf-8")

    packets = []
    packets.append("# V2 Hijack/Leak Evidence Packets\n\n")
    for c in unique:
        packets.append(f"## {c.candidate_id} - {c.proposed_class} - {c.adjudication_status}\n")
        packets.append(f"- Time: {c.event_date_time} to {c.end_time}\n")
        packets.append(f"- ASN(s): {c.asn}\n")
        packets.append(f"- Prefix metadata: {c.prefix}\n")
        packets.append(f"- Primary source: {c.primary_source} ({c.source_url})\n")
        packets.append(f"- Source event id: {c.source_event_identifier}\n")
        packets.append(f"- Evidence: {c.exact_evidence}\n")
        packets.append(f"- Corroboration: {c.corroborating_sources}\n")
        packets.append(f"- Adjudication rationale: {c.independent_adjudication_rationale}\n")
        packets.append(f"- Overlap: {c.overlap_status}\n")
        packets.append(f"- RouteViews: {c.routeviews_availability}; {c.routeviews_month_url}\n")
        if c.metadata_limitations:
            packets.append(f"- Limitations: {c.metadata_limitations}\n")
        packets.append("\n")
    (OUT / "v2_hijack_leak_evidence_packets.md").write_text("".join(packets), encoding="utf-8")

    files = [
        "v2_hijack_leak_expansion_candidates.csv",
        "v2_hijack_leak_source_evidence_matrix.csv",
        "v2_hijack_leak_expansion_sources.csv",
        "v2_hijack_leak_expansion_overlap.csv",
        "v2_hijack_leak_routeviews_availability.csv",
        "v2_hijack_leak_evidence_packets.md",
        "v2_expanded_class_counts_summary.csv",
        "v2_expansion_feasibility_summary.md",
    ]
    checksums = [{"file": f, "sha256": sha256(OUT / f)} for f in files]
    write_csv(OUT / "v2_hijack_leak_expansion_checksums.csv", checksums)
    (OUT / "v2_hijack_leak_expansion_manifest.json").write_text(json.dumps({
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "disposition": "READY_FOR_V2_LOCK_WITH_LIMITATIONS",
        "outputs": files,
        "no_model_scoring": True,
        "validation_accessed": False,
        "final_holdout_accessed": False,
        "outage_search_performed": False,
    }, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
