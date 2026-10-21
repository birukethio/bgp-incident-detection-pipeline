# V2 Independent Validation Pre-Lock Expert Adjudication Packets

Purpose: human expert review of proposed independent confirmation incidents before any V2 evaluation lock.

Blinding: this packet contains only source-derived incident evidence and reviewer fields. It intentionally omits all downstream experimental artifacts.

Reviewer choices:
- Class assessment: `CONFIRM_HIJACK | CONFIRM_LEAK | CONFIRM_OUTAGE | AMBIGUOUS | INSUFFICIENT_EVIDENCE | REJECT`
- Metadata adequacy: `SUFFICIENT_FOR_ROUTING_RECONSTRUCTION | SUFFICIENT_WITH_DOCUMENTED_LIMITATION | INSUFFICIENT`
- Independence assessment: `INDEPENDENT | POSSIBLE_EXISTING_EVENT | REVIEW_REQUIRED`

## V2-HIJACK-001
- Proposed class: Hijack
- Event time: 2026-05-16/2026-05-17 to 2026-05-17
- Affected ASN(s): AS202734; AS402335; AS402333
- Origin ASN where applicable: See affected/hijacker ASN text
- Prefix metadata from source: 240e::/20; multiple IPv4/IPv6 prefixes
- Affected prefix count reported: 6
- Full prefix list available: PARTIAL
- Partial prefix metadata: YES
- Partial-prefix note: 240e::/20; multiple IPv4/IPv6 prefixes | limitation: Carried forward from V2 base audit.
- Primary source: GitHub evidence archive and NANOG thread
- Source type: NOG/NANOG
- Source URL/reference: https://github.com/miao-2011/bgp-hijack-evidence-AS202734; https://lists.nanog.org/archives/list/nanog@lists.nanog.org/thread/MI6VWOX7XOCDIS244RLJSMS2ITZWTGED/
- Source event identifier: V2-HIJACK-001
- Source-derived evidence summary: Independent evidence archive and NANOG thread report AS202734 and affiliated ASNs originated thousands of unauthorized prefixes including China Telecom 240e::/20.
- Exact evidence provided to reviewer: Documented unauthorized originations, affected prefixes, ASNs, and route-collector evidence.
- Corroborating source(s): RIPE BGPlay, Hurricane Electric BGP Toolkit, RouteViews output referenced in archive
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-HIJACK-002
- Proposed class: Hijack
- Event time: 2026-06-16 to 2026-06-16
- Affected ASN(s): AS18101
- Origin ASN where applicable: See affected/hijacker ASN text
- Prefix metadata from source: Telegram IPv4/IPv6 prefixes
- Affected prefix count reported: 6
- Full prefix list available: PARTIAL
- Partial prefix metadata: YES
- Partial-prefix note: Telegram IPv4/IPv6 prefixes | limitation: Carried forward from V2 base audit.
- Primary source: BGPHorizon incident analysis
- Source type: BGPHorizon
- Source URL/reference: https://www.bgphorizon.com/blog/telegram-bgp-hijack-june-2026
- Source event identifier: V2-HIJACK-002
- Source-derived evidence summary: BGPHorizon report says Telegram prefixes were announced by AS18101 instead of Telegram AS62041/AS62014/AS44907 in two waves.
- Exact evidence provided to reviewer: Documented wrong-origin routing for named affected network and ASNs; exact prefix list must be recovered before final roster.
- Corroborating source(s): Other routing monitors referenced by report
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-HIJACK-003
- Proposed class: Hijack
- Event time: 2008-02-24T20:07:25Z to 2008-02-24
- Affected ASN(s): AS36561; AS17557
- Origin ASN where applicable: See affected/hijacker ASN text
- Prefix metadata from source: 208.65.153.0/24
- Affected prefix count reported: 1
- Full prefix list available: YES_OR_EXAMPLES_AVAILABLE
- Partial prefix metadata: NO
- Partial-prefix note: Full or example prefix metadata available from source row.
- Primary source: RouteCause reproducible demo using RIPE RIS/RouteViews raw MRT
- Source type: RouteCause
- Source URL/reference: https://github.com/dim-tsoukalas/RouteCause
- Source event identifier: V2-HIJACK-003
- Source-derived evidence summary: RouteCause demo and well-known Pakistan Telecom/YouTube case show MOAS for YouTube prefix with AS36561 and legitimate AS17557.
- Exact evidence provided to reviewer: Clean wrong-origin/MOAS case with exact prefix, ASNs, and timestamped routing evidence.
- Corroborating source(s): Historic public reports of Pakistan Telecom / YouTube hijack
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-HIJACK-005
- Proposed class: Hijack
- Event time: 2019-04-01/2019-04-10 to 2019-04-10
- Affected ASN(s): AS263444; AS61775; AS265466
- Origin ASN where applicable: See affected/hijacker ASN text
- Prefix metadata from source: multiple split prefixes, examples 1.6.36.0/23 and 178.248.236.0/24
- Affected prefix count reported: 2
- Full prefix list available: PARTIAL
- Partial prefix metadata: YES
- Partial-prefix note: multiple split prefixes, examples 1.6.36.0/23 and 178.248.236.0/24 | limitation: Carried forward from V2 base audit.
- Primary source: Qrator Labs blog
- Source type: Qrator
- Source URL/reference: https://blog.qrator.net/en/new-hijack-attack_42/
- Source event identifier: V2-HIJACK-005
- Source-derived evidence summary: Qrator report documents crafted AS_PATH/split-prefix hijack-style behavior and affected prefix examples.
- Exact evidence provided to reviewer: Report provides BGP table/update examples, ASNs, prefixes, and hijack framing; expert review should verify exact event bounds.
- Corroborating source(s): Raw BGP examples in report
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-HIJACK-006
- Proposed class: Hijack
- Event time: 2020-07-30T01:15:38Z to 2020-07-30T02:27:27Z
- Affected ASN(s): AS10990; victim AS812; Charter/TWC/Videotron and others
- Origin ASN where applicable: AS10990; victim AS812; Charter/TWC/Videotron and others
- Prefix metadata from source: 99.225.224.0/19; 99.228.0.0/17; 145 prefixes in second wave; 179 prefixes in first wave
- Affected prefix count reported: 145
- Full prefix list available: PARTIAL
- Partial prefix metadata: YES
- Partial-prefix note: 99.225.224.0/19; 99.228.0.0/17; 145 prefixes in second wave; 179 prefixes in first wave | limitation: 
- Primary source: MANRS incident analysis
- Source type: MANRS
- Source URL/reference: https://manrs.org/2020/07/another-bgp-incident-impacts-twc-rogers-charter-and-others/
- Source event identifier: BGPStream event 245324 / MANRS AS10990 July 2020
- Source-derived evidence summary: AS10990 announced more-specific prefixes belonging to Rogers/Charter/TWC/Videotron and others.
- Exact evidence provided to reviewer: MANRS reports first BGPStream possible-hijack alert at 01:15:38 UTC; AS10990 announced 99.225.224.0/19 while Rogers AS812 announced covering aggregates; second wave persisted until 02:27:27 UTC.
- Corroborating source(s): Qrator article https://blog.qrator.net/en/as10990-routing-optimization-tale_83/; NANOG mail thread subject BGP route hijack by AS10990
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-HIJACK-007
- Proposed class: Hijack
- Event time: 2022-07-26T21:25:10Z to 2022-07-27T09:39:00Z
- Affected ASN(s): AS12389; victim AS714
- Origin ASN where applicable: AS12389; victim AS714
- Prefix metadata from source: 17.70.96.0/19; Apple mitigation prefix 17.70.96.0/21
- Affected prefix count reported: 2
- Full prefix list available: YES_OR_EXAMPLES_AVAILABLE
- Partial prefix metadata: NO
- Partial-prefix note: Full or example prefix metadata available from source row.
- Primary source: MANRS incident analysis
- Source type: MANRS
- Source URL/reference: https://manrs.org/2022/07/for-12-hours-was-part-of-apple-engineerings-network-hijacked-by-russias-rostelecom/
- Source event identifier: BGPStream event 293915; GRIP submoas-1658870700-714=12389/17.70.96.0-19_17.0.0.0-9
- Source-derived evidence summary: Rostelecom AS12389 announced Apple Engineering prefix 17.70.96.0/19 for about 12 hours.
- Exact evidence provided to reviewer: MANRS gives BGP update lines at 21:25:10-21:29 UTC, BGPStream event 293915, GRIP event id, Apple mitigation at 02:41 UTC, and final withdrawals around 09:39 UTC.
- Corroborating source(s): The Register article; The FPS Review article; GRIP event URL cited by MANRS
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-HIJACK-008
- Proposed class: Hijack
- Event time: 2020-04-01T19:28:00Z to 2020-04-01
- Affected ASN(s): AS12389; affected AS16509/AS14618/AS20940 and others
- Origin ASN where applicable: See affected/hijacker ASN text
- Prefix metadata from source: 104.18.216.0/21; 104.17.128.0/21; 104.18.184.0/21; 95.100.200.0/24; 104.18.168.0/21; 104.107.217.0/24; 95.101.181.0/24; 95.216.178.0/24; 104.17.232.0/21; 95.101.82.0/23; BGPMon reported 8800+ prefixes
- Affected prefix count reported: 8800
- Full prefix list available: PARTIAL
- Partial prefix metadata: YES
- Partial-prefix note: 104.18.216.0/21; 104.17.128.0/21; 104.18.184.0/21; 95.100.200.0/24; 104.18.168.0/21; 104.107.217.0/24; 95.101.181.0/24; 95.216.178.0/24; 104.17.232.0/21; 95.101.82.0/23; BGPMon reported 8800+ prefixes | limitation: 
- Primary source: MANRS incident analysis
- Source type: MANRS
- Source URL/reference: https://manrs.org/2020/04/not-just-another-bgp-hijack/
- Source event identifier: MANRS/Qrator AS12389 April 2020
- Source-derived evidence summary: Rostelecom AS12389 originated many more-specific prefixes for networks including Amazon and Akamai.
- Exact evidence provided to reviewer: MANRS cites Qrator first mis-origination at 19:28 UTC and lists ten hijacked prefixes; it also notes BGPMon reported more than 8,800 prefixes.
- Corroborating source(s): Qrator Labs brief cited by MANRS; BGPMon prefix list cited by MANRS
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-HIJACK-009
- Proposed class: Hijack
- Event time: 2020-09-29 to 2020-09-29
- Affected ASN(s): AS1221; 266 affected ASNs
- Origin ASN where applicable: See affected/hijacker ASN text
- Prefix metadata from source: 472 prefixes announced; 1680+ affected IPv4 prefixes/conflicts; exact prefix list not in public article text
- Affected prefix count reported: 472
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: 472 prefixes announced; 1680+ affected IPv4 prefixes/conflicts; exact prefix list not in public article text | limitation: Exact affected prefix list not recovered from public article text; preserve as prefix-count event pending expert lock.
- Primary source: Qrator Labs Radar article index
- Source type: Qrator
- Source URL/reference: https://blog.qrator.net/en/radar/?page=2
- Source event identifier: Qrator AS1221 hijacking 266 ASNs in 51 countries
- Source-derived evidence summary: Qrator reports Telstra AS1221 announced 472 prefixes in a BGP hijack affecting 266 ASNs.
- Exact evidence provided to reviewer: Qrator archive excerpt: September 29 2020 AS1221 announced 472 prefixes in a BGP hijack event affecting 266 ASNs in 50 countries, creating almost 2000 path-challenge conflicts.
- Corroborating source(s): None recovered in this pass
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-HIJACK-010
- Proposed class: Hijack
- Event time: 2020-10-21T14:11:00Z to 2020-10-21
- Affected ASN(s): AS203; affected AS9198/AS35415/AS7979 and others
- Origin ASN where applicable: See affected/hijacker ASN text
- Prefix metadata from source: 158 announced prefixes; 1000+ conflicts; exact prefix list not recovered from public text
- Affected prefix count reported: 158
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: 158 announced prefixes; 1000+ conflicts; exact prefix list not recovered from public text | limitation: Exact affected prefix list not recovered from public article text.
- Primary source: Qrator Labs Radar article
- Source type: Qrator
- Source URL/reference: https://blog.qrator.net/en/lumen-aka-centurylink-generating-routing-incidents_101/
- Source event identifier: Qrator AS203 Lumen/CenturyLink October 2020
- Source-derived evidence summary: Qrator reports Lumen/Level3 AS203 announced prefixes that hijacked traffic for many original owners.
- Exact evidence provided to reviewer: Qrator states AS203 started announcing 158 prefixes around 14:11 UTC, affecting 31 ISPs in 19 countries and causing path-challenge conflicts.
- Corroborating source(s): None recovered in this pass
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-HIJACK-011
- Proposed class: Hijack
- Event time: 2021-10-25 to 2021-10-25
- Affected ASN(s): AS212046 MEZON
- Origin ASN where applicable: See affected/hijacker ASN text
- Prefix metadata from source: 3786 hijacked prefixes; exact prefix list not recovered from public MANRS summary
- Affected prefix count reported: 3786
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: 3786 hijacked prefixes; exact prefix list not recovered from public MANRS summary | limitation: Prefix count available; full prefix list requires Qrator social/API archive recovery.
- Primary source: MANRS BGP Security in 2021
- Source type: MANRS
- Source URL/reference: https://manrs.org/2022/02/bgp-security-in-2021/
- Source event identifier: MANRS 2021 major hijack list: 2021-10-25 AS212046
- Source-derived evidence summary: MANRS lists AS212046 MEZON as hijacking 3,786 prefixes on October 25, 2021.
- Exact evidence provided to reviewer: MANRS selected this as a particularly major disruption based on impact/number of prefixes.
- Corroborating source(s): Qrator Labs referenced by MANRS as detailed source
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-HIJACK-012
- Proposed class: Hijack
- Event time: 2021-10-13 to 2021-10-13
- Affected ASN(s): AS212046 MEZON
- Origin ASN where applicable: See affected/hijacker ASN text
- Prefix metadata from source: 1029 hijacked prefixes; exact prefix list not recovered from public MANRS summary
- Affected prefix count reported: 1029
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: 1029 hijacked prefixes; exact prefix list not recovered from public MANRS summary | limitation: Prefix count available; full prefix list requires source archive recovery.
- Primary source: MANRS BGP Security in 2021
- Source type: MANRS
- Source URL/reference: https://manrs.org/2022/02/bgp-security-in-2021/
- Source event identifier: MANRS 2021 major hijack list: 2021-10-13 AS212046
- Source-derived evidence summary: MANRS lists AS212046 MEZON as hijacking 1,029 prefixes on October 13, 2021.
- Exact evidence provided to reviewer: Separate date and prefix count from the October 25 MEZON event; treat as distinct pending expert adjudication.
- Corroborating source(s): Qrator Labs referenced by MANRS as detailed source
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-HIJACK-013
- Proposed class: Hijack
- Event time: 2021-09-21 to 2021-09-21
- Affected ASN(s): AS62325 HDHK
- Origin ASN where applicable: See affected/hijacker ASN text
- Prefix metadata from source: 89 hijacked prefixes; exact prefix list not recovered from public MANRS summary
- Affected prefix count reported: 89
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: 89 hijacked prefixes; exact prefix list not recovered from public MANRS summary | limitation: Prefix count only in public source.
- Primary source: MANRS BGP Security in 2021
- Source type: MANRS
- Source URL/reference: https://manrs.org/2022/02/bgp-security-in-2021/
- Source event identifier: MANRS 2021 major hijack list: 2021-09-21 AS62325
- Source-derived evidence summary: MANRS lists AS62325 HDHK as hijacking 89 prefixes on September 21, 2021.
- Exact evidence provided to reviewer: Date, culprit ASN, class, and prefix count are present in the MANRS annual incident list.
- Corroborating source(s): Qrator Labs referenced by MANRS as detailed source
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-HIJACK-014
- Proposed class: Hijack
- Event time: 2021-05-18 to 2021-05-18
- Affected ASN(s): AS48467 PRANET
- Origin ASN where applicable: See affected/hijacker ASN text
- Prefix metadata from source: 454 hijacked prefixes; exact prefix list not recovered from public MANRS summary
- Affected prefix count reported: 454
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: 454 hijacked prefixes; exact prefix list not recovered from public MANRS summary | limitation: Prefix count only in public source.
- Primary source: MANRS BGP Security in 2021
- Source type: MANRS
- Source URL/reference: https://manrs.org/2022/02/bgp-security-in-2021/
- Source event identifier: MANRS 2021 major hijack list: 2021-05-18 AS48467
- Source-derived evidence summary: MANRS lists AS48467 PRANET as hijacking 454 prefixes on May 18, 2021.
- Exact evidence provided to reviewer: Date, culprit ASN, class, and prefix count are present in the MANRS annual incident list.
- Corroborating source(s): Qrator Labs referenced by MANRS as detailed source
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-HIJACK-015
- Proposed class: Hijack
- Event time: 2021-04-16 to 2021-04-16
- Affected ASN(s): AS55410 Vodafone Idea Ltd
- Origin ASN where applicable: See affected/hijacker ASN text
- Prefix metadata from source: 30000 hijacked prefixes; exact prefix list not recovered from public MANRS summary
- Affected prefix count reported: 30000
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: 30000 hijacked prefixes; exact prefix list not recovered from public MANRS summary | limitation: Full prefix list and primary event-specific blog URL should be recovered before lock.
- Primary source: MANRS BGP Security in 2021
- Source type: MANRS
- Source URL/reference: https://manrs.org/2022/02/bgp-security-in-2021/
- Source event identifier: MANRS 2021 major hijack list: 2021-04-16 AS55410
- Source-derived evidence summary: MANRS lists AS55410 Vodafone Idea Ltd as hijacking 30,000 prefixes on April 16, 2021.
- Exact evidence provided to reviewer: MANRS annual summary flags the event as a particularly major disruption.
- Corroborating source(s): MANRS blog referenced in annual summary
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-HIJACK-016
- Proposed class: Hijack
- Event time: 2021-02-05 to 2021-02-05
- Affected ASN(s): AS136168 Campana MYTHIC; victim Twitter prefixes
- Origin ASN where applicable: AS136168 Campana MYTHIC; victim Twitter prefixes
- Prefix metadata from source: Twitter prefixes; exact list not recovered from public MANRS summary
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: Twitter prefixes; exact list not recovered from public MANRS summary | limitation: Exact prefix list not recovered.
- Primary source: MANRS BGP Security in 2021
- Source type: MANRS
- Source URL/reference: https://manrs.org/2022/02/bgp-security-in-2021/
- Source event identifier: MANRS 2021 major hijack list: 2021-02-05 AS136168
- Source-derived evidence summary: MANRS lists AS136168 Campana MYTHIC as hijacking Twitter prefixes on February 5, 2021.
- Exact evidence provided to reviewer: Victim network and culprit ASN are identified by MANRS; exact prefixes require event-specific source recovery.
- Corroborating source(s): MANRS blog referenced in annual summary
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-HIJACK-017
- Proposed class: Hijack
- Event time: 2017-04 to 2017-04
- Affected ASN(s): AS12389 Rostelecom; affected financial/telecom/service provider ASNs
- Origin ASN where applicable: See affected/hijacker ASN text
- Prefix metadata from source: 50 prefixes across MasterCard, Visa, Fortis, Alfa-Bank and others; exact prefix list not recovered here
- Affected prefix count reported: 50
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: 50 prefixes across MasterCard, Visa, Fortis, Alfa-Bank and others; exact prefix list not recovered here | limitation: Month-level date in MANRS summary; exact start/end and full prefix list require BGPMon archive recovery.
- Primary source: MANRS 2017 year-in-review
- Source type: MANRS
- Source URL/reference: https://manrs.org/2018/01/14000-incidents-a-2017-routing-security-year-in-review/
- Source event identifier: MANRS 2017 April Rostelecom 50-prefix hijack
- Source-derived evidence summary: MANRS reports Rostelecom originating 50 prefixes for other ASes for several minutes in April 2017.
- Exact evidence provided to reviewer: The MANRS review describes financial-services prefixes being briefly routed through a Russian telecom.
- Corroborating source(s): BGPmon 'Curious Case of AS12389' referenced in public summaries
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-HIJACK-018
- Proposed class: Hijack
- Event time: 2017-03 to 2017-03
- Affected ASN(s): SECW Telecom Brazil; victims include Cloudflare, Google, Banco do Brasil
- Origin ASN where applicable: SECW Telecom Brazil; victims include Cloudflare, Google, Banco do Brasil
- Prefix metadata from source: Cloudflare, Google, Banco do Brasil prefixes; exact list not recovered from public MANRS summary
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: Cloudflare, Google, Banco do Brasil prefixes; exact list not recovered from public MANRS summary | limitation: Only month-level date and victim networks recovered; before lock, recover exact BGPStream event/prefix details.
- Primary source: MANRS 2017 year-in-review
- Source type: MANRS
- Source URL/reference: https://manrs.org/2018/01/14000-incidents-a-2017-routing-security-year-in-review/
- Source event identifier: MANRS 2017 March SECW Brazil incident
- Source-derived evidence summary: MANRS reports SECW Telecom in Brazil hijacked prefixes of Cloudflare, Google, and Banco do Brasil.
- Exact evidence provided to reviewer: The event is listed as a media-picked example from 2017 BGPStream incidents.
- Corroborating source(s): BGPStream annual data cited by MANRS
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-HIJACK-019
- Proposed class: Hijack
- Event time: 2017-12 to 2017-12
- Affected ASN(s): Previously unused Russian AS; victims include Google, Apple, Facebook, Microsoft, Twitch, NTT Communications, Riot Games
- Origin ASN where applicable: Previously unused Russian AS; victims include Google, Apple, Facebook, Microsoft, Twitch, NTT Communications, Riot Games
- Prefix metadata from source: Major Internet service prefixes; exact list not recovered from public MANRS summary
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: Major Internet service prefixes; exact list not recovered from public MANRS summary | limitation: Exact AS, prefix list, and event IDs not recovered in public summary.
- Primary source: MANRS 2017 year-in-review
- Source type: MANRS
- Source URL/reference: https://manrs.org/2018/01/14000-incidents-a-2017-routing-security-year-in-review/
- Source event identifier: MANRS 2017 December Russian AS reroute
- Source-derived evidence summary: MANRS reports two BGP routing incidents rerouting high-profile sites to a previously unused Russian AS for about three minutes each.
- Exact evidence provided to reviewer: Victim networks and approximate duration are documented in MANRS's 2017 incident examples.
- Corroborating source(s): BGPStream annual data cited by MANRS
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-LEAK-001
- Proposed class: Leak
- Event time: 2021-01-27 to 2021-01-27
- Affected ASN(s): AS61666; AS28146; AS16735
- Origin ASN where applicable: Origin ASNs embedded in leaked prefixes/AS paths where source provides them; see evidence summary
- Prefix metadata from source: 1330 leaked prefixes
- Affected prefix count reported: 1330
- Full prefix list available: PARTIAL
- Partial prefix metadata: YES
- Partial-prefix note: 1330 leaked prefixes | limitation: Carried forward from V2 base audit.
- Primary source: Qrator Labs blog
- Source type: Qrator
- Source URL/reference: https://blog.qrator.net/en/prepending-trouble_115/
- Source event identifier: V2-LEAK-001
- Source-derived evidence summary: Qrator reports AS61666 GLOBO leaked upstream MHNET prefixes to ALGAR; 1,330 prefixes, 8 minute incident.
- Exact evidence provided to reviewer: Documented policy/export violation with leak ASNs, time, duration, and prefix count.
- Corroborating source(s): Qrator Radar analysis
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-LEAK-002
- Proposed class: Leak
- Event time: 2018-05-18T09:36:00Z to 2018-05-18T10:06:00Z
- Affected ASN(s): AS263086; AS53087; AS263444
- Origin ASN where applicable: Origin ASNs embedded in leaked prefixes/AS paths where source provides them; see evidence summary
- Prefix metadata from source: thousands of leaked prefixes
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: PARTIAL
- Partial prefix metadata: YES
- Partial-prefix note: thousands of leaked prefixes | limitation: Carried forward from V2 base audit.
- Primary source: Qrator Labs blog
- Source type: Qrator
- Source URL/reference: https://blog.qrator.net/en/day-internet-survived_14/
- Source event identifier: V2-LEAK-002
- Source-derived evidence summary: Qrator describes PBNET leaking thousands of prefixes between upstreams TELY and OPENX; two waves around half an hour.
- Exact evidence provided to reviewer: Documented export-policy leak between upstreams with time, leaking ASN, and affected scale.
- Corroborating source(s): Qrator Radar analysis
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-LEAK-003
- Proposed class: Leak
- Event time: 2019-06-24T10:35:00Z to 2019-06-24T12:38:00Z
- Affected ASN(s): AS396531; AS701
- Origin ASN where applicable: Origin ASNs embedded in leaked prefixes/AS paths where source provides them; see evidence summary
- Prefix metadata from source: 6.7k+ prefixes
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: PARTIAL
- Partial prefix metadata: YES
- Partial-prefix note: 6.7k+ prefixes | limitation: Carried forward from V2 base audit.
- Primary source: Qrator Labs blog
- Source type: Qrator
- Source URL/reference: https://blog.qrator.net/en/how-difficult-disrupt-service-nowadays_49/
- Source event identifier: V2-LEAK-003
- Source-derived evidence summary: Qrator analysis of Verizon/DQE route leak reports over 6.7k prefixes from 850+ operators; two-hour DoS impact.
- Exact evidence provided to reviewer: Documented large route leak with leaking customer/provider relationship and explicit timing.
- Corroborating source(s): Public incident discussion around Verizon route leak
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-LEAK-004
- Proposed class: Leak
- Event time: 2024-05-24 to 2024-05-24
- Affected ASN(s): Megatelecom; InterNexa Brasil
- Origin ASN where applicable: Origin ASNs embedded in leaked prefixes/AS paths where source provides them; see evidence summary
- Prefix metadata from source: 5333 conflicts
- Affected prefix count reported: 5333
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: 5333 conflicts | limitation: Carried forward from V2 base audit.
- Primary source: Qrator Labs quarterly BGP incidents report
- Source type: Qrator
- Source URL/reference: https://blog.qrator.net/en/q3-2024-ddos-bots-and-bgp-incidents-statistics-and_209/
- Source event identifier: V2-LEAK-004
- Source-derived evidence summary: Qrator Q3 2024 report identifies a major BGP route leak by Brazilian provider Megatelecom after acquisition integration, producing 5,333 conflicts.
- Exact evidence provided to reviewer: Event-level detail is enough for feasibility, but exact prefixes/ASNs need recovery before final roster.
- Corroborating source(s): None locked
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-LEAK-006
- Proposed class: Leak
- Event time: 2021-01-06T04:21:00Z to 2021-01-06T06:51:00Z
- Affected ASN(s): AS9304 leaked through AS15412
- Origin ASN where applicable: Origin ASNs embedded in leaked prefixes/AS paths where source provides them; see evidence summary
- Prefix metadata from source: 8764 leaked prefixes; exact list not recovered from public article text
- Affected prefix count reported: 8764
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: 8764 leaked prefixes; exact list not recovered from public article text | limitation: Full prefix list not in public article text.
- Primary source: Qrator Labs Radar article
- Source type: Qrator
- Source URL/reference: https://blog.qrator.net/en/as9304-leaking-8764-prefixes-through-as15412_111/
- Source event identifier: Qrator AS9304 leaking 8764 prefixes through AS15412
- Source-derived evidence summary: Qrator reports AS9304 leaked 8,764 prefixes through AS15412, affecting 907 ASNs in 66 countries.
- Exact evidence provided to reviewer: Start 04:21 UTC, active phase about 2.5 hours, 9140 conflicts overall.
- Corroborating source(s): Qrator newsletter summary https://blog.qrator.net/en/cybersecurity-newsletter-first-2021_114/
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-LEAK-007
- Proposed class: Leak
- Event time: 2021-02-11T04:36:41Z to 2021-02-11T04:50:10Z
- Affected ASN(s): AS28548; leaked routes from AS14178 to AS18734
- Origin ASN where applicable: Origin ASNs embedded in leaked prefixes/AS paths where source provides them; see evidence summary
- Prefix metadata from source: 2828 prefixes in Qrator summary; 7200+ unique IPv4 prefixes in MANRS/Isolario analysis; example 201.157.24.0/24
- Affected prefix count reported: 2828
- Full prefix list available: PARTIAL
- Partial prefix metadata: YES
- Partial-prefix note: 2828 prefixes in Qrator summary; 7200+ unique IPv4 prefixes in MANRS/Isolario analysis; example 201.157.24.0/24 | limitation: 
- Primary source: MANRS incident analysis
- Source type: MANRS
- Source URL/reference: https://manrs.org/2021/02/major-route-leak-by-as28548-another-bgp-optimizer/
- Source event identifier: Qrator/MANRS AS28548 Cablevision route leak
- Source-derived evidence summary: AS28548 leaked routes it received from AS14178 to AS18734 after routing policy changes.
- Exact evidence provided to reviewer: MANRS reports first changes at 04:36:41 UTC, last leak update 04:48:21, own-prefix announcements at 04:50:10, and example 201.157.24.0/24.
- Corroborating source(s): Qrator Radar page 2 summary; Doug Madory/Kentik tweet cited by MANRS
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-LEAK-008
- Proposed class: Leak
- Event time: 2020-08-24T11:21:00Z to 2020-08-24T16:00:00Z
- Affected ASN(s): AS42910 Premier DC via AS9121/AS61135
- Origin ASN where applicable: Origin ASNs embedded in leaked prefixes/AS paths where source provides them; see evidence summary
- Prefix metadata from source: 1403 leaked prefixes; 1000+ Akamai prefixes; exact list not recovered
- Affected prefix count reported: 1403
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: 1403 leaked prefixes; 1000+ Akamai prefixes; exact list not recovered | limitation: Full affected-prefix list not recovered.
- Primary source: Qrator Labs Radar article
- Source type: Qrator
- Source URL/reference: https://blog.qrator.net/en/as42910-leaking-hundreds-prefixes_89/
- Source event identifier: Qrator AS42910 August 2020 route leak
- Source-derived evidence summary: Qrator reports AS42910 leaked 1,403 prefixes, affecting Akamai and Western Asia.
- Exact evidence provided to reviewer: Incident started at 11:21 UTC, occurred in four waves, and ended around 16:00 UTC.
- Corroborating source(s): Qrator Radar archive page 2
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-LEAK-009
- Proposed class: Leak
- Event time: 2018-01-17T12:01:00Z to 2018-01-17T12:16:00Z
- Affected ASN(s): AS8901; AS12389; AS8732
- Origin ASN where applicable: Origin ASNs embedded in leaked prefixes/AS paths where source provides them; see evidence summary
- Prefix metadata from source: 70000 affected prefixes; example 5.121.176.0/20
- Affected prefix count reported: 70000
- Full prefix list available: PARTIAL
- Partial prefix metadata: YES
- Partial-prefix note: 70000 affected prefixes; example 5.121.176.0/20 | limitation: 
- Primary source: Qrator Labs Radar article
- Source type: Qrator
- Source URL/reference: https://blog.qrator.net/en/moscow-traffic-jam_9/
- Source event identifier: Qrator Moscow Traffic Jam AS8901 route leak
- Source-derived evidence summary: AS8901 leaked prefixes between upstreams Rostelecom and Comcor.
- Exact evidence provided to reviewer: Qrator reports the active phase began at 12:01 UTC, lasted 15 minutes, and peaked at 70,000 affected prefixes; example route 5.121.176.0/20 is shown.
- Corroborating source(s): None recovered in this pass
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-LEAK-010
- Proposed class: Leak
- Event time: 2019-04-04 to 2019-04-04
- Affected ASN(s): AS60280; AS9002; AS205540
- Origin ASN where applicable: Origin ASNs embedded in leaked prefixes/AS paths where source provides them; see evidence summary
- Prefix metadata from source: 18600 leaked prefixes from approximately 1400 origin ASes; exact list not recovered
- Affected prefix count reported: 18600
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: 18600 leaked prefixes from approximately 1400 origin ASes; exact list not recovered | limitation: Exact time and prefix list require article recovery beyond archive excerpt.
- Primary source: Qrator Labs Radar archive
- Source type: Qrator
- Source URL/reference: https://blog.qrator.net/en/radar/?page=4
- Source event identifier: Qrator NTEC AS60280 Belarus route leak
- Source-derived evidence summary: Belarus NTEC AS60280 leaked routes learned from RETN AS9002 to RU-telecom AS205540.
- Exact evidence provided to reviewer: Qrator archive states AS60280 leaked 18,600 prefixes originating from approximately 1,400 ASes on 2019-04-04.
- Corroborating source(s): Qrator blog index page 12
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-LEAK-011
- Proposed class: Leak
- Event time: 2019-06-06T09:43:00Z to 2019-06-06T11:43:00Z
- Affected ASN(s): AS21217 Safe Host; AS4134 China Telecom; victims AS3303/AS1136/AS5410/AS21502
- Origin ASN where applicable: Origin ASNs embedded in leaked prefixes/AS paths where source provides them; see evidence summary
- Prefix metadata from source: 70000+ leaked routes; examples 176.171.75.0/24 and European mobile-network prefixes
- Affected prefix count reported: 1
- Full prefix list available: PARTIAL
- Partial prefix metadata: YES
- Partial-prefix note: 70000+ leaked routes; examples 176.171.75.0/24 and European mobile-network prefixes | limitation: 
- Primary source: MANRS / Oracle Internet Intelligence incident analysis
- Source type: MANRS
- Source URL/reference: https://manrs.org/2019/06/large-european-routing-leak-sends-traffic-through-china-telecom/
- Source event identifier: MANRS/Oracle Safe Host China Telecom leak June 2019
- Source-derived evidence summary: Safe Host leaked over 70,000 routes to China Telecom, redirecting traffic for major European mobile networks.
- Exact evidence provided to reviewer: MANRS reports the leak began at 09:43 UTC, many routes circulated over two hours, and gives example prefix 176.171.75.0/24 with AS path through AS4134/AS21217.
- Corroborating source(s): Oracle Internet Intelligence original article referenced by MANRS; user traceroutes cited in MANRS
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-LEAK-012
- Proposed class: Leak
- Event time: 2023-05-25T11:21:40Z to 2023-05-25T12:43:36Z
- Affected ASN(s): AS37468 Angola Cables; victims include AS20940/AS16509 and others
- Origin ASN where applicable: Origin ASNs embedded in leaked prefixes/AS paths where source provides them; see evidence summary
- Prefix metadata from source: 2.16.0.0/13; example IPv6 prefixes 2001:502:be98::/48, 2001:503:f189::/48, 2001:500:ed30::/48
- Affected prefix count reported: 6
- Full prefix list available: PARTIAL
- Partial prefix metadata: YES
- Partial-prefix note: 2.16.0.0/13; example IPv6 prefixes 2001:502:be98::/48, 2001:503:f189::/48, 2001:500:ed30::/48 | limitation: 
- Primary source: MANRS incident analysis
- Source type: MANRS
- Source URL/reference: https://manrs.org/2023/05/bgp-route-leak-at-angola-cables-slows-connectivity-for-many-australians/
- Source event identifier: MANRS Angola Cables AS37468 route leak
- Source-derived evidence summary: Angola Cables leaked routes via an IX route server, causing high-latency paths for Australian users.
- Exact evidence provided to reviewer: MANRS shows 2.16.0.0/13 path changed to include AS37468 at 11:21 UTC and disappeared after 12:41 UTC; article states route leak lasted around three hours.
- Corroborating source(s): Doug Madory/Kentik commentary cited by MANRS; local Australian operator reports cited
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-LEAK-013
- Proposed class: Leak
- Event time: 2017-08-25 to 2017-08-25
- Affected ASN(s): Google; affected Japanese networks
- Origin ASN where applicable: Origin ASNs embedded in leaked prefixes/AS paths where source provides them; see evidence summary
- Prefix metadata from source: Google leaked BGP prefixes learned from peering relationships; exact list not recovered here
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: Google leaked BGP prefixes learned from peering relationships; exact list not recovered here | limitation: Exact prefix list and start/end time not recovered in this pass.
- Primary source: Internet Society / MANRS article
- Source type: MANRS
- Source URL/reference: https://www.internetsociety.org/blog/2017/08/google-leaked-prefixes-knocked-japan-off-internet/
- Source event identifier: Google Japan route leak August 2017
- Source-derived evidence summary: Google accidentally leaked BGP prefixes learned from peering relationships, causing disruption for Japanese users.
- Exact evidence provided to reviewer: Internet Society reports the incident lasted less than ten minutes but spread quickly and caused large-scale Internet disruption in Japan.
- Corroborating source(s): MANRS 2017 year-in-review lists the incident
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-LEAK-014
- Proposed class: Leak
- Event time: 2017-10 to 2017-10
- Affected ASN(s): Brazilian network; affected CDNs including Twitter/Google and others
- Origin ASN where applicable: Origin ASNs embedded in leaked prefixes/AS paths where source provides them; see evidence summary
- Prefix metadata from source: Major CDN prefixes; exact list not recovered
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: Major CDN prefixes; exact list not recovered | limitation: Month-level date and exact prefix details not recovered.
- Primary source: MANRS 2017 year-in-review
- Source type: MANRS
- Source URL/reference: https://manrs.org/2018/01/14000-incidents-a-2017-routing-security-year-in-review/
- Source event identifier: MANRS 2017 October Brazil CDN route leak
- Source-derived evidence summary: MANRS reports a BGP leak rerouted traffic for Twitter, Google, and other CDNs through Brazil for about 20 minutes.
- Exact evidence provided to reviewer: MANRS lists this as an example BGP mishap causing reachability/performance problems for many large CDNs.
- Corroborating source(s): BGPStream annual data cited by MANRS
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-LEAK-015
- Proposed class: Leak
- Event time: 2017-11 to 2017-11
- Affected ASN(s): Level 3
- Origin ASN where applicable: Origin ASNs embedded in leaked prefixes/AS paths where source provides them; see evidence summary
- Prefix metadata from source: Route leak affecting North America; exact prefix list not recovered
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: Route leak affecting North America; exact prefix list not recovered | limitation: Exact prefix list and event IDs not recovered.
- Primary source: MANRS 2017 year-in-review
- Source type: MANRS
- Source URL/reference: https://manrs.org/2018/01/14000-incidents-a-2017-routing-security-year-in-review/
- Source event identifier: MANRS 2017 November Level 3 route leak
- Source-derived evidence summary: MANRS reports Level 3 BGP routing issues causing large-scale network degradation in North America for slightly more than 90 minutes, classified as another route leak.
- Exact evidence provided to reviewer: The MANRS year-in-review explicitly labels this as a route leak.
- Corroborating source(s): BGPStream annual data cited by MANRS
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-LEAK-017
- Proposed class: Leak
- Event time: 2026-04-01T10:23:49Z to 2026-04-01T10:24:32Z
- Affected ASN(s): AS18106 vantage; path includes AS36692 AS25605 AS30607 AS36692
- Origin ASN where applicable: Origin ASNs embedded in leaked prefixes/AS paths where source provides them; see evidence summary
- Prefix metadata from source: 67.215.94.0/24
- Affected prefix count reported: 1
- Full prefix list available: YES_OR_EXAMPLES_AVAILABLE
- Partial prefix metadata: NO
- Partial-prefix note: Full or example prefix metadata available from source row.
- Primary source: Kentik route leak analysis
- Source type: Kentik
- Source URL/reference: https://www.kentik.com/blog/ephemeral-leaks-and-automated-bgp-route-leak-detection/
- Source event identifier: Kentik ephemeral leak 67.215.94.0/24 2026-04-01
- Source-derived evidence summary: Kentik documents an ephemeral route leak for prefix 67.215.94.0/24 after withdrawals began.
- Exact evidence provided to reviewer: Kentik shows RouteViews update lines from 10:23:49 to 10:24:32 UTC with leak AS paths for 67.215.94.0/24.
- Corroborating source(s): RouteViews excerpts in Kentik article
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-LEAK-018
- Proposed class: Leak
- Event time: 2026-05-21T08:05:00Z to 2026-05-21T09:35:00Z
- Affected ASN(s): AS7303 Telecom; learned from AS22927; leaked toward AS6762 and AS3356
- Origin ASN where applicable: Origin ASNs embedded in leaked prefixes/AS paths where source provides them; see evidence summary
- Prefix metadata from source: 2989 leaked prefixes; exact list not recovered from Qrator social mirror
- Affected prefix count reported: 2989
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: 2989 leaked prefixes; exact list not recovered from Qrator social mirror | limitation: Source URL is a public mirror of Qrator_Radar; original tweet/API URL should be recovered before lock.
- Primary source: Qrator_Radar social feed mirror
- Source type: Qrator
- Source URL/reference: https://twstalker.com/Qrator_Radar
- Source event identifier: Qrator_Radar AS7303 2026-05-21 route leak
- Source-derived evidence summary: Qrator_Radar feed reports AS7303 leaked 2,989 prefixes learned from AS22927 toward AS6762 and AS3356.
- Exact evidence provided to reviewer: Feed states start 08:05 UTC, 3,994 conflicts, 343 ASNs in 4 countries, max propagation 93%, duration about 1.5h.
- Corroborating source(s): None recovered in this pass
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-LEAK-019
- Proposed class: Leak
- Event time: 2026-05-28T08:21:00Z to 2026-05-28T08:26:00Z
- Affected ASN(s): AS21859 ZEN-ECN; learned from AS4755; leaked toward AS9498
- Origin ASN where applicable: Origin ASNs embedded in leaked prefixes/AS paths where source provides them; see evidence summary
- Prefix metadata from source: 1334 leaked prefixes; exact list not recovered from Qrator social mirror
- Affected prefix count reported: 1334
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: 1334 leaked prefixes; exact list not recovered from Qrator social mirror | limitation: Original source should be recovered before final lock.
- Primary source: Qrator_Radar social feed mirror
- Source type: Qrator
- Source URL/reference: https://twstalker.com/Qrator_Radar
- Source event identifier: Qrator_Radar AS21859 2026-05-28 route leak
- Source-derived evidence summary: Qrator_Radar feed reports AS21859 leaked 1,334 prefixes learned from AS4755 toward AS9498.
- Exact evidence provided to reviewer: Feed states 1,334 conflicts with 1,005 ASNs in 75 countries, max propagation 68%, duration about 5 minutes.
- Corroborating source(s): None recovered in this pass
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-LEAK-020
- Proposed class: Leak
- Event time: 2026-06-26T11:25:00Z to 2026-06-26T11:40:00Z
- Affected ASN(s): AS28910 INTAL; learned from AS1299/AS58453; leaked toward AS205103
- Origin ASN where applicable: Origin ASNs embedded in leaked prefixes/AS paths where source provides them; see evidence summary
- Prefix metadata from source: 3095 leaked prefixes; exact list not recovered from Qrator social mirror
- Affected prefix count reported: 3095
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: 3095 leaked prefixes; exact list not recovered from Qrator social mirror | limitation: Original source should be recovered before final lock.
- Primary source: Qrator_Radar social feed mirror
- Source type: Qrator
- Source URL/reference: https://twstalker.com/Qrator_Radar
- Source event identifier: Qrator_Radar AS28910 2026-06-26 route leak
- Source-derived evidence summary: Qrator_Radar feed reports AS28910 leaked 3,095 prefixes learned from AS1299/AS58453 and others toward AS205103.
- Exact evidence provided to reviewer: Feed states 107 ASNs in 35 countries, max propagation 100%, duration about 15 minutes.
- Corroborating source(s): None recovered in this pass
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-LEAK-021
- Proposed class: Leak
- Event time: 2024-05-24 to 2024-05-24
- Affected ASN(s): Megatelecom; InterNexa Brasil integration context
- Origin ASN where applicable: Origin ASNs embedded in leaked prefixes/AS paths where source provides them; see evidence summary
- Prefix metadata from source: 5333 conflicts; exact leaked prefix list not recovered
- Affected prefix count reported: 5333
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: 5333 conflicts; exact leaked prefix list not recovered | limitation: Exact ASN and affected prefix list require deeper source/API recovery.
- Primary source: Qrator Labs Q3 2024 BGP incident overview
- Source type: Qrator
- Source URL/reference: https://blog.qrator.net/en/q3-2024-ddos-bots-and-bgp-incidents-statistics-and_209/
- Source event identifier: Qrator Q2/Q3 2024 Megatelecom route leak
- Source-derived evidence summary: Qrator identifies a major May 24 2024 route leak caused by Brazilian provider Megatelecom.
- Exact evidence provided to reviewer: Qrator reports 5,333 conflicts involving 593 ASes from 68 countries, caused by infrastructure merging during Megatelecom's acquisition of InterNexa Brasil.
- Corroborating source(s): Qrator Q2 2024 overview https://blog.qrator.net/en/q2-2024-ddos-bots-and-bgp-incidents-statistics-and_205/
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-LEAK-022
- Proposed class: Leak
- Event time: 2021-12-24 to 2021-12-24
- Affected ASN(s): AS7633 SOFTNET India
- Origin ASN where applicable: Origin ASNs embedded in leaked prefixes/AS paths where source provides them; see evidence summary
- Prefix metadata from source: 20000 leaked prefixes; exact list not recovered from public MANRS summary
- Affected prefix count reported: 20000
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: 20000 leaked prefixes; exact list not recovered from public MANRS summary | limitation: Full prefix list requires Qrator archive recovery.
- Primary source: MANRS BGP Security in 2021
- Source type: MANRS
- Source URL/reference: https://manrs.org/2022/02/bgp-security-in-2021/
- Source event identifier: MANRS 2021 major leak list: 2021-12-24 AS7633
- Source-derived evidence summary: MANRS lists AS7633 SOFTNET India as leaking 20,000 prefixes on December 24, 2021.
- Exact evidence provided to reviewer: MANRS selected it as a significant 2021 BGP leak based on impact/number of prefixes.
- Corroborating source(s): Qrator Labs referenced by MANRS
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-LEAK-023
- Proposed class: Leak
- Event time: 2021-12-24 to 2021-12-24
- Affected ASN(s): AS132215 POWERGRID
- Origin ASN where applicable: Origin ASNs embedded in leaked prefixes/AS paths where source provides them; see evidence summary
- Prefix metadata from source: 112000 leaked prefixes; exact list not recovered from public MANRS summary
- Affected prefix count reported: 112000
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: 112000 leaked prefixes; exact list not recovered from public MANRS summary | limitation: Full prefix list requires Qrator archive recovery.
- Primary source: MANRS BGP Security in 2021
- Source type: MANRS
- Source URL/reference: https://manrs.org/2022/02/bgp-security-in-2021/
- Source event identifier: MANRS 2021 major leak list: 2021-12-24 AS132215
- Source-derived evidence summary: MANRS lists AS132215 POWERGRID as leaking 112,000 prefixes on December 24, 2021.
- Exact evidence provided to reviewer: Date, leaker ASN, route-leak classification, and prefix count are present in the MANRS annual summary.
- Corroborating source(s): Qrator Labs referenced by MANRS
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-LEAK-024
- Proposed class: Leak
- Event time: 2021-12-08 to 2021-12-08
- Affected ASN(s): AS10442 VOZHD
- Origin ASN where applicable: Origin ASNs embedded in leaked prefixes/AS paths where source provides them; see evidence summary
- Prefix metadata from source: 32000 leaked prefixes; exact list not recovered from public MANRS summary
- Affected prefix count reported: 32000
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: 32000 leaked prefixes; exact list not recovered from public MANRS summary | limitation: Full prefix list requires Qrator archive recovery.
- Primary source: MANRS BGP Security in 2021
- Source type: MANRS
- Source URL/reference: https://manrs.org/2022/02/bgp-security-in-2021/
- Source event identifier: MANRS 2021 major leak list: 2021-12-08 AS10442
- Source-derived evidence summary: MANRS lists AS10442 VOZHD as leaking 32,000 prefixes on December 8, 2021.
- Exact evidence provided to reviewer: Date, leaker ASN, route-leak classification, and prefix count are present in the MANRS annual summary.
- Corroborating source(s): Qrator Labs referenced by MANRS
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-LEAK-025
- Proposed class: Leak
- Event time: 2021-08-19 to 2021-08-19
- Affected ASN(s): AS265038 JNET
- Origin ASN where applicable: Origin ASNs embedded in leaked prefixes/AS paths where source provides them; see evidence summary
- Prefix metadata from source: 11000 leaked prefixes; exact list not recovered from public MANRS summary
- Affected prefix count reported: 11000
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: 11000 leaked prefixes; exact list not recovered from public MANRS summary | limitation: Full prefix list requires Qrator archive recovery.
- Primary source: MANRS BGP Security in 2021
- Source type: MANRS
- Source URL/reference: https://manrs.org/2022/02/bgp-security-in-2021/
- Source event identifier: MANRS 2021 major leak list: 2021-08-19 AS265038
- Source-derived evidence summary: MANRS lists AS265038 JNET as leaking 11,000 prefixes on August 19, 2021.
- Exact evidence provided to reviewer: Date, leaker ASN, route-leak classification, and prefix count are present in the MANRS annual summary.
- Corroborating source(s): Qrator Labs referenced by MANRS
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-LEAK-026
- Proposed class: Leak
- Event time: 2021-07-30 to 2021-07-30
- Affected ASN(s): AS137996 WITGLOBALCOMMUNICATIONS
- Origin ASN where applicable: Origin ASNs embedded in leaked prefixes/AS paths where source provides them; see evidence summary
- Prefix metadata from source: 167000 leaked prefixes; exact list not recovered from public MANRS summary
- Affected prefix count reported: 167000
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: 167000 leaked prefixes; exact list not recovered from public MANRS summary | limitation: Full prefix list requires Qrator archive recovery.
- Primary source: MANRS BGP Security in 2021
- Source type: MANRS
- Source URL/reference: https://manrs.org/2022/02/bgp-security-in-2021/
- Source event identifier: MANRS 2021 major leak list: 2021-07-30 AS137996
- Source-derived evidence summary: MANRS lists AS137996 WITGLOBALCOMMUNICATIONS as leaking 167,000 prefixes on July 30, 2021.
- Exact evidence provided to reviewer: Date, leaker ASN, route-leak classification, and prefix count are present in the MANRS annual summary.
- Corroborating source(s): Qrator Labs referenced by MANRS
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-LEAK-027
- Proposed class: Leak
- Event time: 2021-06-03 to 2021-06-03
- Affected ASN(s): AS199599 CIREX
- Origin ASN where applicable: Origin ASNs embedded in leaked prefixes/AS paths where source provides them; see evidence summary
- Prefix metadata from source: 26000 leaked prefixes; exact list not recovered from public MANRS summary
- Affected prefix count reported: 26000
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: 26000 leaked prefixes; exact list not recovered from public MANRS summary | limitation: Full prefix list requires Qrator archive recovery.
- Primary source: MANRS BGP Security in 2021
- Source type: MANRS
- Source URL/reference: https://manrs.org/2022/02/bgp-security-in-2021/
- Source event identifier: MANRS 2021 major leak list: 2021-06-03 AS199599
- Source-derived evidence summary: MANRS lists AS199599 CIREX as leaking 26,000 prefixes on June 3, 2021.
- Exact evidence provided to reviewer: Date, leaker ASN, route-leak classification, and prefix count are present in the MANRS annual summary.
- Corroborating source(s): Qrator Labs referenced by MANRS
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_MONTH_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-001
- Proposed class: Outage
- Event time: Friday, July 2, 2021, 2:40:00 AM to Friday, July 2, 2021, 3:15:00 AM
- Affected ASN(s): AS (8452)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-001
- Source-derived evidence summary: IODA manually verified AS-scoped outage in Egypt with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=8452&from=1625097600000&to=1625313600000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-002
- Proposed class: Outage
- Event time: Tuesday, June 15, 2021, 1:50:00 PM to Tuesday, June 15, 2021, 2:30:00 PM
- Affected ASN(s): AS (58224)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-002
- Source-derived evidence summary: IODA manually verified AS-scoped outage in Iran with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=58224&from=1623715200000&to=1623931200000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-003
- Proposed class: Outage
- Event time: Friday, June 4, 2021, 2:50:00 AM to Friday, June 4, 2021, 5:50:00 AM
- Affected ASN(s): AS (58224)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-003
- Source-derived evidence summary: IODA manually verified AS-scoped outage in Iran with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=58224&from=1622683210000&to=1622856010000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-004
- Proposed class: Outage
- Event time: Monday, May 10, 2021, 6:40:00 AM to Monday, May 10, 2021, 8:25:00 AM
- Affected ASN(s): AS (58224)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-004
- Source-derived evidence summary: IODA manually verified AS-scoped outage in Iran with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=58224&from=1620518400000&to=1620691200000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-005
- Proposed class: Outage
- Event time: Tuesday, March 16, 2021, 4:45:00 AM to Tuesday, March 16, 2021, 5:30:00 AM
- Affected ASN(s): AS (9299)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-005
- Source-derived evidence summary: IODA manually verified AS-scoped outage in Philippines with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=9299&from=1615687200000&to=1615896000000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-006
- Proposed class: Outage
- Event time: Sunday, March 14, 2021, 10:40:00 PM to Monday, March 15, 2021, 4:00:00 AM
- Affected ASN(s): AS (58224)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-006
- Source-derived evidence summary: IODA manually verified AS-scoped outage in Iran with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=58224&from=1615687200000&to=1615896000000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-007
- Proposed class: Outage
- Event time: Saturday, March 13, 2021, 10:30:00 PM to Sunday, March 14, 2021, 5:20:00 AM
- Affected ASN(s): AS (58224)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-007
- Source-derived evidence summary: IODA manually verified AS-scoped outage in Iran with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=58224&from=1615543200000&to=1615723200000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-008
- Proposed class: Outage
- Event time: Tuesday, March 2, 2021, 5:10:00 AM to Tuesday, March 2, 2021, 6:00:00 AM
- Affected ASN(s): AS (668)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-008
- Source-derived evidence summary: IODA manually verified AS-scoped outage in United States of America (USA) with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=668&from=1614643200000&to=1614859200000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-009
- Proposed class: Outage
- Event time: Friday, February 26, 2021, 5:10:00 AM to Friday, February 26, 2021, 12:00:00 PM
- Affected ASN(s): AS (668)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-009
- Source-derived evidence summary: IODA manually verified AS-scoped outage in United States of America (USA) with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=668&from=1614297600000&to=1614412800000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-010
- Proposed class: Outage
- Event time: Wednesday, February 24, 2021, 1:30:00 AM to Saturday, March 6, 2021, 11:00:00 PM
- Affected ASN(s): AS (37233)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-010
- Source-derived evidence summary: IODA manually verified AS-scoped outage in Niger with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=37233&from=1613952000000&to=1615334400000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-011
- Proposed class: Outage
- Event time: Monday, February 15, 2021, 8:50:00 AM to Monday, February 15, 2021, 10:00:00 AM
- Affected ASN(s): AS (37069)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-011
- Source-derived evidence summary: IODA manually verified AS-scoped outage in Egypt with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=37069&from=1613347200000&to=1613563200000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-012
- Proposed class: Outage
- Event time: Friday, February 12, 2021, 9:20:00 PM to Saturday, February 13, 2021, 7:20:00 AM
- Affected ASN(s): AS (17813)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-012
- Source-derived evidence summary: IODA manually verified AS-scoped outage in India with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=17813&from=1613048400000&to=1613217600000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-013
- Proposed class: Outage
- Event time: Friday, February 12, 2021, 12:20:00 PM to Friday, February 12, 2021, 5:50:00 PM
- Affected ASN(s): AS (17813)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-013
- Source-derived evidence summary: IODA manually verified AS-scoped outage in India with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=17813&from=1613048400000&to=1613217600000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-014
- Proposed class: Outage
- Event time: Wednesday, February 10, 2021, 6:00:00 AM to Wednesday, February 10, 2021, 6:20:00 AM
- Affected ASN(s): AS (8151)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-014
- Source-derived evidence summary: IODA manually verified AS-scoped outage in Mexico with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=8151&from=1612908000000&to=1613044800000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-015
- Proposed class: Outage
- Event time: Monday, February 8, 2021, 11:10:00 PM to Tuesday, February 9, 2021, 12:00:00 AM
- Affected ASN(s): AS (224)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-015
- Source-derived evidence summary: IODA manually verified AS-scoped outage in Norway with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=224&from=1612742422000&to=1612893600000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-016
- Proposed class: Outage
- Event time: Thursday, February 4, 2021, 6:30:00 AM to Thursday, February 4, 2021, 9:00:00 AM
- Affected ASN(s): AS (668)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-016
- Source-derived evidence summary: IODA manually verified AS-scoped outage in United States of America (USA) with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=668&from=1612224000000&to=1612440000000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-017
- Proposed class: Outage
- Event time: Wednesday, February 3, 2021, 12:40:00 PM to Wednesday, February 3, 2021, 1:10:00 PM
- Affected ASN(s): AS (37492)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-017
- Source-derived evidence summary: IODA manually verified AS-scoped outage in Tunisia with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=37492&from=1612224022000&to=1612440022000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-018
- Proposed class: Outage
- Event time: Tuesday, February 2, 2021, 11:00:00 PM to Tuesday, February 2, 2021, 11:20:00 PM
- Affected ASN(s): AS (37492)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-018
- Source-derived evidence summary: IODA manually verified AS-scoped outage in Tunisia with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=37492&from=1612224022000&to=1612440022000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-019
- Proposed class: Outage
- Event time: Tuesday, February 2, 2021, 3:10:00 PM to Tuesday, February 2, 2021, 3:30:00 PM
- Affected ASN(s): AS (37492)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-019
- Source-derived evidence summary: IODA manually verified AS-scoped outage in Tunisia with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=37492&from=1612224022000&to=1612440022000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-020
- Proposed class: Outage
- Event time: Tuesday, February 2, 2021, 5:40:00 AM to Tuesday, February 2, 2021, 6:10:00 AM
- Affected ASN(s): AS (668)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-020
- Source-derived evidence summary: IODA manually verified AS-scoped outage in United States of America (USA) with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=668&from=1612051200000&to=1612267200000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-021
- Proposed class: Outage
- Event time: Wednesday, January 13, 2021, 12:30:00 AM to Wednesday, January 13, 2021, 1:00:00 AM
- Affected ASN(s): AS (55836)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-021
- Source-derived evidence summary: IODA manually verified AS-scoped outage in India with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=55836&from=1610452800000&to=1610539200000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-022
- Proposed class: Outage
- Event time: Monday, January 4, 2021, 3:50:00 AM to Monday, January 4, 2021, 10:45:00 AM
- Affected ASN(s): AS (8386)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-022
- Source-derived evidence summary: IODA manually verified AS-scoped outage in Turkey with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=8386&from=1609675200000&to=1609761600000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-023
- Proposed class: Outage
- Event time: Sunday, August 23, 2020, 12:00:00 AM to Sunday, August 23, 2020, 12:50:00 AM
- Affected ASN(s): AS (12880)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-023
- Source-derived evidence summary: IODA manually verified AS-scoped outage in Iran with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=12880&from=1598054400000&to=1598270400000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-024
- Proposed class: Outage
- Event time: Thursday, July 30, 2020, 4:00:00 PM to Thursday, July 30, 2020, 8:40:00 PM
- Affected ASN(s): AS (8048)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-024
- Source-derived evidence summary: IODA manually verified AS-scoped outage in Venezuela with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=8048&from=1596067200000&to=1596283200000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-025
- Proposed class: Outage
- Event time: Wednesday, July 22, 2020, 10:10:00 AM to Wednesday, July 22, 2020, 10:30:00 AM
- Affected ASN(s): AS (668)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-025
- Source-derived evidence summary: IODA manually verified AS-scoped outage in United States of America (USA) with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=668&from=1595289600000&to=1595451600000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-026
- Proposed class: Outage
- Event time: Tuesday, June 30, 2020, 9:30:00 PM to Tuesday, June 30, 2020, 12:20:00 AM
- Affected ASN(s): AS (58224)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-026
- Source-derived evidence summary: IODA manually verified AS-scoped outage in Iran with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=58224&from=1593475200000&to=1593691200000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-027
- Proposed class: Outage
- Event time: Saturday, April 25, 2020, 9:10:00 AM to Saturday, April 25, 2020, 12:10:00 AM
- Affected ASN(s): AS (1749)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-027
- Source-derived evidence summary: IODA manually verified AS-scoped outage in Finland with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=1759&from=1587686400000&to=1587902400000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-028
- Proposed class: Outage
- Event time: Thursday, April 9, 2020, 7:10:00 AM to Thursday, April 9, 2020, 8:52:00 AM
- Affected ASN(s): AS (4761)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-028
- Source-derived evidence summary: IODA manually verified AS-scoped outage in Indonesia with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=4761&from=1586304000000&to=1586520000000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-029
- Proposed class: Outage
- Event time: Monday, March 16, 2020, 10:00:00 PM to Monday, March 16, 2020, 10:50:00 PM
- Affected ASN(s): AS (6849)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-029
- Source-derived evidence summary: IODA manually verified AS-scoped outage in Ukraine with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=6849&from=1584230400000&to=1584446400000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

## V2-OUTAGE-030
- Proposed class: Outage
- Event time: Sunday, February 23, 2020, 4:10:00 AM to Sunday, February 23, 2020, 4:52:00 AM
- Affected ASN(s): AS (4761)
- Origin ASN where applicable: Not applicable / outage AS scope
- Prefix metadata from source: AS-scoped outage; prefix list not source-native
- Affected prefix count reported: Not explicitly reported
- Full prefix list available: NO
- Partial prefix metadata: YES
- Partial-prefix note: AS-scoped outage; prefix list not source-native | limitation: AS-scoped outage; prefix list not source-native.
- Primary source: IODA curated investigated outages CSV
- Source type: IODA
- Source URL/reference: https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Source event identifier: V2-OUTAGE-030
- Source-derived evidence summary: IODA manually verified AS-scoped outage in Indonesia with BGP visibility marked TRUE.
- Exact evidence provided to reviewer: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Corroborating source(s): https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=4761&from=1582416000000&to=1582459200000
- RouteViews archive availability confirmed: YES (ROUTEVIEWS_AVAILABLE)
- Overlap status with original 1,419-event corpus: NEW_INDEPENDENT_EVENT

Reviewer A decision: ____________________

Reviewer B decision: ____________________

