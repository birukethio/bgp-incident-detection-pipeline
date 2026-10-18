# V2 Hijack/Leak Evidence Packets

## V2-HIJACK-001 - Hijack - ACCEPT
- Time: 2026-05-16/2026-05-17 to 2026-05-17
- ASN(s): AS202734; AS402335; AS402333
- Prefix metadata: 240e::/20; multiple IPv4/IPv6 prefixes
- Primary source: GitHub evidence archive and NANOG thread (https://github.com/miao-2011/bgp-hijack-evidence-AS202734; https://lists.nanog.org/archives/list/nanog@lists.nanog.org/thread/MI6VWOX7XOCDIS244RLJSMS2ITZWTGED/)
- Source event id: V2-HIJACK-001
- Evidence: Documented unauthorized originations, affected prefixes, ASNs, and route-collector evidence.
- Corroboration: RIPE BGPlay, Hurricane Electric BGP Toolkit, RouteViews output referenced in archive
- Adjudication rationale: Documented unauthorized originations, affected prefixes, ASNs, and route-collector evidence.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_AVAILABLE; https://archive.routeviews.org/bgpdata/2026.05/UPDATES/
- Limitations: Carried forward from V2 base audit.

## V2-HIJACK-002 - Hijack - ACCEPT
- Time: 2026-06-16 to 2026-06-16
- ASN(s): AS18101
- Prefix metadata: Telegram IPv4/IPv6 prefixes
- Primary source: BGPHorizon incident analysis (https://www.bgphorizon.com/blog/telegram-bgp-hijack-june-2026)
- Source event id: V2-HIJACK-002
- Evidence: Documented wrong-origin routing for named affected network and ASNs; exact prefix list must be recovered before final roster.
- Corroboration: Other routing monitors referenced by report
- Adjudication rationale: Documented wrong-origin routing for named affected network and ASNs; exact prefix list must be recovered before final roster.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_AVAILABLE; https://archive.routeviews.org/bgpdata/2026.06/UPDATES/
- Limitations: Carried forward from V2 base audit.

## V2-HIJACK-003 - Hijack - ACCEPT
- Time: 2008-02-24T20:07:25Z to 2008-02-24
- ASN(s): AS36561; AS17557
- Prefix metadata: 208.65.153.0/24
- Primary source: RouteCause reproducible demo using RIPE RIS/RouteViews raw MRT (https://github.com/dim-tsoukalas/RouteCause)
- Source event id: V2-HIJACK-003
- Evidence: Clean wrong-origin/MOAS case with exact prefix, ASNs, and timestamped routing evidence.
- Corroboration: Historic public reports of Pakistan Telecom / YouTube hijack
- Adjudication rationale: Clean wrong-origin/MOAS case with exact prefix, ASNs, and timestamped routing evidence.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_AVAILABLE; https://archive.routeviews.org/bgpdata/2008.02/UPDATES/
- Limitations: Carried forward from V2 base audit.

## V2-HIJACK-004 - Hijack - AMBIGUOUS
- Time: 2018-07-30 to 2018-07-30
- ASN(s): AS58224
- Prefix metadata: Telegram prefixes
- Primary source: Qrator Labs blog (https://blog.qrator.net/en/leaked-censorship_16/)
- Source event id: V2-HIJACK-004
- Evidence: Primary source itself says the interpretation is a hypothesis from the outside; requires expert review before ACCEPT.
- Corroboration: None locked
- Adjudication rationale: Primary source itself says the interpretation is a hypothesis from the outside; requires expert review before ACCEPT.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_AVAILABLE; https://archive.routeviews.org/bgpdata/2018.07/UPDATES/
- Limitations: Carried forward from V2 base audit.

## V2-HIJACK-005 - Hijack - ACCEPT
- Time: 2019-04-01/2019-04-10 to 2019-04-10
- ASN(s): AS263444; AS61775; AS265466
- Prefix metadata: multiple split prefixes, examples 1.6.36.0/23 and 178.248.236.0/24
- Primary source: Qrator Labs blog (https://blog.qrator.net/en/new-hijack-attack_42/)
- Source event id: V2-HIJACK-005
- Evidence: Report provides BGP table/update examples, ASNs, prefixes, and hijack framing; expert review should verify exact event bounds.
- Corroboration: Raw BGP examples in report
- Adjudication rationale: Report provides BGP table/update examples, ASNs, prefixes, and hijack framing; expert review should verify exact event bounds.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_AVAILABLE; https://archive.routeviews.org/bgpdata/2019.04/UPDATES/
- Limitations: Carried forward from V2 base audit.

## V2-LEAK-001 - Leak - ACCEPT
- Time: 2021-01-27 to 2021-01-27
- ASN(s): AS61666; AS28146; AS16735
- Prefix metadata: 1330 leaked prefixes
- Primary source: Qrator Labs blog (https://blog.qrator.net/en/prepending-trouble_115/)
- Source event id: V2-LEAK-001
- Evidence: Documented policy/export violation with leak ASNs, time, duration, and prefix count.
- Corroboration: Qrator Radar analysis
- Adjudication rationale: Documented policy/export violation with leak ASNs, time, duration, and prefix count.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_AVAILABLE; https://archive.routeviews.org/bgpdata/2021.01/UPDATES/
- Limitations: Carried forward from V2 base audit.

## V2-LEAK-002 - Leak - ACCEPT
- Time: 2018-05-18T09:36:00Z to 2018-05-18T10:06:00Z
- ASN(s): AS263086; AS53087; AS263444
- Prefix metadata: thousands of leaked prefixes
- Primary source: Qrator Labs blog (https://blog.qrator.net/en/day-internet-survived_14/)
- Source event id: V2-LEAK-002
- Evidence: Documented export-policy leak between upstreams with time, leaking ASN, and affected scale.
- Corroboration: Qrator Radar analysis
- Adjudication rationale: Documented export-policy leak between upstreams with time, leaking ASN, and affected scale.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_AVAILABLE; https://archive.routeviews.org/bgpdata/2018.05/UPDATES/
- Limitations: Carried forward from V2 base audit.

## V2-LEAK-003 - Leak - ACCEPT
- Time: 2019-06-24T10:35:00Z to 2019-06-24T12:38:00Z
- ASN(s): AS396531; AS701
- Prefix metadata: 6.7k+ prefixes
- Primary source: Qrator Labs blog (https://blog.qrator.net/en/how-difficult-disrupt-service-nowadays_49/)
- Source event id: V2-LEAK-003
- Evidence: Documented large route leak with leaking customer/provider relationship and explicit timing.
- Corroboration: Public incident discussion around Verizon route leak
- Adjudication rationale: Documented large route leak with leaking customer/provider relationship and explicit timing.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_AVAILABLE; https://archive.routeviews.org/bgpdata/2019.06/UPDATES/
- Limitations: Carried forward from V2 base audit.

## V2-LEAK-004 - Leak - ACCEPT
- Time: 2024-05-24 to 2024-05-24
- ASN(s): Megatelecom; InterNexa Brasil
- Prefix metadata: 5333 conflicts
- Primary source: Qrator Labs quarterly BGP incidents report (https://blog.qrator.net/en/q3-2024-ddos-bots-and-bgp-incidents-statistics-and_209/)
- Source event id: V2-LEAK-004
- Evidence: Event-level detail is enough for feasibility, but exact prefixes/ASNs need recovery before final roster.
- Corroboration: None locked
- Adjudication rationale: Event-level detail is enough for feasibility, but exact prefixes/ASNs need recovery before final roster.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_AVAILABLE; https://archive.routeviews.org/bgpdata/2024.05/UPDATES/
- Limitations: Carried forward from V2 base audit.

## V2-LEAK-005 - Leak - REJECT
- Time: 2026-03-31T13:08:00Z to 2026-03-31T13:14:57Z
- ASN(s): AS48452; AS8262; AS3257
- Prefix metadata: 193.201.241.0/24
- Primary source: APNIC analysis of Cloudflare Radar leak (https://blog.apnic.net/2026/05/25/ephemeral-leaks-and-automated-bgp-route-leak-detection/)
- Source event id: V2-LEAK-005
- Evidence: Useful evidence packet, but Cloudflare Radar is the underlying primary event source; violates non-Cloudflare primary label rule.
- Corroboration: Raw BGP examples in APNIC post
- Adjudication rationale: Useful evidence packet, but Cloudflare Radar is the underlying primary event source; violates non-Cloudflare primary label rule.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_AVAILABLE; https://archive.routeviews.org/bgpdata/2026.03/UPDATES/
- Limitations: Carried forward from V2 base audit.

## V2-HIJACK-006 - Hijack - ACCEPT
- Time: 2020-07-30T01:15:38Z to 2020-07-30T02:27:27Z
- ASN(s): AS10990; victim AS812; Charter/TWC/Videotron and others
- Prefix metadata: 99.225.224.0/19; 99.228.0.0/17; 145 prefixes in second wave; 179 prefixes in first wave
- Primary source: MANRS incident analysis (https://manrs.org/2020/07/another-bgp-incident-impacts-twc-rogers-charter-and-others/)
- Source event id: BGPStream event 245324 / MANRS AS10990 July 2020
- Evidence: MANRS reports first BGPStream possible-hijack alert at 01:15:38 UTC; AS10990 announced 99.225.224.0/19 while Rogers AS812 announced covering aggregates; second wave persisted until 02:27:27 UTC.
- Corroboration: Qrator article https://blog.qrator.net/en/as10990-routing-optimization-tale_83/; NANOG mail thread subject BGP route hijack by AS10990
- Adjudication rationale: Wrong-origin/more-specific route announcements with explicit BGPStream event id, timestamps, ASNs, and example prefixes.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2020.07/UPDATES/

## V2-HIJACK-007 - Hijack - ACCEPT
- Time: 2022-07-26T21:25:10Z to 2022-07-27T09:39:00Z
- ASN(s): AS12389; victim AS714
- Prefix metadata: 17.70.96.0/19; Apple mitigation prefix 17.70.96.0/21
- Primary source: MANRS incident analysis (https://manrs.org/2022/07/for-12-hours-was-part-of-apple-engineerings-network-hijacked-by-russias-rostelecom/)
- Source event id: BGPStream event 293915; GRIP submoas-1658870700-714=12389/17.70.96.0-19_17.0.0.0-9
- Evidence: MANRS gives BGP update lines at 21:25:10-21:29 UTC, BGPStream event 293915, GRIP event id, Apple mitigation at 02:41 UTC, and final withdrawals around 09:39 UTC.
- Corroboration: The Register article; The FPS Review article; GRIP event URL cited by MANRS
- Adjudication rationale: Explicit wrong-origin/subMOAS event with exact prefix, source event identifiers, and independent MANRS analysis.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2022.07/UPDATES/

## V2-HIJACK-008 - Hijack - ACCEPT
- Time: 2020-04-01T19:28:00Z to 2020-04-01
- ASN(s): AS12389; affected AS16509/AS14618/AS20940 and others
- Prefix metadata: 104.18.216.0/21; 104.17.128.0/21; 104.18.184.0/21; 95.100.200.0/24; 104.18.168.0/21; 104.107.217.0/24; 95.101.181.0/24; 95.216.178.0/24; 104.17.232.0/21; 95.101.82.0/23; BGPMon reported 8800+ prefixes
- Primary source: MANRS incident analysis (https://manrs.org/2020/04/not-just-another-bgp-hijack/)
- Source event id: MANRS/Qrator AS12389 April 2020
- Evidence: MANRS cites Qrator first mis-origination at 19:28 UTC and lists ten hijacked prefixes; it also notes BGPMon reported more than 8,800 prefixes.
- Corroboration: Qrator Labs brief cited by MANRS; BGPMon prefix list cited by MANRS
- Adjudication rationale: Large-scale mis-origination with explicit AS, time, classification, and example prefixes.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2020.04/UPDATES/

## V2-HIJACK-009 - Hijack - ACCEPT
- Time: 2020-09-29 to 2020-09-29
- ASN(s): AS1221; 266 affected ASNs
- Prefix metadata: 472 prefixes announced; 1680+ affected IPv4 prefixes/conflicts; exact prefix list not in public article text
- Primary source: Qrator Labs Radar article index (https://blog.qrator.net/en/radar/?page=2)
- Source event id: Qrator AS1221 hijacking 266 ASNs in 51 countries
- Evidence: Qrator archive excerpt: September 29 2020 AS1221 announced 472 prefixes in a BGP hijack event affecting 266 ASNs in 50 countries, creating almost 2000 path-challenge conflicts.
- Corroboration: None recovered in this pass
- Adjudication rationale: Source-native Qrator Radar hijack classification with date, ASN, and prefix/conflict counts.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2020.09/UPDATES/
- Limitations: Exact affected prefix list not recovered from public article text; preserve as prefix-count event pending expert lock.

## V2-HIJACK-010 - Hijack - ACCEPT
- Time: 2020-10-21T14:11:00Z to 2020-10-21
- ASN(s): AS203; affected AS9198/AS35415/AS7979 and others
- Prefix metadata: 158 announced prefixes; 1000+ conflicts; exact prefix list not recovered from public text
- Primary source: Qrator Labs Radar article (https://blog.qrator.net/en/lumen-aka-centurylink-generating-routing-incidents_101/)
- Source event id: Qrator AS203 Lumen/CenturyLink October 2020
- Evidence: Qrator states AS203 started announcing 158 prefixes around 14:11 UTC, affecting 31 ISPs in 19 countries and causing path-challenge conflicts.
- Corroboration: None recovered in this pass
- Adjudication rationale: Source-native Qrator hijack/path-challenge event with timestamp and AS-level scope.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2020.10/UPDATES/
- Limitations: Exact affected prefix list not recovered from public article text.

## V2-HIJACK-011 - Hijack - ACCEPT
- Time: 2021-10-25 to 2021-10-25
- ASN(s): AS212046 MEZON
- Prefix metadata: 3786 hijacked prefixes; exact prefix list not recovered from public MANRS summary
- Primary source: MANRS BGP Security in 2021 (https://manrs.org/2022/02/bgp-security-in-2021/)
- Source event id: MANRS 2021 major hijack list: 2021-10-25 AS212046
- Evidence: MANRS selected this as a particularly major disruption based on impact/number of prefixes.
- Corroboration: Qrator Labs referenced by MANRS as detailed source
- Adjudication rationale: Independent MANRS annual incident summary with source-native BGPStream/Qrator classification and prefix count.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2021.10/UPDATES/
- Limitations: Prefix count available; full prefix list requires Qrator social/API archive recovery.

## V2-HIJACK-012 - Hijack - ACCEPT
- Time: 2021-10-13 to 2021-10-13
- ASN(s): AS212046 MEZON
- Prefix metadata: 1029 hijacked prefixes; exact prefix list not recovered from public MANRS summary
- Primary source: MANRS BGP Security in 2021 (https://manrs.org/2022/02/bgp-security-in-2021/)
- Source event id: MANRS 2021 major hijack list: 2021-10-13 AS212046
- Evidence: Separate date and prefix count from the October 25 MEZON event; treat as distinct pending expert adjudication.
- Corroboration: Qrator Labs referenced by MANRS as detailed source
- Adjudication rationale: Independent MANRS annual incident summary with date, ASN, class, and count.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2021.10/UPDATES/
- Limitations: Prefix count available; full prefix list requires source archive recovery.

## V2-HIJACK-013 - Hijack - ACCEPT
- Time: 2021-09-21 to 2021-09-21
- ASN(s): AS62325 HDHK
- Prefix metadata: 89 hijacked prefixes; exact prefix list not recovered from public MANRS summary
- Primary source: MANRS BGP Security in 2021 (https://manrs.org/2022/02/bgp-security-in-2021/)
- Source event id: MANRS 2021 major hijack list: 2021-09-21 AS62325
- Evidence: Date, culprit ASN, class, and prefix count are present in the MANRS annual incident list.
- Corroboration: Qrator Labs referenced by MANRS as detailed source
- Adjudication rationale: Accept as expert-reviewable event but exact prefix list must be recovered before operational acquisition lock.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2021.09/UPDATES/
- Limitations: Prefix count only in public source.

## V2-HIJACK-014 - Hijack - ACCEPT
- Time: 2021-05-18 to 2021-05-18
- ASN(s): AS48467 PRANET
- Prefix metadata: 454 hijacked prefixes; exact prefix list not recovered from public MANRS summary
- Primary source: MANRS BGP Security in 2021 (https://manrs.org/2022/02/bgp-security-in-2021/)
- Source event id: MANRS 2021 major hijack list: 2021-05-18 AS48467
- Evidence: Date, culprit ASN, class, and prefix count are present in the MANRS annual incident list.
- Corroboration: Qrator Labs referenced by MANRS as detailed source
- Adjudication rationale: Accept as source-native major hijack candidate; exact prefixes require source archive recovery.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2021.05/UPDATES/
- Limitations: Prefix count only in public source.

## V2-HIJACK-015 - Hijack - ACCEPT
- Time: 2021-04-16 to 2021-04-16
- ASN(s): AS55410 Vodafone Idea Ltd
- Prefix metadata: 30000 hijacked prefixes; exact prefix list not recovered from public MANRS summary
- Primary source: MANRS BGP Security in 2021 (https://manrs.org/2022/02/bgp-security-in-2021/)
- Source event id: MANRS 2021 major hijack list: 2021-04-16 AS55410
- Evidence: MANRS annual summary flags the event as a particularly major disruption.
- Corroboration: MANRS blog referenced in annual summary
- Adjudication rationale: Major source-native hijack candidate with class, date, ASN, and large prefix count.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2021.04/UPDATES/
- Limitations: Full prefix list and primary event-specific blog URL should be recovered before lock.

## V2-HIJACK-016 - Hijack - ACCEPT
- Time: 2021-02-05 to 2021-02-05
- ASN(s): AS136168 Campana MYTHIC; victim Twitter prefixes
- Prefix metadata: Twitter prefixes; exact list not recovered from public MANRS summary
- Primary source: MANRS BGP Security in 2021 (https://manrs.org/2022/02/bgp-security-in-2021/)
- Source event id: MANRS 2021 major hijack list: 2021-02-05 AS136168
- Evidence: Victim network and culprit ASN are identified by MANRS; exact prefixes require event-specific source recovery.
- Corroboration: MANRS blog referenced in annual summary
- Adjudication rationale: Accept as expert-reviewable because affected network, culprit ASN, date, and class are explicit.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2021.02/UPDATES/
- Limitations: Exact prefix list not recovered.

## V2-HIJACK-017 - Hijack - ACCEPT
- Time: 2017-04 to 2017-04
- ASN(s): AS12389 Rostelecom; affected financial/telecom/service provider ASNs
- Prefix metadata: 50 prefixes across MasterCard, Visa, Fortis, Alfa-Bank and others; exact prefix list not recovered here
- Primary source: MANRS 2017 year-in-review (https://manrs.org/2018/01/14000-incidents-a-2017-routing-security-year-in-review/)
- Source event id: MANRS 2017 April Rostelecom 50-prefix hijack
- Evidence: The MANRS review describes financial-services prefixes being briefly routed through a Russian telecom.
- Corroboration: BGPmon 'Curious Case of AS12389' referenced in public summaries
- Adjudication rationale: High-profile wrong-origin event with source-native independent public documentation.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2017.04/UPDATES/
- Limitations: Month-level date in MANRS summary; exact start/end and full prefix list require BGPMon archive recovery.

## V2-HIJACK-018 - Hijack - ACCEPT
- Time: 2017-03 to 2017-03
- ASN(s): SECW Telecom Brazil; victims include Cloudflare, Google, Banco do Brasil
- Prefix metadata: Cloudflare, Google, Banco do Brasil prefixes; exact list not recovered from public MANRS summary
- Primary source: MANRS 2017 year-in-review (https://manrs.org/2018/01/14000-incidents-a-2017-routing-security-year-in-review/)
- Source event id: MANRS 2017 March SECW Brazil incident
- Evidence: The event is listed as a media-picked example from 2017 BGPStream incidents.
- Corroboration: BGPStream annual data cited by MANRS
- Adjudication rationale: Accept with limitations because class, actor, victims, and month are known but exact prefix/time metadata need recovery.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2017.03/UPDATES/
- Limitations: Only month-level date and victim networks recovered; before lock, recover exact BGPStream event/prefix details.

## V2-HIJACK-019 - Hijack - ACCEPT
- Time: 2017-12 to 2017-12
- ASN(s): Previously unused Russian AS; victims include Google, Apple, Facebook, Microsoft, Twitch, NTT Communications, Riot Games
- Prefix metadata: Major Internet service prefixes; exact list not recovered from public MANRS summary
- Primary source: MANRS 2017 year-in-review (https://manrs.org/2018/01/14000-incidents-a-2017-routing-security-year-in-review/)
- Source event id: MANRS 2017 December Russian AS reroute
- Evidence: Victim networks and approximate duration are documented in MANRS's 2017 incident examples.
- Corroboration: BGPStream annual data cited by MANRS
- Adjudication rationale: Treat as ACCEPT_WITH_METADATA_LIMITATION for expert review because exact AS/prefix details need recovery before lock.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2017.12/UPDATES/
- Limitations: Exact AS, prefix list, and event IDs not recovered in public summary.

## V2-LEAK-006 - Leak - ACCEPT
- Time: 2021-01-06T04:21:00Z to 2021-01-06T06:51:00Z
- ASN(s): AS9304 leaked through AS15412
- Prefix metadata: 8764 leaked prefixes; exact list not recovered from public article text
- Primary source: Qrator Labs Radar article (https://blog.qrator.net/en/as9304-leaking-8764-prefixes-through-as15412_111/)
- Source event id: Qrator AS9304 leaking 8764 prefixes through AS15412
- Evidence: Start 04:21 UTC, active phase about 2.5 hours, 9140 conflicts overall.
- Corroboration: Qrator newsletter summary https://blog.qrator.net/en/cybersecurity-newsletter-first-2021_114/
- Adjudication rationale: Source-native route leak classification with timestamp, leaker ASN, transit ASN, and prefix count.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2021.01/UPDATES/
- Limitations: Full prefix list not in public article text.

## V2-LEAK-007 - Leak - ACCEPT
- Time: 2021-02-11T04:36:41Z to 2021-02-11T04:50:10Z
- ASN(s): AS28548; leaked routes from AS14178 to AS18734
- Prefix metadata: 2828 prefixes in Qrator summary; 7200+ unique IPv4 prefixes in MANRS/Isolario analysis; example 201.157.24.0/24
- Primary source: MANRS incident analysis (https://manrs.org/2021/02/major-route-leak-by-as28548-another-bgp-optimizer/)
- Source event id: Qrator/MANRS AS28548 Cablevision route leak
- Evidence: MANRS reports first changes at 04:36:41 UTC, last leak update 04:48:21, own-prefix announcements at 04:50:10, and example 201.157.24.0/24.
- Corroboration: Qrator Radar page 2 summary; Doug Madory/Kentik tweet cited by MANRS
- Adjudication rationale: Strong source-native route leak with AS path direction, timestamp, example prefix, and corroborating analyst evidence.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2021.02/UPDATES/

## V2-LEAK-008 - Leak - ACCEPT
- Time: 2020-08-24T11:21:00Z to 2020-08-24T16:00:00Z
- ASN(s): AS42910 Premier DC via AS9121/AS61135
- Prefix metadata: 1403 leaked prefixes; 1000+ Akamai prefixes; exact list not recovered
- Primary source: Qrator Labs Radar article (https://blog.qrator.net/en/as42910-leaking-hundreds-prefixes_89/)
- Source event id: Qrator AS42910 August 2020 route leak
- Evidence: Incident started at 11:21 UTC, occurred in four waves, and ended around 16:00 UTC.
- Corroboration: Qrator Radar archive page 2
- Adjudication rationale: Source-native route leak with start/end timing, leaker ASN, scope, and affected organization.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2020.08/UPDATES/
- Limitations: Full affected-prefix list not recovered.

## V2-LEAK-009 - Leak - ACCEPT
- Time: 2018-01-17T12:01:00Z to 2018-01-17T12:16:00Z
- ASN(s): AS8901; AS12389; AS8732
- Prefix metadata: 70000 affected prefixes; example 5.121.176.0/20
- Primary source: Qrator Labs Radar article (https://blog.qrator.net/en/moscow-traffic-jam_9/)
- Source event id: Qrator Moscow Traffic Jam AS8901 route leak
- Evidence: Qrator reports the active phase began at 12:01 UTC, lasted 15 minutes, and peaked at 70,000 affected prefixes; example route 5.121.176.0/20 is shown.
- Corroboration: None recovered in this pass
- Adjudication rationale: Source-native route leak with exact start, duration, AS path context, and example prefix.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2018.01/UPDATES/

## V2-LEAK-010 - Leak - ACCEPT
- Time: 2019-04-04 to 2019-04-04
- ASN(s): AS60280; AS9002; AS205540
- Prefix metadata: 18600 leaked prefixes from approximately 1400 origin ASes; exact list not recovered
- Primary source: Qrator Labs Radar archive (https://blog.qrator.net/en/radar/?page=4)
- Source event id: Qrator NTEC AS60280 Belarus route leak
- Evidence: Qrator archive states AS60280 leaked 18,600 prefixes originating from approximately 1,400 ASes on 2019-04-04.
- Corroboration: Qrator blog index page 12
- Adjudication rationale: Accept as source-native route leak candidate; exact prefix list not recovered.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2019.04/UPDATES/
- Limitations: Exact time and prefix list require article recovery beyond archive excerpt.

## V2-LEAK-011 - Leak - ACCEPT
- Time: 2019-06-06T09:43:00Z to 2019-06-06T11:43:00Z
- ASN(s): AS21217 Safe Host; AS4134 China Telecom; victims AS3303/AS1136/AS5410/AS21502
- Prefix metadata: 70000+ leaked routes; examples 176.171.75.0/24 and European mobile-network prefixes
- Primary source: MANRS / Oracle Internet Intelligence incident analysis (https://manrs.org/2019/06/large-european-routing-leak-sends-traffic-through-china-telecom/)
- Source event id: MANRS/Oracle Safe Host China Telecom leak June 2019
- Evidence: MANRS reports the leak began at 09:43 UTC, many routes circulated over two hours, and gives example prefix 176.171.75.0/24 with AS path through AS4134/AS21217.
- Corroboration: Oracle Internet Intelligence original article referenced by MANRS; user traceroutes cited in MANRS
- Adjudication rationale: Strong independent route leak with exact timing, AS path, example prefix, and affected networks.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2019.06/UPDATES/

## V2-LEAK-012 - Leak - ACCEPT
- Time: 2023-05-25T11:21:40Z to 2023-05-25T12:43:36Z
- ASN(s): AS37468 Angola Cables; victims include AS20940/AS16509 and others
- Prefix metadata: 2.16.0.0/13; example IPv6 prefixes 2001:502:be98::/48, 2001:503:f189::/48, 2001:500:ed30::/48
- Primary source: MANRS incident analysis (https://manrs.org/2023/05/bgp-route-leak-at-angola-cables-slows-connectivity-for-many-australians/)
- Source event id: MANRS Angola Cables AS37468 route leak
- Evidence: MANRS shows 2.16.0.0/13 path changed to include AS37468 at 11:21 UTC and disappeared after 12:41 UTC; article states route leak lasted around three hours.
- Corroboration: Doug Madory/Kentik commentary cited by MANRS; local Australian operator reports cited
- Adjudication rationale: Strong independent route leak with route examples, timestamps, and operator context.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2023.05/UPDATES/

## V2-LEAK-013 - Leak - ACCEPT
- Time: 2017-08-25 to 2017-08-25
- ASN(s): Google; affected Japanese networks
- Prefix metadata: Google leaked BGP prefixes learned from peering relationships; exact list not recovered here
- Primary source: Internet Society / MANRS article (https://www.internetsociety.org/blog/2017/08/google-leaked-prefixes-knocked-japan-off-internet/)
- Source event id: Google Japan route leak August 2017
- Evidence: Internet Society reports the incident lasted less than ten minutes but spread quickly and caused large-scale Internet disruption in Japan.
- Corroboration: MANRS 2017 year-in-review lists the incident
- Adjudication rationale: Independent route leak candidate with date, actor, affected region, and class; exact prefix/time details need recovery.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2017.08/UPDATES/
- Limitations: Exact prefix list and start/end time not recovered in this pass.

## V2-LEAK-014 - Leak - ACCEPT
- Time: 2017-10 to 2017-10
- ASN(s): Brazilian network; affected CDNs including Twitter/Google and others
- Prefix metadata: Major CDN prefixes; exact list not recovered
- Primary source: MANRS 2017 year-in-review (https://manrs.org/2018/01/14000-incidents-a-2017-routing-security-year-in-review/)
- Source event id: MANRS 2017 October Brazil CDN route leak
- Evidence: MANRS lists this as an example BGP mishap causing reachability/performance problems for many large CDNs.
- Corroboration: BGPStream annual data cited by MANRS
- Adjudication rationale: Accepted as source-native route leak candidate with source limitations; exact prefix event id should be recovered before lock.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2017.10/UPDATES/
- Limitations: Month-level date and exact prefix details not recovered.

## V2-LEAK-015 - Leak - ACCEPT
- Time: 2017-11 to 2017-11
- ASN(s): Level 3
- Prefix metadata: Route leak affecting North America; exact prefix list not recovered
- Primary source: MANRS 2017 year-in-review (https://manrs.org/2018/01/14000-incidents-a-2017-routing-security-year-in-review/)
- Source event id: MANRS 2017 November Level 3 route leak
- Evidence: The MANRS year-in-review explicitly labels this as a route leak.
- Corroboration: BGPStream annual data cited by MANRS
- Adjudication rationale: Accepted with metadata limitations for expert review; exact source event details needed before lock.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2017.11/UPDATES/
- Limitations: Exact prefix list and event IDs not recovered.

## V2-LEAK-016 - Leak - AMBIGUOUS
- Time: 2022-01-19T17:00:07Z to 2022-01-20
- ASN(s): AS57695; AS60068; route views peer AS6447
- Prefix metadata: 0.0.0.0/0; 104.0.0.0/2; 154.117.72.0/22; 154.117.64.0/22
- Primary source: MANRS incident analysis (https://manrs.org/2022/04/rfc-7911-what-happens-when-routers-do-not-speak-the-same-language/)
- Source event id: MANRS AS57695 RFC7911 leak/malformed update event
- Evidence: Article provides BGP update example at 2022-01-19 17:00:07 with prefixes including 0.0.0.0/0 and 154.117.72.0/22.
- Corroboration: RouteViews updates shown in article
- Adjudication rationale: Route leak classification is source-native, but event was not globally visible; useful as review candidate.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2022.01/UPDATES/
- Limitations: Article emphasizes collector-specific visibility; mark ambiguous for confirmation-set eligibility.

## V2-LEAK-017 - Leak - ACCEPT
- Time: 2026-04-01T10:23:49Z to 2026-04-01T10:24:32Z
- ASN(s): AS18106 vantage; path includes AS36692 AS25605 AS30607 AS36692
- Prefix metadata: 67.215.94.0/24
- Primary source: Kentik route leak analysis (https://www.kentik.com/blog/ephemeral-leaks-and-automated-bgp-route-leak-detection/)
- Source event id: Kentik ephemeral leak 67.215.94.0/24 2026-04-01
- Evidence: Kentik shows RouteViews update lines from 10:23:49 to 10:24:32 UTC with leak AS paths for 67.215.94.0/24.
- Corroboration: RouteViews excerpts in Kentik article
- Adjudication rationale: Strong single-prefix leak example with exact prefix, times, and RouteViews evidence.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2026.04/UPDATES/

## V2-LEAK-018 - Leak - ACCEPT
- Time: 2026-05-21T08:05:00Z to 2026-05-21T09:35:00Z
- ASN(s): AS7303 Telecom; learned from AS22927; leaked toward AS6762 and AS3356
- Prefix metadata: 2989 leaked prefixes; exact list not recovered from Qrator social mirror
- Primary source: Qrator_Radar social feed mirror (https://twstalker.com/Qrator_Radar)
- Source event id: Qrator_Radar AS7303 2026-05-21 route leak
- Evidence: Feed states start 08:05 UTC, 3,994 conflicts, 343 ASNs in 4 countries, max propagation 93%, duration about 1.5h.
- Corroboration: None recovered in this pass
- Adjudication rationale: Accept as Qrator source-native leak candidate but source should be upgraded to original X/API archive before final lock.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2026.05/UPDATES/
- Limitations: Source URL is a public mirror of Qrator_Radar; original tweet/API URL should be recovered before lock.

## V2-LEAK-019 - Leak - ACCEPT
- Time: 2026-05-28T08:21:00Z to 2026-05-28T08:26:00Z
- ASN(s): AS21859 ZEN-ECN; learned from AS4755; leaked toward AS9498
- Prefix metadata: 1334 leaked prefixes; exact list not recovered from Qrator social mirror
- Primary source: Qrator_Radar social feed mirror (https://twstalker.com/Qrator_Radar)
- Source event id: Qrator_Radar AS21859 2026-05-28 route leak
- Evidence: Feed states 1,334 conflicts with 1,005 ASNs in 75 countries, max propagation 68%, duration about 5 minutes.
- Corroboration: None recovered in this pass
- Adjudication rationale: Accept as Qrator source-native leak candidate with social-source limitation.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2026.05/UPDATES/
- Limitations: Original source should be recovered before final lock.

## V2-LEAK-020 - Leak - ACCEPT
- Time: 2026-06-26T11:25:00Z to 2026-06-26T11:40:00Z
- ASN(s): AS28910 INTAL; learned from AS1299/AS58453; leaked toward AS205103
- Prefix metadata: 3095 leaked prefixes; exact list not recovered from Qrator social mirror
- Primary source: Qrator_Radar social feed mirror (https://twstalker.com/Qrator_Radar)
- Source event id: Qrator_Radar AS28910 2026-06-26 route leak
- Evidence: Feed states 107 ASNs in 35 countries, max propagation 100%, duration about 15 minutes.
- Corroboration: None recovered in this pass
- Adjudication rationale: Accept as source-native Qrator social event with source-archive limitation.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2026.06/UPDATES/
- Limitations: Original source should be recovered before final lock.

## V2-LEAK-021 - Leak - ACCEPT
- Time: 2024-05-24 to 2024-05-24
- ASN(s): Megatelecom; InterNexa Brasil integration context
- Prefix metadata: 5333 conflicts; exact leaked prefix list not recovered
- Primary source: Qrator Labs Q3 2024 BGP incident overview (https://blog.qrator.net/en/q3-2024-ddos-bots-and-bgp-incidents-statistics-and_209/)
- Source event id: Qrator Q2/Q3 2024 Megatelecom route leak
- Evidence: Qrator reports 5,333 conflicts involving 593 ASes from 68 countries, caused by infrastructure merging during Megatelecom's acquisition of InterNexa Brasil.
- Corroboration: Qrator Q2 2024 overview https://blog.qrator.net/en/q2-2024-ddos-bots-and-bgp-incidents-statistics-and_205/
- Adjudication rationale: Source-native Qrator global route leak event; exact prefix list not recovered.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2024.05/UPDATES/
- Limitations: Exact ASN and affected prefix list require deeper source/API recovery.

## V2-LEAK-022 - Leak - ACCEPT
- Time: 2021-12-24 to 2021-12-24
- ASN(s): AS7633 SOFTNET India
- Prefix metadata: 20000 leaked prefixes; exact list not recovered from public MANRS summary
- Primary source: MANRS BGP Security in 2021 (https://manrs.org/2022/02/bgp-security-in-2021/)
- Source event id: MANRS 2021 major leak list: 2021-12-24 AS7633
- Evidence: MANRS selected it as a significant 2021 BGP leak based on impact/number of prefixes.
- Corroboration: Qrator Labs referenced by MANRS
- Adjudication rationale: Accept as expert-reviewable leak candidate with exact date/ASN/count.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2021.12/UPDATES/
- Limitations: Full prefix list requires Qrator archive recovery.

## V2-LEAK-023 - Leak - ACCEPT
- Time: 2021-12-24 to 2021-12-24
- ASN(s): AS132215 POWERGRID
- Prefix metadata: 112000 leaked prefixes; exact list not recovered from public MANRS summary
- Primary source: MANRS BGP Security in 2021 (https://manrs.org/2022/02/bgp-security-in-2021/)
- Source event id: MANRS 2021 major leak list: 2021-12-24 AS132215
- Evidence: Date, leaker ASN, route-leak classification, and prefix count are present in the MANRS annual summary.
- Corroboration: Qrator Labs referenced by MANRS
- Adjudication rationale: Accept with exact-prefix limitation.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2021.12/UPDATES/
- Limitations: Full prefix list requires Qrator archive recovery.

## V2-LEAK-024 - Leak - ACCEPT
- Time: 2021-12-08 to 2021-12-08
- ASN(s): AS10442 VOZHD
- Prefix metadata: 32000 leaked prefixes; exact list not recovered from public MANRS summary
- Primary source: MANRS BGP Security in 2021 (https://manrs.org/2022/02/bgp-security-in-2021/)
- Source event id: MANRS 2021 major leak list: 2021-12-08 AS10442
- Evidence: Date, leaker ASN, route-leak classification, and prefix count are present in the MANRS annual summary.
- Corroboration: Qrator Labs referenced by MANRS
- Adjudication rationale: Accept with exact-prefix limitation.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2021.12/UPDATES/
- Limitations: Full prefix list requires Qrator archive recovery.

## V2-LEAK-025 - Leak - ACCEPT
- Time: 2021-08-19 to 2021-08-19
- ASN(s): AS265038 JNET
- Prefix metadata: 11000 leaked prefixes; exact list not recovered from public MANRS summary
- Primary source: MANRS BGP Security in 2021 (https://manrs.org/2022/02/bgp-security-in-2021/)
- Source event id: MANRS 2021 major leak list: 2021-08-19 AS265038
- Evidence: Date, leaker ASN, route-leak classification, and prefix count are present in the MANRS annual summary.
- Corroboration: Qrator Labs referenced by MANRS
- Adjudication rationale: Accept with exact-prefix limitation.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2021.08/UPDATES/
- Limitations: Full prefix list requires Qrator archive recovery.

## V2-LEAK-026 - Leak - ACCEPT
- Time: 2021-07-30 to 2021-07-30
- ASN(s): AS137996 WITGLOBALCOMMUNICATIONS
- Prefix metadata: 167000 leaked prefixes; exact list not recovered from public MANRS summary
- Primary source: MANRS BGP Security in 2021 (https://manrs.org/2022/02/bgp-security-in-2021/)
- Source event id: MANRS 2021 major leak list: 2021-07-30 AS137996
- Evidence: Date, leaker ASN, route-leak classification, and prefix count are present in the MANRS annual summary.
- Corroboration: Qrator Labs referenced by MANRS
- Adjudication rationale: Accept with exact-prefix limitation.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2021.07/UPDATES/
- Limitations: Full prefix list requires Qrator archive recovery.

## V2-LEAK-027 - Leak - ACCEPT
- Time: 2021-06-03 to 2021-06-03
- ASN(s): AS199599 CIREX
- Prefix metadata: 26000 leaked prefixes; exact list not recovered from public MANRS summary
- Primary source: MANRS BGP Security in 2021 (https://manrs.org/2022/02/bgp-security-in-2021/)
- Source event id: MANRS 2021 major leak list: 2021-06-03 AS199599
- Evidence: Date, leaker ASN, route-leak classification, and prefix count are present in the MANRS annual summary.
- Corroboration: Qrator Labs referenced by MANRS
- Adjudication rationale: Accept with exact-prefix limitation.
- Overlap: NEW_INDEPENDENT_EVENT
- RouteViews: ROUTEVIEWS_MONTH_AVAILABLE; https://archive.routeviews.org/bgpdata/2021.06/UPDATES/
- Limitations: Full prefix list requires Qrator archive recovery.

