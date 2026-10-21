# V2 Candidate Evidence Packets

## V2-HIJACK-001 — Hijack

- Event time: 2026-05-16/2026-05-17 to 2026-05-17
- ASN: AS202734; AS402335; AS402333
- Prefix: 240e::/20; multiple IPv4/IPv6 prefixes
- Primary evidence: GitHub evidence archive and NANOG thread — https://github.com/miao-2011/bgp-hijack-evidence-AS202734; https://lists.nanog.org/archives/list/nanog@lists.nanog.org/thread/MI6VWOX7XOCDIS244RLJSMS2ITZWTGED/
- Secondary evidence: RIPE BGPlay, Hurricane Electric BGP Toolkit, RouteViews output referenced in archive
- Evidence summary: Independent evidence archive and NANOG thread report AS202734 and affiliated ASNs originated thousands of unauthorized prefixes including China Telecom 240e::/20.
- Adjudication: ACCEPT
- Rationale: Documented unauthorized originations, affected prefixes, ASNs, and route-collector evidence.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-HIJACK-002 — Hijack

- Event time: 2026-06-16 to 2026-06-16
- ASN: AS18101
- Prefix: Telegram IPv4/IPv6 prefixes
- Primary evidence: BGPHorizon incident analysis — https://www.bgphorizon.com/blog/telegram-bgp-hijack-june-2026
- Secondary evidence: Other routing monitors referenced by report
- Evidence summary: BGPHorizon report says Telegram prefixes were announced by AS18101 instead of Telegram AS62041/AS62014/AS44907 in two waves.
- Adjudication: ACCEPT
- Rationale: Documented wrong-origin routing for named affected network and ASNs; exact prefix list must be recovered before final roster.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-HIJACK-003 — Hijack

- Event time: 2008-02-24T20:07:25Z to 2008-02-24
- ASN: AS36561; AS17557
- Prefix: 208.65.153.0/24
- Primary evidence: RouteCause reproducible demo using RIPE RIS/RouteViews raw MRT — https://github.com/dim-tsoukalas/RouteCause
- Secondary evidence: Historic public reports of Pakistan Telecom / YouTube hijack
- Evidence summary: RouteCause demo and well-known Pakistan Telecom/YouTube case show MOAS for YouTube prefix with AS36561 and legitimate AS17557.
- Adjudication: ACCEPT
- Rationale: Clean wrong-origin/MOAS case with exact prefix, ASNs, and timestamped routing evidence.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-HIJACK-004 — Hijack

- Event time: 2018-07-30 to 2018-07-30
- ASN: AS58224
- Prefix: Telegram prefixes
- Primary evidence: Qrator Labs blog — https://blog.qrator.net/en/leaked-censorship_16/
- Secondary evidence: None locked
- Evidence summary: Qrator report describes Iranian ISP TCI leaking static routes to BGP, affecting three Telegram prefixes and nine ASNs.
- Adjudication: AMBIGUOUS
- Rationale: Primary source itself says the interpretation is a hypothesis from the outside; requires expert review before ACCEPT.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-HIJACK-005 — Hijack

- Event time: 2019-04-01/2019-04-10 to 2019-04-10
- ASN: AS263444; AS61775; AS265466
- Prefix: multiple split prefixes, examples 1.6.36.0/23 and 178.248.236.0/24
- Primary evidence: Qrator Labs blog — https://blog.qrator.net/en/new-hijack-attack_42/
- Secondary evidence: Raw BGP examples in report
- Evidence summary: Qrator report documents crafted AS_PATH/split-prefix hijack-style behavior and affected prefix examples.
- Adjudication: ACCEPT
- Rationale: Report provides BGP table/update examples, ASNs, prefixes, and hijack framing; expert review should verify exact event bounds.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-LEAK-001 — Leak

- Event time: 2021-01-27 to 2021-01-27
- ASN: AS61666; AS28146; AS16735
- Prefix: 1330 leaked prefixes
- Primary evidence: Qrator Labs blog — https://blog.qrator.net/en/prepending-trouble_115/
- Secondary evidence: Qrator Radar analysis
- Evidence summary: Qrator reports AS61666 GLOBO leaked upstream MHNET prefixes to ALGAR; 1,330 prefixes, 8 minute incident.
- Adjudication: ACCEPT
- Rationale: Documented policy/export violation with leak ASNs, time, duration, and prefix count.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-LEAK-002 — Leak

- Event time: 2018-05-18T09:36:00Z to 2018-05-18T10:06:00Z
- ASN: AS263086; AS53087; AS263444
- Prefix: thousands of leaked prefixes
- Primary evidence: Qrator Labs blog — https://blog.qrator.net/en/day-internet-survived_14/
- Secondary evidence: Qrator Radar analysis
- Evidence summary: Qrator describes PBNET leaking thousands of prefixes between upstreams TELY and OPENX; two waves around half an hour.
- Adjudication: ACCEPT
- Rationale: Documented export-policy leak between upstreams with time, leaking ASN, and affected scale.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-LEAK-003 — Leak

- Event time: 2019-06-24T10:35:00Z to 2019-06-24T12:38:00Z
- ASN: AS396531; AS701
- Prefix: 6.7k+ prefixes
- Primary evidence: Qrator Labs blog — https://blog.qrator.net/en/how-difficult-disrupt-service-nowadays_49/
- Secondary evidence: Public incident discussion around Verizon route leak
- Evidence summary: Qrator analysis of Verizon/DQE route leak reports over 6.7k prefixes from 850+ operators; two-hour DoS impact.
- Adjudication: ACCEPT
- Rationale: Documented large route leak with leaking customer/provider relationship and explicit timing.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-LEAK-004 — Leak

- Event time: 2024-05-24 to 2024-05-24
- ASN: Megatelecom; InterNexa Brasil
- Prefix: 5333 conflicts
- Primary evidence: Qrator Labs quarterly BGP incidents report — https://blog.qrator.net/en/q3-2024-ddos-bots-and-bgp-incidents-statistics-and_209/
- Secondary evidence: None locked
- Evidence summary: Qrator Q3 2024 report identifies a major BGP route leak by Brazilian provider Megatelecom after acquisition integration, producing 5,333 conflicts.
- Adjudication: ACCEPT
- Rationale: Event-level detail is enough for feasibility, but exact prefixes/ASNs need recovery before final roster.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-LEAK-005 — Leak

- Event time: 2026-03-31T13:08:00Z to 2026-03-31T13:14:57Z
- ASN: AS48452; AS8262; AS3257
- Prefix: 193.201.241.0/24
- Primary evidence: APNIC analysis of Cloudflare Radar leak — https://blog.apnic.net/2026/05/25/ephemeral-leaks-and-automated-bgp-route-leak-detection/
- Secondary evidence: Raw BGP examples in APNIC post
- Evidence summary: APNIC blog analyzes an ephemeral route leak but source event is Cloudflare Radar event #497796.
- Adjudication: REJECT
- Rationale: Useful evidence packet, but Cloudflare Radar is the underlying primary event source; violates non-Cloudflare primary label rule.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-001 — Outage

- Event time: Friday, July 2, 2021, 2:40:00 AM to Friday, July 2, 2021, 3:15:00 AM
- ASN: AS (8452)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=8452&from=1625097600000&to=1625313600000
- Evidence summary: IODA manually verified AS-scoped outage in Egypt with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-002 — Outage

- Event time: Tuesday, June 15, 2021, 1:50:00 PM to Tuesday, June 15, 2021, 2:30:00 PM
- ASN: AS (58224)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=58224&from=1623715200000&to=1623931200000
- Evidence summary: IODA manually verified AS-scoped outage in Iran with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-003 — Outage

- Event time: Friday, June 4, 2021, 2:50:00 AM to Friday, June 4, 2021, 5:50:00 AM
- ASN: AS (58224)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=58224&from=1622683210000&to=1622856010000
- Evidence summary: IODA manually verified AS-scoped outage in Iran with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-004 — Outage

- Event time: Monday, May 10, 2021, 6:40:00 AM to Monday, May 10, 2021, 8:25:00 AM
- ASN: AS (58224)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=58224&from=1620518400000&to=1620691200000
- Evidence summary: IODA manually verified AS-scoped outage in Iran with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-005 — Outage

- Event time: Tuesday, March 16, 2021, 4:45:00 AM to Tuesday, March 16, 2021, 5:30:00 AM
- ASN: AS (9299)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=9299&from=1615687200000&to=1615896000000
- Evidence summary: IODA manually verified AS-scoped outage in Philippines with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-006 — Outage

- Event time: Sunday, March 14, 2021, 10:40:00 PM to Monday, March 15, 2021, 4:00:00 AM
- ASN: AS (58224)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=58224&from=1615687200000&to=1615896000000
- Evidence summary: IODA manually verified AS-scoped outage in Iran with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-007 — Outage

- Event time: Saturday, March 13, 2021, 10:30:00 PM to Sunday, March 14, 2021, 5:20:00 AM
- ASN: AS (58224)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=58224&from=1615543200000&to=1615723200000
- Evidence summary: IODA manually verified AS-scoped outage in Iran with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-008 — Outage

- Event time: Tuesday, March 2, 2021, 5:10:00 AM to Tuesday, March 2, 2021, 6:00:00 AM
- ASN: AS (668)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=668&from=1614643200000&to=1614859200000
- Evidence summary: IODA manually verified AS-scoped outage in United States of America (USA) with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-009 — Outage

- Event time: Friday, February 26, 2021, 5:10:00 AM to Friday, February 26, 2021, 12:00:00 PM
- ASN: AS (668)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=668&from=1614297600000&to=1614412800000
- Evidence summary: IODA manually verified AS-scoped outage in United States of America (USA) with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-010 — Outage

- Event time: Wednesday, February 24, 2021, 1:30:00 AM to Saturday, March 6, 2021, 11:00:00 PM
- ASN: AS (37233)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=37233&from=1613952000000&to=1615334400000
- Evidence summary: IODA manually verified AS-scoped outage in Niger with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-011 — Outage

- Event time: Monday, February 15, 2021, 8:50:00 AM to Monday, February 15, 2021, 10:00:00 AM
- ASN: AS (37069)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=37069&from=1613347200000&to=1613563200000
- Evidence summary: IODA manually verified AS-scoped outage in Egypt with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-012 — Outage

- Event time: Friday, February 12, 2021, 9:20:00 PM to Saturday, February 13, 2021, 7:20:00 AM
- ASN: AS (17813)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=17813&from=1613048400000&to=1613217600000
- Evidence summary: IODA manually verified AS-scoped outage in India with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-013 — Outage

- Event time: Friday, February 12, 2021, 12:20:00 PM to Friday, February 12, 2021, 5:50:00 PM
- ASN: AS (17813)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=17813&from=1613048400000&to=1613217600000
- Evidence summary: IODA manually verified AS-scoped outage in India with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-014 — Outage

- Event time: Wednesday, February 10, 2021, 6:00:00 AM to Wednesday, February 10, 2021, 6:20:00 AM
- ASN: AS (8151)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=8151&from=1612908000000&to=1613044800000
- Evidence summary: IODA manually verified AS-scoped outage in Mexico with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-015 — Outage

- Event time: Monday, February 8, 2021, 11:10:00 PM to Tuesday, February 9, 2021, 12:00:00 AM
- ASN: AS (224)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=224&from=1612742422000&to=1612893600000
- Evidence summary: IODA manually verified AS-scoped outage in Norway with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-016 — Outage

- Event time: Thursday, February 4, 2021, 6:30:00 AM to Thursday, February 4, 2021, 9:00:00 AM
- ASN: AS (668)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=668&from=1612224000000&to=1612440000000
- Evidence summary: IODA manually verified AS-scoped outage in United States of America (USA) with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-017 — Outage

- Event time: Wednesday, February 3, 2021, 12:40:00 PM to Wednesday, February 3, 2021, 1:10:00 PM
- ASN: AS (37492)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=37492&from=1612224022000&to=1612440022000
- Evidence summary: IODA manually verified AS-scoped outage in Tunisia with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-018 — Outage

- Event time: Tuesday, February 2, 2021, 11:00:00 PM to Tuesday, February 2, 2021, 11:20:00 PM
- ASN: AS (37492)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=37492&from=1612224022000&to=1612440022000
- Evidence summary: IODA manually verified AS-scoped outage in Tunisia with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-019 — Outage

- Event time: Tuesday, February 2, 2021, 3:10:00 PM to Tuesday, February 2, 2021, 3:30:00 PM
- ASN: AS (37492)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=37492&from=1612224022000&to=1612440022000
- Evidence summary: IODA manually verified AS-scoped outage in Tunisia with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-020 — Outage

- Event time: Tuesday, February 2, 2021, 5:40:00 AM to Tuesday, February 2, 2021, 6:10:00 AM
- ASN: AS (668)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=668&from=1612051200000&to=1612267200000
- Evidence summary: IODA manually verified AS-scoped outage in United States of America (USA) with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-021 — Outage

- Event time: Wednesday, January 13, 2021, 12:30:00 AM to Wednesday, January 13, 2021, 1:00:00 AM
- ASN: AS (55836)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=55836&from=1610452800000&to=1610539200000
- Evidence summary: IODA manually verified AS-scoped outage in India with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-022 — Outage

- Event time: Monday, January 4, 2021, 3:50:00 AM to Monday, January 4, 2021, 10:45:00 AM
- ASN: AS (8386)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=8386&from=1609675200000&to=1609761600000
- Evidence summary: IODA manually verified AS-scoped outage in Turkey with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-023 — Outage

- Event time: Sunday, August 23, 2020, 12:00:00 AM to Sunday, August 23, 2020, 12:50:00 AM
- ASN: AS (12880)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=12880&from=1598054400000&to=1598270400000
- Evidence summary: IODA manually verified AS-scoped outage in Iran with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-024 — Outage

- Event time: Thursday, July 30, 2020, 4:00:00 PM to Thursday, July 30, 2020, 8:40:00 PM
- ASN: AS (8048)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=8048&from=1596067200000&to=1596283200000
- Evidence summary: IODA manually verified AS-scoped outage in Venezuela with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-025 — Outage

- Event time: Wednesday, July 22, 2020, 10:10:00 AM to Wednesday, July 22, 2020, 10:30:00 AM
- ASN: AS (668)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=668&from=1595289600000&to=1595451600000
- Evidence summary: IODA manually verified AS-scoped outage in United States of America (USA) with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-026 — Outage

- Event time: Tuesday, June 30, 2020, 9:30:00 PM to Tuesday, June 30, 2020, 12:20:00 AM
- ASN: AS (58224)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=58224&from=1593475200000&to=1593691200000
- Evidence summary: IODA manually verified AS-scoped outage in Iran with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-027 — Outage

- Event time: Saturday, April 25, 2020, 9:10:00 AM to Saturday, April 25, 2020, 12:10:00 AM
- ASN: AS (1749)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=1759&from=1587686400000&to=1587902400000
- Evidence summary: IODA manually verified AS-scoped outage in Finland with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-028 — Outage

- Event time: Thursday, April 9, 2020, 7:10:00 AM to Thursday, April 9, 2020, 8:52:00 AM
- ASN: AS (4761)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=4761&from=1586304000000&to=1586520000000
- Evidence summary: IODA manually verified AS-scoped outage in Indonesia with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-029 — Outage

- Event time: Monday, March 16, 2020, 10:00:00 PM to Monday, March 16, 2020, 10:50:00 PM
- ASN: AS (6849)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=6849&from=1584230400000&to=1584446400000
- Evidence summary: IODA manually verified AS-scoped outage in Ukraine with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE

## V2-OUTAGE-030 — Outage

- Event time: Sunday, February 23, 2020, 4:10:00 AM to Sunday, February 23, 2020, 4:52:00 AM
- ASN: AS (4761)
- Prefix: AS-scoped outage; prefix list not source-native
- Primary evidence: IODA curated investigated outages CSV — https://github.com/InetIntel/internet_outages/blob/main/data/ioda/ioda_investigated_outages_cleaned_phase1+2.csv
- Secondary evidence: https://internal.ioda.inetintel.cc.gatech.edu/d/BNtjHk9nk/historical-per-asn-ioda?orgId=1&var-VISIBILITY_THRESHOLD=min_50%25_ff_peer_asns&var-ASN=4761&from=1582416000000&to=1582459200000
- Evidence summary: IODA manually verified AS-scoped outage in Indonesia with BGP visibility marked TRUE.
- Adjudication: ACCEPT
- Rationale: Manually verified IODA outage, AS-scoped, BGP-visible, with start and end time.
- Overlap status: NEW_INDEPENDENT_EVENT
- RouteViews availability: ROUTEVIEWS_AVAILABLE
