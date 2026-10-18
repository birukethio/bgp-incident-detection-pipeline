# Hijack:68538 Provenance Audit v1

Generated UTC: 2026-09-14T23:51:22.937760+00:00

## Identity and Corpus Entry

- Incident UID: `Hijack:68538`
- Incident ID: `68538`
- Final class: `Hijack`
- Final partition: `holdout`
- Incident name: `Hijack_AS133623_68538_2024-10-11`
- Roster version/status: `v2` / `FROZEN`
- Freeze date: `2026-08-28`
- Source commit: `0ac193838ad71c42085792ed1608aac63466bf90`

`Hijack:68538` entered the final corpus through the Cloudflare Radar BGP hijack detector/source feed and survived V2 roster construction as a retained canonical/nonduplicate record. It was subsequently assigned to the V2 Final Holdout partition by the frozen partition manifest. The roster note indicates it was selected as part of a stratified quality sample favoring longer duration, more detector messages, more peer visibility, more prefixes, and higher confidence.

## Preserved Cloudflare/Source Evidence

- Source: Cloudflare Radar BGP hijack detector/source feed
- Source event ID: `68538`
- Source label: Hijack / Cloudflare Radar BGP hijack event
- Event type: `0`
- Min hijack timestamp: `2024-10-11T22:13:48.105`
- Max hijack timestamp: `2024-11-02T14:59:37.104`
- Max detector message timestamp: `2024-11-02T15:16:21.059`
- Duration seconds from source: `1875753`
- Hijacker/origin ASN: `133623`
- Hijacker country: `PH`
- Victim ASNs: `[134966, 138965]`
- Victim countries: `['PH']`
- Affected prefixes: `['103.6.104.0/24', '103.137.205.0/24', '103.137.206.0/24', '103.137.211.0/24']`
- Hijack detector message count: `730`
- Peer IP count: `19`
- Peer ASNs: `[1031, 3170, 3491, 3741, 6453, 13237, 14537, 34224, 38880, 49544, 49788, 58511, 59605, 199524, 267613]`
- Ongoing count: `425`
- Stale flag: `True`
- Confidence score: `12`
- Detector tags: `irr_new_origin_invalid:4; irr_old_origin_invalid:-2; irr_old_origin_valid:0; rpki_new_origin_invalid:8; rpki_old_origin_invalid:-2; rpki_old_origin_valid:0`

## Observation Window and RouteViews Acquisition

The final Holdout acquisition used detector-supported active-segment boundaries rather than the full first-to-last detector span. Two active 5-minute windows were retained for the incident, with 24 pre-context windows and 26 post-context windows, for 52 analytical rows total.

- Collector requested: `route-views2`
- Distinct active segments: `2`
- RouteViews files requested: `21`
- RouteViews files successfully retrieved: `21`
- Download status counts: `{200: 21}`
- Requested collection ranges: `2024-10-11T21:00:00Z` to `2024-11-02T16:00:00Z`

## RouteViews Files Requested

- https://archive.routeviews.org/bgpdata/2024.10/UPDATES/updates.20241011.2100.bz2
- https://archive.routeviews.org/bgpdata/2024.10/UPDATES/updates.20241011.2115.bz2
- https://archive.routeviews.org/bgpdata/2024.10/UPDATES/updates.20241011.2130.bz2
- https://archive.routeviews.org/bgpdata/2024.10/UPDATES/updates.20241011.2145.bz2
- https://archive.routeviews.org/bgpdata/2024.10/UPDATES/updates.20241011.2200.bz2
- https://archive.routeviews.org/bgpdata/2024.10/UPDATES/updates.20241011.2215.bz2
- https://archive.routeviews.org/bgpdata/2024.10/UPDATES/updates.20241011.2230.bz2
- https://archive.routeviews.org/bgpdata/2024.10/UPDATES/updates.20241011.2245.bz2
- https://archive.routeviews.org/bgpdata/2024.10/UPDATES/updates.20241011.2300.bz2
- https://archive.routeviews.org/bgpdata/2024.10/UPDATES/updates.20241011.2315.bz2
- https://archive.routeviews.org/bgpdata/2024.10/UPDATES/updates.20241011.2330.bz2
- https://archive.routeviews.org/bgpdata/2024.11/UPDATES/updates.20241102.1345.bz2
- https://archive.routeviews.org/bgpdata/2024.11/UPDATES/updates.20241102.1400.bz2
- https://archive.routeviews.org/bgpdata/2024.11/UPDATES/updates.20241102.1415.bz2
- https://archive.routeviews.org/bgpdata/2024.11/UPDATES/updates.20241102.1430.bz2
- https://archive.routeviews.org/bgpdata/2024.11/UPDATES/updates.20241102.1445.bz2
- https://archive.routeviews.org/bgpdata/2024.11/UPDATES/updates.20241102.1500.bz2
- https://archive.routeviews.org/bgpdata/2024.11/UPDATES/updates.20241102.1515.bz2
- https://archive.routeviews.org/bgpdata/2024.11/UPDATES/updates.20241102.1530.bz2
- https://archive.routeviews.org/bgpdata/2024.11/UPDATES/updates.20241102.1545.bz2
- https://archive.routeviews.org/bgpdata/2024.11/UPDATES/updates.20241102.1600.bz2

## Non-Destructive Scope

This audit did not retrain, rescore, alter the final roster, alter the Final Holdout result, or remove `Hijack:68538`.
