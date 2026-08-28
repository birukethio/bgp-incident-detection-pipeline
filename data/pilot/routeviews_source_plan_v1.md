# RouteViews Source Plan v1

- Collector: `route-views2`
- Source: RouteViews archive UPDATE files.
- Archive URL pattern for named collectors: `https://archive.routeviews.org/<collector>/bgpdata/YYYY.MM/UPDATES/updates.YYYYMMDD.HHMM.bz2`
- Initial pilot collector path for `route-views2`: `https://archive.routeviews.org/bgpdata/YYYY.MM/UPDATES/updates.YYYYMMDD.HHMM.bz2`
- UPDATE cadence: 15-minute UTC slots.
- Filename convention: `updates.YYYYMMDD.HHMM.bz2`.
- UTC handling: incident timestamps are parsed as UTC; collection starts are floored to the previous 15-minute boundary and collection ends are ceiled to the next 15-minute boundary after adding configurable context buffers.
- This phase is dry-run only. URL availability is marked REVIEW until a non-downloading remote availability check is approved and performed.
- RIPE RIS is not used in this pilot unless a later review shows RouteViews coverage is inadequate for a selected incident.
