# RouteViews Pipeline Reproducibility v1

## Collector and Archive

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

## Parser

The recorded parser environment is `bgpdump 1.6.2` using `bgpdump -q -m <input-file.bz2>`. One parsed output row represents one prefix-level announcement or withdrawal observation emitted from an UPDATE record, not a final feature row.

## Acquisition and Processing

MRT files were planned in 15-minute UTC UPDATE slots. The full TRAIN plan recorded 25,099 MRT assignments and 20,524 unique MRT URLs. The processing path retained incident-relevant prefix-level observations and later aggregated them into five-minute analytical windows.

## Non-recovered Details

Exact network transfer conditions and all temporary cache states are not part of the frozen methodology; source URLs, manifests, and parser metadata are preserved.
