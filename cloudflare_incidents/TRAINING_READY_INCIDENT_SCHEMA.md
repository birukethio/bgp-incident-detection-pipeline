# Training-Ready BGP Incident Roster Schema

This file preserves the polished normalized schema for model-ready BGP incident labels across **Leak**, **Outage**, and **Hijack** records.

Do not modify or reinterpret raw source records. The raw Cloudflare source files remain separate. This normalized roster is the label table used to align incidents with later RouteViews / RIPE RIS MRT feature extraction.

## Canonical Output

Primary normalized roster:

`normalized_master_incident_roster_2023-01_to_2026-01.csv`

Supporting outputs:

`normalized_master_summary_counts_2023-01_to_2026-01.csv`
`normalized_master_missing_unverified_2023-01_to_2026-01.csv`
`normalized_master_window_counts_2023-01_to_2026-01.csv`

## Common Columns

| Column | Meaning |
|---|---|
| `incident_id` | Original source record ID. Never replace with generated IDs. |
| `incident_name` | Human-readable name. If generated, use neutral format such as `Leak_AS123_YYYY-MM-DD`. |
| `category` | One of `Leak`, `Outage`, `Hijack`. |
| `incident_date` | UTC calendar date derived from the incident start/detection time. |
| `start_utc` | Incident start timestamp in UTC ISO-8601 format. |
| `end_utc` | Incident end timestamp in UTC ISO-8601 format. |
| `duration_minutes` | Duration in minutes. Calculate from `end_utc - start_utc` if not supplied. |
| `primary_asn` | Main ASN: leak ASN, hijacker ASN, or null for outage when no single primary ASN exists. |
| `affected_asns` | JSON list of affected ASNs or source ASN list. |
| `affected_prefixes` | JSON list of affected prefixes when available. |
| `prefix_count` | Count of affected prefixes when available. |
| `peer_count` | Count of observing peers or peer ASNs when available. |
| `countries` | JSON list of countries from the source. |
| `source_url` | External/source URL when supplied by source. |
| `confidence_score` | Source confidence score when available, especially hijacks. |
| `routeviews_collection_start` | Reserved for later MRT feature extraction window. Leave blank until frozen. |
| `routeviews_collection_end` | Reserved for later MRT feature extraction window. Leave blank until frozen. |
| `five_minute_window_count` | `ceil(duration_minutes / 5)`. |
| `partition` | Reserved for train/validation/test split after final review. Leave blank until frozen. |
| `notes` | Normalization notes, cause/type tags, generated-name markers, or source caveats. |

## Source Mappings

### Leak

| Normalized field | Source mapping |
|---|---|
| `incident_id` | `id` |
| `category` | `Leak` |
| `incident_date` | date from `incident_date` / `detected_ts` |
| `start_utc` | `min_ts`, or `detected_ts` if `min_ts` is unavailable |
| `end_utc` | `max_ts` |
| `primary_asn` | `leak_asn` |
| `affected_asns` | `leak_seg` and available affected origin ASNs |
| `affected_prefixes` | null unless source prefixes are available |
| `prefix_count` | `prefix_count` |
| `peer_count` | `peer_count` |
| `countries` | `countries` |
| `notes` | include `leak_type`, `origin_count`, and generated-name marker when relevant |

### Outage

| Normalized field | Source mapping |
|---|---|
| `incident_id` | `id` |
| `category` | `Outage` |
| `incident_date` | date from `startDate` |
| `start_utc` | `startDate` |
| `end_utc` | `endDate` |
| `duration_minutes` | source duration if available, otherwise calculated |
| `primary_asn` | null unless a single primary outage ASN is clearly supplied |
| `affected_asns` | `asns` |
| `countries` | `locations` |
| `source_url` | `linkedUrl` |
| `notes` | include outage cause/type, for example `outageCause`, `outageType`, `dataSource` |

### Hijack

| Normalized field | Source mapping |
|---|---|
| `incident_id` | `id` |
| `category` | `Hijack` |
| `incident_date` | date from `min_hijack_ts` |
| `start_utc` | `min_hijack_ts` |
| `end_utc` | `max_hijack_ts` |
| `duration_minutes` | calculated from `max_hijack_ts - min_hijack_ts` if source duration is unavailable |
| `primary_asn` | `hijacker_asn` |
| `affected_asns` | `victim_asns` |
| `affected_prefixes` | `prefixes` |
| `prefix_count` | number of `prefixes` |
| `peer_count` | number of `peer_asns` |
| `countries` | `hijacker_country` plus `victim_countries` |
| `confidence_score` | `confidence_score` |
| `notes` | include relevant hijack tags and stale/ongoing indicators |

## Rules To Preserve

1. Convert all timestamps to UTC ISO-8601 format.
2. Calculate `duration_minutes` from `end_utc - start_utc` when missing.
3. Calculate `five_minute_window_count = ceil(duration_minutes / 5)`.
4. For hijacks, do **not** use `max_msg_ts` as the end time. Use `max_hijack_ts`.
5. Do not guess missing ASN, prefix, timestamp, or source information. Use null/blank, or `UNVERIFIED` only when a text marker is needed.
6. Preserve ASN lists, prefix lists, countries, and tags as JSON-style structured lists in CSV cells.
7. Keep `incident_name` neutral and human-readable. Mark generated names in `notes`.
8. Keep original source record IDs in `incident_id`.
9. Leave `routeviews_collection_start` and `routeviews_collection_end` blank until the final MRT collection window is chosen.
10. Leave `partition` blank until the incident roster is reviewed and frozen.

## Training Use

Use the normalized roster as the label table. Use RouteViews / RIPE RIS MRT archives later only for feature extraction, not for discovering or changing labels.

Recommended label-confidence values can be tracked in a later companion table:

| Confidence label | Meaning |
|---|---|
| `cloudflare_only` | Present in Cloudflare structured data only. |
| `external_validated` | Independently matched against credible external source by time plus ASN/path/prefix evidence. |
| `external_partial` | External source supports date/category/ASN but lacks enough detail for a strong match. |
| `unverified` | Missing core fields or no usable validation evidence. |
