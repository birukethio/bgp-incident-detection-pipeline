# BGP Incident Detection Pipeline

Research pipeline for building labeled BGP incident datasets and training a two-stage detector/classifier:

1. **Stage 1:** `Normal` vs `Incident`
2. **Stage 2:** `Hijack` vs `Leak` vs `Outage`

The current repository starts with quality-controlled Cloudflare incident labels and supporting validation notes. Raw MRT archives and large generated feature matrices are intentionally excluded from Git.

## Current Label Pool

The balanced incident-level roster is:

`cloudflare_incidents/balanced_incident_level_roster_473_each_leak_hijack_outage.csv`

It contains:

| Category | Incidents |
|---|---:|
| Leak | 473 |
| Hijack | 473 |
| Outage | 473 |
| **Total** | **1,419** |

Leak and Hijack were selected using stratified, quality-focused sampling across year, ASN/network, country, duration, prefix count, and visibility metrics. Outages use the quality-controlled Cloudflare outage pool with affected ASNs listed where Cloudflare provides them.

## Core Design Rules

- One real-world incident remains one incident.
- Balancing is performed at the incident level first.
- Splits must be by incident, not by 5-minute window.
- Long incidents should be capped during feature extraction so they do not dominate training windows.
- RouteViews / RIPE RIS MRT archives are reserved for feature extraction, not label discovery.
- API keys, tokens, raw MRT archives, raw Cloudflare dumps, and large feature matrices are not committed.

## Recommended Window Cap

During feature extraction:

```text
selected_windows_per_incident = min(raw_five_minute_window_count, 24)
```

For incidents longer than 24 windows, sample representative windows from onset, middle, recovery, and evenly spaced positions.

## Important Files

| File | Purpose |
|---|---|
| `cloudflare_incidents/TRAINING_READY_INCIDENT_SCHEMA.md` | Canonical normalized schema and mapping rules |
| `cloudflare_incidents/balanced_incident_level_roster_473_each_leak_hijack_outage.csv` | Current balanced roster for model development |
| `cloudflare_incidents/stratified_quality_leak_sample_473.csv` | Leak sample |
| `cloudflare_incidents/stratified_quality_hijack_sample_473.csv` | Hijack sample |
| `cloudflare_incidents/clean_cloudflare_outage_recommended_final_pool_all_asns.csv` | Outage pool with ASN lists |
| `cloudflare_incidents/stratified_quality_sampling_summary.csv` | Sampling summary |
| `cloudflare_incidents/clean_cloudflare_outage_asn_summary.csv` | Outage ASN completeness summary |
| `cloudflare_incidents/timed_external_bgp_route_leak_label_candidates.csv` | External timed leak-label candidates used for spot validation |

## Rebuild Scripts

| Script | Purpose |
|---|---|
| `cloudflare_incidents/fetch_cloudflare_all_incidents_to_2026_01.mjs` | Fetch all available Cloudflare incidents up to 2026-02-01 |
| `cloudflare_incidents/build_training_ready_all_cloudflare_roster.mjs` | Normalize full unsampled Cloudflare dump |
| `cloudflare_incidents/build_clean_outage_asn_roster.mjs` | Deduplicate and QC outage records with ASN completeness |
| `cloudflare_incidents/build_quality_controlled_outage_roster.mjs` | Build the initial outage QC roster |
| `cloudflare_incidents/build_stratified_quality_leak_hijack_samples.mjs` | Build stratified leak/hijack samples and combined balanced roster |

## Next Pipeline Steps

1. Define normal-window selection rules.
2. Implement incident-level train/validation/holdout split.
3. Implement per-incident 5-minute window capping.
4. Add MRT downloader for RouteViews and RIPE RIS.
5. Add BGP UPDATE parser and 5-minute feature extractor.
6. Train Stage 1 and Stage 2 models.
7. Run feature ablation experiments.
