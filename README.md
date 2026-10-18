# BGP Incident Detection Pipeline

Research pipeline for building labeled BGP incident datasets and training a two-stage detector/classifier:

1. **Stage 1:** `Normal` vs `Incident`
2. **Stage 2:** `Hijack` vs `Leak` vs `Outage`

The current repository starts with quality-controlled Cloudflare incident labels and supporting validation notes. Raw MRT archives and large generated feature matrices are intentionally excluded from Git.

## Current Label Pool

The authoritative frozen incident corpus is Roster v2:

`data/roster_v2/frozen_incident_roster_v2.csv`

It contains:

| Category | Incidents |
|---|---:|
| Leak | 473 |
| Hijack | 473 |
| Outage | 473 |
| **Total** | **1,419** |

Roster v2 contains 1,419 independent incidents after duplicate remediation, timestamp-semantics review, and Leak prefix disposition review. v1 is retained only for audit history.

Leak and Hijack were selected using stratified, quality-focused sampling across year, ASN/network, country, duration, prefix count where available, and visibility metrics. Outages use the quality-controlled Cloudflare outage pool with affected ASNs listed where Cloudflare provides them.

## Core Design Rules

- One real-world incident remains one incident.
- Balancing is performed at the incident level first.
- Splits must be by incident, not by 5-minute window.
- All future 5-minute windows and feature rows must inherit the incident's frozen partition.
- Never re-split after feature extraction.
- The final holdout must never be used for threshold selection, feature selection, balancing decisions, hyperparameter tuning, or model comparison.
- Long incidents may need window controls during feature extraction so they do not dominate training, but the cap has not been fixed yet.
- RouteViews / RIPE RIS MRT archives are reserved for feature extraction, not label discovery.
- API keys, tokens, raw MRT archives, raw Cloudflare dumps, and large feature matrices are not committed.

## Frozen Incident Partitions

The authoritative Roster v2 corpus is split once at the incident level using fixed random seed `20260828` and split version `v2`.

The source `incident_id` is preserved in the partition outputs. Because source IDs may be schema-scoped, the frozen experimental unit is `incident_uid`.

| Partition | Hijack | Leak | Outage | Total |
|---|---:|---:|---:|---:|
| Train | 331 | 331 | 331 | 993 |
| Validation | 71 | 71 | 71 | 213 |
| Final Holdout | 71 | 71 | 71 | 213 |
| **Total** | **473** | **473** | **473** | **1,419** |

The v2 partition files live in `data/partitions_v2/`. The authoritative experimental manifest is `data/partitions_v2/frozen_partition_manifest_v2.csv`.

v1 partition files in `data/partitions/` are retained only for audit history and must not be used as the final experimental split.

## Final Holdout Protection

The Final Holdout is used only after the complete pipeline is frozen. It must never be used for:

- feature selection
- feature ablation decisions
- Normal-rule threshold tuning
- class/window balancing decisions
- hyperparameter tuning
- Stage 1 threshold selection
- model selection

## Frozen Experimental Components

| Component | Status |
|---|---|
| Incident Roster v2 | FROZEN |
| Incident partitions v2 | FROZEN |
| Behavioral feature schema v1 | 44 features, FROZEN |
| CAIDA AS-relationship schema | 14 features, FROZEN |
| Historical RPKI/ROV schema | 16 features, FROZEN |
| Final V4 schema | 74 features, FROZEN |
| Normal ground-truth methodology v1 | FROZEN |
| Normal development corpus v1 | 516 verified windows, FROZEN_FOR_DEVELOPMENT |
| TRAIN grouped/nested evaluation | COMPLETE |
| Validation confirmation | COMPLETE |
| Final Holdout evaluation | COMPLETE, TERMINAL |

Normal methodology v1 and the Normal development corpus are documented in `config/normal_ground_truth_method_v1.yaml`, `docs/normal_ground_truth_methodology_v1.md`, and `data/normal_frozen/`.

`NORMAL_VERIFIED` maps to `NORMAL` for supervised Stage 1 training. `Hijack`, `Leak`, and `Outage` map to `INCIDENT`. `UNKNOWN` windows are excluded from supervised training.

The completed V4 representation contains 44 Behavioral, 14 historical CAIDA, and 16 historical RPKI/ROV features. The final incident-level Holdout results are Macro F1 `0.920177`, Top-1 `0.920188`, Top-2 `0.990610`, and MRR `0.958529`. These terminal results are immutable; the repository's later audits and sensitivity analyses are additive and do not replace them.

## Window Cap Status

No fixed `max_windows_per_incident` is defined yet. The window cap will be determined later from the observed duration and 5-minute window-count distribution after the incident roster is frozen and before model training.

## Pre-MRT Incident Integrity Audit

Incident partitions are frozen before feature generation, then audited for duplicate-event risk, timestamp integrity, ASN/prefix overlap, and partition diversity before raw BGP data collection.

The audit is diagnostic only:

- Do not re-split the data.
- Do not automatically remove incidents.
- Do not change labels.
- Do not download MRT data yet.
- Do not create Normal labels yet.
- Do not introduce a window cap.
- Treat ASN/prefix overlap as a diagnostic, not automatically as leakage.
- Treat the real-world incident as the independent experimental unit.

The current pre-MRT audit status is `REVIEW`: the frozen partition mechanics pass, but possible duplicate-event pairs, extreme-duration events, and completeness diagnostics should be reviewed before MRT acquisition.

## Important Files

| File | Purpose |
|---|---|
| `cloudflare_incidents/TRAINING_READY_INCIDENT_SCHEMA.md` | Canonical normalized schema and mapping rules |
| `data/roster_v2/frozen_incident_roster_v2.csv` | Authoritative frozen Roster v2 incident corpus |
| `data/partitions_v2/frozen_partition_manifest_v2.csv` | Authoritative v2 incident-level train/validation/holdout assignment |
| `data/partitions_v2/partition_v2_quality_audit.csv` | PASS / REVIEW / FAIL audit for v2 partition mechanics and secondary balance |
| `data/partitions_v2/partition_v2_distribution_summary.csv` | Duration, year, ASN/network, and country summaries by partition |
| `cloudflare_incidents/balanced_incident_level_roster_473_each_leak_hijack_outage.csv` | v1 balanced roster retained for audit history |
| `cloudflare_incidents/stratified_quality_leak_sample_473.csv` | Leak sample |
| `cloudflare_incidents/stratified_quality_hijack_sample_473.csv` | Hijack sample |
| `cloudflare_incidents/clean_cloudflare_outage_recommended_final_pool_all_asns.csv` | Outage pool with ASN lists |
| `cloudflare_incidents/stratified_quality_sampling_summary.csv` | Sampling summary |
| `cloudflare_incidents/clean_cloudflare_outage_asn_summary.csv` | Outage ASN completeness summary |
| `cloudflare_incidents/timed_external_bgp_route_leak_label_candidates.csv` | External timed leak-label candidates used for spot validation |
| `data/partitions/frozen_partition_manifest.csv` | Frozen incident-level train/validation/holdout assignment |
| `notebooks/02_incident_partitioning.ipynb` | Reproducible incident partitioning notebook |
| `notebooks/03_partition_integrity_and_roster_audit.ipynb` | Pre-MRT partition integrity and roster audit notebook |
| `notebooks/05_freeze_roster_v2_and_partition.ipynb` | Freeze Roster v2 and create the final v2 incident-level partitions |
| `data/partitions/partition_integrity_audit_v1.csv` | PASS / REVIEW / FAIL audit summary |
| `data/partitions/incident_quality_audit_v1.csv` | One-row-per-incident quality audit |
| `data/partitions/possible_duplicate_incidents.csv` | Possible real-world duplicate-event pairs for manual review |

## Rebuild Scripts

| Script | Purpose |
|---|---|
| `cloudflare_incidents/fetch_cloudflare_all_incidents_to_2026_01.mjs` | Fetch all available Cloudflare incidents up to 2026-02-01 |
| `cloudflare_incidents/build_training_ready_all_cloudflare_roster.mjs` | Normalize full unsampled Cloudflare dump |
| `cloudflare_incidents/build_clean_outage_asn_roster.mjs` | Deduplicate and QC outage records with ASN completeness |
| `cloudflare_incidents/build_quality_controlled_outage_roster.mjs` | Build the initial outage QC roster |
| `cloudflare_incidents/build_stratified_quality_leak_hijack_samples.mjs` | Build stratified leak/hijack samples and combined balanced roster |
| `src/bgp_incident_detection/partitioning.py` | Validate and freeze incident-level partitions |
| `src/bgp_incident_detection/partitioning_v2.py` | Freeze Roster v2 and create the final v2 incident-level partitions |
| `src/bgp_incident_detection/audit.py` | Audit frozen partitions before MRT acquisition |

## Final Project Status

The Praxis experiment, reproducibility audits, TRAIN-only early-classification analyses, post-hoc sensitivity analyses, and publication figures are complete. Raw RouteViews archives, generated feature matrices, and oversized serialized development models remain local and are intentionally excluded from Git; compact provenance manifests, schemas, code, checksums, and result summaries are versioned here.
