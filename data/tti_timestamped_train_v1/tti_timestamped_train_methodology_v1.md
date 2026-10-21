# TTI Timestamped TRAIN Evidence Methodology v1

Purpose: reconstruct timestamp-preserving incident-relevant RouteViews evidence for the complete 993-incident TRAIN partition.

Scope limits: TRAIN only; no Validation or Final Holdout access; no model scoring; no model retraining; no modification of the primary five-minute evidence store.

The reconstruction reuses the existing TRAIN acquisition plan, RouteViews collector/url handling, `bgpdump -q -m` parser logic, and incident relevance predicates from the original behavioral feature pipeline. Unlike the compact enrichment evidence store, this layer preserves `bgp_timestamp_utc` at observation grain so later 30/60/120/300-second horizon construction can assert no future observations were used.

Output grain: one row per retained incident-relevant BGP observation. Files are partitioned by incident as Parquet under `data/tti_timestamped_train_v1/evidence/`.
