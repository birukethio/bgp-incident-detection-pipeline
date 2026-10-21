# Extended TTI Horizon Feasibility Audit v1

Scope: read-only feasibility audit for adding cumulative 600-second and 900-second retrospective early-classification horizons. No model predictions were generated or regenerated; no model was retrained, tuned, calibrated, or modified; Final Holdout was not accessed.

## Evidence Coverage Result

| scope      | category   |   horizon_seconds |   evaluable_incidents |   covered_incidents |   covered_percent |   lacking_incidents |
|:-----------|:-----------|------------------:|----------------------:|--------------------:|------------------:|--------------------:|
| TRAIN      | ALL        |               600 |                   983 |                 973 |             98.98 |                  10 |
| TRAIN      | Hijack     |               600 |                   327 |                 325 |             99.39 |                   2 |
| TRAIN      | Leak       |               600 |                   329 |                 326 |             99.09 |                   3 |
| TRAIN      | Outage     |               600 |                   327 |                 322 |             98.47 |                   5 |
| TRAIN      | ALL        |               900 |                   983 |                 972 |             98.88 |                  11 |
| TRAIN      | Hijack     |               900 |                   327 |                 325 |             99.39 |                   2 |
| TRAIN      | Leak       |               900 |                   329 |                 326 |             99.09 |                   3 |
| TRAIN      | Outage     |               900 |                   327 |                 321 |             98.17 |                   6 |
| Validation | ALL        |               600 |                   212 |                 212 |            100    |                   0 |
| Validation | Hijack     |               600 |                    70 |                  70 |            100    |                   0 |
| Validation | Leak       |               600 |                    71 |                  71 |            100    |                   0 |
| Validation | Outage     |               600 |                    71 |                  71 |            100    |                   0 |
| Validation | ALL        |               900 |                   212 |                 212 |            100    |                   0 |
| Validation | Hijack     |               900 |                    70 |                  70 |            100    |                   0 |
| Validation | Leak       |               900 |                    71 |                  71 |            100    |                   0 |
| Validation | Outage     |               900 |                    71 |                  71 |            100    |                   0 |

## Interpretation

- TRAIN TTI-evaluable cohort: 983 incidents.
- TRAIN coverage through 600s: 973/983 (98.98%).
- TRAIN coverage through 900s: 972/983 (98.88%).
- Validation TTI-evaluable cohort: 212 incidents.
- Validation coverage through 600s: 212/212 (100.00%).
- Validation coverage through 900s: 212/212 (100.00%).

Coverage is sufficient for a cohort-level extension in both TRAIN and Validation. A small number of incidents do not have enough retained post-onset evidence through 600s and/or 900s; those incidents would require a predeclared handling rule before any extension is executed, such as excluding only the unavailable horizon for that incident or marking the horizon as not evaluable. The current audit does not choose or apply that rule.

## Feature and Model Compatibility

- 44 Behavioral features: technically reusable unchanged. The existing feature builder aggregates all observations up to a supplied cutoff; 600s and 900s are longer cumulative cutoffs using the same timestamp-preserving evidence.
- 14 CAIDA AS-relationship features: technically reusable unchanged. They are derived from AS paths observable by the horizon cutoff and historical CAIDA snapshot selection; no future incident outcome is required.
- 16 RPKI/ROV features: technically reusable unchanged. They depend on prefix-origin observations available by the horizon cutoff and historical VRP snapshot mapping/fallback behavior.
- Frozen V4 schema: structurally compatible. Adding horizons creates additional rows with the same 74 columns; it does not require changing feature names, ordering, or datatypes.
- Verified Level-1 ensemble: technically compatible with 600s and 900s V4 rows because it consumes the same 74-feature schema. This audit did not score those rows.

## Runtime and Storage Estimate

- No MRT download or reparse should be required if the extension uses the existing timestamped evidence stores.
- Additional TRAIN horizon rows if executed for all evaluable TRAIN incidents: 1966. Estimated additional V4 Parquet size: ~0.43 MiB.
- Additional Validation horizon rows if executed for all evaluable Validation incidents: 424. Estimated additional V4 Parquet size: ~0.13 MiB.
- Expected runtime is dominated by CAIDA/RPKI enrichment and feature aggregation from existing evidence, not by RouteViews parsing. Based on the completed v2.1 TRAIN and Validation horizon construction, adding two horizons would likely be materially cheaper than full reconstruction, but still non-trivial because RPKI validation must aggregate additional horizon-level prefix-origin evidence.
- Rough order-of-magnitude runtime if implemented with the existing optimized RPKI path: TRAIN hours-scale but less than the original full 4-horizon construction; Validation tens-of-minutes scale or less. Exact runtime should be measured only if the extension is approved.

## Files

- Coverage CSV: `data/tti_extended_horizon_feasibility_v1/tti_extended_horizon_coverage_v1.csv`
- Methodology risk memo: `data/tti_extended_horizon_feasibility_v1/tti_extended_horizon_methodology_risk_v1.md`

Technical feasibility disposition: `EXTENDED_HORIZONS_FEASIBLE`.
