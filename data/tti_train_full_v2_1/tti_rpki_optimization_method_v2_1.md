# TTI RPKI Optimization Method v2.1

This correction changes computation order only. It does not change the frozen 16 RPKI/ROV feature definitions, validation-state semantics, historical TRAIN snapshot mapping, onset rule, horizons, or V4 schema.

Optimized flow:

1. Read only timestamp, prefix, and origin ASN evidence needed for the 30/60/120/300-second horizons.
2. Collapse repeated observations to horizon-level prefix-origin counts.
3. Map each observation horizon to the exact historical TRAIN RPKI snapshot/fallback date using `data/enrichment/rpki/train_rpki_snapshot_mapping_v1.csv`.
4. Validate each unique `(snapshot_date, prefix, origin_asn)` once.
5. Aggregate validation states back to the 16 frozen RPKI/ROV features with observation-count multiplicity preserved.

- 9-incident pilot equivalence against prior validated v2 RPKI output: PASS
- full TRAIN horizon RPKI rows: 3932
- elapsed seconds at doc write: 4725.576
