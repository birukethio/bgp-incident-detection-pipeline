# Corpus Balancing Reproducibility v1

## Disposition

`REPRODUCIBLE_WITH_DOCUMENTED_GAPS`

## What Is Fully Reproducible

- Frozen v2 roster: `data/roster_v2/frozen_incident_roster_v2.csv` with SHA-256 `1d596b2da403fb075dc9536e6e0fc995c717b1de82e1db15e337c66999d5af83`.
- Frozen v2 partition manifest: `data/partitions_v2/frozen_partition_manifest_v2.csv` with SHA-256 `e459ffb1b3c66fe8151e66688bc9eca09ca6b19427108ef164e872cefb5d9aaf`.
- Final class counts: 473 Hijack / 473 Leak / 473 Outage.
- v2 duplicate remediation: `data/roster_v2/duplicate_canonicalization_plan.csv` and `data/roster_v2/replacement_incidents.csv`.
- I1 incident-aware weighting formula: `1 / number_of_windows_for_incident_or_model_group`, computed inside training folds only.
- Natural-prior sensitivity is documented separately in `experiments/natural_distribution_v1/natural_distribution_accounting_v1.csv` and does not redefine the balanced corpus.

## Documented Gaps

- Full-universe Hijack/Leak deduplication before the initial v1 473 selection was not found.
- The original executable quality-stratified sampling script for the first 473 Hijack/Leak selection was not uniquely recovered, though the selected rows, strata, quality scores, rank fields, and summary method are preserved.
- Cloudflare source label provenance is preserved, but the study's collected-corpus distribution should not be described as global Internet-wide incident prevalence.
