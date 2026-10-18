# Corpus Partition Trace v1

The authoritative v2 split is `data/partitions_v2/frozen_partition_manifest_v2.csv` with SHA-256 `e459ffb1b3c66fe8151e66688bc9eca09ca6b19427108ef164e872cefb5d9aaf`.

The split uses `random_seed = 20260828`, `roster_version = v2`, and `split_version = v2`.

## Counts

| partition  | Hijack | Leak | Outage | total |
| ---------- | ------ | ---- | ------ | ----- |
| holdout    | 71     | 71   | 71     | 213   |
| train      | 331    | 331  | 331    | 993   |
| validation | 71     | 71   | 71     | 213   |

## Quality Audit

| check_name                    | result | count  | status | interpretation                                                                            | action_required |
| ----------------------------- | ------ | ------ | ------ | ----------------------------------------------------------------------------------------- | --------------- |
| total_incident_count          | PASS   | 1419.0 | PASS   | exactly 1,419 incidents required                                                          | none            |
| class_balance                 | PASS   | 473.0  | PASS   | 473 incidents per class                                                                   | none            |
| partition_counts              | PASS   | 1419.0 | PASS   | {"holdout": 213, "train": 993, "validation": 213}                                         | none            |
| partition_class_counts        | PASS   | 0.0    | PASS   | 331/71/71 per class satisfied                                                             | none            |
| cross_partition_overlap       | PASS   | 0.0    | PASS   | {"TRAIN \u2229 HOLDOUT": 0, "TRAIN \u2229 VALIDATION": 0, "VALIDATION \u2229 HOLDOUT": 0} | none            |
| incident_uid_once             | PASS   | 1419.0 | PASS   | every incident appears exactly once                                                       | none            |
| duration_distribution_balance | PASS   | 1.264  | PASS   | secondary check only; do not re-split unless class counts fail                            | none            |
| final_holdout_protection      | PASS   | 1.0    | PASS   | holdout reserved until complete pipeline is frozen                                        | none            |

## Distribution Summary

| partition  | incident_count | class_counts                                | duration_min | duration_median | duration_mean | duration_p90 | duration_max | year_distribution                                                | asn_network_diversity | country_diversity |
| ---------- | -------------- | ------------------------------------------- | ------------ | --------------- | ------------- | ------------ | ------------ | ---------------------------------------------------------------- | --------------------- | ----------------- |
| train      | 993            | {"Hijack": 331, "Leak": 331, "Outage": 331} | 1.0          | 900.0           | 4859.25       | 10422.4      | 119968.0     | {"2022": 31, "2023": 153, "2024": 271, "2025": 405, "2026": 133} | 1823                  | 205               |
| validation | 213            | {"Hijack": 71, "Leak": 71, "Outage": 71}    | 3.0          | 807.0           | 6235.86       | 16600.6      | 119500.0     | {"2022": 6, "2023": 26, "2024": 71, "2025": 92, "2026": 18}      | 1011                  | 140               |
| holdout    | 213            | {"Hijack": 71, "Leak": 71, "Outage": 71}    | 1.0          | 1020.0          | 6945.46       | 17662.8      | 161656.0     | {"2022": 8, "2023": 26, "2024": 53, "2025": 92, "2026": 34}      | 1055                  | 147               |

This partitioning is distinct from both initial class balancing and later I1 model-time incident-aware weighting.
