# Partition and Final Holdout Independence Forensic Audit v1

## Scope

This audit is additive and forensic only. It did not retrain models, repartition incidents, recompute predictions, alter the frozen roster, modify features, or change any official result.

## Source Artifacts

- Frozen roster: `data/roster_v2/frozen_incident_roster_v2.csv`; SHA-256 `1d596b2da403fb075dc9536e6e0fc995c717b1de82e1db15e337c66999d5af83`
- Frozen v2 partition manifest: `data/partitions_v2/frozen_partition_manifest_v2.csv`; SHA-256 `e459ffb1b3c66fe8151e66688bc9eca09ca6b19427108ef164e872cefb5d9aaf`
- Duplicate lineage: `data/review/duplicate_resolution_recommendations.csv` and `data/roster_v2/duplicate_canonicalization_plan.csv`
- Corpus-balancing audit linkage: `experiments/corpus_balancing_audit_v1/corpus_balancing_audit_summary_v1.md` if present

## Partition Counts

| partition  | Hijack | Leak | Outage | total |
| ---------- | ------ | ---- | ------ | ----- |
| holdout    | 71     | 71   | 71     | 213   |
| train      | 331    | 331  | 331    | 993   |
| validation | 71     | 71   | 71     | 213   |

## Partition Independence Summary

| Comparison         | Exact incident overlap | Potential duplicate events | Confirmed duplicate events | Shared prefixes | Shared ASNs | Close-time related events | Final assessment                    |
| ------------------ | ---------------------- | -------------------------- | -------------------------- | --------------- | ----------- | ------------------------- | ----------------------------------- |
| train↔validation   | 0                      | 0                          | 0                          | 567             | 347         | 8                         | PASS_WITH_DOCUMENTED_RELATED_EVENTS |
| train↔holdout      | 0                      | 0                          | 0                          | 625             | 369         | 9                         | PASS_WITH_DOCUMENTED_RELATED_EVENTS |
| validation↔holdout | 0                      | 0                          | 0                          | 163             | 190         | 1                         | PASS_WITH_DOCUMENTED_RELATED_EVENTS |

## Exact Identity Result

Exact incident UID overlap across TRAIN/Validation/Holdout comparisons: `0`.

## Final Holdout Independence Summary

- Holdout incidents: `213`
- Exact duplicates with TRAIN or Validation: `0`
- Potential duplicate events involving any partition comparison: `0`
- Potential related/review-required pairs: `790`
- Holdout CLEAR cases: `30`
- Holdout EXPECTED_CONTEXT_OVERLAP cases: `134`
- Holdout POTENTIAL_RELATED_EVENT cases: `38`
- Holdout POTENTIAL_DUPLICATE_EVENT cases: `0`
- Holdout REVIEW_REQUIRED cases: `11`

## Interpretation Boundary

Repeated ASNs, prefixes, RouteViews collectors, archive dates, CAIDA snapshots, and RPKI snapshots were explicitly treated as shared Internet routing context. These forms of recurrence are expected and do not by themselves constitute incident leakage.

## Final Disposition

`PASS_WITH_DOCUMENTED_RELATED_EVENTS`
