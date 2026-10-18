| Verification item          | Result                                         | Status                   | Source artifact                                                                         |
| -------------------------- | ---------------------------------------------- | ------------------------ | --------------------------------------------------------------------------------------- |
| Partition counts           | 993 TRAIN / 213 Validation / 213 Final Holdout | PASS                     | data/partitions_v2/frozen_partition_manifest_v2.csv                                     |
| Exact incident UID overlap | 0                                              | PASS                     | data/partitions_v2/frozen_partition_manifest_v2.csv                                     |
| Potential duplicate events | 0                                              | PASS                     | experiments/partition_independence_audit_v1/partition_near_duplicate_events_v1.csv      |
| Confirmed duplicate events | 0                                              | PASS                     | experiments/partition_independence_audit_v1/partition_near_duplicate_events_v1.csv      |
| Prefix/ASN recurrence      | Observed and documented                        | EXPECTED_CONTEXT_OVERLAP | experiments/partition_independence_audit_v1/partition_prefix_overlap_v1.csv             |
| CAIDA/RPKI context reuse   | Observed and expected                          | PASS                     | experiments/partition_independence_audit_v1/partition_enrichment_context_overlap_v1.csv |
