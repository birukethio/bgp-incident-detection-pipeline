# Figure 4.1 title and caption

**Title:** Figure 4.1. Final Corpus, Partitions, and V4 Feature Composition

**Caption:** The final balanced corpus contained 1,419 independent incidents, comprising 473 Hijack, 473 Leak, and 473 Outage incidents. Incident-level partitioning assigned 993 incidents to TRAIN and 213 incidents each to Validation and Final Holdout, while preserving exact class balance within every partition. The frozen V4 representation contained 74 features: 44 Behavioral BGP features, 14 CAIDA AS-relationship features, and 16 historical RPKI/ROV features. No incident identifier crossed partition boundaries, and all subsequently generated windows inherited the partition of their parent incident.

**Suggested insertion:** Place at the beginning of the Chapter 4 results section, immediately after the corpus and experimental-partition summary and before model-comparison results.

**Source values:** `data/partitions_v2/frozen_partition_manifest_v2.csv`, `config/behavioral_feature_schema_v1.yaml`, `config/caida_feature_schema_v1.yaml`, `config/rpki_feature_schema_v1.yaml`, and `config/feature_variants_v1.yaml`.
