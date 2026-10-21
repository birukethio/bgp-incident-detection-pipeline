# CAIDA AS Relationship Feature Reproducibility v1

## Feature Set

The frozen V4 schema contains 14 CAIDA AS-relationship features, documented in `config/caida_feature_schema_v1.yaml`.

## Historical Alignment

CAIDA relationship data are selected as historical context for the observation period. Features are computed from observed AS_PATH transitions and valley-free relationship checks; source/provider identifiers are not included as model features.

## Definitions

| family_order | feature_name | definition | formula |
| --- | --- | --- | --- |
| 1 | caida_path_observation_count | Number of parsed pilot observations with an AS_PATH containing at least two ASNs. | count(len(cleaned_as_path) >= 2) |
| 2 | caida_paths_with_no_as_path_count | Parsed observations without an evaluable AS_PATH. | count(len(cleaned_as_path) < 2) |
| 3 | caida_paths_with_unknown_relationship_count | AS paths containing at least one adjacent AS pair absent from the selected CAIDA snapshot. | count(path_unknown_transition_count > 0) |
| 4 | caida_unknown_relationship_transition_count | Adjacent AS transitions absent from the selected CAIDA snapshot. | sum(relationship == unknown) |
| 5 | caida_customer_to_provider_transition_count | Known customer-to-provider transitions in observed AS paths. | sum(relationship == c2p) |
| 6 | caida_provider_to_customer_transition_count | Known provider-to-customer transitions in observed AS paths. | sum(relationship == p2c) |
| 7 | caida_peer_to_peer_transition_count | Known peer-to-peer transitions in observed AS paths. | sum(relationship == p2p) |
| 8 | caida_valley_free_valid_path_count | Paths with known relationships and no valley-free violation. | count(unknowns == 0 and violations == 0) |
| 9 | caida_valley_free_violation_path_count | Paths with known relationships and at least one valley-free violation. | count(unknowns == 0 and violations > 0) |
| 10 | caida_valley_free_violation_ratio | Share of evaluable AS paths with a valley-free violation. | violation_path_count / path_observation_count |
| 11 | caida_max_violation_count_per_path | Maximum valley-free violation count on any observed path. | max(path_violation_count) |
| 12 | caida_mean_violation_count_per_path | Mean valley-free violation count across observed paths. | mean(path_violation_count) |
| 13 | caida_customer_provider_transition_ratio | Share of known transitions that are customer/provider links. | (c2p+p2c)/(c2p+p2c+p2p) |
| 14 | caida_peer_transition_ratio | Share of known transitions that are peer-to-peer links. | p2p/(c2p+p2c+p2p) |
