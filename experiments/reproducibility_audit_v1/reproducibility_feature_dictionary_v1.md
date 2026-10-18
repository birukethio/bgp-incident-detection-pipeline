# Complete Frozen V4 Feature Dictionary v1

## Scope

This appendix dictionary documents the frozen V4 74-feature representation used by the final Praxis model. It is assembled from the frozen behavioral, CAIDA, and RPKI schema files and does not redefine any feature.

## Feature Inventory

| global_order | feature_name | feature_family | definition | formula | missing_or_zero_behavior |
| --- | --- | --- | --- | --- | --- |
| 1 | update_count | Behavioral | Incident-relevant prefix-level UPDATE observations in the window. | announcements + withdrawals | 0 |
| 2 | announcement_count | Behavioral | Incident-relevant announcement observations. | count(type == announcement) | 0 |
| 3 | withdrawal_count | Behavioral | Incident-relevant withdrawal observations. | count(type == withdrawal) | 0 |
| 4 | update_rate_per_minute | Behavioral | Incident-relevant UPDATE observation rate. | update_count / 5 | 0 |
| 5 | announcement_rate_per_minute | Behavioral | Announcement observation rate. | announcement_count / 5 | 0 |
| 6 | withdrawal_rate_per_minute | Behavioral | Withdrawal observation rate. | withdrawal_count / 5 | 0 |
| 7 | announcement_ratio | Behavioral | Share of relevant observations that are announcements. | announcement_count / update_count | NaN when update_count=0 |
| 8 | withdrawal_ratio | Behavioral | Share of relevant observations that are withdrawals. | withdrawal_count / update_count | NaN when update_count=0 |
| 9 | announcement_to_withdrawal_ratio | Behavioral | Announcement-to-withdrawal balance. | announcement_count / withdrawal_count | NaN when withdrawal_count=0 |
| 10 | unique_prefix_count | Behavioral | Distinct prefixes among incident-relevant observations. | count_distinct(prefix) | 0 |
| 11 | unique_announced_prefix_count | Behavioral | Distinct prefixes announced in relevant observations. | count_distinct(prefix where type=announcement) | 0 |
| 12 | unique_withdrawn_prefix_count | Behavioral | Distinct prefixes withdrawn in relevant observations. | count_distinct(prefix where type=withdrawal) | 0 |
| 13 | prefix_churn_count | Behavioral | Total distinct announced and withdrawn prefix activity. | unique_announced_prefix_count + unique_withdrawn_prefix_count | 0 |
| 14 | prefix_with_both_announce_withdraw_count | Behavioral | Prefixes both announced and withdrawn in the same window. | count(prefix in announced_prefixes intersect withdrawn_prefixes) | 0 |
| 15 | unique_peer_asn_count | Behavioral | Distinct RouteViews peer ASNs seeing relevant observations. | count_distinct(peer_asn) | 0 |
| 16 | unique_origin_asn_count | Behavioral | Distinct origin ASNs in relevant announcements. | count_distinct(origin_asn) | 0 |
| 17 | origin_diversity_ratio | Behavioral | Origin diversity normalized by prefix count. | unique_origin_asn_count / unique_prefix_count | NaN when unique_prefix_count=0 |
| 18 | moas_prefix_count | Behavioral | Prefixes with more than one observed origin ASN in the window. | count(prefix where distinct origins > 1) | 0 |
| 19 | moas_prefix_ratio | Behavioral | Share of prefixes with multiple origins. | moas_prefix_count / unique_prefix_count | NaN when unique_prefix_count=0 |
| 20 | origin_change_event_count | Behavioral | Additional origin alternatives beyond one per prefix. | sum(max(0, origin_count_per_prefix - 1)) | 0 |
| 21 | unique_as_path_count | Behavioral | Distinct AS_PATH strings in relevant announcements. | count_distinct(as_path) | 0 |
| 22 | as_path_length_min | Behavioral | Minimum AS_PATH length. | min(len(as_path)) | NaN when no AS_PATH exists |
| 23 | as_path_length_max | Behavioral | Maximum AS_PATH length. | max(len(as_path)) | NaN when no AS_PATH exists |
| 24 | as_path_length_mean | Behavioral | Mean AS_PATH length. | mean(len(as_path)) | NaN when no AS_PATH exists |
| 25 | as_path_length_median | Behavioral | Median AS_PATH length. | median(len(as_path)) | NaN when no AS_PATH exists |
| 26 | as_path_length_std | Behavioral | Population standard deviation of AS_PATH length. | pstdev(len(as_path)) | NaN when no AS_PATH exists |
| 27 | as_path_length_p95 | Behavioral | 95th percentile AS_PATH length. | percentile_95(len(as_path)) | NaN when no AS_PATH exists |
| 28 | as_path_length_range | Behavioral | Range of AS_PATH lengths. | max(len(as_path)) - min(len(as_path)) | NaN when no AS_PATH exists |
| 29 | path_prepending_observation_count | Behavioral | Relevant announcements whose AS_PATH contains repeated ASNs. | count(path where len(path) > len(unique(path))) | 0 |
| 30 | path_prepending_ratio | Behavioral | Share of relevant announcements with path prepending. | path_prepending_observation_count / announcement_count | NaN when announcement_count=0 |
| 31 | prepended_asn_repetition_count | Behavioral | Total repeated ASN positions beyond unique ASNs across paths. | sum(len(path) - len(unique(path))) | 0 |
| 32 | multi_path_prefix_count | Behavioral | Prefixes with more than one observed AS_PATH. | count(prefix where distinct AS_PATHs > 1) | 0 |
| 33 | path_diversity_mean_per_prefix | Behavioral | Average number of distinct AS_PATHs per prefix. | mean(distinct_as_paths_per_prefix) | NaN when no prefix/path exists |
| 34 | peer_prefix_pair_count | Behavioral | Distinct peer ASN and prefix pairs. | count_distinct(peer_asn, prefix) | 0 |
| 35 | peer_origin_pair_count | Behavioral | Distinct peer ASN and origin ASN pairs. | count_distinct(peer_asn, origin_asn) | 0 |
| 36 | peer_as_path_pair_count | Behavioral | Distinct peer ASN and AS_PATH pairs. | count_distinct(peer_asn, as_path) | 0 |
| 37 | unique_next_hop_count | Behavioral | Distinct NEXT_HOP values in relevant announcements. | count_distinct(next_hop) | 0 |
| 38 | community_observation_count | Behavioral | Relevant observations carrying at least one BGP community value. | count(communities not empty) | 0 |
| 39 | community_observation_ratio | Behavioral | Share of relevant observations carrying communities. | community_observation_count / update_count | NaN when update_count=0 |
| 40 | unique_community_count | Behavioral | Distinct BGP community tokens observed. | count_distinct(split(communities)) | 0 |
| 41 | med_observation_count | Behavioral | Relevant announcements with MED populated. | count(med not empty) | 0 |
| 42 | unique_med_count | Behavioral | Distinct MED values observed. | count_distinct(med) | 0 |
| 43 | local_pref_observation_count | Behavioral | Relevant announcements with LOCAL_PREF populated by parser. | count(local_pref not empty) | 0 |
| 44 | atomic_aggregate_count | Behavioral | Relevant announcements carrying an atomic aggregate marker other than NAG/empty. | count(atomic_aggregate not empty and != NAG) | 0 |
| 45 | caida_path_observation_count | CAIDA AS-relationship | Number of parsed pilot observations with an AS_PATH containing at least two ASNs. | count(len(cleaned_as_path) >= 2) | zero: 0; missing: 0 when no AS_PATH observations |
| 46 | caida_paths_with_no_as_path_count | CAIDA AS-relationship | Parsed observations without an evaluable AS_PATH. | count(len(cleaned_as_path) < 2) | zero: 0; missing: separate from unknown CAIDA relationships |
| 47 | caida_paths_with_unknown_relationship_count | CAIDA AS-relationship | AS paths containing at least one adjacent AS pair absent from the selected CAIDA snapshot. | count(path_unknown_transition_count > 0) | zero: 0; missing: explicit unknown-relationship state |
| 48 | caida_unknown_relationship_transition_count | CAIDA AS-relationship | Adjacent AS transitions absent from the selected CAIDA snapshot. | sum(relationship == unknown) | zero: 0; missing: explicit unknown-relationship state |
| 49 | caida_customer_to_provider_transition_count | CAIDA AS-relationship | Known customer-to-provider transitions in observed AS paths. | sum(relationship == c2p) | zero: 0; missing: 0 if no known c2p transitions |
| 50 | caida_provider_to_customer_transition_count | CAIDA AS-relationship | Known provider-to-customer transitions in observed AS paths. | sum(relationship == p2c) | zero: 0; missing: 0 if no known p2c transitions |
| 51 | caida_peer_to_peer_transition_count | CAIDA AS-relationship | Known peer-to-peer transitions in observed AS paths. | sum(relationship == p2p) | zero: 0; missing: 0 if no known p2p transitions |
| 52 | caida_valley_free_valid_path_count | CAIDA AS-relationship | Paths with known relationships and no valley-free violation. | count(unknowns == 0 and violations == 0) | zero: 0; missing: unknown paths not counted valid |
| 53 | caida_valley_free_violation_path_count | CAIDA AS-relationship | Paths with known relationships and at least one valley-free violation. | count(unknowns == 0 and violations > 0) | zero: 0; missing: unknown paths not counted violation |
| 54 | caida_valley_free_violation_ratio | CAIDA AS-relationship | Share of evaluable AS paths with a valley-free violation. | violation_path_count / path_observation_count | zero: NaN if denominator is zero; missing: NaN when no AS_PATH observations |
| 55 | caida_max_violation_count_per_path | CAIDA AS-relationship | Maximum valley-free violation count on any observed path. | max(path_violation_count) | zero: NaN if no AS paths; missing: NaN when no AS_PATH observations |
| 56 | caida_mean_violation_count_per_path | CAIDA AS-relationship | Mean valley-free violation count across observed paths. | mean(path_violation_count) | zero: NaN if no AS paths; missing: NaN when no AS_PATH observations |
| 57 | caida_customer_provider_transition_ratio | CAIDA AS-relationship | Share of known transitions that are customer/provider links. | (c2p+p2c)/(c2p+p2c+p2p) | zero: NaN if no known transitions; missing: NaN when no known CAIDA transitions |
| 58 | caida_peer_transition_ratio | CAIDA AS-relationship | Share of known transitions that are peer-to-peer links. | p2p/(c2p+p2c+p2p) | zero: NaN if no known transitions; missing: NaN when no known CAIDA transitions |
| 59 | rpki_evidence_observation_count | RPKI/ROV | Underlying incident-relevant BGP observations represented by compact evidence rows. | sum(observation_count) | zero: 0 when no evidence; missing: 0 means no prefix/origin evidence in the window |
| 60 | rpki_evaluable_observation_count | RPKI/ROV | Observation-weighted count with parseable prefix and origin ASN. | valid+invalid+not_found | zero: 0 when no evaluable evidence; missing: not equivalent to VALID |
| 61 | rpki_valid_observation_count | RPKI/ROV | Observation-weighted count classified VALID. | sum(observation_count where state=VALID) | zero: 0 if no VALID observations; missing: 0 can mean no evidence or all non-VALID; use denominator features |
| 62 | rpki_invalid_observation_count | RPKI/ROV | Observation-weighted count classified INVALID. | INVALID_ORIGIN + INVALID_LENGTH | zero: 0 if no INVALID observations; missing: 0 is meaningful only with evaluable denominator |
| 63 | rpki_not_found_observation_count | RPKI/ROV | Observation-weighted count with no covering VRP. | sum(observation_count where state=NOT_FOUND) | zero: 0 if no NOT_FOUND observations; missing: NOT_FOUND is not VALID |
| 64 | rpki_unevaluable_observation_count | RPKI/ROV | Observation-weighted count with missing/malformed prefix or origin. | sum(observation_count where state=UNEVALUABLE) | zero: 0 if all evidence evaluable; missing: separate from NOT_FOUND |
| 65 | rpki_invalid_origin_observation_count | RPKI/ROV | Observation-weighted INVALID caused by origin mismatch. | sum(observation_count where state=INVALID_ORIGIN) | zero: 0 if no origin mismatch invalids; missing: separate from maxLength violation |
| 66 | rpki_invalid_maxlength_observation_count | RPKI/ROV | Observation-weighted INVALID caused by maxLength violation. | sum(observation_count where state=INVALID_LENGTH) | zero: 0 if no maxLength invalids; missing: separate from origin mismatch |
| 67 | rpki_valid_observation_ratio | RPKI/ROV | Share of evaluable observations classified VALID. | valid/evaluable | zero: NaN if denominator zero; missing: NaN when no evaluable evidence |
| 68 | rpki_invalid_observation_ratio | RPKI/ROV | Share of evaluable observations classified INVALID. | invalid/evaluable | zero: NaN if denominator zero; missing: NaN when no evaluable evidence |
| 69 | rpki_not_found_observation_ratio | RPKI/ROV | Share of evaluable observations classified NOT_FOUND. | not_found/evaluable | zero: NaN if denominator zero; missing: NaN when no evaluable evidence |
| 70 | rpki_unique_valid_prefix_count | RPKI/ROV | Unique prefixes with at least one VALID observation. | nunique(prefix where state=VALID) | zero: 0 if none; missing: prefix-unique, not observation-weighted |
| 71 | rpki_unique_invalid_prefix_count | RPKI/ROV | Unique prefixes with at least one INVALID observation. | nunique(prefix where state starts INVALID) | zero: 0 if none; missing: prefix-unique, not observation-weighted |
| 72 | rpki_unique_not_found_prefix_count | RPKI/ROV | Unique prefixes with at least one NOT_FOUND observation. | nunique(prefix where state=NOT_FOUND) | zero: 0 if none; missing: prefix-unique, not observation-weighted |
| 73 | rpki_state_diversity_count | RPKI/ROV | Number of distinct RPKI states seen in the window. | count distinct VALID/INVALID_ORIGIN/INVALID_LENGTH/NOT_FOUND/UNEVALUABLE with count > 0 | zero: 0 if no evidence; missing: captures mixed state windows |
| 74 | rpki_dominant_state_code | RPKI/ROV | Numeric code for the most common observation-weighted RPKI state. | argmax state count mapped to code | zero: 0 if no evidence; missing: codes documented in missing/zero policy |
