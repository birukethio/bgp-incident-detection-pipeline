# RPKI ROV Feature Reproducibility v1

## Feature Set

The frozen V4 schema contains 16 RPKI/ROV features, documented in `config/rpki_feature_schema_v1.yaml`.

## Historical Alignment

RPKI/VRP state is evaluated using historical VRP information corresponding to the observation period. The feature family preserves VALID, INVALID_ORIGIN, INVALID_LENGTH, NOT_FOUND, and UNEVALUABLE states without adding post-outcome label information.

## Definitions

| family_order | feature_name | definition | formula |
| --- | --- | --- | --- |
| 1 | rpki_evidence_observation_count | Underlying incident-relevant BGP observations represented by compact evidence rows. | sum(observation_count) |
| 2 | rpki_evaluable_observation_count | Observation-weighted count with parseable prefix and origin ASN. | valid+invalid+not_found |
| 3 | rpki_valid_observation_count | Observation-weighted count classified VALID. | sum(observation_count where state=VALID) |
| 4 | rpki_invalid_observation_count | Observation-weighted count classified INVALID. | INVALID_ORIGIN + INVALID_LENGTH |
| 5 | rpki_not_found_observation_count | Observation-weighted count with no covering VRP. | sum(observation_count where state=NOT_FOUND) |
| 6 | rpki_unevaluable_observation_count | Observation-weighted count with missing/malformed prefix or origin. | sum(observation_count where state=UNEVALUABLE) |
| 7 | rpki_invalid_origin_observation_count | Observation-weighted INVALID caused by origin mismatch. | sum(observation_count where state=INVALID_ORIGIN) |
| 8 | rpki_invalid_maxlength_observation_count | Observation-weighted INVALID caused by maxLength violation. | sum(observation_count where state=INVALID_LENGTH) |
| 9 | rpki_valid_observation_ratio | Share of evaluable observations classified VALID. | valid/evaluable |
| 10 | rpki_invalid_observation_ratio | Share of evaluable observations classified INVALID. | invalid/evaluable |
| 11 | rpki_not_found_observation_ratio | Share of evaluable observations classified NOT_FOUND. | not_found/evaluable |
| 12 | rpki_unique_valid_prefix_count | Unique prefixes with at least one VALID observation. | nunique(prefix where state=VALID) |
| 13 | rpki_unique_invalid_prefix_count | Unique prefixes with at least one INVALID observation. | nunique(prefix where state starts INVALID) |
| 14 | rpki_unique_not_found_prefix_count | Unique prefixes with at least one NOT_FOUND observation. | nunique(prefix where state=NOT_FOUND) |
| 15 | rpki_state_diversity_count | Number of distinct RPKI states seen in the window. | count distinct VALID/INVALID_ORIGIN/INVALID_LENGTH/NOT_FOUND/UNEVALUABLE with count > 0 |
| 16 | rpki_dominant_state_code | Numeric code for the most common observation-weighted RPKI state. | argmax state count mapped to code |
