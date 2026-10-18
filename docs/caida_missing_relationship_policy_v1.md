# CAIDA Missing Relationship Policy v1

No AS_PATH observations, unknown CAIDA relationships, and valid zero-violation paths are represented separately.

- No AS_PATH observations: `caida_path_observation_count = 0`; ratio/statistical features are `NaN` rather than zero.
- AS_PATH exists but CAIDA relationship is unknown: unknown path and transition counters increase; the path is not counted valid or violating.
- Valid path with zero violations: path contributes to `caida_valley_free_valid_path_count`; violation counters remain zero.

Silent windows are not converted into relationship evidence. CAIDA features are an enrichment layer joined by `window_id` and never multiply ML rows.
