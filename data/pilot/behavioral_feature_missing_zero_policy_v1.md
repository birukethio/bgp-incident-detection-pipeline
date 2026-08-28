# Behavioral Feature Missing and Zero Policy v1

Scope: 9-incident TRAIN pilot behavioral BGP features only.

A zero relevant-observation window is preserved as one ML feature row. It is not dropped and is not labeled Normal.

Use numeric 0 when zero is semantically valid:

- count features such as `announcement_count`, `withdrawal_count`, `unique_prefix_count`, and `unique_peer_asn_count`
- rate features whose numerator is a count over the fixed 5-minute window

Use missing/NaN when the statistic is mathematically undefined:

- ratios with a zero denominator
- AS_PATH summary statistics when no AS_PATH is present
- per-prefix diversity summaries when no relevant prefix/path exists

`has_relevant_observation` and `raw_observation_count` are diagnostic fields retained for audit. They are not counted as canonical behavioral features in v1.

No model imputation is performed in this step.
No `NORMAL` temporal status or Normal label is created in this step.
