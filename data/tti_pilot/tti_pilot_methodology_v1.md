# TTI Pilot Methodology v1

Scope: TRAIN-only feasibility pilot for early BGP incident classification at 30, 60, 120, and 300 seconds.

Pilot selection: reused the existing reproducible 9-incident MRT pilot roster because it contains 3 Hijack, 3 Leak, and 3 Outage TRAIN incidents with short/median/long duration buckets per class. No Validation or Final Holdout incidents are used.

Observable onset: the first incident-relevant RouteViews BGP observation in the selected pilot MRT evidence after applying frozen incident-relevance predicates from the existing parser pipeline. The externally documented incident start is retained for context but is not used as the TTI onset unless it is also observed in RouteViews evidence.

Onset ambiguity handling: if the first relevant RouteViews observation occurs before the externally documented incident start, the incident is flagged as `PRE_DOCUMENTED_START_RELEVANCE_CONTEXT`. This means the relevance predicate saw related ASN/prefix/path activity in the pre-context window, but the observation should not automatically be interpreted as true incident onset without a stricter event-specific onset rule.

Horizon construction: for each incident and horizon H, include only evidence with `bgp_timestamp_utc <= observable_onset_utc + H`. Horizons are cumulative checkpoints, not exact continuous-time identification claims.

Model gate: the frozen Level-2 K1 stacker is excluded. The frozen Level-1 XGBoost may be used only if the full 74-feature V4 schema is rebuilt without future leakage and a serialized frozen Level-1 model artifact is available.
