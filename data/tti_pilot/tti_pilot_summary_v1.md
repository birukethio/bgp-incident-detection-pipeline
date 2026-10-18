# TTI Pilot Summary v1

## Pilot Scope

- Incidents: 9
- Class counts: Hijack=3, Leak=3, Outage=3
- Partition: TRAIN only
- Raw pilot MRT files reparsed: 216
- Timestamped incident-relevant observations retained: 775320
- Parser status counts: {'PASS': 216}

## Can exact partial-horizon V4 features be generated safely?

Not fully in this pilot. The 44 Behavioral features were reconstructed at 30/60/120/300 seconds from timestamped pilot observations. However, the CAIDA and RPKI/ROV feature groups were not reconstructed in this pilot because they require a versioned horizon-aware enrichment step using as-of snapshots. Therefore the full frozen 74-feature V4 schema was not produced.

## Is the frozen Level-1 XGBoost compatible?

Not yet for scoring. It is technically compatible with a 74-column V4 vector, but this pilot produced only the 44 Behavioral partial-horizon features. In addition, no serialized frozen Level-1 XGBoost model artifact was found in the workspace audit; existing artifacts document the candidate and contain historical metrics/probabilities, but not a reusable model binary for this pilot.

## Classification by horizon

Model evaluation was intentionally not run. The output files `tti_horizon_results_v1.csv` and `tti_incident_predictions_v1.csv` contain `NOT_EVALUATED` rows because the predeclared model gate did not pass.

## Leakage assertions

- Assertion failures: 0
- Incidents without observable onset: 0
- Onset ambiguity counts: {'PRE_DOCUMENTED_START_RELEVANCE_CONTEXT': 8, 'NONE': 1}

Every constructed horizon row passed the assertion `max(bgp_timestamp_utc) <= observable_onset_utc + horizon`.

## Checkpoint-based TTI distribution

Not computed because model scoring was not run. TTI requires predictions and is defined as the earliest evaluated checkpoint where Top-1 is correct. Top-2 TTI requires the true class in the Top-2 ranking.

## Validity concerns

- Rate features retain the frozen `/5 minutes` denominator for schema compatibility, but that is not an elapsed-time rate at 30/60/120 seconds.
- Several pilot incidents have first relevant observations before the externally documented incident start because the selected evidence includes pre-context and broad incident-relevance predicates. These cases require a stricter event-specific onset rule before scaling TTI claims.
- Full V4 compatibility requires CAIDA/RPKI remapping from horizon-filtered evidence.
- The Level-2 K1 temporal stacker remains invalid for this initial TTI pilot because it uses full incident temporal summaries.

## Scaling Recommendation

Scaling to all 993 TRAIN incidents is scientifically justified only after a second controlled step adds horizon-aware CAIDA/RPKI reconstruction and either locates/creates an explicitly frozen reusable Level-1 model artifact or predeclares a TRAIN-only retraining protocol for a TTI-specific model.
