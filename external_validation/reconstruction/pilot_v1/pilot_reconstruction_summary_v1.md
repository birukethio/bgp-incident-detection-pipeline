# External Level-1 Reconstruction Pilot v1

**Scope:** Prospective source-separated external validation of the frozen reproducibly preserved Level-1 BGP incident-classification path.

This engineering pilot does not validate the historical Level-2 temporal stacker. The originally fitted Level-2 artifact was not persisted.

## Yield

- Timestamp-PASS incidents attempted: 8 (2 Hijack / 3 Leak / 3 Outage).
- RouteViews retrieval, MRT parsing, relevance filtering, and Behavioral reconstruction: 8/8 PASS.
- Raw BGP observations inspected: 57,720,505.
- Incident-relevant observations retained: 4,110,370.
- Parser failures: 0.
- Five-minute rows: 322.
- Exact 74-feature historical V4 compatibility: 7/8.
- Frozen Level-1 ensemble execution and mean aggregation: 7/8.
- `V2-HIJACK-008`: retained in timestamp REVIEW and never reconstructed or scored.

## Documented limitation

`V2-HIJACK-003` passed RouteViews and Behavioral reconstruction but did not pass exact V4. The February 2008 CAIDA serial-2 snapshot and same-date five-TAL RPKI archive are unavailable (HTTP 404). No later snapshot, zero substitution, inferred enrichment, or prediction-based workaround was used. Its V4 row set is retained only as an attempted reconstruction and was not scored.

## Frozen compatibility

- Feature names/order: exact 74-feature schema.
- Schema SHA-256: `38ca70a2aa50a39172f2a90d1c893fdd08dfa38a49b3e5945b19d9cab2a202f3`.
- Feature data types for the seven compatible incidents: 74/74 exact against the frozen TRAIN V4 Parquet schema.
- Missing values: frozen NaN behavior preserved; no imputation or calibration added.
- Level-1 artifacts: all recorded model/schema checksums matched.
- Inference: arithmetic mean of `predict_proba` across the five preserved fold models.
- Incident aggregation: arithmetic mean class probability across all eligible five-minute windows.

Prediction correctness was not used to alter retrieval, filtering, features, gates, or inclusion.
