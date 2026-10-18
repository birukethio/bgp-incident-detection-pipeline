# Final K1 Latency Summary v1

This benchmark is TRAIN-only and does not recompute Validation or Final Holdout performance.

The system uses non-overlapping five-minute analytical windows. A window cannot be fully calculated until its observation interval has been collected. Operational latency is therefore:

`observation-time requirement + feature computation + model inference`

The measured warm computational path uses cached TRAIN first-level probabilities and frozen K1 meta-feature construction because serialized final XGBoost model binaries are not present in the repository and retraining is prohibited in Phase N.

Measured warm fixture:

- Level-1 probability averaging mean/median/p95: `0.000011` / `0.000011` / `0.000012` ms/window
- K1 meta-feature construction mean/median/p95: `23.276590` / `22.651500` / `24.432975` ms/incident
- Level-2 probability ranking mean/median/p95: `0.095524` / `0.094167` / `0.098151` ms/incident
- Complete measured path mean/median/p95: `23.378865` / `22.751167` / `24.538595` ms/incident

Classification: `POST_WINDOW_INCIDENT_CLASSIFICATION`; computationally fast after feature availability, but the current architecture assumes the configured incident observation window has been collected.
