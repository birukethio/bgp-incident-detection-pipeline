# TTI Timestamped TRAIN Evidence Summary v1

This is an additive TRAIN-only evidence reconstruction gate. It does not score TTI rows, retrain models, or touch Validation/Final Holdout artifacts.

## Preflight Estimate

- Expected TRAIN incidents: 993
- Class counts: {"Hijack": 331, "Leak": 331, "Outage": 331}
- Planned MRT assignments: 25099
- Unique MRT URLs: 20524
- Estimated compressed MRT transfer: 35.948 GiB
- Previous raw BGP observations inspected: 6,691,837,988
- Previous relevant observations retained: 144,905,473
- Previous full TRAIN runtime: 14.197 hours
- Projected timestamped Parquet size: 1.167 GiB
- Projected timestamped CSV size: 36.446 GiB

## Gate Finding

Storage is reasonable only if processed batch-by-batch and stored as partitioned Parquet. Runtime and network/parse volume are long-running, so the script is resumable and records incident-level status.

FULL_TRAIN_TIMESTAMPED_EVIDENCE_REQUIRES_REVIEW
