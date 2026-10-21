# Final Experimental Pipeline v1

This document records the terminal Praxis evaluation pipeline after all model development was complete.

## Corpus and Split

- Frozen roster: Roster v2.
- TRAIN: 993 incidents, 331 Hijack / 331 Leak / 331 Outage.
- Validation: excluded from Phase L.
- Final Holdout: 213 incidents, 71 Hijack / 71 Leak / 71 Outage.

## Locked Model

Phase L uses only `A0_XGB_TO_XGB` with decision `KEEP_XGB_XGB_K1`.

The first-level model is the Phase I2 XGBoost candidate using the frozen 74-feature V4 schema and I1 incident-aware weighting. Five grouped TRAIN fold models predict each Final Holdout window, and their class probabilities are combined with a fixed arithmetic mean.

The second-level model is `K1_FINAL_SECOND_LEVEL_XGB_V1` with parameter hash `40df040321ef`. It is trained on TRAIN-only leakage-safe K1 meta-features and evaluated once on Final Holdout K1 meta-features.

## Holdout Protection

The Final Holdout result is terminal. It must not be used for feature selection, model tuning, threshold tuning, architecture comparison, class balancing, aggregation changes, or any other modeling decision.

Stage 1 remains `UNRESOLVED_EXPERIMENTAL_AUXILIARY`.
