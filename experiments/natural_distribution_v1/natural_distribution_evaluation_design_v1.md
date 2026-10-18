# Natural Distribution Evaluation Design v1

## Objective

Evaluate how the already-developed K1 classifier behavior would summarize under the observed collected-corpus class prior, without retraining and without touching Validation or Final Holdout.

## Evaluation Type

**TRAIN-only class-prior reweighted sensitivity analysis.**

The selected prediction artifact is `data/modeling_k1/k1_incident_level_predictions_v1.parquet` filtered to `K1-M2_XGB_K1-TEMPORAL`. This is the existing TRAIN-only nested-CV incident-level K1 prediction artifact:

- incidents: 993
- class balance: 331 Hijack / 331 Leak / 331 Outage
- Validation used: no
- Final Holdout status: sealed

## Why Not a New Natural Final Holdout?

The all-available pre-balancing corpus does not have final K1 features/predictions for every candidate incident. Creating those predictions would require additional acquisition/feature generation/model execution beyond this audit. Reusing or reshaping the sealed Final Holdout would risk confusing the terminal balanced holdout result, so this design avoids it.

## Reweighting Method

1. Compute class-conditional confusion behavior from existing TRAIN nested-CV incident predictions.
2. Apply those class-conditional rates to the observed natural class counts:
   - Hijack: 112,290
   - Leak: 125,051
   - Outage: 473
3. Recompute natural-prior precision, recall, F1, weighted F1, Top-1, Top-2, and MRR.

## Interpretation Boundary

Balanced corpus = controlled scientific comparison across classes.

Natural distribution = sensitivity analysis under observed class prevalence in the collected source corpus.

This analysis does not replace the authoritative balanced Final Holdout result and does not estimate global Internet-wide incident prevalence.
