# Paired Comparison Plan v1

## Purpose

This plan defines how to compare frozen alternatives on the same independent confirmation incidents without retraining or post-hoc selection.

## H2: Behavioral-Only vs Full V4

### Required Artifacts

- Frozen Behavioral-only comparator model or deterministic reconstruction spec.
- Frozen full V4 K1 model.
- Same eligible confirmation incidents for both systems.
- Same incident windows and class labels.

### Metrics

For every incident, compute predictions from both systems and record:

- true class;
- predicted class;
- class probabilities/ranking;
- true-class rank;
- correctness indicators.

Calculate paired differences for:

- Macro F1;
- Top-1;
- Top-2;
- MRR;
- Hijack F1;
- Leak F1;
- Outage F1.

### Decision

H2 is considered supported if V4 improves Macro F1 by at least +0.03 and the paired bootstrap interval does not indicate a clear negative effect. If the Behavioral-only model cannot be frozen without retraining, H2 is not executable as a confirmation claim.

## H3: Mean Aggregation vs K1 Temporal Stacker

### Required Artifacts

- Frozen Level-1 probabilities.
- Mean-aggregation incident predictions.
- Frozen K1 stacker predictions.

### Metrics

Use identical incident denominators and compute:

- Macro F1 difference;
- Top-1 difference;
- Top-2 difference;
- MRR difference;
- per-class F1 differences;
- number and percentage of incidents where K1 changes the Top-1 result compared with mean aggregation.

### Statistical Procedure

- Incident-level paired bootstrap.
- 10,000 resamples.
- Seed 20260914.
- Percentile 95% CI.

## Reporting

Report both point estimates and intervals. Do not use p-value-only language. Avoid causal wording such as "proved" or "caused"; use "was associated with" or "improved under the paired protocol."
