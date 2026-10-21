# Natural-Distribution Reweighting Verification v1

## Verification Scope

This document verifies how `natural_distribution_metrics_v1.csv` and `natural_distribution_confusion_matrix_v1.csv` were derived. It is documentation-only and does not rerun, modify, retrain, recalibrate, or replace any frozen experiment, model, Validation artifact, Final Holdout artifact, manuscript artifact, TTI artifact, or existing natural-distribution output.

## Source Artifacts Verified

- Prediction artifact: `data/modeling_k1/k1_incident_level_predictions_v1.parquet`
- Candidate used: `K1-M2_XGB_K1-TEMPORAL`
- Prediction rows used: 993 TRAIN nested-CV incident predictions
- Balanced TRAIN support: 331 Hijack / 331 Leak / 331 Outage
- Natural prior source: `natural_distribution_accounting_v1.csv`, stage `quality_filtering_usable_prebalancing`
- Metric output: `natural_distribution_metrics_v1.csv`
- Confusion output: `natural_distribution_confusion_matrix_v1.csv`

## Direct Answers

### 1. Were predictions changed?

No. The stored TRAIN nested-CV predictions were not changed. The class probabilities, predicted class, true class, and true-class ranks came from the existing prediction artifact. Only the evaluation prior/class weights used to summarize those predictions were changed.

### 2. Exact reweighting procedure

Let the class order be:

`Hijack, Leak, Outage`

The balanced TRAIN nested-CV confusion matrix for `K1-M2_XGB_K1-TEMPORAL` was:

| True class | Pred Hijack | Pred Leak | Pred Outage |
|---|---:|---:|---:|
| Hijack | 300 | 30 | 1 |
| Leak | 22 | 305 | 4 |
| Outage | 3 | 5 | 323 |

Each row was converted into a class-conditional prediction-rate row:

`R[i,j] = C[i,j] / sum_j C[i,j]`

Then each true-class row was multiplied by the observed usable pre-balancing class count:

`W[i,j] = R[i,j] * N_observed[i]`

where:

- `N_observed[Hijack] = 112,290`
- `N_observed[Leak] = 125,051`
- `N_observed[Outage] = 473`

This creates a fractional, prior-reweighted confusion matrix. It is not a duplicated incident dataset and not a model rerun.

### 3. How observed proportions were applied

The observed usable pre-balancing proportions were:

| Class | Count | Proportion |
|---|---:|---:|
| Hijack | 112,290 | 47.2176% |
| Leak | 125,051 | 52.5835% |
| Outage | 473 | 0.1989% |

These proportions were applied only during metric aggregation by replacing the balanced class prior of 1/3 each with the observed collected-corpus class prior above. The evaluation uses the balanced TRAIN model behavior conditional on each class, then asks how those same class-conditional behaviors summarize under the observed prior.

### 4. Model retraining

PASS. No model was retrained.

### 5. Probability recalibration

PASS. No class probabilities were recalibrated, and neither Validation nor Final Holdout was used.

### 6. Incident duplication

PASS. No incidents were duplicated or resampled to simulate the natural distribution. The natural-prior view is computed analytically from class-conditional rates and observed class counts.

## Metric Calculations

### Confusion Matrix

The reweighted confusion matrix is:

| True class | Pred Hijack | Pred Leak | Pred Outage |
|---|---:|---:|---:|
| Hijack | 101,773.413897 | 10,177.341390 | 339.244713 |
| Leak | 8,311.546828 | 115,228.262840 | 1,511.190332 |
| Outage | 4.287009 | 7.145015 | 461.567976 |

The entries are fractional because they represent expected counts under the observed prior, not literal duplicated incident records.

### Precision, Recall, and F1

For each class `k`:

- `TP_k = W[k,k]`
- `Predicted_k = sum_i W[i,k]`
- `Actual_k = sum_j W[k,j]`
- `Precision_k = TP_k / Predicted_k`
- `Recall_k = TP_k / Actual_k`
- `F1_k = 2 * Precision_k * Recall_k / (Precision_k + Recall_k)`

Verified per-class results:

| Class | Precision | Recall | F1 |
|---|---:|---:|---:|
| Hijack | 0.924463 | 0.906344 | 0.915314 |
| Leak | 0.918792 | 0.921450 | 0.920119 |
| Outage | 0.199640 | 0.975831 | 0.331467 |

### Macro F1

Macro F1 is the unweighted mean of the three reweighted per-class F1 values:

`(0.915314 + 0.920119 + 0.331467) / 3 = 0.722300`

### Weighted F1

Weighted F1 uses the observed class proportions as support weights:

`0.472176 * F1_Hijack + 0.525835 * F1_Leak + 0.001989 * F1_Outage = 0.916680`

### Top-1

Top-1 is computed from the reweighted confusion matrix:

`Top1 = trace(W) / sum(W) = 0.914426`

### Top-2

Top-2 is computed as the observed-prior weighted mean of class-conditional Top-2 rates from the fixed prediction artifact:

`Top2 = sum_k p_observed[k] * Top2_rate[k] = 0.989852`

### MRR

MRR is computed as the observed-prior weighted mean of class-conditional reciprocal rank:

`MRR = sum_k p_observed[k] * mean(1 / true_class_rank | class=k) = 0.955522`

## Why Macro F1 Falls While Weighted F1 Remains High

Macro F1 falls to `0.722300` because it gives Hijack, Leak, and Outage equal importance after reweighting. Under the observed collected-corpus prior, Outage is extremely rare, and the model's Outage precision drops to `0.199640`: many predicted-Outage cases under the reweighted view come from the much larger Hijack and Leak populations, even though Outage recall remains high at `0.975831`.

Weighted F1 remains high at `0.916680` because Hijack and Leak dominate the observed corpus proportions and both retain high F1 values:

- Hijack F1 = `0.915314`
- Leak F1 = `0.920119`
- Outage F1 = `0.331467`

Since Outage contributes only `0.1989%` of the observed prior, its low F1 has little effect on weighted F1, but it has one-third of the influence in Macro F1.

## Best Terminology

The most scientifically defensible term is:

**prevalence-reweighted prior-shift sensitivity analysis**

Recommended wording:

> This is a TRAIN-only prevalence-reweighted prior-shift sensitivity analysis using observed collected-corpus class proportions before deliberate balancing.

Less precise alternatives:

- `natural-distribution evaluation`: acceptable only with a caveat, because the distribution is natural to the collected source corpus, not global Internet-wide prevalence.
- `natural-distribution sensitivity analysis`: acceptable shorthand if immediately defined.
- `prevalence-reweighted sensitivity analysis`: accurate and dissertation-friendly.

## Statement Verification

Statement:

> The analysis does not estimate real-world global BGP incident prevalence. It evaluates the sensitivity of the frozen TRAIN predictions to the class proportions observed in the collected source corpus before deliberate balancing.

Disposition: **PASS**

This statement is accurate. The analysis uses repository-observed collected-source proportions only, keeps the fixed TRAIN nested-CV predictions unchanged, and does not claim global BGP incident prevalence.

## Final Verification Disposition

`PASS_PREVALENCE_REWEIGHTED_PRIOR_SHIFT_SENSITIVITY_VERIFIED`
