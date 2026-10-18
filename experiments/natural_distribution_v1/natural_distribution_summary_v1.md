# Natural Distribution Summary v1

## Disposition

`NATURAL_DISTRIBUTION_TRAIN_ONLY_SENSITIVITY_COMPLETE`

## Natural Distribution Counts

- Hijack: 112,290 (47.2176%)
- Leak: 125,051 (52.5835%)
- Outage: 473 (0.1989%)

## Reweighted Metrics

- macro_f1: 0.722300
- weighted_f1: 0.916680
- top1_accuracy: 0.914426
- top2_accuracy: 0.989852
- mrr: 0.955522

## Per-Class Natural-Prior Metrics

| category   |       f1 |   precision |   recall |
|:-----------|---------:|------------:|---------:|
| Hijack     | 0.915314 |    0.924463 | 0.906344 |
| Leak       | 0.920119 |    0.918792 | 0.921450 |
| Outage     | 0.331467 |    0.199640 | 0.975831 |

## Balanced K1 Reference

- Candidate: K1-M2_XGB_K1-TEMPORAL
- Balanced TRAIN nested-CV Macro F1: 0.934666
- Balanced TRAIN nested-CV Top-1: 0.934542
- Balanced TRAIN nested-CV Top-2: 0.992951
- Balanced TRAIN nested-CV MRR: 0.966096

## Caveat

Because outages are rare in the observed collected-corpus distribution, weighted aggregate scores are dominated by Hijack and Leak behavior. Macro F1 remains the more class-balanced summary; weighted F1 is the prevalence-sensitive summary.
