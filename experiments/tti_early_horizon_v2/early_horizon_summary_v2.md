# Early Horizon Summary v2

**Scope:** TRAIN-only, frozen Level-1 XGBoost, post-hoc early-horizon study.

All v2 outputs and metrics are TRAIN-only; no Validation or Final Holdout rows are present in the produced artifacts. No model was retrained, tuned, calibrated, modified, or replaced. Level-2 temporal stacking was not used.

## Manuscript-ready table

| horizon          |   macro_f1 |   top1_accuracy |   top2_accuracy |      mrr |   hijack_f1 |   leak_f1 |   outage_f1 |
|:-----------------|-----------:|----------------:|----------------:|---------:|------------:|----------:|------------:|
| 30 sec           |   0.790817 |        0.790437 |        0.932859 | 0.884028 |    0.778378 |  0.769231 |    0.824841 |
| 60 sec           |   0.843014 |        0.842319 |        0.953204 | 0.91336  |    0.824022 |  0.829822 |    0.875197 |
| 120 sec          |   0.873308 |        0.872838 |        0.97355  | 0.932011 |    0.857143 |  0.877743 |    0.885039 |
| 300 sec (5 min)  |   0.89844  |        0.898271 |        0.972533 | 0.944557 |    0.88724  |  0.901538 |    0.906542 |
| 600 sec (10 min) |   0.904445 |        0.904419 |        0.979445 | 0.948784 |    0.891603 |  0.913505 |    0.908228 |
| 900 sec (15 min) |   0.89306  |        0.893004 |        0.972222 | 0.941872 |    0.882083 |  0.897898 |    0.8992   |

## Saturation deltas

| transition   |   from_seconds |   to_seconds |   macro_f1_absolute_change |   macro_f1_relative_change_percent |   top1_accuracy_absolute_change |   top1_accuracy_relative_change_percent |   top2_accuracy_absolute_change |   top2_accuracy_relative_change_percent |   mrr_absolute_change |   mrr_relative_change_percent |
|:-------------|---------------:|-------------:|---------------------------:|-----------------------------------:|--------------------------------:|----------------------------------------:|--------------------------------:|----------------------------------------:|----------------------:|------------------------------:|
| H30_to_H60   |             30 |           60 |                 0.0521972  |                           6.60042  |                      0.051882   |                                6.56371  |                      0.0203459  |                                2.18103  |            0.029332   |                      3.31799  |
| H60_to_H120  |             60 |          120 |                 0.0302945  |                           3.5936   |                      0.0305188  |                                3.62319  |                      0.0203459  |                                2.13447  |            0.0186504  |                      2.04195  |
| H120_to_H300 |            120 |          300 |                 0.0251319  |                           2.87778  |                      0.0254323  |                                2.91375  |                     -0.00101729 |                               -0.104493 |            0.0125466  |                      1.34619  |
| H300_to_H600 |            300 |          600 |                 0.00600511 |                           0.668393 |                      0.00614872 |                                0.684507 |                      0.00691195 |                                0.710717 |            0.00422635 |                      0.447443 |
| H600_to_H900 |            600 |          900 |                -0.0113852  |                          -1.25881  |                     -0.0114152  |                               -1.26216  |                     -0.00722279 |                               -0.737437 |           -0.0069114  |                     -0.728449 |

## Scientific interpretation

1. After 30 seconds, Macro F1 was 0.790817, Top-1 was 0.790437, Top-2 was 0.932859, and MRR was 0.884028.
2. By 60 seconds, Macro F1 increased to 0.843014; by 120 seconds it increased to 0.873308.
3. At 300 seconds, Macro F1 was 0.898440, Top-1 was 0.898271, Top-2 was 0.972533, and MRR was 0.944557.
4. From 300 to 600 seconds, Macro F1 changed by 0.006005; from 600 to 900 seconds it changed by -0.011385.
5. These results support five minutes as a practical analytical horizon when framed as a tradeoff point: performance improves strongly from 30 to 300 seconds, while gains beyond 300 seconds are smaller and inconsistent rather than monotonically improving.
6. Cumulative Top-1 TTI counts: <=30s=777, <=60s=64, <=120s=42, <=300s=27, <=600s=16, <=900s=7, NOT_IDENTIFIED_WITHIN_AVAILABLE_HORIZONS=50.
7. Cumulative Top-2 TTI counts: <=30s=917, <=60s=26, <=120s=19, <=300s=3, <=600s=8, <=900s=1, NOT_IDENTIFIED_WITHIN_AVAILABLE_HORIZONS=9.
8. Median checkpoint Top-1 TTI among identified incidents was <= 30 seconds; median checkpoint Top-2 TTI was <= 30 seconds.
9. Based on median Top-1 checkpoint time, the class requiring the most observation time was Hijack.

## Interpretation boundary

This experiment provides empirical support for the five-minute analytical representation, but it must not be described as a pre-development horizon-optimization experiment. It is post-hoc and TRAIN-only.
