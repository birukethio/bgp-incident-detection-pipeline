# Validation TTI Confirmation Summary v1

**ONE-TIME INDEPENDENT VALIDATION OF RETROSPECTIVE EARLY CLASSIFICATION / ROUTEVIEWS-OBSERVABLE CHECKPOINT TTI**

- Frozen protocol hash verification: PASS
- Validation incidents processed: 213
- TTI evaluability status counts: {"TTI_EVALUABLE": 212, "TTI_NOT_EVALUABLE_INSUFFICIENT_ROUTEVIEWS_EVIDENCE": 1}
- Final Holdout accessed/recomputed/analyzed for TTI: NO
- Model retrained/tuned/calibrated/modified: NO
- Existing Final Holdout metrics remain authoritative: Macro F1 = 0.920177; Top-2 = 0.990610; MRR = 0.958529

## Horizon Metrics

|   horizon_seconds |   n_incidents |   macro_f1 |   macro_f1_ci_lower |   macro_f1_ci_upper |   top1_accuracy |   top2_accuracy |      mrr |
|------------------:|--------------:|-----------:|--------------------:|--------------------:|----------------:|----------------:|---------:|
|                30 |           212 |   0.707416 |            0.641634 |            0.764731 |        0.707547 |        0.900943 | 0.837264 |
|                60 |           212 |   0.75129  |            0.690211 |            0.803859 |        0.75     |        0.924528 | 0.862421 |
|               120 |           212 |   0.783423 |            0.727774 |            0.837371 |        0.783019 |        0.919811 | 0.878145 |
|               300 |           212 |   0.782441 |            0.723086 |            0.834434 |        0.783019 |        0.910377 | 0.876572 |

## Cumulative Identification

| identification_type   | checkpoint                 |   count |   percent |   denominator |
|:----------------------|:---------------------------|--------:|----------:|--------------:|
| Top-1                 | <=30s                      |     150 | 0.707547  |           212 |
| Top-1                 | <=60s                      |     163 | 0.768868  |           212 |
| Top-1                 | <=120s                     |     172 | 0.811321  |           212 |
| Top-1                 | <=300s                     |     180 | 0.849057  |           212 |
| Top-1                 | NOT_IDENTIFIED_WITHIN_300S |      32 | 0.150943  |           212 |
| Top-2                 | <=30s                      |     191 | 0.900943  |           212 |
| Top-2                 | <=60s                      |     198 | 0.933962  |           212 |
| Top-2                 | <=120s                     |     199 | 0.938679  |           212 |
| Top-2                 | <=300s                     |     199 | 0.938679  |           212 |
| Top-2                 | NOT_IDENTIFIED_WITHIN_300S |      13 | 0.0613208 |           212 |

## TRAIN vs Validation Deltas

| comparison                | horizon_seconds   | metric                                    |     train |   validation |   delta_validation_minus_train |
|:--------------------------|:------------------|:------------------------------------------|----------:|-------------:|-------------------------------:|
| horizon_metric            | 30                | macro_f1                                  | 0.790817  |    0.707416  |                   -0.083401    |
| horizon_metric            | 30                | top1_accuracy                             | 0.790437  |    0.707547  |                   -0.0828903   |
| horizon_metric            | 30                | top2_accuracy                             | 0.932859  |    0.900943  |                   -0.0319152   |
| horizon_metric            | 30                | mrr                                       | 0.884028  |    0.837264  |                   -0.0467643   |
| horizon_metric            | 60                | macro_f1                                  | 0.843014  |    0.75129   |                   -0.0917236   |
| horizon_metric            | 60                | top1_accuracy                             | 0.842319  |    0.75      |                   -0.0923194   |
| horizon_metric            | 60                | top2_accuracy                             | 0.953204  |    0.924528  |                   -0.0286762   |
| horizon_metric            | 60                | mrr                                       | 0.91336   |    0.862421  |                   -0.0509391   |
| horizon_metric            | 120               | macro_f1                                  | 0.873308  |    0.783423  |                   -0.0898854   |
| horizon_metric            | 120               | top1_accuracy                             | 0.872838  |    0.783019  |                   -0.0898194   |
| horizon_metric            | 120               | top2_accuracy                             | 0.97355   |    0.919811  |                   -0.053739    |
| horizon_metric            | 120               | mrr                                       | 0.932011  |    0.878145  |                   -0.0538662   |
| horizon_metric            | 300               | macro_f1                                  | 0.89844   |    0.782441  |                   -0.115999    |
| horizon_metric            | 300               | top1_accuracy                             | 0.898271  |    0.783019  |                   -0.115252    |
| horizon_metric            | 300               | top2_accuracy                             | 0.972533  |    0.910377  |                   -0.0621557   |
| horizon_metric            | 300               | mrr                                       | 0.944557  |    0.876572  |                   -0.0679852   |
| cumulative_identification |                   | Top-1 <=30s                               | 0.790437  |    0.707547  |                   -0.0828903   |
| cumulative_identification |                   | Top-1 <=60s                               | 0.855544  |    0.768868  |                   -0.0866763   |
| cumulative_identification |                   | Top-1 <=120s                              | 0.898271  |    0.811321  |                   -0.0869498   |
| cumulative_identification |                   | Top-1 <=300s                              | 0.925738  |    0.849057  |                   -0.0766809   |
| cumulative_identification |                   | Top-1 NOT_IDENTIFIED_WITHIN_300S          | 0.0742625 |    0.150943  |                    0.0766809   |
| cumulative_identification |                   | Top-2 <=30s                               | 0.932859  |    0.900943  |                   -0.0319152   |
| cumulative_identification |                   | Top-2 <=60s                               | 0.959308  |    0.933962  |                   -0.025346    |
| cumulative_identification |                   | Top-2 <=120s                              | 0.978637  |    0.938679  |                   -0.0399576   |
| cumulative_identification |                   | Top-2 <=300s                              | 0.981689  |    0.938679  |                   -0.0430095   |
| cumulative_identification |                   | Top-2 NOT_IDENTIFIED_WITHIN_300S          | 0.0183113 |    0.0613208 |                    0.0430095   |
| stability                 |                   | <=30s                                     | 0.760936  |    0.65566   |                   -0.105276    |
| stability                 |                   | <=60s                                     | 0.0569685 |    0.0471698 |                   -0.00979865  |
| stability                 |                   | <=120s                                    | 0.0427263 |    0.0424528 |                   -0.000273518 |
| stability                 |                   | <=300s                                    | 0.0376399 |    0.0377358 |                    9.59711e-05 |
| stability                 |                   | NOT_IDENTIFIED_WITHIN_300S                | 0.101729  |    0.216981  |                    0.115252    |
| stability                 |                   | BECOMES_TOP1_CORRECT_THEN_LATER_INCORRECT | 0.0396745 |    0.0707547 |                    0.0310803   |

Decision: VALIDATION_TTI_CONFIRMATION_COMPLETE
