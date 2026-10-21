# Early Horizon Final Verification v2

This is a verification-only continuation of the additive TRAIN-only Level-1 early-horizon experiment. No Validation or Final Holdout rows were accessed, recomputed, or modified. No frozen model or manuscript result was changed.

## Final disposition

`PASS_WITH_DOCUMENTED_EXCLUSIONS`

## Incident accounting

| row_type          | incident_uid   | incident_id   | category   | train_corpus_count   | tti_evaluable_count   | excluded_count   | final_tti_denominator   | status                                             | exclusion_reason                                             | evidence                                                                                                                                                                                                   |
|:------------------|:---------------|:--------------|:-----------|:---------------------|:----------------------|:-----------------|:------------------------|:---------------------------------------------------|:-------------------------------------------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| SUMMARY           |                |               |            | 993                  | 983                   | 10               | 983                     | PASS                                               | 993 TRAIN -> 983 TTI-evaluable -> 10 excluded before scoring | train roster, tti_train_evaluable_cohort_v2_1, early_horizon_predictions_v2                                                                                                                                |
| EXCLUDED_INCIDENT | Hijack:125603  | 125603        | Hijack     |                      |                       |                  |                         | TTI_NOT_EVALUABLE_INSUFFICIENT_ROUTEVIEWS_EVIDENCE | TTI_NOT_EVALUABLE_INSUFFICIENT_ROUTEVIEWS_EVIDENCE           | MRT files were processed under the frozen relevance predicates; no incident-relevant RouteViews observations were retained.                                                                                |
| EXCLUDED_INCIDENT | Hijack:130023  | 130023        | Hijack     |                      |                       |                  |                         | TTI_NOT_EVALUABLE_INSUFFICIENT_ROUTEVIEWS_EVIDENCE | TTI_NOT_EVALUABLE_INSUFFICIENT_ROUTEVIEWS_EVIDENCE           | MRT files were processed under the frozen relevance predicates; no incident-relevant RouteViews observations were retained.                                                                                |
| EXCLUDED_INCIDENT | Hijack:3930    | 3930          | Hijack     |                      |                       |                  |                         | TTI_NOT_EVALUABLE_INSUFFICIENT_ROUTEVIEWS_EVIDENCE | TTI_NOT_EVALUABLE_INSUFFICIENT_ROUTEVIEWS_EVIDENCE           | MRT files were processed under the frozen relevance predicates; no incident-relevant RouteViews observations were retained.                                                                                |
| EXCLUDED_INCIDENT | Hijack:88054   | 88054         | Hijack     |                      |                       |                  |                         | TTI_NOT_EVALUABLE_INSUFFICIENT_ROUTEVIEWS_EVIDENCE | TTI_NOT_EVALUABLE_INSUFFICIENT_ROUTEVIEWS_EVIDENCE           | MRT files were processed under the frozen relevance predicates; no incident-relevant RouteViews observations were retained.                                                                                |
| EXCLUDED_INCIDENT | Leak:467171    | 467171        | Leak       |                      |                       |                  |                         | TTI_NOT_EVALUABLE_INSUFFICIENT_ROUTEVIEWS_EVIDENCE | TTI_NOT_EVALUABLE_INSUFFICIENT_ROUTEVIEWS_EVIDENCE           | MRT files were processed under the frozen relevance predicates; no incident-relevant RouteViews observations were retained.                                                                                |
| EXCLUDED_INCIDENT | Leak:468388    | 468388        | Leak       |                      |                       |                  |                         | TTI_NOT_EVALUABLE_INSUFFICIENT_ROUTEVIEWS_EVIDENCE | TTI_NOT_EVALUABLE_INSUFFICIENT_ROUTEVIEWS_EVIDENCE           | MRT files were processed under the frozen relevance predicates; no incident-relevant RouteViews observations were retained.                                                                                |
| EXCLUDED_INCIDENT | Outage:1034    | 1034          | Outage     |                      |                       |                  |                         | TTI_NOT_EVALUABLE_INSUFFICIENT_ROUTEVIEWS_EVIDENCE | TTI_NOT_EVALUABLE_INSUFFICIENT_ROUTEVIEWS_EVIDENCE           | MRT files were processed under the frozen relevance predicates; no incident-relevant RouteViews observations were retained.                                                                                |
| EXCLUDED_INCIDENT | Outage:1074    | 1074          | Outage     |                      |                       |                  |                         | TTI_NOT_EVALUABLE_INSUFFICIENT_ROUTEVIEWS_EVIDENCE | TTI_NOT_EVALUABLE_INSUFFICIENT_ROUTEVIEWS_EVIDENCE           | MRT files were processed under the frozen relevance predicates; no incident-relevant RouteViews observations were retained.                                                                                |
| EXCLUDED_INCIDENT | Outage:377     | 377           | Outage     |                      |                       |                  |                         | TTI_NOT_EVALUABLE_ONSET_UNRESOLVED                 | TTI_NOT_EVALUABLE_ONSET_UNRESOLVED                           | Timestamped evidence was retained, but every retained observation precedes the documented incident start; the approved FIRST_POST_DOCUMENTED_EVENT_EVIDENCE onset rule cannot define t0 for this incident. |
| EXCLUDED_INCIDENT | Outage:696     | 696           | Outage     |                      |                       |                  |                         | TTI_NOT_EVALUABLE_INSUFFICIENT_ROUTEVIEWS_EVIDENCE | TTI_NOT_EVALUABLE_INSUFFICIENT_ROUTEVIEWS_EVIDENCE           | MRT files were processed under the frozen relevance predicates; no incident-relevant RouteViews observations were retained.                                                                                |

## Horizon denominators

|   horizon_seconds | horizon          |   prediction_rows |   unique_incidents | same_as_tti_denominator_983   |   missing_from_983_count |   extra_vs_983_count |
|------------------:|:-----------------|------------------:|-------------------:|:------------------------------|-------------------------:|---------------------:|
|                30 | 30 sec           |               983 |                983 | True                          |                        0 |                    0 |
|                60 | 60 sec           |               983 |                983 | True                          |                        0 |                    0 |
|               120 | 120 sec          |               983 |                983 | True                          |                        0 |                    0 |
|               300 | 300 sec (5 min)  |               983 |                983 | True                          |                        0 |                    0 |
|               600 | 600 sec (10 min) |               973 |                973 | False                         |                       10 |                    0 |
|               900 | 900 sec (15 min) |               972 |                972 | False                         |                       11 |                    0 |

The 10 absent TRAIN incidents were excluded before TTI scoring: nine had genuinely insufficient RouteViews evidence under the frozen relevance predicates, and one had unresolved observable onset under the frozen FIRST_POST_DOCUMENTED_EVENT_EVIDENCE rule.

## Metric verification

| horizon          |   evaluable_incidents |   macro_f1 |   top1_accuracy |   top2_accuracy |      mrr |   hijack_f1 |   leak_f1 |   outage_f1 |
|:-----------------|----------------------:|-----------:|----------------:|----------------:|---------:|------------:|----------:|------------:|
| 30 sec           |                   983 |   0.790817 |        0.790437 |        0.932859 | 0.884028 |    0.778378 |  0.769231 |    0.824841 |
| 60 sec           |                   983 |   0.843014 |        0.842319 |        0.953204 | 0.91336  |    0.824022 |  0.829822 |    0.875197 |
| 120 sec          |                   983 |   0.873308 |        0.872838 |        0.97355  | 0.932011 |    0.857143 |  0.877743 |    0.885039 |
| 300 sec (5 min)  |                   983 |   0.89844  |        0.898271 |        0.972533 | 0.944557 |    0.88724  |  0.901538 |    0.906542 |
| 600 sec (10 min) |                   973 |   0.904445 |        0.904419 |        0.979445 | 0.948784 |    0.891603 |  0.913505 |    0.908228 |
| 900 sec (15 min) |                   972 |   0.89306  |        0.893004 |        0.972222 | 0.941872 |    0.882083 |  0.897898 |    0.8992   |

All rounded-to-6 expected metric checks passed: `True`.
Leakage assertion failures: `0`.

## TTI cumulative percentages

| metric   | checkpoint                                       | checkpoint_seconds   |   newly_identified_count |   cumulative_identified_count |   eligible_denominator |   newly_identified_percent |   cumulative_identified_percent |
|:---------|:-------------------------------------------------|:---------------------|-------------------------:|------------------------------:|-----------------------:|---------------------------:|--------------------------------:|
| Top-1    | <=30s                                            | 30                   |                      777 |                           777 |                    983 |                  79.0437   |                         79.0437 |
| Top-1    | <=60s                                            | 60                   |                       64 |                           841 |                    983 |                   6.51068  |                         85.5544 |
| Top-1    | <=120s                                           | 120                  |                       42 |                           883 |                    983 |                   4.27263  |                         89.8271 |
| Top-1    | <=300s                                           | 300                  |                       27 |                           910 |                    983 |                   2.74669  |                         92.5738 |
| Top-1    | <=600s                                           | 600                  |                       16 |                           926 |                    983 |                   1.62767  |                         94.2014 |
| Top-1    | <=900s                                           | 900                  |                        7 |                           933 |                    983 |                   0.712106 |                         94.9135 |
| Top-1    | NOT_IDENTIFIED_WITHIN_900S_OR_AVAILABLE_HORIZONS |                      |                       50 |                           933 |                    983 |                   5.08647  |                         94.9135 |
| Top-2    | <=30s                                            | 30                   |                      917 |                           917 |                    983 |                  93.2859   |                         93.2859 |
| Top-2    | <=60s                                            | 60                   |                       26 |                           943 |                    983 |                   2.64496  |                         95.9308 |
| Top-2    | <=120s                                           | 120                  |                       19 |                           962 |                    983 |                   1.93286  |                         97.8637 |
| Top-2    | <=300s                                           | 300                  |                        3 |                           965 |                    983 |                   0.305188 |                         98.1689 |
| Top-2    | <=600s                                           | 600                  |                        8 |                           973 |                    983 |                   0.813835 |                         98.9827 |
| Top-2    | <=900s                                           | 900                  |                        1 |                           974 |                    983 |                   0.101729 |                         99.0844 |
| Top-2    | NOT_IDENTIFIED_WITHIN_900S_OR_AVAILABLE_HORIZONS |                      |                        9 |                           974 |                    983 |                   0.915565 |                         99.0844 |

## Class-specific Top-1 cumulative TTI

| class   |   checkpoint_seconds | checkpoint   |   top1_cumulative_identified_count |   class_denominator |   top1_cumulative_identified_percent |
|:--------|---------------------:|:-------------|-----------------------------------:|--------------------:|-------------------------------------:|
| Hijack  |                   30 | <=30s        |                                288 |                 327 |                              88.0734 |
| Hijack  |                   60 | <=60s        |                                297 |                 327 |                              90.8257 |
| Hijack  |                  120 | <=120s       |                                303 |                 327 |                              92.6606 |
| Hijack  |                  300 | <=300s       |                                310 |                 327 |                              94.8012 |
| Hijack  |                  600 | <=600s       |                                311 |                 327 |                              95.107  |
| Hijack  |                  900 | <=900s       |                                312 |                 327 |                              95.4128 |
| Leak    |                   30 | <=30s        |                                230 |                 329 |                              69.9088 |
| Leak    |                   60 | <=60s        |                                263 |                 329 |                              79.9392 |
| Leak    |                  120 | <=120s       |                                290 |                 329 |                              88.1459 |
| Leak    |                  300 | <=300s       |                                298 |                 329 |                              90.5775 |
| Leak    |                  600 | <=600s       |                                308 |                 329 |                              93.617  |
| Leak    |                  900 | <=900s       |                                312 |                 329 |                              94.8328 |
| Outage  |                   30 | <=30s        |                                259 |                 327 |                              79.2049 |
| Outage  |                   60 | <=60s        |                                281 |                 327 |                              85.9327 |
| Outage  |                  120 | <=120s       |                                290 |                 327 |                              88.685  |
| Outage  |                  300 | <=300s       |                                302 |                 327 |                              92.3547 |
| Outage  |                  600 | <=600s       |                                307 |                 327 |                              93.8838 |
| Outage  |                  900 | <=900s       |                                309 |                 327 |                              94.4954 |

## Saturation check

| transition   |   macro_f1_delta |
|:-------------|-----------------:|
| 30->60       |       0.0521972  |
| 60->120      |       0.0302945  |
| 120->300     |       0.0251319  |
| 300->600     |       0.00600511 |
| 600->900     |      -0.0113852  |

Classification performance improved substantially as evidence accumulated through the first five minutes. Beyond 300 seconds, gains were small and inconsistent: Macro F1 increased by 0.006005 from 300 to 600 seconds and then declined by 0.011385 from 600 to 900 seconds. Five minutes therefore represents a practical analytical tradeoff point rather than a mathematically proven optimum.

## Median checkpoint TTI

Median checkpoint TTI is calculated over the 983 TTI-denominator incidents by taking the median of the earliest checkpoint seconds where the relevant condition is met; incidents not identified within available horizons are excluded from the numeric median and reported separately.

- Median Top-1 checkpoint TTI among identified incidents: <= 30 seconds.
- Median Top-2 checkpoint TTI among identified incidents: <= 30 seconds.
