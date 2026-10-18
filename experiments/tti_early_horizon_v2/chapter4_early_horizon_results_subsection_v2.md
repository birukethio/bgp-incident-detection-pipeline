# Proposed Chapter 4 Insertion: Retrospective Early-Horizon Level-1 Results

**Suggested location:** Chapter 4, after final model-performance sections or as a short post-hoc TTI subsection before the operational-latency discussion.

The retrospective early-horizon experiment evaluated the frozen Level-1 XGBoost classifier at cumulative RouteViews-observable horizons of 30, 60, 120, 300, 600, and 900 seconds. This was a TRAIN-only, post-hoc analysis and was not used to modify the primary model, the Level-2 stacker, Validation results, or Final Holdout results.

The incident accounting was 993 TRAIN incidents to 983 TTI-evaluable incidents. The 10 exclusions were documented before scoring: nine incidents lacked incident-relevant timestamped RouteViews evidence under the frozen predicates, and one outage had unresolved observable onset. The 30-, 60-, 120-, and 300-second checkpoints used all 983 evaluable incidents. The 600-second and 900-second checkpoints had denominators of 973 and 972 incidents because not every TRAIN incident had sufficient extended temporal coverage.

**Early Level-1 Classification Performance by Observation Horizon**

| Horizon          |   Macro F1 |    Top-1 |    Top-2 |      MRR |   Hijack F1 |   Leak F1 |   Outage F1 |   n |
|:-----------------|-----------:|---------:|---------:|---------:|------------:|----------:|------------:|----:|
| 30 sec           |   0.790817 | 0.790437 | 0.932859 | 0.884028 |    0.778378 |  0.769231 |    0.824841 | 983 |
| 60 sec           |   0.843014 | 0.842319 | 0.953204 | 0.91336  |    0.824022 |  0.829822 |    0.875197 | 983 |
| 120 sec          |   0.873308 | 0.872838 | 0.97355  | 0.932011 |    0.857143 |  0.877743 |    0.885039 | 983 |
| 300 sec (5 min)  |   0.89844  | 0.898271 | 0.972533 | 0.944557 |    0.88724  |  0.901538 |    0.906542 | 983 |
| 600 sec (10 min) |   0.904445 | 0.904419 | 0.979445 | 0.948784 |    0.891603 |  0.913505 |    0.908228 | 973 |
| 900 sec (15 min) |   0.89306  | 0.893004 | 0.972222 | 0.941872 |    0.882083 |  0.897898 |    0.8992   | 972 |

**Checkpoint-Based Cumulative TTI**

| Metric   | Checkpoint                                       |   Newly identified |   Cumulative identified |   Denominator |   Cumulative percent |
|:---------|:-------------------------------------------------|-------------------:|------------------------:|--------------:|---------------------:|
| Top-1    | <=30s                                            |                777 |                     777 |           983 |              79.0437 |
| Top-1    | <=60s                                            |                 64 |                     841 |           983 |              85.5544 |
| Top-1    | <=120s                                           |                 42 |                     883 |           983 |              89.8271 |
| Top-1    | <=300s                                           |                 27 |                     910 |           983 |              92.5738 |
| Top-1    | <=600s                                           |                 16 |                     926 |           983 |              94.2014 |
| Top-1    | <=900s                                           |                  7 |                     933 |           983 |              94.9135 |
| Top-1    | NOT_IDENTIFIED_WITHIN_900S_OR_AVAILABLE_HORIZONS |                 50 |                     933 |           983 |              94.9135 |
| Top-2    | <=30s                                            |                917 |                     917 |           983 |              93.2859 |
| Top-2    | <=60s                                            |                 26 |                     943 |           983 |              95.9308 |
| Top-2    | <=120s                                           |                 19 |                     962 |           983 |              97.8637 |
| Top-2    | <=300s                                           |                  3 |                     965 |           983 |              98.1689 |
| Top-2    | <=600s                                           |                  8 |                     973 |           983 |              98.9827 |
| Top-2    | <=900s                                           |                  1 |                     974 |           983 |              99.0844 |
| Top-2    | NOT_IDENTIFIED_WITHIN_900S_OR_AVAILABLE_HORIZONS |                  9 |                     974 |           983 |              99.0844 |

Performance improved substantially through the first five minutes. Beyond 300 seconds, gains were small and inconsistent. Five minutes is therefore supported as a practical analytical tradeoff point, not a mathematically proven optimum.

The final verification disposition for the early-horizon package was `PASS_WITH_DOCUMENTED_EXCLUSIONS`. These results should be interpreted as a retrospective Level-1 analysis of evidence accumulation and not as a replacement for the final incident-level stacking architecture or the one-time Final Holdout result.
