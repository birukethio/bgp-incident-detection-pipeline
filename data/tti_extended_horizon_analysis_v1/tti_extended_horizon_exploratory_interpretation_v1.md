# Extended Horizon Exploratory Interpretation v1

**POST-HOC EXPLORATORY / SENSITIVITY TEMPORAL-CURVE ANALYSIS**

The 600- and 900-second checkpoints were added after the pre-specified Validation TTI results had been observed. They are therefore exploratory sensitivity analyses and are not part of the terminal confirmatory TTI evaluation.

No Final Holdout access occurred. No Level-1 model retraining, tuning, calibration, optimization, or modification occurred. Feature definitions, onset methodology, CAIDA/RPKI mapping, class order, and V4 schema were preserved.

## Coverage

TRAIN extended-horizon coverage:

|   horizon_seconds |   EVALUABLE |   NOT_EVALUABLE_INSUFFICIENT_TEMPORAL_COVERAGE |
|------------------:|------------:|-----------------------------------------------:|
|               600 |         973 |                                             10 |
|               900 |         972 |                                             11 |

Validation extended-horizon coverage:

|   horizon_seconds |   EVALUABLE |
|------------------:|------------:|
|               600 |         212 |
|               900 |         212 |

## 600/900 Metrics

| scope      |   horizon_seconds |   n_incidents |   macro_f1 |   macro_f1_ci_lower |   macro_f1_ci_upper |   top1_accuracy |   top2_accuracy |      mrr |
|:-----------|------------------:|--------------:|-----------:|--------------------:|--------------------:|----------------:|----------------:|---------:|
| TRAIN      |               600 |           973 |   0.904445 |            0.886097 |            0.922329 |        0.904419 |        0.979445 | 0.948784 |
| TRAIN      |               900 |           972 |   0.89306  |            0.874233 |            0.911485 |        0.893004 |        0.972222 | 0.941872 |
| Validation |               600 |           212 |   0.787027 |            0.727797 |            0.838947 |        0.787736 |        0.90566  | 0.878145 |
| Validation |               900 |           212 |   0.791313 |            0.735457 |            0.84179  |        0.792453 |        0.919811 | 0.882862 |

## Descriptive Temporal-Curve Finding

- Validation Macro F1 moved from 300s=0.782441 to 900s=0.791313.
- TRAIN Macro F1 moved from 300s=0.898440 to 900s=0.893060.
- This exploratory curve should be interpreted descriptively only; it must not be used to select a new optimal TTI horizon or redefine the confirmatory TTI checkpoint.
- Incidents becoming stable-correct only at 600s/900s: {'TRAIN': 25, 'Validation': 9}.

## Files

- V4 features: `data/tti_extended_horizon_analysis_v1/tti_extended_horizon_v4_features_v1.parquet`
- predictions: `data/tti_extended_horizon_analysis_v1/tti_extended_horizon_predictions_v1.csv`
- metrics: `data/tti_extended_horizon_analysis_v1/tti_extended_horizon_metrics_v1.csv`
- combined curve table: `data/tti_extended_horizon_analysis_v1/tti_extended_temporal_curve_table_v1.csv`
- figure PNG/PDF/JPG: `data/tti_extended_horizon_analysis_v1/figures/figure_tti_extended_temporal_curve_v1.png`, `data/tti_extended_horizon_analysis_v1/figures/figure_tti_extended_temporal_curve_v1.pdf`, `data/tti_extended_horizon_analysis_v1/figures/figure_tti_extended_temporal_curve_v1_highres_chart_only.jpg`

Elapsed seconds: 6539.528

Disposition: `EXTENDED_HORIZON_EXPLORATORY_ANALYSIS_COMPLETE`
