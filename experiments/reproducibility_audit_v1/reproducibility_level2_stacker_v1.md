# Level 2 Temporal Stacker Reproducibility v1

## Architecture

The final Praxis architecture is `A0_XGB_TO_XGB`: five fold-specific Level-1 XGBoost models generate window-level class probabilities, and a Level-2 XGBoost temporal stacker consumes incident-level meta-features derived from those probabilities.

## Meta Feature Schema

`config/k1_incident_meta_feature_schema_v1.yaml` freezes 74 incident-level meta-features, including probability summaries, class-vote proportions, confidence/margin/entropy summaries, early/middle/late temporal summaries, and probability slopes.

## Inference

Final first-level inference strategy: `CROSSFIT_ENSEMBLE_FIRST_LEVEL`. Ranking rule: `descending P(Hijack), P(Leak), P(Outage)`. Second-level configuration: `config/k1_second_level_xgb_final_v1.yaml`.
