# Model Baseline And Ablation Plan v1

This is a planning document only. No model has been trained, no thresholds have been tuned, and no ablation results are generated here.

Future model baselines:

- Single-stage Random Forest.
- Single-stage XGBoost.
- Two-stage hierarchical Random Forest.

Future imbalance conditions:

- Natural: use the frozen 68,031 TRAIN rows as observed.
- Incident-aware weighting: retain all rows while each incident receives approximately equal aggregate influence.
- p95 cap + incident-aware weighting: use the TRAIN-derived p95 cap of 164 windows per incident, then apply incident-aware weighting.

Feature ablation variants:

- V1 Behavioral = 44 features, frozen.
- V2 Behavioral + CAIDA = pending exact inventory.
- V3 Behavioral + RPKI = pending exact inventory.
- V4 Behavioral + CAIDA + RPKI = pending exact inventory.

Later feature-family removal experiments should evaluate:

- Withdrawal/activity features.
- AS-path/path-instability features.
- Origin-change features.
- CAIDA relationship features.
- RPKI/ROV features.

Primary evaluation metrics:

- Macro F1.
- Top-2 Accuracy.
- MRR.

Final Holdout protection:

The Final Holdout must not be used for feature selection, feature ablation decisions, Normal-rule threshold tuning, class/window balancing decisions, hyperparameter tuning, Stage 1 threshold selection, or model selection. It is used only after the complete pipeline is frozen.
