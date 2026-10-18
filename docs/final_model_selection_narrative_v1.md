# Final Model Selection Narrative v1

Behavioral RF baseline established a reproducible starting point. Imbalance treatment introduced incident-aware weighting. CAIDA and RPKI enrichment produced V4. Refined Random Forest remained a strong benchmark, but refined XGBoost performed better under TRAIN grouped-CV and passed Phase J Validation. K1 then used TRAIN-only incident-level stacking to improve over mean probability aggregation. K2 and K2.5 checked leakage, stability, and architecture alternatives. L0 froze the deployable XGB-to-XGB K1 model before the one-time Final Holdout evaluation.
