# Chapter 4 Figure Insert Guide v1

This guide maps the generated Chapter 4 figure pack to the current final Praxis result story. The figures replace the older seven-event holdout, threshold-0.70, and Random Forest-final narrative with the corrected v2/K1/Final Holdout evidence trail.

## Recommended Figure Order

1. `figures/chapter4/figure_ch4_model_performance_progression_v1.png`
   - Use near the Chapter 4 overview.
   - Caption: Incident Macro F1 improved from the behavioral Random Forest baseline through XGBoost and K1 stacking, with the final sealed Holdout result remaining close to the fixed TRAIN reference.

2. `figures/chapter4/figure_ch4_v4_feature_composition_v1.png`
   - Use before feature-variant or feature-family ablation results.
   - Caption: The final V4 feature corpus combines 44 behavioral, 14 CAIDA, and 16 RPKI/ROV features for 74 total model inputs.

3. `figures/chapter4/figure_ch4_feature_variant_ablation_v1.png`
   - Use in the feature-variant ablation section.
   - Caption: Feature-variant ablation separates behavioral-only evidence from CAIDA and RPKI/ROV enrichment effects before the later XGBoost and K1 phases.

4. `figures/chapter4/figure_ch4_feature_family_removal_sensitivity_v1.png`
   - Use in the feature-family ablation section.
   - Caption: Feature-family removal highlights which groups most affected grouped Macro F1 in the controlled TRAIN-only ablation.

5. `figures/chapter4/figure_ch4_refined_rf_vs_xgboost_v1.png`
   - Use in the RF-vs-XGBoost model-selection section.
   - Caption: Refined XGBoost improved Macro F1, Top-1, Top-2, and MRR relative to the refined Random Forest benchmark under the selected TRAIN-only comparison.

6. `figures/chapter4/figure_ch4_k1_stacking_gain_v1.png`
   - Use in the K1 stacking section.
   - Caption: K1 temporal stacking materially improved incident-level classification over simple mean probability aggregation in the TRAIN-only K1 experiment.

7. `figures/chapter4/figure_ch4_k2_multiseed_stability_v1.png`
   - Use in the K2 stability subsection.
   - Caption: K2 showed low seed sensitivity for the selected K1 architecture before the final deployable freeze.

8. `figures/chapter4/figure_ch4_k25_architecture_comparator_v1.png`
   - Use in the K2.5 architecture-comparison subsection.
   - Caption: The K2.5 architecture comparator supported keeping the XGBoost-to-XGBoost K1 design.

9. `figures/chapter4/figure_ch4_final_holdout_headline_metrics_v1.png`
   - Use at the start of the Final Holdout results section.
   - Caption: The frozen K1 model generalized strongly on the sealed Final Holdout, with high classification and ranking metrics.

10. `figures/chapter4/figure_ch4_final_holdout_per_class_metrics_v1.png`
    - Use in the per-class analysis section.
    - Caption: Per-class Final Holdout metrics show strongest performance for Outage and the lowest F1 for Hijack.

11. `figures/chapter4/figure_ch4_final_holdout_ranking_distribution_v1.png`
    - Use in the ranking-output section.
    - Caption: The system ranked the true class first for 196 incidents and second for 15 incidents, yielding Top-2 coverage for 211 of 213 Final Holdout incidents.

12. `figures/chapter4/figure_ch4_final_holdout_confusion_matrix_v1.png`
    - Use in the final error-analysis section.
    - Caption: The final confusion matrix shows most residual errors occur between Hijack and Leak, while Outage is sharply separated.

13. `figures/chapter4/figure_ch4_train_vs_final_holdout_delta_v1.png`
    - Use near the end of Chapter 4 to compare TRAIN reference and terminal Holdout.
    - Caption: TRAIN-to-Holdout deltas are small for aggregate ranking metrics, with the largest class-specific difference in Hijack F1.

## Interpretation Boundaries

- These figures describe predictive classification and ranking performance, not causal proof of root cause.
- K1 was developed after Phase J Validation using TRAIN only, and should not be described as Validation-confirmed.
- Final Holdout figures are terminal results; they must not be used to justify new model tuning.
- Stage 1 Normal-vs-Incident results remain auxiliary and unresolved.

