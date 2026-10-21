# Section 4.3 Figure Captions v1

## Figure 4.x Feature Variant Progression

This figure reports incident-level Macro F1 for the frozen V1-V4 feature variants using the authoritative TRAIN-only grouped cross-validation artifact. V1 contains 44 Behavioral BGP features, V2 adds 14 CAIDA AS-relationship features, V3 adds 16 RPKI/ROV features, and V4 combines all three families for 74 total features. Higher Macro F1 indicates better balanced incident-level classification across Hijack, Leak, and Outage. These comparisons were used during TRAIN-only feature development; Validation and Final Holdout results were not used for feature selection.

## Figure 4.x Feature Variant Ranking Metrics

This figure reports Top-2 accuracy and mean reciprocal rank for the same frozen V1-V4 TRAIN-only grouped cross-validation comparison. Top-2 measures whether the true incident class appears among the two highest-ranked classes. MRR rewards placing the true class closer to rank 1. Top-1 was not measured in the authoritative V1-V4 ablation artifact and is therefore excluded rather than estimated.

## Figure 4.x Feature-Family Ablation

This figure reports the change in incident-level Macro F1 after removing each feature family from the full V4 representation under TRAIN-only grouped cross-validation. The delta is calculated as the ablated model Macro F1 minus the full V4 Macro F1. Negative values mean performance decreased after removing the family; larger negative values provide stronger predictive evidence that the removed feature family contributed useful information. Near-zero or positive values indicate redundancy or limited incremental contribution in this specific RF_HIER/I1 experiment.

## Figure 4.x Class-Specific Feature-Family Impact

This heatmap reports class-specific F1 deltas for Hijack, Leak, and Outage after removing each feature family from full V4. Negative cells indicate that the class became harder to classify when that feature family was removed. This figure is supported because the authoritative feature-family ablation artifact contains Hijack, Leak, and Outage F1 for every ablation row. The interpretation is predictive rather than causal: the figure shows measured classification sensitivity, not proof that a feature family caused a real-world incident.

## Evidence Boundary

All Section 4.3 figures are based on existing TRAIN-only artifacts:

- `data/modeling/feature_variant_ablation_results_v1.csv`
- `data/modeling/feature_family_ablation_results_v1.csv`

No model was retrained. Validation was not recomputed or used. Final Holdout was not recomputed or used.
