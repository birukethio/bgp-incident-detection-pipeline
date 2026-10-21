# Section 4.3 Paper Figure Text v1

These text blocks are separated from the high-resolution chart-only JPG figures so the dissertation document can control headings, captions, spacing, and source notes directly.

## Figure 4.x Feature Variant Progression

Title: Feature Variant Progression

Subtitle: Incident-level Macro F1 from TRAIN-only grouped cross-validation. V1 = Behavioral; V2 = Behavioral + CAIDA; V3 = Behavioral + RPKI/ROV; V4 = Behavioral + CAIDA + RPKI/ROV.

Under-figure note: Higher Macro F1 indicates better balanced incident-level classification across Hijack, Leak, and Outage.

Caption: This figure compares the frozen V1-V4 feature variants during TRAIN-only grouped cross-validation. V3 achieved the highest Macro F1 in this experiment, while V4 retained the complete 74-feature representation and strongest overall ranking/per-class balance used by the later pipeline.

Source: `data/modeling/feature_variant_ablation_results_v1.csv`

Image: `figures/chapter4/figure_4_feature_variant_progression_v1_highres_chart_only.jpg`

## Figure 4.x Feature-Family Ablation

Title: Feature-Family Ablation

Subtitle: Delta Incident Macro F1 versus full V4 under TRAIN-only grouped cross-validation. Negative values mean performance decreased when that feature family was removed.

Under-figure note: Sorted by Macro-F1 impact. Larger negative bars provide stronger evidence of useful predictive contribution in this experiment.

Caption: This figure reports the change in incident-level Macro F1 after removing each feature family from the full V4 representation. RPKI/ROV removal produced the largest Macro-F1 decrease, indicating the strongest measured contribution among the tested feature families.

Source: `data/modeling/feature_family_ablation_results_v1.csv`

Image: `figures/chapter4/figure_4_feature_family_ablation_v1_highres_chart_only.jpg`

## Figure 4.x Class-Specific Feature-Family Impact

Title: Class-Specific Feature-Family Impact

Subtitle: Class F1 delta after removing each feature family from full V4. Negative cells indicate the class became harder to classify.

Under-figure note: Use as class-level evidence only; the experiment is TRAIN-only and not a causal proof of feature mechanisms.

Caption: This heatmap shows class-level sensitivity to feature-family removal. RPKI/ROV most affected Hijack F1, peer visibility most affected Leak F1, and CAIDA AS-relationship removal most affected Outage F1 in this TRAIN-only ablation.

Source: `data/modeling/feature_family_ablation_results_v1.csv`

Image: `figures/chapter4/figure_4_feature_family_class_impact_v1_highres_chart_only.jpg`
