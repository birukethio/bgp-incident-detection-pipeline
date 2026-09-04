# Section 4.5 Figure Captions v1

## Figure 4.x Stage 1 Threshold Stability

This figure shows fold-specific optimal tau values for the initial TRAIN-only Stage 1 Normal-vs-Incident experiment. The fold thresholds were 0.06, 0.62, 0.32, 0.32, and 0.45, while the final TRAIN-CV proposed tau was 0.06. The spread across folds documents threshold instability. Stage 1 remained experimental and auxiliary, and tau was not used in the final K1 classifier.

## Figure 4.x Stage 1 ROC and Precision-Recall Evidence

This figure compares the initial Stage 1 configuration with the W1 class-and-group weighted Stage 1 configuration using TRAIN-only ROC-AUC and Normal PR-AUC. W1 improved ROC-AUC from 0.696260 to 0.758050 and Normal PR-AUC from 0.014019 to 0.016167, but precision-recall performance for the Normal class remained weak and the W1 false-Normal incident rate was 0.265188. Therefore Stage 1 was not adopted as a final hard gate and remained auxiliary. Actual ROC/PR curves were not regenerated. The out-of-fold probability Parquet files exist, but no Parquet engine was available in the current runtime, so Figure 4.x uses authoritative summary AUC metrics only.

## Evidence Boundary

All Section 4.5 outputs are based on existing TRAIN-only artifacts:

- `docs/stage1_threshold_results_v1.csv`
- `data/modeling/stage1_threshold_selection_summary_v1.csv`
- `data/modeling/stage1_threshold_stability_v1.csv`
- `data/modeling/stage1_class_group_weight_results_v1.csv`
- `data/modeling/stage1_class_group_weight_probability_comparison_v1.csv`

No model was retrained. No threshold was reselected. Validation was not accessed or recomputed. Final Holdout was not accessed or recomputed.
