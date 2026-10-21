# Section 4.6 Figure Caption

**Figure 4.8. Random Forest optimization and stability results, TRAIN-only grouped cross-validation.** The figure compares the V4/I1 Random Forest baseline, the Phase H tuned Random Forest winner, and the Phase H2 refined Random Forest candidate. Phase H increased incident Macro F1 from 0.742814 to 0.783443. Phase H2 produced a smaller additional increase to 0.784588 and includes multi-seed stability analysis (artifact SD = 0.001342). These are development results computed only on the TRAIN partition using grouped cross-validation; Validation and Final Holdout were not accessed or recomputed. The refined RF is the strongest Random Forest benchmark retained for later RF-vs-XGBoost comparison, not the final Praxis model.

Source artifacts: `data/modeling/rf_hyperparameter_search_results_v1.csv`, `data/modeling/rf_multiseed_stability_results_v1.csv`, `data/modeling/rf_h2_final_comparison_v1.csv`, and `config/final_model_candidate_v2_1_rf_refined.yaml`.
