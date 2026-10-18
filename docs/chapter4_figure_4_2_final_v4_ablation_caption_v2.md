# Figure 4.2 title and caption

**Title:** Figure 4.2. TRAIN-Only V4 Feature-Family Ablation and Class-Specific Sensitivity

**Caption:** Leave-one-family-out ablation was performed under the frozen V4/I1 TRAIN-only grouped cross-validation framework. Panel A reports the change in incident-level Macro F1 after removing each feature family from the full 74-feature V4 representation; negative values indicate lower performance after removal. Panel B reports the corresponding class-specific F1 changes for Hijack, Leak, and Outage. Removing the 16 RPKI/ROV features produced the largest overall decrease and the largest Hijack-specific decrease. CAIDA removal produced a small positive overall Macro-F1 change despite reducing each individual class F1, reflecting the difference between fold-aggregated macro metrics and the displayed class-specific means. These findings are controlled TRAIN-only associations and should not be interpreted as causal proof.

**Authoritative source:** `data/modeling/feature_family_ablation_results_v1.csv`, summarized in `docs/chapter4_feature_family_ablation_results_v1.csv`.

**Important boundary:** The unsupported aggregate removal of all 44 Behavioral features is not shown because that experiment does not exist in the authoritative final ablation artifact.
