# Section 4.12 Figure Captions

**Figure 4.12. Final Holdout primary performance for the frozen K1 architecture.** The figure reports the one-time terminal Final Holdout incident-level Macro F1, Top-1 accuracy, Top-2 accuracy, and MRR for 213 incidents. The Macro F1 interval is the existing 95% bootstrap confidence interval from the frozen Phase L artifact; no new bootstrap samples were generated for this documentation figure.

**Figure 4.13. Final Holdout true-class ranking distribution.** The figure shows the rank position assigned to the true incident class across the 213 Final Holdout incidents. The model ranked the true class first for 196 incidents, second for 15 incidents, and third for 2 incidents, yielding Top-2 correctness of 211/213 = 0.990610.

**Figure 4.14. Fixed TRAIN nested-CV reference versus Final Holdout.** The figure compares the fixed deployable K1 TRAIN nested-CV reference against the one-time Final Holdout evaluation for Macro F1, Top-1, Top-2, and MRR. This comparison uses the fixed deployable TRAIN values, not the earlier fold-selected K1 result, and is intended to show the observed generalization gap transparently.
