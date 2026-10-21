# Locked Hypothesis Specification v1

## H1: Final Classification and Ranking Performance

**Population.** All events in the locked independent confirmation cohort that pass predeclared metadata, overlap, RouteViews reconstruction, and V4 compatibility gates.

**Model.** Frozen XGBoost-to-XGBoost K1 architecture with no retraining, tuning, threshold selection, feature selection, or recalibration.

**Primary metric.** Incident-level Macro F1.

**Secondary metrics.** Top-1 accuracy, Top-2 accuracy, MRR, per-class precision/recall/F1, confusion matrix, and mean true-class rank.

**Minimum practical support rule.** H1 is supported if Macro F1 is at least 0.70 and the incident-level bootstrap 95% CI lower bound is at least 0.60, with Top-2 at least 0.85. These are practical confirmation floors, not a replacement for the terminal Final Holdout result.

**Statistical procedure.** Incident-level paired or unpaired bootstrap as applicable, 10,000 resamples, fixed seed 20260914, percentile 95% CI. The incident is the unit of inference.

**Decision rule.**

- `SUPPORTED`: primary floor and ranking floor pass.
- `SUPPORTED_WITH_CAVEAT`: point estimate passes but CI lower bound or a class-specific result requires review.
- `NOT_SUPPORTED`: primary point estimate falls below floor or a severe class-specific failure is observed.

## H2: Behavioral-Only vs Behavioral + CAIDA + RPKI/ROV

**Question.** Does the full V4 representation materially improve over Behavioral-only representation on an independent confirmation cohort?

**Comparator.** Behavioral-only frozen comparator may be used only if a pre-existing model/config can be reconstructed and locked before confirmation scoring. No new training may occur after confirmation labels are inspected.

**Primary metric.** Paired incident-level Macro F1 difference: V4 minus Behavioral-only.

**Minimum practical difference.** +0.03 Macro F1.

**Secondary metrics.** Top-2, MRR, Hijack F1, Leak F1, Outage F1.

**Statistical procedure.** Paired incident bootstrap over incidents, 10,000 resamples, fixed seed 20260914, percentile 95% CI.

**Execution gate.** If no artifact-equivalent Behavioral-only comparator can be frozen before scoring, H2 should be documented as not executable on the independent confirmation set without methodological change.

## H3: Mean Aggregation vs Temporal Stacking

**Question.** Does the K1 temporal stacker materially improve incident-level classification/ranking over mean probability aggregation on the same independent confirmation cohort?

**Comparator.** Mean class probability across eligible incident windows using the same frozen Level-1 predictions.

**Primary metric.** Paired incident-level Macro F1 difference: K1 stacker minus mean aggregation.

**Minimum practical difference.** +0.03 Macro F1 or +0.02 MRR, with no severe per-class regression.

**Secondary metrics.** Top-1, Top-2, MRR, per-class F1, and fold/source-specific sensitivity where sample size permits.

**Statistical procedure.** Paired incident bootstrap, 10,000 resamples, fixed seed 20260914, percentile 95% CI.

**Decision rule.**

- `SUPPORTED`: point estimate meets minimum practical difference and CI is not strongly negative.
- `SUPPORTED_WITH_CAVEAT`: improvement is small or class-specific degradation appears.
- `NOT_SUPPORTED`: mean aggregation matches/exceeds K1 or K1 has severe class-specific degradation.

## General Rules

- No Final Holdout access.
- No model updates after seeing confirmation performance.
- No post-hoc event exclusions except failures covered by the predeclared exclusion rules.
- All comparisons must use identical eligible incident denominators.
