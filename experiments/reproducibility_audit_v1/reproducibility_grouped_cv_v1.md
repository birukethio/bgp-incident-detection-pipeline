# Grouped Cross Validation Reproducibility v1

## Grouping Rule

Cross-validation is incident grouped: no incident appears in more than one split for a given training/evaluation comparison. Window rows inherit incident membership, preventing window-level leakage.

## Fold Assignment Evidence

Recovered artifacts cite `data/modeling/baseline_v1_grouped_cv_assignments_v1.csv`, with `cv_seed=20260828`, and K1 leakage audits confirm grouped out-of-fold probability generation for Level-1.

## Validation and Holdout

Validation was first accessed in Phase J for a single confirmation of the locked refined XGBoost candidate. K1 was developed after Validation using TRAIN-only nested/grouped procedures and was not Validation-confirmed. Final Holdout remained sealed until Phase L and is now closed.
