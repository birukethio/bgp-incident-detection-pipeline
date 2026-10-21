# Evaluation Integrity Narrative v1

TRAIN was used for iterative data engineering, feature development, model comparison, and K1 architecture development. Grouped cross-validation used incident identity as the grouping unit so windows from the same incident could not cross folds.

Validation was first opened in Phase J for a single predeclared confirmation of the refined XGBoost candidate. K1 was subsequently developed as a versioned TRAIN-only post-Validation experiment and was not evaluated on Validation; therefore K1 should not be described as Validation-confirmed.

Final Holdout remained sealed through K1, K2, K2.5, and L0. Phase L was the first Final Holdout access for the fixed deployable K1 model. No model changes followed Holdout evaluation.

Stage 1 Normal-vs-Incident discrimination remains explicitly auxiliary and unresolved.
