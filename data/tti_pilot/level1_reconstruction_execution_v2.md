# Level-1 Reconstruction Execution v2

Scope: TRAIN-only reconstruction and probability-fingerprint verification.

- Validation accessed/recomputed: NO
- Final Holdout accessed/recomputed: NO
- TTI scoring performed: NO
- Hyperparameter tuning/search performed: NO
- Frozen primary Praxis artifacts modified: NO

Historically plausible candidates were reconstructed only to resolve the `tree_method` ambiguity. Selection used preserved TRAIN probability fingerprints, not Macro F1 or TTI performance.

Selected `hist_njobs_minus1` using probability-fingerprint equivalence only.

Disposition: `RECONSTRUCTED_LEVEL1_EQUIVALENCE_PASS`
