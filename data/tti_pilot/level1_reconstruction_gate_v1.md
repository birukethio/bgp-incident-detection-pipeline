# Level-1 Reconstruction Gate v1

## Gate Result

The original serialized frozen Level-1 model cannot be used because it was not preserved as a loadable artifact. However, the final training recipe is substantially recoverable:

- exact TRAIN corpus path recovered;
- exact TRAIN roster recovered;
- exact V4 feature schema and ordering recovered;
- exact I1 sample-weight function recovered;
- exact XGBoost hyperparameters recovered;
- class order recovered;
- missing-value handling recovered;
- grouped fold assignment artifact recovered;
- final protocol identifies the deployable Level-1 form as a five-model crossfit ensemble;
- TRAIN-derived probability fingerprints exist for verification.

The main caveats are seed sensitivity, missing serialized imputer/model state, environment mismatch, and the need to verify reproduced probabilities rather than accepting similar performance.

## Required Future Reconstruction Rule

A future reconstruction phase must rebuild the five fold-specific Level-1 XGBoost models only from TRAIN artifacts, serialize them as a new clearly versioned reconstructed artifact, and compare their probabilities against preserved TRAIN OOF fingerprints before any TTI scoring. Validation and Final Holdout must remain untouched unless a separate historical read-only verification is explicitly authorized.

Disposition: SAFE_TO_RECONSTRUCT_AND_VERIFY
