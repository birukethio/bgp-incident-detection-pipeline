# K2.5 RF vs XGBoost Architecture Comparator v1

K2.5 is a bounded TRAIN-only post-Validation architecture comparator. It compares XGB->XGB, XGB->RF, RF->XGB, and RF->RF under the same grouped nested topology and frozen K1 meta-feature schema. Validation is not used, and Final Holdout remains sealed. No ensembles, new features, or hyperparameter searches are introduced.
